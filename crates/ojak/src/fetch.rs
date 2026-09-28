//! Fetching documents from other servers.
//!
//! A fetch is a GET through the guarded [`Client`], signed when the caller
//! gives a key so that a server requiring authorized fetch answers it. The
//! fetcher follows redirects itself: a signature covers the URL it was made
//! for, so each hop is checked and signed again for where it goes, and a
//! redirect from `https` to `http` is refused. A signed GET that is refused
//! is tried once in the other scheme, as a delivery is, and the fetcher
//! remembers which scheme each host accepted.
//!
//! [`Fetcher::document`] returns a document only when it may be trusted as
//! what it says it is: it came as ActivityPub, it is a JSON object with an
//! `id`, and that `id` has the origin of the URL it was finally served from.
//! Anyone can serve a document naming any `id`, and the only thing that
//! vouches for an unsigned one is where it came from. [`Fetcher::lookup`]
//! goes one step further, as Mastodon does: a document whose `id` is on
//! another origin is fetched again from its `id`, once, and trusted only if
//! the owner of the `id` serves it.
//!
//! A portable object, whose `id` is an `ap://` IRI, is never trusted from a
//! fetch alone: its origin is a key, and only its proof vouches for it.
//! [`Fetcher::portable`] asks its gateways for it and keeps the first copy
//! whose proof holds; [`Fetcher::lookup`] sends a portable URL there.

use crate::client::{Client, RequestError, Response};
use crate::delivery::{Scheme, SenderKey};
use crate::portable::{self, DidResolver};
use ojak_core::origin::Origin;
use ojak_core::portable::ApUri;
use ojak_runtime::{rfc9421, signature};
use ojak_vocab::json::{FromJson, ToJson};
use ojak_vocab::{Read, ReadError, Registry, read_reporting};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock, Mutex};
use url::Url;

/// What a fetch asks for: ActivityStreams, in either of its media types.
pub const ACTIVITY_ACCEPT: &str = "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

/// What a gateway is asked for, as FEP-ef61 has it.
pub const PORTABLE_ACCEPT: &str =
    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

/// Why a fetch did not produce a document.
#[derive(Debug)]
pub enum FetchError {
    /// The request was not answered, or was refused before it was sent.
    Request(RequestError),
    /// The request could not be signed.
    Signing(String),
    /// A redirect could not be followed: too many, no `Location`, or from
    /// `https` to `http`.
    Redirect(String),
    /// The server answered with a status other than success.
    Status(u16),
    /// The response is not ActivityPub; the content type it had.
    NotActivityPub(String),
    /// The response is not a JSON object.
    Invalid(String),
    /// The document has no `id`.
    NoId,
    /// The document's `id` is not on the origin it was served from, and
    /// nothing else vouches for it.
    CrossOrigin { id: String, url: Url },
    /// The document was established but is not a value of the type asked
    /// for.
    Read(ReadError),
    /// No gateway served a portable object whose proof holds; why, for each
    /// gateway tried.
    Portable(Vec<(String, String)>),
}

impl FetchError {
    /// The status the server answered with, if it answered with one other
    /// than success. A 404 or 410 says the object is gone.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status(status) => Some(*status),
            _ => None,
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Signing(error) => write!(f, "signing: {error}"),
            Self::Redirect(error) => write!(f, "redirect: {error}"),
            Self::Status(status) => write!(f, "HTTP {status}"),
            Self::NotActivityPub(content_type) => {
                write!(f, "not ActivityPub: {content_type:?}")
            }
            Self::Invalid(error) => write!(f, "not a JSON object: {error}"),
            Self::NoId => f.write_str("document has no id"),
            Self::CrossOrigin { id, url } => {
                write!(f, "document served from {url} claims id {id}")
            }
            Self::Read(error) => error.fmt(f),
            Self::Portable(tried) if tried.is_empty() => {
                f.write_str("portable object with no gateway to ask")
            }
            Self::Portable(tried) => {
                f.write_str("no gateway served it:")?;
                for (gateway, why) in tried {
                    write!(f, " {gateway}: {why};")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for FetchError {}

impl From<RequestError> for FetchError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// A document, fetched and established as what it says it is.
#[derive(Clone, Debug, PartialEq)]
pub struct Document {
    /// Its `id`.
    pub id: String,
    /// The URL it was finally served from, after any redirects.
    pub url: Url,
    /// The document as it came, not yet normalised.
    pub json: Value,
}

/// A document fetched, established and read into a vocabulary type.
#[derive(Debug)]
pub struct Typed<T> {
    /// The document as it came, with where it came from.
    pub document: Document,
    /// What it read as, and what reading lost.
    pub read: Read<T>,
}

/// The contexts documents are read over, parsed once.
pub(crate) static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::bundled);

/// Contexts processed over [`REGISTRY`], kept for the next document naming
/// them. Processing a context costs ten times what reading the document
/// with it does, and the fediverse sends a few dozen distinct ones.
pub(crate) static CONTEXTS: LazyLock<ContextCache> = LazyLock::new(ContextCache::default);

/// A bounded [`ojak_jsonld::ContextCache`].
///
/// Inline contexts are the sender's to write, so a sender could name a new
/// one with every activity. Rather than grow with them, the cache starts
/// over when full; that costs only the processing it was saving.
#[derive(Default)]
pub(crate) struct ContextCache(Mutex<HashMap<String, Arc<ojak_jsonld::ProcessedContext>>>);

impl ContextCache {
    const CAPACITY: usize = 1_024;
}

impl ojak_jsonld::ContextCache for ContextCache {
    fn get(&self, key: &str) -> Option<Arc<ojak_jsonld::ProcessedContext>> {
        self.0.lock().ok()?.get(key).cloned()
    }

    fn put(&self, key: String, context: Arc<ojak_jsonld::ProcessedContext>) {
        if let Ok(mut contexts) = self.0.lock() {
            if contexts.len() >= Self::CAPACITY {
                contexts.clear();
            }
            contexts.insert(key, context);
        }
    }
}

/// Fetches from other servers. Cheap to share; one per process is enough.
pub struct Fetcher {
    client: Client,
    first_scheme: Scheme,
    /// The scheme each host last accepted.
    schemes: Mutex<HashMap<String, Scheme>>,
    resolver: Option<Arc<dyn DidResolver>>,
}

impl fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetcher")
            .field("client", &self.client)
            .field("first_scheme", &self.first_scheme)
            .finish_non_exhaustive()
    }
}

impl Fetcher {
    /// A fetcher that signs in `first_scheme` until a host has accepted one.
    #[must_use]
    pub fn new(client: Client, first_scheme: Scheme) -> Self {
        Self {
            client,
            first_scheme,
            schemes: Mutex::new(HashMap::new()),
            resolver: None,
        }
    }

    /// Resolve DID methods other than `did:key` with `resolver`, when
    /// verifying portable objects.
    #[must_use]
    pub fn did_resolver(mut self, resolver: Arc<dyn DidResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The resolver portable objects are verified with, if any.
    #[must_use]
    pub fn resolver(&self) -> Option<&dyn DidResolver> {
        self.resolver.as_deref()
    }

    /// The client the fetcher sends through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// GET `url`, signed with `key` when given, following redirects.
    ///
    /// The response's `url` is where it was finally served from.
    ///
    /// # Errors
    ///
    /// When a URL is refused, a redirect cannot be followed, the request
    /// cannot be signed, or it fails. A response with any other status is
    /// `Ok`.
    pub async fn get(
        &self,
        url: &Url,
        accept: &str,
        key: Option<&SenderKey>,
    ) -> Result<Response, FetchError> {
        let mut url = url.clone();
        let mut redirects = 0;
        loop {
            let response = self.get_once(&url, accept, key).await?;
            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            redirects += 1;
            if redirects > self.client.config().max_redirects {
                return Err(FetchError::Redirect("too many redirects".into()));
            }
            let location = response
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| FetchError::Redirect("no Location".into()))?;
            let next = url
                .join(location)
                .map_err(|error| FetchError::Redirect(format!("{location:?}: {error}")))?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err(FetchError::Redirect(format!("{url} to {next}")));
            }
            url = next;
        }
    }

    /// One request, with no redirect followed; a signed one refused in its
    /// first scheme is tried in the other.
    async fn get_once(
        &self,
        url: &Url,
        accept: &str,
        key: Option<&SenderKey>,
    ) -> Result<Response, FetchError> {
        let Some(key) = key else {
            return Ok(self.client.get_direct(url, headers(accept)?).await?);
        };
        let host = url.host_str().unwrap_or_default().to_owned();
        let first = self
            .schemes
            .lock()
            .expect("scheme lock")
            .get(&host)
            .copied()
            .unwrap_or(self.first_scheme);
        let mut response = self.signed(url, accept, key, first).await?;
        let mut scheme = first;
        if matches!(response.status, 400 | 401) {
            scheme = first.other();
            response = self.signed(url, accept, key, scheme).await?;
        }
        if (200..400).contains(&response.status) {
            self.schemes
                .lock()
                .expect("scheme lock")
                .insert(host, scheme);
        }
        Ok(response)
    }

    async fn signed(
        &self,
        url: &Url,
        accept: &str,
        key: &SenderKey,
        scheme: Scheme,
    ) -> Result<Response, FetchError> {
        let mut headers = headers(accept)?;
        match scheme {
            Scheme::DraftCavage => {
                let signed =
                    signature::sign_get_with_key(url.as_str(), &key.key_id, &key.private_key)
                        .map_err(|error| FetchError::Signing(error.to_string()))?;
                insert(&mut headers, "date", &signed.date)?;
                insert(&mut headers, "signature", &signed.signature)?;
            }
            Scheme::Rfc9421 => {
                let signed = rfc9421::sign_request(
                    "get",
                    url.as_str(),
                    None,
                    &key.key_id,
                    &rfc9421::SigningKey::Rsa(&key.private_key),
                )
                .map_err(|error| FetchError::Signing(error.to_string()))?;
                insert(&mut headers, "signature-input", &signed.signature_input)?;
                insert(&mut headers, "signature", &signed.signature)?;
            }
        }
        Ok(self.client.get_direct(url, headers).await?)
    }

    /// Fetch the ActivityPub document at `url` and establish it: served as
    /// ActivityPub with success, a JSON object, and with an `id` on the
    /// origin it was finally served from.
    ///
    /// # Errors
    ///
    /// As [`Fetcher::get`], and when the document is not established; a
    /// document whose `id` is elsewhere is [`FetchError::CrossOrigin`].
    pub async fn document(
        &self,
        url: &Url,
        key: Option<&SenderKey>,
    ) -> Result<Document, FetchError> {
        let response = self.get(url, ACTIVITY_ACCEPT, key).await?;
        if !(200..300).contains(&response.status) {
            return Err(FetchError::Status(response.status));
        }
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !is_activity_content_type(content_type) {
            return Err(FetchError::NotActivityPub(content_type.to_owned()));
        }
        let json: Value = serde_json::from_slice(&response.body)
            .map_err(|error| FetchError::Invalid(error.to_string()))?;
        if !json.is_object() {
            return Err(FetchError::Invalid("not an object".into()));
        }
        let id = json
            .get("id")
            .and_then(Value::as_str)
            .ok_or(FetchError::NoId)?
            .to_owned();
        if !served_by_its_origin(&id, &response.url) {
            return Err(FetchError::CrossOrigin {
                id,
                url: response.url,
            });
        }
        Ok(Document {
            id,
            url: response.url,
            json,
        })
    }

    /// [`Fetcher::document`], and when the document's `id` is on another
    /// origin, fetch that `id` instead, once: what comes back is trusted only
    /// if the owner of the `id` serves it.
    ///
    /// # Errors
    ///
    /// As [`Fetcher::document`], for the second fetch when there is one.
    ///
    /// A portable URL, `ap` or at a gateway, is fetched with
    /// [`Fetcher::portable`] instead.
    pub async fn lookup(&self, url: &Url, key: Option<&SenderKey>) -> Result<Document, FetchError> {
        if let Some(uri) = ApUri::parse(url.as_str()) {
            return self.portable(&uri, &[], key).await;
        }
        match self.document(url, key).await {
            Err(FetchError::CrossOrigin { id, url: served }) => {
                let Ok(own) = Url::parse(&id) else {
                    return Err(FetchError::CrossOrigin { id, url: served });
                };
                if !matches!(own.scheme(), "http" | "https") {
                    return Err(FetchError::CrossOrigin { id, url: served });
                }
                self.document(&own, key).await
            }
            other => other,
        }
    }
}

impl Fetcher {
    /// Fetch the portable object `uri` names from its gateways: the hints it
    /// carries, then `gateways`, in order. The first document served as
    /// ActivityPub whose `id` is `uri` and whose proof by `uri`'s DID holds
    /// is returned; a gateway that fails any of that is passed over.
    ///
    /// # Errors
    ///
    /// [`FetchError::Portable`], with why each gateway was passed over.
    pub async fn portable(
        &self,
        uri: &ApUri,
        gateways: &[&str],
        key: Option<&SenderKey>,
    ) -> Result<Document, FetchError> {
        let mut tried = Vec::new();
        let mut asked: Vec<&str> = Vec::new();
        for gateway in uri
            .gateways()
            .iter()
            .map(String::as_str)
            .chain(gateways.iter().copied())
        {
            if asked.contains(&gateway) {
                continue;
            }
            asked.push(gateway);
            match self.ask_gateway(uri, gateway, key).await {
                Ok(document) => return Ok(document),
                Err(why) => tried.push((gateway.to_owned(), why)),
            }
        }
        Err(FetchError::Portable(tried))
    }

    async fn ask_gateway(
        &self,
        uri: &ApUri,
        gateway: &str,
        key: Option<&SenderKey>,
    ) -> Result<Document, String> {
        let url = Url::parse(&uri.at_gateway(gateway)).map_err(|error| error.to_string())?;
        let response = self
            .get(&url, PORTABLE_ACCEPT, key)
            .await
            .map_err(|error| error.to_string())?;
        if !(200..300).contains(&response.status) {
            return Err(FetchError::Status(response.status).to_string());
        }
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !is_activity_content_type(content_type) {
            return Err(FetchError::NotActivityPub(content_type.to_owned()).to_string());
        }
        let json: Value =
            serde_json::from_slice(&response.body).map_err(|error| error.to_string())?;
        let id = portable::verify(&json, self.resolver())
            .await
            .map_err(|error| error.to_string())?;
        if id != *uri {
            return Err(format!("served {id} for {uri}"));
        }
        Ok(Document {
            id: json
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            url: response.url,
            json,
        })
    }

    /// [`Fetcher::lookup`], and read what it found into `T`: an actor, a
    /// note, `AnyObject` for whatever it turns out to be. What reading lost
    /// is in [`Read::lost`].
    ///
    /// # Errors
    ///
    /// As [`Fetcher::lookup`], and [`FetchError::Read`] when the document is
    /// not a `T`.
    pub async fn lookup_as<T: FromJson + ToJson>(
        &self,
        url: &Url,
        key: Option<&SenderKey>,
    ) -> Result<Typed<T>, FetchError> {
        let document = self.lookup(url, key).await?;
        let read = read_reporting(&REGISTRY, &document.json).map_err(FetchError::Read)?;
        Ok(Typed { document, read })
    }
}

/// Whether `id` has the origin of `url`, where it was served from. A
/// portable `id` has a key for its origin, never a host, so it is never
/// vouched for by where it was served.
fn served_by_its_origin(id: &str, url: &Url) -> bool {
    match (Origin::of(id), Origin::of(url.as_str())) {
        (Some(id @ Origin::Web { .. }), Some(served)) => id == served,
        _ => false,
    }
}

/// Whether `content_type` is ActivityStreams: `application/activity+json`,
/// or `application/ld+json` with the ActivityStreams profile. Plain JSON is
/// not enough; a server that lets its users upload files would otherwise
/// serve documents in its own name that none of its actors wrote.
#[must_use]
pub fn is_activity_content_type(content_type: &str) -> bool {
    let mut parts = content_type.split(';').map(str::trim);
    let essence = parts.next().unwrap_or_default().to_ascii_lowercase();
    match essence.as_str() {
        "application/activity+json" => true,
        "application/ld+json" => parts.any(|parameter| {
            parameter.split_once('=').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("profile")
                    && value
                        .trim()
                        .trim_matches('"')
                        .split_whitespace()
                        .any(|profile| profile == "https://www.w3.org/ns/activitystreams")
            })
        }),
        _ => false,
    }
}

fn headers(accept: &str) -> Result<HeaderMap, FetchError> {
    let mut headers = HeaderMap::new();
    insert(&mut headers, "accept", accept)?;
    Ok(headers)
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), FetchError> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| FetchError::Signing(format!("{name}: {error}")))?;
    headers.insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activitystreams_is_recognised_in_either_media_type() {
        for content_type in [
            "application/activity+json",
            "application/activity+json; charset=utf-8",
            "Application/Activity+JSON",
            "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
            "application/ld+json;profile=https://www.w3.org/ns/activitystreams",
            "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams https://example.com/other\"",
        ] {
            assert!(is_activity_content_type(content_type), "{content_type}");
        }
        for content_type in [
            "",
            "application/json",
            "application/ld+json",
            "application/ld+json; profile=\"https://example.com/other\"",
            "text/html",
        ] {
            assert!(!is_activity_content_type(content_type), "{content_type}");
        }
    }

    #[test]
    fn an_id_is_vouched_for_only_by_its_own_origin() {
        let url = Url::parse("https://a.example/users/bob").unwrap();
        assert!(served_by_its_origin("https://a.example/users/bob", &url));
        assert!(served_by_its_origin("https://A.example:443/other", &url));
        assert!(!served_by_its_origin("https://b.example/users/bob", &url));
        assert!(!served_by_its_origin("http://a.example/users/bob", &url));
        assert!(!served_by_its_origin(
            "ap://did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2/actor",
            &url
        ));
        assert!(!served_by_its_origin("not an iri", &url));
    }
}
