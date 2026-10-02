//! JSON-LD contexts ojak does not ship, fetched to check a Linked Data
//! Signature as Mastodon checks one.
//!
//! An `RsaSignature2017` signs the RDF a document means, and what it means
//! depends on every context it names. Mastodon turns a signed activity into
//! RDF with the contexts it preloads and fetches any other
//! (`JsonLdHelper#load_jsonld_context`): a GET asking for
//! `application/ld+json`, taken only when it answers `200` with that type,
//! read up to a megabyte, and kept in its cache for 30 days. [`fetch`] makes
//! that request, [`fetch_cached`] keeps what it got in a [`KvStore`], and
//! [`resolve`] finds what a document is missing and adds it to a
//! [`Registry`].
//!
//! Nothing here runs unless an application asks: reading a document never
//! fetches a context (see *ojak-jsonld*'s `contexts/README.md` for why), and
//! the inbox fetches only to check the signature on an activity it has to
//! take on one, when the application has given it a loader
//! (`Builder::remote_contexts`). The fetch is the request-forgery surface
//! that boundary exists to avoid, so it is bounded on every side: the
//! guarded client refuses private addresses unless the application allows
//! them and follows at most its configured redirects, a context is at most
//! [`MAX_CONTEXT_BYTES`], and a document may cause at most
//! [`Limits::max_remote`] fetches within [`Limits::timeout`] in all.

use crate::client::{Client, RequestError};
use crate::kv::{KvError, KvStore};
use http::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use ojak_jsonld::Registry;
use serde_json::Value;
use std::fmt;
use std::future::Future;
use std::time::Duration;
use url::Url;

/// What a context is asked for as, and the only type it is taken as.
pub const MEDIA_TYPE: &str = "application/ld+json";

/// How long a fetched context is kept: Mastodon's `expires_in: 30.days`.
pub const CACHE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The largest context taken: `Request#body_with_limit`'s default.
pub const MAX_CONTEXT_BYTES: usize = 1024 * 1024;

/// Bounds on what one document may cause to be fetched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// How many contexts one document may cause to be loaded, counting
    /// those its contexts name in turn, which is also how deeply they may
    /// nest. Every context the fediverse names but ojak does not ship is
    /// one server's own, and an activity names at most a couple.
    pub max_remote: usize,
    /// How long loading them may take, all together. Each request is also
    /// held to the client's own timeouts.
    pub timeout: Duration,
    /// The bounds on expanding the document, as *ojak-jsonld* applies them.
    pub json_ld: ojak_jsonld::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_remote: 8,
            // `Request::TIMEOUT[:read_deadline]`.
            timeout: Duration::from_secs(30),
            json_ld: ojak_jsonld::Limits::default(),
        }
    }
}

/// Why a context could not be loaded, or a document's contexts resolved.
#[derive(Debug)]
pub enum Error {
    /// The IRI is not an `http` or `https` URL.
    InvalidIri(String),
    /// The request was refused or failed: a private address, a response
    /// past [`MAX_CONTEXT_BYTES`], a network failure.
    Request(String, RequestError),
    /// The server answered other than `200`.
    Status(String, u16),
    /// The server answered with a type other than [`MEDIA_TYPE`].
    MediaType(String, Option<String>),
    /// What came back is not a JSON object with an `@context` member.
    NotAContext(String),
    /// The application's loader failed.
    Load(String, String),
    /// The key-value store failed.
    Kv(KvError),
    /// The document named more contexts to load than [`Limits::max_remote`].
    TooMany(usize),
    /// Loading took longer than [`Limits::timeout`].
    TimedOut,
    /// The document cannot be expanded.
    JsonLd(ojak_jsonld::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIri(iri) => write!(f, "not a context IRI ojak will fetch: {iri}"),
            Self::Request(iri, error) => write!(f, "context {iri}: {error}"),
            Self::Status(iri, status) => write!(f, "context {iri}: answered {status}"),
            Self::MediaType(iri, Some(kind)) => {
                write!(f, "context {iri}: served as {kind}, not {MEDIA_TYPE}")
            }
            Self::MediaType(iri, None) => write!(f, "context {iri}: served with no type"),
            Self::NotAContext(iri) => write!(f, "context {iri}: not a JSON-LD context"),
            Self::Load(iri, why) => write!(f, "context {iri}: {why}"),
            Self::Kv(error) => write!(f, "context cache: {error}"),
            Self::TooMany(limit) => {
                write!(
                    f,
                    "names more than {limit} contexts ojak would have to fetch"
                )
            }
            Self::TimedOut => f.write_str("fetching its contexts took too long"),
            Self::JsonLd(error) => write!(f, "JSON-LD: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// Fetch the context `iri` names, as `JsonLdHelper#load_jsonld_context`
/// requests one: a GET asking for [`MEDIA_TYPE`], taken only when it
/// answers `200` with that type, its body at most [`MAX_CONTEXT_BYTES`] and
/// at most the client's own limit. What comes back is the body, which
/// Mastodon keeps as it came.
///
/// # Errors
///
/// When the IRI is not one to fetch, the client refuses it or fails, or the
/// response is not a context by those rules.
pub async fn fetch(client: &Client, iri: &str) -> Result<String, Error> {
    let url = Url::parse(iri).map_err(|_| Error::InvalidIri(iri.to_owned()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::InvalidIri(iri.to_owned()));
    }
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
    let response = client
        .get(&url, headers)
        .await
        .map_err(|error| Error::Request(iri.to_owned(), error))?;
    if response.status != 200 {
        return Err(Error::Status(iri.to_owned(), response.status));
    }
    // `res.mime_type`: the type without its parameters.
    let kind = response
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    if kind.as_deref() != Some(MEDIA_TYPE) {
        return Err(Error::MediaType(iri.to_owned(), kind));
    }
    if response.body.len() > MAX_CONTEXT_BYTES {
        return Err(Error::Request(iri.to_owned(), RequestError::TooLarge));
    }
    String::from_utf8(response.body).map_err(|_| Error::NotAContext(iri.to_owned()))
}

/// [`fetch`], kept in `kv` for `ttl` (Mastodon keeps it for [`CACHE_TTL`])
/// under `["jsonld", "context", iri]`, as `Rails.cache` keeps it under
/// `jsonld:context:<iri>`. Only a context that was taken is kept.
///
/// # Errors
///
/// As [`fetch`], or when the store fails.
pub async fn fetch_cached<K: KvStore>(
    kv: &K,
    client: &Client,
    iri: &str,
    ttl: Duration,
) -> Result<String, Error> {
    let key = ["jsonld", "context", iri];
    if let Some(Value::String(body)) = kv.get(&key).await.map_err(Error::Kv)? {
        return Ok(body);
    }
    let body = fetch(client, iri).await?;
    kv.set(&key, Value::String(body.clone()), Some(ttl))
        .await
        .map_err(Error::Kv)?;
    Ok(body)
}

/// `registry` with every context `document` names that it does not hold,
/// each loaded with `load` (the body [`fetch`] would return): what a Linked
/// Data Signature on `document` has to be checked over. `None` when
/// `registry` already holds every one, so a caller keeps using the registry,
/// and any cache, it already has.
///
/// A context a loaded one names is loaded too. Every load counts against
/// [`Limits::max_remote`], and all of them together against
/// [`Limits::timeout`].
///
/// # Errors
///
/// When a context cannot be loaded or is not a context, when there are more
/// than the limits allow, or when the document cannot be expanded.
pub async fn resolve<F, Fut, E>(
    registry: &Registry,
    document: &Value,
    limits: Limits,
    load: F,
) -> Result<Option<Registry>, Error>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String, E>>,
    E: fmt::Display,
{
    tokio::time::timeout(
        limits.timeout,
        resolve_within(registry, document, limits, load),
    )
    .await
    .unwrap_or(Err(Error::TimedOut))
}

async fn resolve_within<F, Fut, E>(
    registry: &Registry,
    document: &Value,
    limits: Limits,
    mut load: F,
) -> Result<Option<Registry>, Error>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String, E>>,
    E: fmt::Display,
{
    let mut extended: Option<Registry> = None;
    let mut loaded = 0;
    loop {
        let current = extended.as_ref().unwrap_or(registry);
        let missing = ojak_jsonld::rdf::unresolved_contexts(current, document, limits.json_ld)
            .map_err(Error::JsonLd)?;
        if missing.is_empty() {
            return Ok(extended);
        }
        let mut next = current.clone();
        for iri in missing {
            if next.knows(&iri) {
                continue;
            }
            loaded += 1;
            if loaded > limits.max_remote {
                return Err(Error::TooMany(limits.max_remote));
            }
            let body = load(iri.clone())
                .await
                .map_err(|error| Error::Load(iri.clone(), error.to_string()))?;
            let parsed: Value =
                serde_json::from_str(&body).map_err(|_| Error::NotAContext(iri.clone()))?;
            if !parsed
                .as_object()
                .is_some_and(|members| members.contains_key("@context"))
            {
                return Err(Error::NotAContext(iri));
            }
            next = next.with(iri, parsed);
        }
        extended = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;

    fn signed_with(context: Value) -> Value {
        json!({
            "@context": context,
            "id": "https://a.example/notes/1",
            "type": "Note",
            "content": "hello",
        })
    }

    #[tokio::test]
    async fn nothing_is_loaded_for_a_document_over_bundled_contexts() {
        let registry = Registry::bundled();
        let document = signed_with(json!("https://www.w3.org/ns/activitystreams"));
        let resolved = resolve(&registry, &document, Limits::default(), |iri| async move {
            Err::<String, _>(format!("asked for {iri}"))
        })
        .await
        .unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn a_context_and_the_one_it_names_are_loaded() {
        let registry = Registry::bundled();
        let document = signed_with(json!([
            "https://www.w3.org/ns/activitystreams",
            "https://a.example/ns"
        ]));
        let asked = RefCell::new(Vec::new());
        let resolved = resolve(&registry, &document, Limits::default(), |iri| {
            asked.borrow_mut().push(iri.clone());
            async move {
                Ok::<_, String>(match iri.as_str() {
                    "https://a.example/ns" => json!({"@context": [
                        "https://a.example/more",
                        {"mood": "https://a.example/ns#mood"}
                    ]})
                    .to_string(),
                    _ => {
                        json!({"@context": {"weather": "https://a.example/ns#weather"}}).to_string()
                    }
                })
            }
        })
        .await
        .unwrap()
        .expect("contexts were added");
        assert_eq!(
            *asked.borrow(),
            ["https://a.example/ns", "https://a.example/more"]
        );
        let canonical = ojak_jsonld::rdf::canonize(
            &resolved,
            &json!({
                "@context": ["https://www.w3.org/ns/activitystreams", "https://a.example/ns"],
                "id": "https://a.example/notes/1",
                "mood": "sunny",
                "weather": "fair",
            }),
        )
        .unwrap();
        assert!(canonical.contains("<https://a.example/ns#mood> \"sunny\""));
        assert!(canonical.contains("<https://a.example/ns#weather> \"fair\""));
    }

    #[tokio::test]
    async fn too_many_contexts_are_refused() {
        let registry = Registry::bundled();
        let names: Vec<Value> = (0..3)
            .map(|n| Value::from(format!("https://a.example/ns/{n}")))
            .collect();
        let document = signed_with(Value::Array(names));
        let limits = Limits {
            max_remote: 2,
            ..Limits::default()
        };
        let result = resolve(&registry, &document, limits, |_| async {
            Ok::<_, String>(json!({"@context": {}}).to_string())
        })
        .await;
        assert!(matches!(result, Err(Error::TooMany(2))), "{result:?}");
    }

    #[tokio::test]
    async fn a_context_that_names_itself_in_a_ring_is_bounded() {
        let registry = Registry::bundled();
        let document = signed_with(json!("https://a.example/0"));
        // Each names the next, forever.
        let result = resolve(&registry, &document, Limits::default(), |iri| async move {
            let n: u32 = iri.rsplit('/').next().unwrap().parse().unwrap();
            Ok::<_, String>(json!({"@context": format!("https://a.example/{}", n + 1)}).to_string())
        })
        .await;
        assert!(matches!(result, Err(Error::TooMany(8))), "{result:?}");
    }

    #[tokio::test]
    async fn what_is_not_a_context_is_refused() {
        let registry = Registry::bundled();
        let document = signed_with(json!("https://a.example/ns"));
        for body in ["not json", "[1, 2]", "{\"terms\": {}}"] {
            let result = resolve(&registry, &document, Limits::default(), |_| async move {
                Ok::<_, String>(body.to_owned())
            })
            .await;
            assert!(
                matches!(result, Err(Error::NotAContext(_))),
                "{body}: {result:?}"
            );
        }
        let result = resolve(&registry, &document, Limits::default(), |_| async {
            Err::<String, _>("gone")
        })
        .await;
        assert!(matches!(result, Err(Error::Load(_, _))), "{result:?}");
    }

    #[tokio::test]
    async fn loading_is_held_to_a_deadline() {
        let registry = Registry::bundled();
        let document = signed_with(json!("https://a.example/ns"));
        let limits = Limits {
            timeout: Duration::from_millis(20),
            ..Limits::default()
        };
        let result = resolve(&registry, &document, limits, |_| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, String>(json!({"@context": {}}).to_string())
        })
        .await;
        assert!(matches!(result, Err(Error::TimedOut)), "{result:?}");
    }
}
