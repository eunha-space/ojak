//! Finding an actor by its handle, through WebFinger (RFC 7033).
//!
//! A handle, `@alice@social.example`, is an [`Address`]: a user and a host.
//! [`Fetcher::webfinger`] asks the host's WebFinger endpoint for it, through
//! the guarded client, and reads the actors its `self` links name. The host
//! answers only for itself: an actor it names on another origin is a claim an
//! application that shows the handle should check against the actor, as it
//! would any other.

use crate::fetch::{FetchError, Fetcher};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;
use std::fmt;
use std::future::Future;
use url::Url;

/// What a WebFinger query asks for.
pub const JRD_ACCEPT: &str = "application/jrd+json, application/json";

/// What a host-meta query asks for.
pub const XRD_ACCEPT: &str = "application/xrd+xml, application/xml, text/xml";

/// A handle: a user at a host.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    user: String,
    host: String,
}

impl Address {
    /// Read a handle as people write it, `@alice@social.example`,
    /// `alice@social.example`, or `acct:alice@social.example`. The user is
    /// what RFC 3986 allows unencoded in a URI's userinfo, and
    /// percent-encodings; the host a domain name, lower-cased, or an IP
    /// literal, with a port if it has one. A host in Unicode is not read: an
    /// international domain is written in its ASCII form, as the host
    /// serves it.
    #[must_use]
    pub fn parse(handle: &str) -> Option<Self> {
        let handle = handle.trim();
        let handle = handle
            .strip_prefix("acct:")
            .or_else(|| handle.strip_prefix('@'))
            .unwrap_or(handle);
        let (user, host) = handle.rsplit_once('@')?;
        let host = host.to_ascii_lowercase();
        let valid_user = !user.is_empty()
            && user.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                            | b'%'
                    )
            });
        if !valid_user || !is_host(&host) {
            return None;
        }
        Some(Self {
            user: user.to_owned(),
            host,
        })
    }

    /// The user, before the `@`.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The host, with its port if it has one.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The `acct:` URI WebFinger is asked about.
    #[must_use]
    pub fn acct(&self) -> String {
        format!("acct:{}@{}", self.user, self.host)
    }

    /// The URL of the host's WebFinger query for this address, over `https`,
    /// or over `http` for an onion service, as Mastodon asks one.
    ///
    /// # Panics
    ///
    /// Never: the host has been checked to be one.
    #[must_use]
    pub fn webfinger_url(&self) -> Url {
        /// What a query parameter's value may not hold unencoded.
        const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'.')
            .remove(b'_')
            .remove(b'~')
            .remove(b':')
            .remove(b'@');
        let acct = self.acct();
        let resource = utf8_percent_encode(&acct, QUERY_VALUE);
        let scheme = if self.is_onion() { "http" } else { "https" };
        Url::parse(&format!(
            "{scheme}://{}/.well-known/webfinger?resource={resource}",
            self.host
        ))
        .expect("a checked host makes a URL")
    }
}

impl Address {
    /// The URL of the host's host-meta document (RFC 6415), over `https`,
    /// or over `http` for an onion service, as Mastodon asks it.
    ///
    /// # Panics
    ///
    /// Never: the host has been checked to be one.
    #[must_use]
    pub fn host_meta_url(&self) -> Url {
        let scheme = if self.is_onion() { "http" } else { "https" };
        Url::parse(&format!("{scheme}://{}/.well-known/host-meta", self.host))
            .expect("a checked host makes a URL")
    }

    fn is_onion(&self) -> bool {
        self.host
            .split(':')
            .next()
            .is_some_and(|name| name.ends_with(".onion"))
    }
}

/// The WebFinger query template a host-meta document (an XRD) gives in its
/// `lrdd` link, as Mastodon's `Webfinger#url_from_template` reads it: the
/// first `Link` element, in the document's default namespace, whose `rel`
/// is `lrdd`.
///
/// # Errors
///
/// When the document is not XML, has no default namespace, or has no such
/// link with a `template`.
pub fn lrdd_template(xrd: &str) -> Result<String, String> {
    let document =
        roxmltree::Document::parse(xrd).map_err(|error| format!("invalid XML: {error}"))?;
    let namespace = document
        .root_element()
        .default_namespace()
        .ok_or("invalid XML: no default namespace")?;
    document
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "Link"
                && node.tag_name().namespace() == Some(namespace)
                && node.attribute("rel") == Some("lrdd")
        })
        .ok_or("host-meta without link to Webfinger")?
        .attribute("template")
        .map(str::to_owned)
        .ok_or_else(|| "host-meta link to Webfinger without a template".to_owned())
}

/// An `acct:` URI or a bare handle split at its `@`s as Ruby's
/// `split('@')` splits it, keeping the first two parts: what Mastodon's
/// `ProcessAccountService#split_acct` reads an actor's [FEP-2c59]
/// `webfinger` property as. A part that is missing is empty.
///
/// [FEP-2c59]: https://codeberg.org/fediverse/fep/src/branch/main/fep/2c59/fep-2c59.md
#[must_use]
pub fn split_acct(acct: &str) -> (String, String) {
    let acct = acct.strip_prefix("acct:").unwrap_or(acct);
    let mut parts = acct.split('@');
    (
        parts.next().unwrap_or_default().to_owned(),
        parts.next().unwrap_or_default().to_owned(),
    )
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.user, self.host)
    }
}

/// Whether `host` is a lower-case domain name or an IP literal, with a
/// numeric port if it has one.
fn is_host(host: &str) -> bool {
    let (name, port) = if let Some(literal) = host.strip_prefix('[') {
        let Some((address, rest)) = literal.split_once(']') else {
            return false;
        };
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match rest {
            "" => return true,
            rest => (None, rest.strip_prefix(':')),
        }
    } else {
        match host.split_once(':') {
            Some((name, port)) => (Some(name), Some(port)),
            None => (Some(host), None),
        }
    };
    let port_ok = port.is_none_or(|port| port.parse::<u16>().is_ok());
    let name_ok = name.is_none_or(|name| {
        !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    });
    port_ok && name_ok
}

/// An actor a WebFinger answer names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Named {
    /// The actor's `id`.
    pub id: Url,
    /// Its ActivityStreams type, when the link says: Lemmy answers for a
    /// name that is both a user and a community with a `self` link for each,
    /// telling them apart this way.
    pub kind: Option<String>,
}

/// What a WebFinger answer says of an address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Found {
    /// The `subject`: the canonical `acct:` URI, when the host gives one.
    pub subject: Option<String>,
    /// The actors its `self` links name, in the order it gave them.
    pub actors: Vec<Named>,
}

impl Found {
    /// Read a JRD: the `self` links with an ActivityStreams type and an
    /// `http`, `https` or `ap` `href`. A link that is not one, or whose
    /// `properties` are missing or `null`, is read as far as it goes.
    #[must_use]
    pub fn from_jrd(jrd: &Value) -> Self {
        let links = jrd
            .get("links")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let actors = links
            .iter()
            .filter(|link| link.get("rel").and_then(Value::as_str) == Some("self"))
            .filter(|link| {
                link.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(crate::fetch::is_activity_content_type)
            })
            .filter_map(|link| {
                let id = Url::parse(link.get("href")?.as_str()?).ok()?;
                if !matches!(id.scheme(), "http" | "https" | "ap") {
                    return None;
                }
                let kind = link
                    .get("properties")
                    .and_then(|properties| {
                        properties.get("https://www.w3.org/ns/activitystreams#type")
                    })
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                Some(Named { id, kind })
            })
            .collect();
        Self {
            subject: jrd
                .get("subject")
                .and_then(Value::as_str)
                .map(str::to_owned),
            actors,
        }
    }

    /// The first actor named, or the first of type `kind` when there is one.
    #[must_use]
    pub fn actor(&self, kind: Option<&str>) -> Option<&Url> {
        kind.and_then(|kind| {
            self.actors
                .iter()
                .find(|named| named.kind.as_deref() == Some(kind))
        })
        .or_else(|| self.actors.first())
        .map(|named| &named.id)
    }
}

/// A handle resolved through WebFinger: the handle its host gave as the
/// `subject`, and the actor the answer's first ActivityPub `self` link names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// The canonical handle, as the host spells it.
    pub address: Address,
    /// The actor it names.
    pub actor: Url,
    /// The whole answer the actor was read from.
    pub found: Found,
}

/// Why a handle could not be resolved.
#[derive(Debug)]
pub enum ResolveError {
    /// A host could not be asked, or did not answer with a JRD. A `410
    /// Gone` is here, with its status: the handle is gone from its host.
    Fetch(FetchError),
    /// The answer for `asked` has no `subject`.
    NoSubject { asked: String },
    /// The answer for `asked` names no ActivityPub actor.
    NoActor { asked: String },
    /// The `subject` of the answer for `asked` is not a handle.
    BadSubject { asked: String, subject: String },
    /// The handle the answer for `asked` gave as canonical names yet
    /// another one, `stopped_at`.
    TooManyRedirects { asked: String, stopped_at: String },
    /// The handle, resolved, names another actor than the one it was
    /// expected to.
    NotLoopingBack { handle: String, actor: String },
}

impl ResolveError {
    /// The status a host answered with, if it answered with one other than
    /// success; a `410` says the handle is gone.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Fetch(error) => error.status(),
            _ => None,
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(error) => error.fmt(f),
            Self::NoSubject { asked } => write!(f, "Missing subject in response for {asked}"),
            Self::NoActor { asked } => write!(f, "Missing self link in response for {asked}"),
            Self::BadSubject { asked, subject } => write!(
                f,
                "Webfinger response for {asked} has a subject that is not a handle: {subject}"
            ),
            Self::TooManyRedirects { asked, stopped_at } => write!(
                f,
                "Too many webfinger redirects for URI {asked} (stopped at {stopped_at})"
            ),
            Self::NotLoopingBack { handle, actor } => write!(
                f,
                "Webfinger response for {handle} does not loop back to {actor}"
            ),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fetch(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FetchError> for ResolveError {
    fn from(error: FetchError) -> Self {
        Self::Fetch(error)
    }
}

/// Resolve `address` through WebFinger as Mastodon's `ResolveAccountService`
/// does, asking each host with `lookup`: an answer has to have a `subject`
/// and an ActivityPub `self` link. When the `subject` is the handle asked
/// about, compared without regard to case, that is the answer; when it is
/// another, that handle is asked about in turn, once, and its answer has to
/// name itself. An application that builds the query URL itself — over
/// plain `http` for an onion service, say — passes a `lookup` that calls
/// [`Fetcher::webfinger_at`]; [`Fetcher::resolve`] asks with
/// [`Fetcher::webfinger`].
///
/// The actor is only what the host claims: look it up afterwards to
/// establish it like any other.
///
/// # Errors
///
/// When a host cannot be asked or its answer is missing either part, the
/// `subject` is not a handle, or a redirect leads to yet another handle.
pub async fn resolve_with<F, Fut>(address: &Address, lookup: F) -> Result<Resolved, ResolveError>
where
    F: FnMut(&Address) -> Fut,
    Fut: Future<Output = Result<Found, FetchError>>,
{
    resolve_reading(address, Reading::Strict, lookup).await
}

/// How a `subject` is read as a handle.
#[derive(Clone, Copy)]
enum Reading {
    /// `ResolveAccountService#split_acct`: split at its `@`s, it has to have
    /// exactly two parts.
    Strict,
    /// `ProcessAccountService#split_acct`: the first two of its parts,
    /// whatever follows them, as [`split_acct`] reads it.
    FirstTwoParts,
}

async fn resolve_reading<F, Fut>(
    address: &Address,
    reading: Reading,
    mut lookup: F,
) -> Result<Resolved, ResolveError>
where
    F: FnMut(&Address) -> Fut,
    Fut: Future<Output = Result<Found, FetchError>>,
{
    let same = |a: &Address, b: &Address| {
        a.user.eq_ignore_ascii_case(&b.user) && a.host.eq_ignore_ascii_case(&b.host)
    };
    let first = read_answer(address, lookup(address).await?, reading)?;
    if same(&first.address, address) {
        return Ok(first);
    }
    // The handle does not match, so it may have been redirected.
    let canonical = first.address;
    let second = read_answer(&canonical, lookup(&canonical).await?, reading)?;
    if !same(&second.address, &canonical) {
        return Err(ResolveError::TooManyRedirects {
            asked: address.to_string(),
            stopped_at: second.address.to_string(),
        });
    }
    Ok(second)
}

/// Confirm that `address` names `actor`, as Mastodon's
/// `ProcessAccountService#check_webfinger!` does before it believes an
/// actor's handle: [`resolve_with`], and the actor the canonical handle's
/// answer names has to be `actor`. Returns what it resolved to, whose
/// `address` is the handle to show.
///
/// A `subject` is read as `check_webfinger!` reads it, by its first two
/// parts split at `@`, so `acct:alice@social.example@elsewhere` is
/// `alice@social.example`; [`resolve_with`] refuses it, as
/// `ResolveAccountService` does.
///
/// # Errors
///
/// As [`resolve_with`], and when the handle names another actor.
pub async fn confirm_with<F, Fut>(
    address: &Address,
    actor: &str,
    lookup: F,
) -> Result<Resolved, ResolveError>
where
    F: FnMut(&Address) -> Fut,
    Fut: Future<Output = Result<Found, FetchError>>,
{
    let resolved = resolve_reading(address, Reading::FirstTwoParts, lookup).await?;
    if resolved.actor.as_str() != actor {
        return Err(ResolveError::NotLoopingBack {
            handle: resolved.address.to_string(),
            actor: actor.to_owned(),
        });
    }
    Ok(resolved)
}

/// `Webfinger::Response`'s checks of the answer for `asked`, and the handle
/// its `subject` names, which is an `acct:` URI or a bare `user@host`.
fn read_answer(asked: &Address, found: Found, reading: Reading) -> Result<Resolved, ResolveError> {
    let asked = asked.acct();
    let subject = found
        .subject
        .clone()
        .filter(|subject| !subject.trim().is_empty())
        .ok_or_else(|| ResolveError::NoSubject {
            asked: asked.clone(),
        })?;
    let actor = found
        .actors
        .first()
        .map(|named| named.id.clone())
        .ok_or_else(|| ResolveError::NoActor {
            asked: asked.clone(),
        })?;
    let address = match reading {
        Reading::Strict => Some(subject.trim())
            .filter(|subject| !subject.starts_with('@'))
            .and_then(Address::parse),
        Reading::FirstTwoParts => {
            let (user, host) = split_acct(subject.trim());
            Some(())
                .filter(|()| !user.is_empty() && !host.is_empty())
                .and_then(|()| Address::parse(&format!("{user}@{host}")))
        }
    }
    .ok_or(ResolveError::BadSubject { asked, subject })?;
    Ok(Resolved {
        address,
        actor,
        found,
    })
}

impl Fetcher {
    /// Ask `address`'s host what it says of it, as Mastodon's `Webfinger`
    /// does: at [`Address::webfinger_url`], and, when that answers `404`, at
    /// the query the host's host-meta `lrdd` template names, whose own `404`
    /// is not followed further.
    ///
    /// # Errors
    ///
    /// As [`Fetcher::webfinger_at`], and when host-meta does not answer
    /// `200` or names no query.
    pub async fn webfinger(&self, address: &Address) -> Result<Found, FetchError> {
        let plain = |mut url: Url| {
            if self.plain_http_webfinger() {
                // A scheme change between two special schemes always succeeds.
                let _ = url.set_scheme("http");
            }
            url
        };
        match self.webfinger_at(&plain(address.webfinger_url())).await {
            // `Webfinger#body_from_host_meta`: a host that does not answer at
            // the standard place may say where it does, once.
            Err(FetchError::Status(404)) => {
                let url = self
                    .host_meta_query(address, plain(address.host_meta_url()))
                    .await?;
                self.webfinger_at(&url).await
            }
            answer => answer,
        }
    }

    /// The WebFinger query for `address` that the host-meta document at
    /// `url` names. A failure is [`FetchError::Invalid`], never a status, so
    /// that a host-meta `410` is not taken for the handle being gone.
    async fn host_meta_query(&self, address: &Address, url: Url) -> Result<Url, FetchError> {
        let acct = address.acct();
        let response = self.get(&url, XRD_ACCEPT, None).await?;
        if response.status != 200 {
            return Err(FetchError::Invalid(format!(
                "Request for {acct} returned HTTP {}",
                response.status
            )));
        }
        let xrd = String::from_utf8_lossy(&response.body);
        let template = lrdd_template(&xrd)
            .map_err(|error| FetchError::Invalid(format!("{error} for {acct}")))?;
        Url::parse(&template.replace("{uri}", &acct))
            .map_err(|error| FetchError::Invalid(format!("Invalid URI for {acct}: {error}")))
    }

    /// Confirm that `address` names `actor`, as [`confirm_with`] does,
    /// asking each host with [`Fetcher::webfinger`].
    ///
    /// # Errors
    ///
    /// As [`confirm_with`].
    pub async fn confirm(&self, address: &Address, actor: &str) -> Result<Resolved, ResolveError> {
        confirm_with(address, actor, |address| {
            let address = address.clone();
            async move { self.webfinger(&address).await }
        })
        .await
    }

    /// Resolve `address` to the handle its host says is canonical and the
    /// actor that names, as [`resolve_with`] does, asking each host with
    /// [`Fetcher::webfinger`].
    ///
    /// # Errors
    ///
    /// As [`resolve_with`].
    pub async fn resolve(&self, address: &Address) -> Result<Resolved, ResolveError> {
        resolve_with(address, |address| {
            let address = address.clone();
            async move { self.webfinger(&address).await }
        })
        .await
    }

    /// Ask the WebFinger query `url` what it says, unsigned, as WebFinger
    /// is asked; [`Address::webfinger_url`] is the query for an address.
    ///
    /// # Errors
    ///
    /// When the request fails or is refused, the answer is not a `200`, as
    /// Mastodon requires, or it is not a JSON object.
    pub async fn webfinger_at(&self, url: &Url) -> Result<Found, FetchError> {
        let response = self.get(url, JRD_ACCEPT, None).await?;
        if response.status != 200 {
            return Err(FetchError::Status(response.status));
        }
        let jrd: Value = serde_json::from_slice(&response.body)
            .map_err(|error| FetchError::Invalid(error.to_string()))?;
        if !jrd.is_object() {
            return Err(FetchError::Invalid("not an object".into()));
        }
        Ok(Found::from_jrd(&jrd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_handle_is_read_however_it_is_written() {
        let address = Address::parse("@alice@social.example").unwrap();
        for handle in [
            "alice@social.example",
            "acct:alice@social.example",
            " @alice@Social.Example ",
        ] {
            assert_eq!(Address::parse(handle).as_ref(), Some(&address), "{handle}");
        }
        assert_eq!(address.user(), "alice");
        assert_eq!(address.acct(), "acct:alice@social.example");
        assert_eq!(address.to_string(), "alice@social.example");
        assert_eq!(
            Address::parse("bob@localhost:3000").unwrap().host(),
            "localhost:3000"
        );
        assert_eq!(
            Address::parse("bob@[::1]:3000").unwrap().host(),
            "[::1]:3000"
        );
        assert_eq!(Address::parse("bob@127.0.0.1").unwrap().host(), "127.0.0.1");
    }

    #[test]
    fn what_is_not_a_handle() {
        for handle in [
            "",
            "alice",
            "@alice",
            "@social.example",
            "alice@",
            "al ice@social.example",
            "alice@social example",
            "alice@social.example/path",
            "alice@social.example?x",
            "alice@social.example#x",
            "alice@evil.example\\@social.example",
            "alice@bücher.example",
            "alice@-social.example",
            "alice@social..example",
            "alice@social.example:https",
            "alice@[not-an-address]",
            "alice/x@social.example",
        ] {
            assert_eq!(Address::parse(handle), None, "{handle:?}");
        }
    }

    #[test]
    fn the_resource_is_encoded_in_the_query() {
        let address = Address::parse("al+ice@social.example").unwrap();
        assert_eq!(
            address.webfinger_url().as_str(),
            "https://social.example/.well-known/webfinger?resource=acct:al%2Bice@social.example"
        );
    }

    #[test]
    fn a_jrd_names_its_actors_by_their_self_links() {
        let found = Found::from_jrd(&json!({
            "subject": "acct:lemmy@lemmy.example",
            "links": [
                {"rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": "https://lemmy.example/u/lemmy"},
                {
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": "https://lemmy.example/u/lemmy",
                    "properties": {"https://www.w3.org/ns/activitystreams#type": "Person"}
                },
                {
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": "https://lemmy.example/c/lemmy",
                    "properties": {"https://www.w3.org/ns/activitystreams#type": "Group"}
                },
                {"rel": "self", "type": "application/activity+json", "href": "https://elsewhere.example/x", "properties": null},
                {"rel": "self", "type": "text/html", "href": "https://lemmy.example/html"},
                {"rel": "self", "type": "application/activity+json", "href": "javascript:alert(1)"}
            ]
        }));
        assert_eq!(found.subject.as_deref(), Some("acct:lemmy@lemmy.example"));
        assert_eq!(found.actors.len(), 3);
        assert_eq!(found.actors[2].kind, None);
        assert_eq!(
            found.actor(None).map(Url::as_str),
            Some("https://lemmy.example/u/lemmy")
        );
        assert_eq!(
            found.actor(Some("Group")).map(Url::as_str),
            Some("https://lemmy.example/c/lemmy")
        );
        assert_eq!(
            found.actor(Some("Service")).map(Url::as_str),
            Some("https://lemmy.example/u/lemmy")
        );
        assert!(
            Found::from_jrd(&json!({"subject": "acct:x@y"}))
                .actors
                .is_empty()
        );
    }

    /// Answers by handle, as hosts would give them.
    async fn resolve_from(
        asked: &str,
        answers: &[(&str, Value)],
    ) -> Result<Resolved, ResolveError> {
        let answers: std::collections::HashMap<String, Found> = answers
            .iter()
            .map(|(handle, jrd)| ((*handle).to_owned(), Found::from_jrd(jrd)))
            .collect();
        resolve_with(&Address::parse(asked).unwrap(), |address| {
            let found = answers
                .get(&address.to_string())
                .cloned()
                .ok_or(FetchError::Status(404));
            async move { found }
        })
        .await
    }

    fn jrd(subject: &str, actor: &str) -> Value {
        json!({
            "subject": subject,
            "links": [{"rel": "self", "type": "application/activity+json", "href": actor}],
        })
    }

    #[tokio::test]
    async fn a_handle_resolves_to_the_actor_its_host_names() {
        let resolved = resolve_from(
            "alice@social.example",
            &[(
                "alice@social.example",
                jrd(
                    "acct:Alice@social.example",
                    "https://social.example/users/alice",
                ),
            )],
        )
        .await
        .unwrap();
        assert_eq!(resolved.address.user(), "Alice", "as the host spells it");
        assert_eq!(
            resolved.actor.as_str(),
            "https://social.example/users/alice"
        );
    }

    #[tokio::test]
    async fn one_redirect_is_followed_and_has_to_name_itself() {
        let redirected = jrd("acct:alice@social.example", "https://example.com/ignored");
        let resolved = resolve_from(
            "alice@example.com",
            &[
                ("alice@example.com", redirected.clone()),
                (
                    "alice@social.example",
                    jrd(
                        "acct:alice@social.example",
                        "https://social.example/users/alice",
                    ),
                ),
            ],
        )
        .await
        .unwrap();
        assert_eq!(resolved.address.to_string(), "alice@social.example");
        assert_eq!(
            resolved.actor.as_str(),
            "https://social.example/users/alice"
        );

        let error = resolve_from(
            "alice@example.com",
            &[
                ("alice@example.com", redirected),
                (
                    "alice@social.example",
                    jrd("acct:alice@third.example", "https://third.example/alice"),
                ),
            ],
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, ResolveError::TooManyRedirects { .. }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_answer_missing_a_part_or_gone_is_an_error() {
        let error = resolve_from(
            "alice@social.example",
            &[("alice@social.example", json!({"links": []}))],
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ResolveError::NoSubject { .. }));
        let error = resolve_from(
            "alice@social.example",
            &[(
                "alice@social.example",
                json!({"subject": "acct:alice@social.example"}),
            )],
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ResolveError::NoActor { .. }));
        let error = resolve_from(
            "alice@social.example",
            &[(
                "alice@social.example",
                jrd("acct:a@b@social.example", "https://social.example/a"),
            )],
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ResolveError::BadSubject { .. }));
        let error = resolve_from("alice@social.example", &[]).await.unwrap_err();
        assert_eq!(error.status(), Some(404));
    }

    #[test]
    fn an_onion_service_is_asked_over_http() {
        let url = Address::parse("alice@abcdef.onion")
            .unwrap()
            .webfinger_url();
        assert_eq!(url.scheme(), "http");
        let url = Address::parse("alice@social.example")
            .unwrap()
            .webfinger_url();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn an_acct_is_split_like_ruby_splits_it() {
        assert_eq!(
            split_acct("acct:alice@example.com"),
            ("alice".into(), "example.com".into())
        );
        assert_eq!(split_acct("alice"), ("alice".into(), String::new()));
        assert_eq!(
            split_acct("a@b@c"),
            ("a".into(), "b".into()),
            "only the first two parts count"
        );
    }

    #[tokio::test]
    async fn a_confirmed_handle_has_to_name_the_actor() {
        let answers = [(
            "alice@social.example",
            jrd(
                "acct:alice@social.example",
                "https://social.example/users/alice",
            ),
        )];
        let lookup = |address: &Address| {
            let found = answers
                .iter()
                .find(|(handle, _)| *handle == address.to_string())
                .map(|(_, jrd)| Found::from_jrd(jrd))
                .ok_or(FetchError::Status(404));
            async move { found }
        };
        let address = Address::parse("alice@social.example").unwrap();
        assert!(
            confirm_with(&address, "https://social.example/users/alice", lookup)
                .await
                .is_ok()
        );
        let error = confirm_with(&address, "https://social.example/users/mallory", lookup)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ResolveError::NotLoopingBack { .. }),
            "{error}"
        );
    }

    #[test]
    fn host_meta_names_the_query_in_its_lrdd_link() {
        let xrd = r#"<?xml version="1.0"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="other" template="https://x.example/no"/>
  <Link rel="lrdd" type="application/xrd+xml" template="https://x.example/wf?resource={uri}"/>
</XRD>"#;
        assert_eq!(
            lrdd_template(xrd).unwrap(),
            "https://x.example/wf?resource={uri}"
        );
        assert!(
            lrdd_template("<XRD><Link rel=\"lrdd\" template=\"t\"/></XRD>").is_err(),
            "no default namespace"
        );
        assert!(lrdd_template("<XRD xmlns=\"urn:x\"/>").is_err());
        assert!(lrdd_template("not xml").is_err());
        assert_eq!(
            Address::parse("alice@abcdef.onion")
                .unwrap()
                .host_meta_url()
                .as_str(),
            "http://abcdef.onion/.well-known/host-meta"
        );
    }

    #[tokio::test]
    async fn confirming_reads_a_subject_by_its_first_two_parts() {
        let answers = [(
            "alice@social.example",
            jrd(
                "acct:alice@social.example@elsewhere.example",
                "https://social.example/users/alice",
            ),
        )];
        let lookup = |address: &Address| {
            let found = answers
                .iter()
                .find(|(handle, _)| *handle == address.to_string())
                .map(|(_, jrd)| Found::from_jrd(jrd))
                .ok_or(FetchError::Status(404));
            async move { found }
        };
        let address = Address::parse("alice@social.example").unwrap();
        let confirmed = confirm_with(&address, "https://social.example/users/alice", lookup)
            .await
            .unwrap();
        assert_eq!(confirmed.address.to_string(), "alice@social.example");
        let error = resolve_with(&address, lookup).await.unwrap_err();
        assert!(matches!(error, ResolveError::BadSubject { .. }), "{error}");
    }
}
