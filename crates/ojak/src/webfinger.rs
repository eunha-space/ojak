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
use url::Url;

/// What a WebFinger query asks for.
pub const JRD_ACCEPT: &str = "application/jrd+json, application/json";

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

    /// The URL of the host's WebFinger query for this address, over `https`.
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
        Url::parse(&format!(
            "https://{}/.well-known/webfinger?resource={resource}",
            self.host
        ))
        .expect("a checked host makes a URL")
    }
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

impl Fetcher {
    /// Ask `address`'s host what it says of it.
    ///
    /// # Errors
    ///
    /// As [`Fetcher::webfinger_at`].
    pub async fn webfinger(&self, address: &Address) -> Result<Found, FetchError> {
        self.webfinger_at(&address.webfinger_url()).await
    }

    /// Ask the WebFinger query `url` what it says, unsigned, as WebFinger
    /// is asked; [`Address::webfinger_url`] is the query for an address.
    ///
    /// # Errors
    ///
    /// When the request fails or is refused, the answer is not a success,
    /// or it is not a JSON object.
    pub async fn webfinger_at(&self, url: &Url) -> Result<Found, FetchError> {
        let response = self.get(url, JRD_ACCEPT, None).await?;
        if !(200..300).contains(&response.status) {
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
}
