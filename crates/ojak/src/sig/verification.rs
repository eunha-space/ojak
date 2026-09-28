//! Checking a signed request that arrives in an inbox.
//!
//! In three steps, kept apart so that each can be inspected and tested alone:
//!
//! 1.  [`parse`] reads the signature, draft-cavage or RFC 9421, into plain
//!     data: which key signed, when, and what it covers.
//! 2.  [`check`] applies the policy a signature has to meet before its key is
//!     even fetched: it covers the request target, the host, when it was made
//!     and, for a request with a body, the body's digest; the digest is there
//!     and matches the body; it was made recently; and it was made for this
//!     server.
//! 3.  [`verify`] checks the signature against a key the caller found.
//!
//! What lies between the second and third steps — fetching the key, and
//! checking that the actor who signed is the actor the activity is from — is
//! the caller's, since it needs the network and the application's cache.
//! [`key_owner`] and [`published_key_pem`] are the pure halves of that.
//!
//! Without the second step a signature over `date` alone would authorise any
//! body, and a request captured on its way to another server, or an hour
//! ago, could be replayed here. `signature::verify_request` checks a digest
//! only when one happens to be sent, and never the time or the host.

use crate::sig::{rfc9421, signature};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt;

/// A request as it arrived.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The method, in any case.
    pub method: &'a str,
    /// The path and query the request was made to, as received.
    pub path_and_query: &'a str,
    /// Every header, with lower-case names.
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

impl Request<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    fn has_body(&self) -> bool {
        !self.method.eq_ignore_ascii_case("get") && !self.method.eq_ignore_ascii_case("head")
    }
}

/// What a signature has to meet.
#[derive(Clone, Copy, Debug)]
pub struct Policy<'a> {
    /// The hosts this server answers to — its domain and any aliases. A
    /// request signed for another host is refused. A host listed without a port
    /// also accepts itself with one, which is how a server on a non-default
    /// port is reached; one listed with a port accepts only that port.
    pub hosts: &'a [&'a str],
    /// How far from now a signature may have been made, in either direction.
    pub max_skew_seconds: i64,
}

impl<'a> Policy<'a> {
    /// The policy Mastodon applies: an hour either way.
    #[must_use]
    pub fn new(hosts: &'a [&'a str]) -> Self {
        Self {
            hosts,
            max_skew_seconds: 3600,
        }
    }
}

/// Which signature scheme a request is signed with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    DraftCavage,
    Rfc9421,
}

/// A signature, read but not yet checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub scheme: Scheme,
    /// The IRI of the key that made it.
    pub key_id: String,
    /// What it covers: header names in lower case for draft-cavage, component
    /// names for RFC 9421.
    pub covered: Vec<String>,
    /// When it was made, from `created` or the `Date` header, as seconds since
    /// the Unix epoch.
    pub created: Option<i64>,
    signature: String,
    signature_input: Option<String>,
}

/// Why a request is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rejection {
    /// No `Signature` header.
    Unsigned,
    /// A signature header that cannot be read.
    Malformed(String),
    /// The signature does not cover something it has to.
    NotCovered(String),
    /// A header the signature relies on is missing.
    MissingHeader(&'static str),
    /// The body is not the one the digest describes.
    DigestMismatch,
    /// The signature was made too far from now.
    Stale { seconds: i64 },
    /// The request was signed for another host.
    WrongHost(String),
    /// The signature does not verify against the key.
    Invalid(String),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned => f.write_str("no Signature header"),
            Self::Malformed(why) => write!(f, "malformed signature: {why}"),
            Self::NotCovered(what) => write!(f, "signature does not cover {what}"),
            Self::MissingHeader(name) => write!(f, "missing {name} header"),
            Self::DigestMismatch => f.write_str("the body does not match its digest"),
            Self::Stale { seconds } => write!(f, "signature made {seconds}s from now"),
            Self::WrongHost(host) => write!(f, "signed for another host: {host}"),
            Self::Invalid(why) => write!(f, "signature does not verify: {why}"),
        }
    }
}

impl std::error::Error for Rejection {}

/// The key a signature is checked against.
#[derive(Clone, Copy, Debug)]
pub enum Key<'a> {
    /// A PEM-encoded RSA public key.
    RsaPem(&'a str),
    /// A raw Ed25519 public key. Only RFC 9421 signatures use one.
    Ed25519(&'a [u8; 32]),
}

/// Read the signature on `request`.
///
/// # Errors
///
/// When there is none, or it cannot be read.
pub fn parse(request: &Request<'_>) -> Result<Signature, Rejection> {
    let signature = request
        .header("signature")
        .ok_or(Rejection::Unsigned)?
        .to_owned();
    // A `Signature-Input` beside it means RFC 9421: the two schemes share the
    // `Signature` field name and nothing else.
    if let Some(input) = request.header("signature-input") {
        let key_id = rfc9421::key_id(input)
            .ok_or_else(|| Rejection::Malformed("no keyid in Signature-Input".into()))?;
        let covered = rfc9421::covered_components(input)
            .ok_or_else(|| Rejection::Malformed("unreadable Signature-Input".into()))?;
        return Ok(Signature {
            scheme: Scheme::Rfc9421,
            key_id,
            covered,
            created: rfc9421::created_at(input),
            signature,
            signature_input: Some(input.to_owned()),
        });
    }

    let params = signature::parse_params(&signature);
    let key_id = params
        .get("keyId")
        .cloned()
        .ok_or_else(|| Rejection::Malformed("no keyId".into()))?;
    let covered: Vec<String> = params
        .get("headers")
        .map_or("date", String::as_str)
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let created = match params.get("created") {
        Some(created) => Some(
            created
                .parse()
                .map_err(|_| Rejection::Malformed("unreadable created".into()))?,
        ),
        None => request.header("date").and_then(http_date),
    };
    Ok(Signature {
        scheme: Scheme::DraftCavage,
        key_id,
        covered,
        created,
        signature,
        signature_input: None,
    })
}

/// Apply `policy` to `signature` on `request`, `now` being seconds since the
/// Unix epoch.
///
/// # Errors
///
/// With the first rule the signature breaks.
pub fn check(
    signature: &Signature,
    request: &Request<'_>,
    policy: &Policy<'_>,
    now: i64,
) -> Result<(), Rejection> {
    let covers = |name: &str| signature.covered.iter().any(|covered| covered == name);
    let require = |name: &str| {
        if covers(name) {
            Ok(())
        } else {
            Err(Rejection::NotCovered(name.to_owned()))
        }
    };
    match signature.scheme {
        Scheme::DraftCavage => {
            require("(request-target)")?;
            require("host")?;
            if !covers("date") && !covers("(created)") {
                return Err(Rejection::NotCovered("date".into()));
            }
            if request.has_body() {
                require("digest")?;
                let digest = request
                    .header("digest")
                    .ok_or(Rejection::MissingHeader("Digest"))?;
                if !digest_matches(digest, request.body) {
                    return Err(Rejection::DigestMismatch);
                }
            }
        }
        Scheme::Rfc9421 => {
            require("@method")?;
            require("@target-uri")?;
            if request.has_body() {
                require("content-digest")?;
                let digest = request
                    .header("content-digest")
                    .ok_or(Rejection::MissingHeader("Content-Digest"))?;
                if !content_digest_matches(digest, request.body) {
                    return Err(Rejection::DigestMismatch);
                }
            }
        }
    }

    let created = signature.created.ok_or(Rejection::MissingHeader("Date"))?;
    let seconds = created - now;
    if seconds.abs() > policy.max_skew_seconds {
        return Err(Rejection::Stale { seconds });
    }

    let host = request
        .header("host")
        .ok_or(Rejection::MissingHeader("Host"))?;
    if !policy
        .hosts
        .iter()
        .any(|accepted| host_matches(accepted, host))
    {
        return Err(Rejection::WrongHost(host.to_owned()));
    }
    Ok(())
}

/// Whether a `Host` header names `accepted`: exactly, or with a port when
/// `accepted` has none. Both are compared without case or a trailing dot.
fn host_matches(accepted: &str, host: &str) -> bool {
    let normalise = |value: &str| value.trim().trim_end_matches('.').to_ascii_lowercase();
    let (accepted, host) = (normalise(accepted), normalise(host));
    if accepted == host {
        return true;
    }
    if split_port(&accepted).is_some() {
        return false;
    }
    split_port(&host).is_some_and(|name| name.trim_end_matches('.') == accepted)
}

/// The host part of `host:port`, when there is a numeric port.
fn split_port(value: &str) -> Option<&str> {
    let (name, port) = value.rsplit_once(':')?;
    // A bare IPv6 address is all colons; only `[…]:port` has a port.
    if name.contains(':') && !name.ends_with(']') {
        return None;
    }
    (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())).then_some(name)
}

/// Check `signature` on `request` against `key`.
///
/// # Errors
///
/// When it does not verify, or `key` is not a kind the scheme can use.
pub fn verify(signature: &Signature, request: &Request<'_>, key: Key<'_>) -> Result<(), Rejection> {
    match signature.scheme {
        Scheme::DraftCavage => {
            let Key::RsaPem(pem) = key else {
                return Err(Rejection::Invalid(
                    "a draft-cavage signature is checked with an RSA key".into(),
                ));
            };
            signature::verify_request(
                &request.method.to_ascii_lowercase(),
                request.path_and_query,
                request.headers,
                request.body,
                pem,
            )
            .map_err(|error| Rejection::Invalid(error.to_string()))
        }
        Scheme::Rfc9421 => {
            let host = request
                .header("host")
                .ok_or(Rejection::MissingHeader("Host"))?;
            // The sender signed the URL it addressed, and federation always
            // reaches an inbox over https, however this process is fronted.
            let target = format!("https://{host}{}", request.path_and_query);
            let key = match key {
                Key::RsaPem(pem) => rfc9421::VerifyingKey::RsaPem(pem),
                Key::Ed25519(bytes) => rfc9421::VerifyingKey::Ed25519(bytes),
            };
            rfc9421::verify_request(
                request.method,
                &target,
                signature.signature_input.as_deref().unwrap_or_default(),
                &signature.signature,
                request.header("content-digest"),
                request.body,
                &key,
            )
            .map_err(|error| Rejection::Invalid(error.to_string()))
        }
    }
}

/// The actor a key ID most likely belongs to: the key ID without its
/// fragment, or without GoToSocial's `/main-key` path, which is where the key
/// is fetched from and whose owner is then checked.
#[must_use]
pub fn key_owner(key_id: &str) -> &str {
    if let Some((owner, _)) = key_id.split_once('#') {
        return owner;
    }
    key_id.strip_suffix("/main-key").unwrap_or(key_id)
}

/// The PEM of `key_id` if `actor` publishes it as its own key: a `publicKey`
/// whose `id` is `key_id` and whose `owner`, if it names one, is the actor.
///
/// This is the other half of the claim a key ID makes. The key ID says which
/// actor it belongs to; the actor has to say so too, or anyone who can put a
/// key document on a server could sign as any actor there.
#[must_use]
pub fn published_key_pem(actor: &Value, key_id: &str) -> Option<String> {
    let actor_id = actor.get("id").and_then(Value::as_str)?;
    let keys: Vec<&Value> = match actor.get("publicKey")? {
        Value::Array(keys) => keys.iter().collect(),
        key => vec![key],
    };
    keys.into_iter().find_map(|key| {
        let id = key.get("id").and_then(Value::as_str)?;
        let owner = key.get("owner").and_then(Value::as_str);
        (id == key_id && owner.is_none_or(|owner| owner == actor_id))
            .then(|| key.get("publicKeyPem").and_then(Value::as_str))
            .flatten()
            .map(str::to_owned)
    })
}

/// Parse an HTTP-date (RFC 9110), as a `Date` header carries.
fn http_date(value: &str) -> Option<i64> {
    let value = value.trim();
    chrono::NaiveDateTime::parse_from_str(value, "%a, %d %b %Y %H:%M:%S GMT")
        .map(|date| date.and_utc().timestamp())
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(value).map(|date| date.timestamp()))
        .ok()
}

/// Whether a `Digest` header (RFC 3230) holds the body's SHA-256. It may list
/// several algorithms; the SHA-256 one has to be there and has to match.
fn digest_matches(header: &str, body: &[u8]) -> bool {
    let expected = BASE64.encode(Sha256::digest(body));
    header.split(',').any(|part| {
        part.trim()
            .split_once('=')
            .is_some_and(|(algorithm, value)| {
                algorithm.eq_ignore_ascii_case("sha-256") && value == expected
            })
    })
}

/// Whether a `Content-Digest` header (RFC 9530) holds the body's SHA-256.
fn content_digest_matches(header: &str, body: &[u8]) -> bool {
    let expected = format!(":{}:", BASE64.encode(Sha256::digest(body)));
    header.split(',').any(|part| {
        part.trim()
            .split_once('=')
            .is_some_and(|(algorithm, value)| {
                algorithm.eq_ignore_ascii_case("sha-256") && value.trim() == expected
            })
    })
}

#[cfg(test)]
mod tests {
    use super::host_matches;

    #[test]
    fn a_host_is_matched_with_or_without_its_port() {
        assert!(host_matches("eunha.example", "eunha.example"));
        assert!(host_matches("eunha.example", "EUNHA.example."));
        assert!(host_matches("eunha.example", "eunha.example:8443"));
        assert!(host_matches("localhost:3000", "localhost:3000"));
        assert!(host_matches("[::1]", "[::1]:3000"));
        assert!(!host_matches("localhost:3000", "localhost:4000"));
        assert!(!host_matches("localhost:3000", "localhost"));
        assert!(!host_matches("eunha.example", "other.example"));
        assert!(!host_matches("eunha.example", "eunha.example.evil.example"));
        assert!(!host_matches("eunha.example", "eunha.example:"));
        assert!(!host_matches("eunha.example", "eunha.example:https"));
    }
}
