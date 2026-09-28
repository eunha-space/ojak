//! Where an identifier's authority comes from.
//!
//! Every rule of the form "the key must belong to the actor's server" or
//! "an object fetched from here must say it is from here" compares origins,
//! and an origin is one of two things:
//!
//!  -  for an `http` or `https` IRI, its scheme, host and port, as the web
//!     defines an origin;
//!  -  for an `ap://` IRI (FEP-ef61) or a DID URL, the DID: a portable object
//!     is vouched for by the key that controls it, wherever it is served from.
//!     So is a portable object's compatible `https` identifier at a gateway,
//!     `https://gateway.example/.well-known/apgateway/did:key:…/path`: the
//!     gateway is where it is, not who vouches for it.
//!
//! The rules are written once against [`Origin`], never against hostnames, so
//! that portable objects are the same rules over a second kind of origin.

use crate::portable::{ApUri, did_of};
use alloc::string::{String, ToString};

/// An identifier's origin.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Origin {
    /// An `http` or `https` origin. The host is lower-cased and the port is
    /// the effective one, so `https://A.example` and `https://a.example:443`
    /// are one origin.
    Web {
        scheme: String,
        host: String,
        port: u16,
    },
    /// A DID, the authority of a portable object.
    Did(String),
}

impl Origin {
    /// The origin of `iri`, or `None` when it has none Ojak recognises: not
    /// `http`, `https`, `ap` or `did`, or malformed.
    #[must_use]
    pub fn of(iri: &str) -> Option<Self> {
        let (scheme, rest) = iri.split_once(':')?;
        match scheme.to_ascii_lowercase().as_str() {
            scheme @ ("http" | "https") => match ApUri::parse(iri) {
                Some(portable) => Some(Self::Did(portable.did().to_string())),
                None => web(scheme, rest),
            },
            "ap" | "ap+ef61" => ApUri::parse(iri).map(|uri| Self::Did(uri.did().to_string())),
            "did" => did_of(iri).map(|did| Self::Did(did.to_string())),
            _ => None,
        }
    }

    /// Whether this is a portable object's origin.
    #[must_use]
    pub fn is_portable(&self) -> bool {
        matches!(self, Self::Did(_))
    }
}

/// Whether `a` and `b` have the same origin. An identifier with no origin
/// Ojak recognises is never the same as anything.
#[must_use]
pub fn same_origin(a: &str, b: &str) -> bool {
    match (Origin::of(a), Origin::of(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The part of `rest` up to the first `/`, `?` or `#`.
fn authority(rest: &str) -> &str {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

fn web(scheme: &str, rest: &str) -> Option<Origin> {
    let authority = authority(rest.strip_prefix("//")?);
    // Userinfo is not part of an origin, and has no business in an
    // ActivityPub identifier; it is dropped rather than trusted.
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let (address, after) = bracketed.split_once(']')?;
        let port = match after {
            "" => None,
            port => Some(port.strip_prefix(':')?),
        };
        (address, port)
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let default = if scheme == "https" { 443 } else { 80 };
    let port = match port {
        None | Some("") => default,
        Some(port) => port.parse().ok()?,
    };
    Some(Origin::Web {
        scheme: scheme.to_string(),
        host: host.to_ascii_lowercase(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web(scheme: &str, host: &str, port: u16) -> Option<Origin> {
        Some(Origin::Web {
            scheme: scheme.into(),
            host: host.into(),
            port,
        })
    }

    #[test]
    fn a_web_origin_is_scheme_host_and_effective_port() {
        assert_eq!(
            Origin::of("https://A.Example/users/a"),
            web("https", "a.example", 443)
        );
        assert_eq!(
            Origin::of("https://a.example:443/x"),
            web("https", "a.example", 443)
        );
        assert_eq!(
            Origin::of("http://a.example:8080"),
            web("http", "a.example", 8080)
        );
        assert_eq!(
            Origin::of("https://[2001:db8::1]:8443/"),
            web("https", "2001:db8::1", 8443)
        );
        assert_eq!(
            Origin::of("https://user@a.example/"),
            web("https", "a.example", 443)
        );
        assert_eq!(
            Origin::of("https://a.example#main-key"),
            web("https", "a.example", 443)
        );
    }

    #[test]
    fn a_portable_origin_is_the_did() {
        let origin = Origin::Did("did:key:z6MkAbc".into());
        let did = Some(origin.clone());
        assert_eq!(Origin::of("ap://did:key:z6MkAbc/users/alice"), did);
        assert_eq!(Origin::of("ap://did%3Akey%3Az6MkAbc/users/alice"), did);
        assert_eq!(Origin::of("ap+ef61://did:key:z6MkAbc/objects/1"), did);
        assert_eq!(Origin::of("did:key:z6MkAbc#z6MkAbc"), did);
        assert!(origin.is_portable());
    }

    #[test]
    fn what_has_no_origin_is_never_the_same() {
        for iri in [
            "",
            "acct:alice@a.example",
            "https://",
            "https://:443/",
            "did:key",
            "mailto:x@y",
        ] {
            assert_eq!(Origin::of(iri), None, "{iri}");
        }
        assert!(!same_origin("acct:a@b", "acct:a@b"));
    }

    #[test]
    fn same_origin_compares_origins_not_strings() {
        assert!(same_origin(
            "https://a.example/users/alice#main-key",
            "https://A.example:443/users/alice"
        ));
        assert!(!same_origin("https://a.example/", "http://a.example/"));
        assert!(!same_origin(
            "https://a.example/",
            "https://a.example:8443/"
        ));
        assert!(!same_origin("https://a.example/", "https://b.example/"));
        assert!(same_origin(
            "ap://did:key:z6MkAbc/users/alice",
            "did:key:z6MkAbc#z6MkAbc"
        ));
        // A compatible identifier is the portable object's, not the
        // gateway's.
        assert!(same_origin(
            "ap://did:key:z6MkAbc/users/alice",
            "https://gateway.example/.well-known/apgateway/did:key:z6MkAbc/users/alice"
        ));
        assert!(!same_origin(
            "https://gateway.example/users/bob",
            "https://gateway.example/.well-known/apgateway/did:key:z6MkAbc/users/alice"
        ));
    }
}
