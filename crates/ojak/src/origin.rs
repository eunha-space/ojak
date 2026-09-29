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
        let (scheme, _) = iri.split_once(':')?;
        match scheme.to_ascii_lowercase().as_str() {
            "http" | "https" => match ApUri::parse(iri) {
                Some(portable) => Some(Self::Did(portable.did().to_string())),
                None => web(iri),
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

/// The origin of an `http` or `https` IRI, read as the `url` crate reads it,
/// since that is how every request Ojak makes and every identifier it hands
/// on is read. An IRI that is not well formed has none: WHATWG URL parsing
/// forgives what RFC 3987 does not, reading a backslash as `/`, so a hand-split
/// authority and the parsed one could name different hosts, and an
/// identifier that means one server to one rule and another to the next is
/// not an identifier.
fn web(iri: &str) -> Option<Origin> {
    if !well_formed(iri) {
        return None;
    }
    let url = url::Url::parse(iri).ok()?;
    let host = url.host_str()?;
    if host.is_empty() {
        return None;
    }
    Some(Origin::Web {
        scheme: url.scheme().to_string(),
        host: host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_string(),
        port: url.port_or_known_default()?,
    })
}

/// Whether `iri` has only what RFC 3987 allows in an IRI: no control
/// characters, spaces, backslashes or the other characters it excludes, and
/// `%` only as a percent-encoding.
fn well_formed(iri: &str) -> bool {
    let bytes = iri.as_bytes();
    bytes.iter().enumerate().all(|(index, &byte)| match byte {
        b'%' => bytes
            .get(index + 1..index + 3)
            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)),
        b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}' => false,
        byte => byte > b' ' && byte != 0x7f,
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
    fn a_web_origin_is_the_one_a_url_parser_reads() {
        // An IDN host is its punycode, as the URL it is fetched at has it.
        assert_eq!(
            Origin::of("https://bücher.example/"),
            web("https", "xn--bcher-kva.example", 443)
        );
        assert!(same_origin(
            "https://bücher.example/a",
            "https://xn--bcher-kva.example/b"
        ));
        // A percent-encoded host is the host it decodes to.
        assert!(same_origin("https://a%2Eexample/", "https://a.example/"));
    }

    #[test]
    fn an_identifier_that_is_not_well_formed_has_no_origin() {
        // A URL parser reads the backslash as `/`, making the host
        // a.example; split by hand, the host is after the `@`.
        for iri in [
            "https://a.example\\@evil.example/users/alice",
            "https://a.example\\evil.example/",
            "https://a.example/users/ alice",
            "https://a.example/users/%zz",
            "https://a.example/\u{7f}",
            "https://a.example/{x}",
        ] {
            assert_eq!(Origin::of(iri), None, "{iri:?}");
        }
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
