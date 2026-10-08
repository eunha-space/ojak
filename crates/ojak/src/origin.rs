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

/// Whether `comparison` is an `http` or `https` URL on the same host as
/// `base`, whatever their schemes and ports: Mastodon's
/// `non_matching_uri_hosts?`, negated, which is how it decides that a
/// collection page or a pinned post is on an account's server. Hosts are
/// compared without regard to case.
#[must_use]
pub fn same_host(base: &str, comparison: &str) -> bool {
    let host = |iri: &str| {
        url::Url::parse(iri)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
    };
    let web = comparison.starts_with("http://") || comparison.starts_with("https://");
    match (web, host(base), host(comparison)) {
        (true, Some(base), Some(comparison)) => base == comparison,
        _ => false,
    }
}

/// Whether `a` and `b` have the same authority, as a rule that only cares
/// which server vouches for an identifier compares them: the same DID for
/// portable identifiers, and for `http` and `https` ones the same host,
/// whatever their schemes and ports, compared without regard to case. A
/// portable identifier never has the authority of a web one, and an
/// identifier that is neither has none.
#[must_use]
pub fn same_authority(a: &str, b: &str) -> bool {
    match (Origin::of(a), Origin::of(b)) {
        (Some(Origin::Did(a)), Some(Origin::Did(b))) => a == b,
        (Some(Origin::Did(_)), _) | (_, Some(Origin::Did(_))) => false,
        _ => is_web(a) && same_host(a, b),
    }
}

/// Whether `iri` is an `http` or `https` URL, by its scheme, without regard
/// to case.
fn is_web(iri: &str) -> bool {
    iri.split_once(':').is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    })
}

/// The host of the URL `iri`, without its port, in the form hosts are
/// compared in: lower case, an internationalised name in its ASCII form, an
/// IPv6 address in brackets. `None` when `iri` is not a URL or has no host.
/// This is the host Mastodon's `Addressable::URI.parse(url).normalized_host`
/// reads, by which it tracks deliveries and matches domain blocks.
#[must_use]
pub fn host_of(iri: &str) -> Option<String> {
    let url = url::Url::parse(iri).ok()?;
    url.host_str()
        .filter(|host| !host.is_empty())
        .map(str::to_ascii_lowercase)
}

/// What [`normalize_host`] does with a port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Port {
    /// Keep it as it was written, `:443` included: Mastodon's
    /// `TagManager#normalize_domain`, by which an account on a server at a
    /// port is told from one on the same host without.
    Keep,
    /// Leave it out.
    Drop,
}

/// A host as written by hand — a domain typed into a form, or taken from a
/// handle — in the form hosts are compared in: lower case, percent-encoding
/// decoded, an internationalised name in its ASCII form (IDNA), and a single
/// trailing dot left off, as `Addressable::URI#normalized_host` has it. The
/// port is kept or left out as `port` says. `None` when it is empty or is
/// not a host, such as one with a space, `/` or `@` in it.
#[must_use]
pub fn normalize_host(authority: &str, port: Port) -> Option<String> {
    let (host, written_port) = split_port(authority);
    if host.is_empty() {
        return None;
    }
    let mut host = url::Host::parse(host).ok()?.to_string();
    if host.ends_with('.') && !host.ends_with("..") {
        host.pop();
    }
    Some(match (port, written_port) {
        (Port::Keep, Some(written)) => alloc::format!("{host}:{written}"),
        _ => host,
    })
}

/// `authority` split into its host and the port written after it, if any.
fn split_port(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(end) => {
                let (host, rest) = authority.split_at(end + 1);
                (host, rest.strip_prefix(':'))
            }
            None => (authority, None),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => (host, Some(port)),
        _ => (authority, None),
    }
}

/// Whether `host` is `parent` or one of its subdomains, without regard to
/// case: `a.example.com` and `example.com` are within `example.com`, and
/// `notexample.com` is not. This is how a block on a domain covers its
/// subdomains, as Mastodon's `DomainBlock.rule_for` matches every suffix of
/// a host. An empty parent has nothing within it.
#[must_use]
pub fn host_within(host: &str, parent: &str) -> bool {
    if parent.is_empty()
        || host.len() < parent.len()
        || !host.is_char_boundary(host.len() - parent.len())
    {
        return false;
    }
    let (rest, suffix) = host.split_at(host.len() - parent.len());
    suffix.eq_ignore_ascii_case(parent) && (rest.is_empty() || rest.ends_with('.'))
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
    fn same_authority_is_the_did_or_the_host() {
        assert!(same_authority(
            "https://A.example/users/a",
            "http://a.example:8443/x"
        ));
        assert!(!same_authority("https://a.example/", "https://b.example/"));
        assert!(!same_authority("ftp://a.example/", "https://a.example/"));
        assert!(!same_authority("https://a.example/", "ftp://a.example/"));
        assert!(same_authority(
            "ap://did:key:z6MkAbc/users/alice",
            "did:key:z6MkAbc#z6MkAbc"
        ));
        assert!(!same_authority(
            "ap://did:key:z6MkAbc/users/alice",
            "https://a.example/"
        ));
        assert!(!same_authority(
            "https://gateway.example/users/bob",
            "https://gateway.example/.well-known/apgateway/did:key:z6MkAbc/users/alice"
        ));
    }

    #[test]
    fn host_of_is_the_normalized_host_without_a_port() {
        assert_eq!(
            host_of("https://Bücher.Example:8443/inbox").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(host_of("https://[::1]/").as_deref(), Some("[::1]"));
        assert_eq!(host_of("not a url"), None);
        assert_eq!(host_of("mailto:a@b.example"), None);
    }

    #[test]
    fn normalize_host_is_addressables_normalized_host() {
        let keep = |host| normalize_host(host, Port::Keep);
        assert_eq!(keep("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(
            keep("bücher.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(keep("127.0.0.1:3000").as_deref(), Some("127.0.0.1:3000"));
        assert_eq!(keep("a.example:443").as_deref(), Some("a.example:443"));
        assert_eq!(
            normalize_host("a.example:443", Port::Drop).as_deref(),
            Some("a.example")
        );
        assert_eq!(
            keep("[2001:DB8::1]:8443").as_deref(),
            Some("[2001:db8::1]:8443")
        );
        assert_eq!(keep("a.example.").as_deref(), Some("a.example"));
        assert_eq!(keep("a%2Eexample").as_deref(), Some("a.example"));
        for invalid in ["", "a b.example", "a/b", "a@b.example", ":443"] {
            assert_eq!(keep(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn host_within_is_the_host_or_a_subdomain() {
        assert!(host_within("example.com", "example.com"));
        assert!(host_within("a.example.com", "example.com"));
        assert!(host_within("deep.sub.EXAMPLE.com", "Example.COM"));
        assert!(!host_within("notexample.com", "example.com"));
        assert!(!host_within("example.com.attacker.test", "example.com"));
        assert!(!host_within("example.org", "example.com"));
        assert!(!host_within("example.com", ""));
        assert!(!host_within("", "example.com"));
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
