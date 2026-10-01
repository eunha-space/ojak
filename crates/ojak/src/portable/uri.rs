//! Identifiers of portable objects (FEP-ef61): `ap` URIs, whose authority is
//! a DID rather than a host.
//!
//! One identifier has several spellings. [`ApUri::parse`] reads each of them,
//! and [`ApUri::canonical`] is the one they are compared by:
//!
//!  -  `ap://did:key:z6Mk…/path`, canonical;
//!  -  `ap+ef61://…`, or the DID's colons percent-encoded;
//!  -  the compatible form at a gateway,
//!     `https://gateway.example/.well-known/apgateway/did:key:z6Mk…/path`.
//!
//! The query of an `ap` URI is not part of the identifier. It carries
//! location hints, `@gateway` parameters naming where the object may be
//! fetched, which are kept as [`ApUri::gateways`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// The well-known path a gateway serves portable objects under.
pub const GATEWAY_PATH: &str = "/.well-known/apgateway/";

/// A portable object's identifier.
#[derive(Clone, Debug)]
pub struct ApUri {
    did: String,
    path: String,
    fragment: Option<String>,
    gateways: Vec<String>,
}

impl PartialEq for ApUri {
    /// Two `ap` URIs are the same identifier when their canonical forms are;
    /// where they say the object may be found is not part of it.
    fn eq(&self, other: &Self) -> bool {
        self.did == other.did && self.path == other.path && self.fragment == other.fragment
    }
}

impl Eq for ApUri {}

impl ApUri {
    /// Read `iri` in any of its spellings; `None` when it is not a portable
    /// object's identifier.
    #[must_use]
    pub fn parse(iri: &str) -> Option<Self> {
        let (scheme, rest) = iri.split_once("://")?;
        match scheme.to_ascii_lowercase().as_str() {
            "ap" | "ap+ef61" => {
                let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                Self::from_parts(&percent_decode(&rest[..end]), &rest[end..], Vec::new())
            }
            "http" | "https" => {
                let slash = rest.find('/')?;
                let (host, path) = rest.split_at(slash);
                let after = path.strip_prefix(GATEWAY_PATH)?;
                // The DID runs to the first `/`: a DID has no slash of its
                // own, and a portable path always starts with one.
                let end = after.find(['/', '?', '#']).unwrap_or(after.len());
                let gateway = alloc::format!("{scheme}://{host}").to_ascii_lowercase();
                Self::from_parts(
                    &percent_decode(&after[..end]),
                    &after[end..],
                    alloc::vec![gateway],
                )
            }
            _ => None,
        }
    }

    fn from_parts(did: &str, rest: &str, mut gateways: Vec<String>) -> Option<Self> {
        if !is_did(did) {
            return None;
        }
        let (rest, fragment) = match rest.split_once('#') {
            Some((rest, fragment)) => (rest, Some(fragment.to_string())),
            None => (rest, None),
        };
        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };
        // The path is required, and opaque, but it is a path: something
        // after its `/`, and not an authority of its own, which would make
        // `ap://did:key:…//host/x` a second identifier for a host.
        if !path.starts_with('/') || path.len() == 1 || path.starts_with("//") || lossy(path) {
            return None;
        }
        for parameter in query.into_iter().flat_map(|query| query.split('&')) {
            // `@gateway` names one gateway; `gateways`, the form FEP-ef61 had
            // before it, a comma-separated list.
            let hinted = if let Some(gateway) = parameter.strip_prefix("@gateway=") {
                alloc::vec![percent_decode(gateway)]
            } else if let Some(list) = parameter.strip_prefix("gateways=") {
                percent_decode(list)
                    .split(',')
                    .map(str::to_string)
                    .collect()
            } else {
                Vec::new()
            };
            for gateway in hinted {
                if is_gateway(&gateway) && !gateways.contains(&gateway) {
                    gateways.push(gateway);
                }
            }
        }
        Some(Self {
            did: did.to_string(),
            path: path.to_string(),
            fragment,
            gateways,
        })
    }

    /// The identifier `path` names under `did`; `None` when `did` is not a
    /// DID or `path` does not start with `/`.
    #[must_use]
    pub fn new(did: &str, path: &str) -> Option<Self> {
        if path.contains(['?', '#']) {
            return None;
        }
        Self::from_parts(did, path, Vec::new())
    }

    /// The DID that controls the object, which is its origin.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The path under the DID, starting with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The fragment, without its `#`.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Where the identifier says the object may be fetched: its `@gateway`
    /// hints, or the gateway a compatible identifier was served by.
    #[must_use]
    pub fn gateways(&self) -> &[String] {
        &self.gateways
    }

    /// `ap://did/path#fragment`: the form identifiers are compared in, and
    /// the one Ojak writes.
    #[must_use]
    pub fn canonical(&self) -> String {
        self.spelled(&self.did)
    }

    /// The canonical form with the DID's colons percent-encoded: the spelling
    /// an RFC 3986 parser accepts, for where a type needs an IRI.
    #[must_use]
    pub fn encoded(&self) -> String {
        self.spelled(&self.did.replace(':', "%3A"))
    }

    fn spelled(&self, authority: &str) -> String {
        let mut uri = alloc::format!("ap://{authority}{}", self.path);
        if let Some(fragment) = &self.fragment {
            uri.push('#');
            uri.push_str(fragment);
        }
        uri
    }

    /// The canonical form with `gateways` as location hints, as a reference
    /// to another actor is written.
    #[must_use]
    pub fn with_hints(&self, gateways: &[&str]) -> String {
        let mut uri = alloc::format!("ap://{}{}", self.did, self.path);
        for (index, gateway) in gateways.iter().enumerate() {
            uri.push(if index == 0 { '?' } else { '&' });
            uri.push_str("@gateway=");
            uri.push_str(&percent_encode(gateway));
        }
        if let Some(fragment) = &self.fragment {
            uri.push('#');
            uri.push_str(fragment);
        }
        uri
    }

    /// Where `gateway`, an origin such as `https://server.example`, serves
    /// this object: the compatible identifier, without its fragment.
    #[must_use]
    pub fn at_gateway(&self, gateway: &str) -> String {
        alloc::format!(
            "{}{GATEWAY_PATH}{}{}",
            gateway.trim_end_matches('/'),
            self.did,
            self.path
        )
    }
}

impl fmt::Display for ApUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// Whether `iri`, in any spelling, identifies a portable object.
#[must_use]
pub fn is_portable(iri: &str) -> bool {
    ApUri::parse(iri).is_some()
}

/// Whether two identifiers name the same portable object, however each is
/// spelled.
#[must_use]
pub fn same_object(a: &str, b: &str) -> bool {
    match (ApUri::parse(a), ApUri::parse(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The DID a DID URL is under: `did:method:id`, without path, query or
/// fragment. `None` when it is not a DID URL.
#[must_use]
pub fn did_of(did_url: &str) -> Option<&str> {
    let end = did_url.find(['/', '?', '#']).unwrap_or(did_url.len());
    let did = &did_url[..end];
    is_did(did).then_some(did)
}

/// `did:method:id` as DID Core writes one: a lower-case method, and an id
/// of letters, digits, `.`, `-`, `_`, percent-encodings and `:`, not ending
/// in `:`.
fn is_did(did: &str) -> bool {
    let mut parts = did.splitn(3, ':');
    let (Some("did"), Some(method), Some(id)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let bytes = id.as_bytes();
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !id.is_empty()
        && !id.ends_with(':')
        && bytes.iter().enumerate().all(|(index, &byte)| match byte {
            b'%' => bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)),
            byte => byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'),
        })
}

/// Whether `path` would name another object once it is a URL's: the path of
/// an `ap` URI is opaque, but at a gateway it is an `https` URL's, and a URL
/// parser removes tabs and line breaks, reads `\` as `/`, and resolves `.`
/// and `..` segments, `%2e` spelled or not. `ap://did:key:…/a/../b` would be
/// fetched, served and delivered to as `/b`.
fn lossy(path: &str) -> bool {
    path.contains(['\\', '\t', '\n', '\r'])
        || path.split('/').any(|segment| {
            let segment = segment.to_ascii_lowercase().replace("%2e", ".");
            segment == "." || segment == ".."
        })
}

/// Whether `gateway` is what FEP-ef61 allows as one: an `http` or `https`
/// URI with a host and no path, query or fragment, `https://server.example`,
/// or with the one `/` of an empty path.
#[must_use]
pub fn is_gateway(gateway: &str) -> bool {
    let Some((scheme, rest)) = gateway.split_once("://") else {
        return false;
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    matches!(scheme, "http" | "https")
        && !authority.is_empty()
        && !authority.contains(['/', '\\', '?', '#', '@'])
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(index + 1).and_then(|byte| hex(*byte)),
                bytes.get(index + 2).and_then(|byte| hex(*byte)),
            )
        {
            out.push(high * 16 + low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Encode everything but RFC 3986's unreserved characters, as a query value
/// holding a URI has to be.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&alloc::format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    #[test]
    fn every_spelling_is_one_identifier() {
        let canonical = alloc::format!("ap://{DID}/actor");
        let uri = ApUri::parse(&canonical).unwrap();
        assert_eq!(uri.did(), DID);
        assert_eq!(uri.path(), "/actor");
        assert_eq!(uri.canonical(), canonical);
        for spelling in [
            alloc::format!("ap+ef61://{DID}/actor"),
            alloc::format!("AP://{}/actor", DID.replace(':', "%3A")),
            alloc::format!("ap://{}/actor", DID.replace(':', "%3a")),
            alloc::format!("https://Server.example/.well-known/apgateway/{DID}/actor"),
            alloc::format!(
                "ap://{DID}/actor?@gateway=https%3A%2F%2Fserver1.example&@gateway=https%3A%2F%2Fserver2.example"
            ),
        ] {
            let other = ApUri::parse(&spelling).unwrap();
            assert_eq!(other, uri, "{spelling}");
            assert_eq!(other.canonical(), canonical, "{spelling}");
        }
    }

    #[test]
    fn hints_are_where_to_look_and_not_the_identifier() {
        let uri = ApUri::parse(&alloc::format!(
            "ap://{DID}/actor?@gateway=https%3A%2F%2Fserver1.example&other=1&@gateway=https%3A%2F%2Fserver2.example&@gateway=https%3A%2F%2Fbad.example%2Fpath"
        ))
        .unwrap();
        assert_eq!(
            uri.gateways(),
            ["https://server1.example", "https://server2.example"]
        );
        let written = uri.with_hints(&["https://server1.example"]);
        assert_eq!(
            written,
            alloc::format!("ap://{DID}/actor?@gateway=https%3A%2F%2Fserver1.example")
        );
        assert_eq!(ApUri::parse(&written).unwrap(), uri);

        let compatible = ApUri::parse(&alloc::format!(
            "https://g.example/.well-known/apgateway/{DID}/x"
        ))
        .unwrap();
        assert_eq!(compatible.gateways(), ["https://g.example"]);

        // The list FEP-ef61 had before `@gateway`.
        let listed = ApUri::parse(&alloc::format!(
            "ap://{DID}/actor?gateways=https%3A%2F%2Fserver1.example,https%3A%2F%2Fserver2.example"
        ))
        .unwrap();
        assert_eq!(
            listed.gateways(),
            ["https://server1.example", "https://server2.example"]
        );
        assert_eq!(listed, uri);
    }

    #[test]
    fn a_gateway_serves_the_compatible_form() {
        let uri = ApUri::parse(&alloc::format!("ap://{DID}/objects/1#part")).unwrap();
        assert_eq!(uri.fragment(), Some("part"));
        assert_eq!(
            uri.at_gateway("https://g.example/"),
            alloc::format!("https://g.example/.well-known/apgateway/{DID}/objects/1")
        );
        assert_eq!(
            uri.encoded(),
            alloc::format!("ap://{}/objects/1#part", DID.replace(':', "%3A"))
        );
    }

    #[test]
    fn what_is_not_portable() {
        for iri in [
            "https://a.example/users/alice",
            "https://a.example/.well-known/apgateway/",
            "https://a.example/.well-known/apgateway/not-a-did/x",
            "ap://did:key:z6Mk",
            "ap://did:key:z6Mk?x=1",
            "ap://did::z6Mk/actor",
            "ap://did:KEY:z6Mk/actor",
            "ap://host.example/actor",
            "ap://did:key:z6Mk/",
            "ap://did:key:z6Mk//host.example/actor",
            "ap://did:key:z6Mk@evil.example/actor",
            "ap://did:key:z6Mk%5C@evil.example/actor",
            "ap://did:key:z6Mk%20x/actor",
            "ap://did:key:z6Mk:/actor",
            "ap://did:key:z6Mk%zz/actor",
            "ap://did:key:z6Mk/a/../b",
            "ap://did:key:z6Mk/a/./b",
            "ap://did:key:z6Mk/a/%2E%2e/b",
            "ap://did:key:z6Mk/a/.%2e",
            "ap://did:key:z6Mk/..",
            "ap://did:key:z6Mk/a\\..\\b",
            "ap://did:key:z6Mk/a/.\t./b",
            "https://g.example/.well-known/apgateway/did:key:z6Mk/a/../b",
            "did:key:z6Mk",
            "",
        ] {
            assert!(ApUri::parse(iri).is_none(), "{iri}");
        }
    }

    #[test]
    fn a_dot_that_is_not_a_segment_is_part_of_the_path() {
        let uri = ApUri::parse(&alloc::format!("ap://{DID}/a/..b/c./.d")).unwrap();
        assert_eq!(uri.path(), "/a/..b/c./.d");
    }

    #[test]
    fn a_gateway_is_an_origin() {
        for gateway in [
            "https://server.example",
            "https://server.example/",
            "http://127.0.0.1:8080",
        ] {
            assert!(is_gateway(gateway), "{gateway}");
        }
        for gateway in [
            "https://server.example/path",
            "https://server.example//",
            "https://server.example?",
            "https://server.example/#",
            "https://user@server.example",
            "https://",
            "https:///",
            "ftp://server.example",
            "server.example",
        ] {
            assert!(!is_gateway(gateway), "{gateway}");
        }
    }

    #[test]
    fn a_did_url_is_under_its_did() {
        assert_eq!(did_of(&alloc::format!("{DID}#z6Mk")), Some(DID));
        assert_eq!(did_of(DID), Some(DID));
        assert_eq!(did_of("https://a.example#key"), None);
        assert!(same_object(
            &alloc::format!("ap://{DID}/a"),
            &alloc::format!("https://g.example/.well-known/apgateway/{DID}/a")
        ));
        assert!(!same_object(
            &alloc::format!("ap://{DID}/a"),
            &alloc::format!("ap://{DID}/b")
        ));
    }
}
