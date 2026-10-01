//! Media of portable objects (FEP-ef61): named by what they are, not where.
//!
//! A portable object that refers to an image or any other resource carries
//! its SHA-256 digest, `digestMultibase`, and names it, as FEP-ef61 advises,
//! by a hashlink, `hl:zQm…`, the same digest as a URI. A gateway serves it
//! at `/.well-known/apgateway/hl:zQm…`, and whoever fetches it checks what
//! came back against the digest, so a gateway is again a location and not
//! an authority.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use sha2::{Digest, Sha256};

/// The multihash code of SHA-256, and the length of its digest.
const SHA2_256: [u8; 2] = [0x12, 0x20];

/// A resource a portable object refers to, as a gateway serves it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Media {
    /// Its media type, `image/png`.
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// A SHA-256 digest as a hashlink names it and `digestMultibase` writes it:
/// a multihash, in base58btc.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Hashlink {
    digest: [u8; 32],
}

impl Hashlink {
    /// The hashlink of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            digest: Sha256::digest(bytes).into(),
        }
    }

    /// Read a hashlink, `hl:zQm…`. `None` when it is not one of a SHA-256
    /// digest, or carries metadata, which gateways do not serve by.
    #[must_use]
    pub fn parse(hashlink: &str) -> Option<Self> {
        let (scheme, digest) = hashlink.split_once(':')?;
        if !scheme.eq_ignore_ascii_case("hl") {
            return None;
        }
        Self::from_multibase(digest)
    }

    /// Read a `digestMultibase`, `zQm…`. `None` when it is not a SHA-256
    /// multihash in base58btc, the only digest FEP-ef61 allows.
    #[must_use]
    pub fn from_multibase(multibase: &str) -> Option<Self> {
        let encoded = multibase.strip_prefix('z')?;
        let decoded: Vec<u8> = bs58::decode(encoded).into_vec().ok()?;
        let digest = decoded.strip_prefix(&SHA2_256)?;
        Some(Self {
            digest: digest.try_into().ok()?,
        })
    }

    /// The digest itself.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The digest as `digestMultibase` writes it, `zQm…`.
    #[must_use]
    pub fn multibase(&self) -> String {
        let mut multihash = Vec::with_capacity(34);
        multihash.extend_from_slice(&SHA2_256);
        multihash.extend_from_slice(&self.digest);
        let mut multibase = String::from("z");
        multibase.push_str(&bs58::encode(multihash).into_string());
        multibase
    }

    /// Whether `bytes` are what this names.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        Self::of(bytes) == *self
    }
}

impl fmt::Display for Hashlink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hl:{}", self.multibase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FEP-ef61's own example: the same digest, as a hashlink and as a
    /// `digestMultibase`.
    const EXAMPLE: &str = "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";

    #[test]
    fn a_hashlink_is_its_digest() {
        let link = Hashlink::parse(&alloc::format!("hl:{EXAMPLE}")).unwrap();
        assert_eq!(link, Hashlink::from_multibase(EXAMPLE).unwrap());
        assert_eq!(link.multibase(), EXAMPLE);
        assert_eq!(link.to_string(), alloc::format!("hl:{EXAMPLE}"));
    }

    #[test]
    fn bytes_are_what_their_digest_names() {
        let link = Hashlink::of(b"hello");
        assert!(link.matches(b"hello"));
        assert!(!link.matches(b"hello!"));
        // The SHA-256 multihash of "hello", in base58btc.
        assert_eq!(
            link.multibase(),
            "zQmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5"
        );
        assert_eq!(Hashlink::parse(&link.to_string()), Some(link));
    }

    #[test]
    fn what_is_not_a_hashlink() {
        for hashlink in [
            "",
            "hl:",
            EXAMPLE,
            &alloc::format!("https:{EXAMPLE}"),
            &alloc::format!("hl:{}", &EXAMPLE[1..]),
            &alloc::format!(
                "hl:{EXAMPLE}:zCwPSdabLuj3jue1qYujzunnKwpL4myKdyeqySyFhnzZ8qdfW3bb6W8dVdRu"
            ),
            // SHA-1, and a truncated SHA-256.
            "hl:z5dtAYsVQU6SojhprzGZSsEvMGpE1VW",
            "hl:zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1",
        ] {
            assert!(Hashlink::parse(hashlink).is_none(), "{hashlink}");
        }
    }
}
