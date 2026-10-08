//! Followers collection synchronization ([FEP-8fcf]): the digest of the
//! followers a server holds for an actor, and the `Collection-Synchronization`
//! header that carries it on a delivery, so that the receiving server can
//! tell when its idea of who follows the actor there has drifted.
//!
//! The digest of a set of actor IDs is the XOR of their SHA-256 hashes,
//! written in lowercase hex: it is the same whatever order the IDs are
//! taken in, and the empty set's is all zeros. The header names the
//! collection the digest is of, the digest, and where the followers on the
//! receiving server are listed, in the syntax of an HTTP signature's
//! parameters, as Mastodon writes and reads it.
//!
//! [FEP-8fcf]: https://codeberg.org/fediverse/fep/src/branch/main/fep/8fcf/fep-8fcf.md

use sha2::{Digest as _, Sha256};

/// The header a delivery carries it in.
pub const HEADER: &str = "Collection-Synchronization";

/// A digest of actor IDs, being built.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The empty set's: all zeros.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The digest of `ids`.
    #[must_use]
    pub fn of<'a>(ids: impl IntoIterator<Item = &'a str>) -> Self {
        let mut digest = Self::new();
        for id in ids {
            digest.add(id);
        }
        digest
    }

    /// Fold `id` in. Folding the same ID in twice takes it out again.
    pub fn add(&mut self, id: &str) {
        let hash = Sha256::digest(id.as_bytes());
        for (byte, other) in self.0.iter_mut().zip(hash.iter()) {
            *byte ^= other;
        }
    }

    /// Whether it is all zeros: the empty set's, or two equal sets' folded
    /// together.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Read a digest written in hex; `None` when it is not 32 bytes of hex.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Its lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.0
            .iter()
            .fold(String::with_capacity(64), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            })
    }
}

/// What a `Collection-Synchronization` header says.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionSynchronization {
    /// The followers collection the digest is of.
    pub collection_id: String,
    /// The followers on the receiving server, as a partial collection.
    pub url: String,
    /// The digest of the followers on the receiving server, in hex.
    pub digest: String,
}

impl CollectionSynchronization {
    /// The header's value: `collectionId="…", digest="…", url="…"`.
    #[must_use]
    pub fn to_header(&self) -> String {
        format!(
            "collectionId=\"{}\", digest=\"{}\", url=\"{}\"",
            self.collection_id, self.digest, self.url
        )
    }

    /// Read a header's value, as the parameters of an HTTP signature are
    /// read: `key=value` or `key="value"`, separated by commas, each key
    /// once. `None` when it does not parse or lacks one of the three.
    #[must_use]
    pub fn parse(header: &str) -> Option<Self> {
        let params = parameters(header.strip_prefix("Signature ").unwrap_or(header))?;
        let get = |name: &str| {
            params
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        Some(Self {
            collection_id: get("collectionId")?,
            url: get("url")?,
            digest: get("digest")?,
        })
    }
}

fn is_token(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c)
}

/// `SignatureParser.parse`: the parameters, or `None` when they do not
/// parse or a key is repeated.
fn parameters(raw: &str) -> Option<Vec<(String, String)>> {
    let mut params: Vec<(String, String)> = Vec::new();
    let mut rest = raw;
    loop {
        let key_end = rest.find(|c: char| !is_token(c)).unwrap_or(rest.len());
        if key_end == 0 {
            return None;
        }
        let key = &rest[..key_end];
        rest = rest[key_end..].trim_start().strip_prefix('=')?.trim_start();
        let value;
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut end = None;
            let mut escaped = false;
            for (index, c) in quoted.char_indices() {
                match c {
                    _ if escaped => escaped = false,
                    '\\' => escaped = true,
                    '"' => {
                        end = Some(index);
                        break;
                    }
                    _ => {}
                }
            }
            let end = end?;
            value = quoted[..end].to_owned();
            rest = &quoted[end + 1..];
        } else {
            let end = rest.find(|c: char| !is_token(c)).unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            value = rest[..end].to_owned();
            rest = &rest[end..];
        }
        if params.iter().any(|(existing, _)| existing == key) {
            return None;
        }
        params.push((key.to_owned(), value));
        rest = rest.trim_start();
        if rest.is_empty() {
            return Some(params);
        }
        rest = rest.strip_prefix(',')?.trim_start();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_the_xor_of_the_ids_hashes_in_any_order() {
        let a = Digest::of(["https://a.test/users/1", "https://a.test/users/2"]);
        let b = Digest::of(["https://a.test/users/2", "https://a.test/users/1"]);
        assert_eq!(a, b);
        assert!(Digest::new().is_zero());
        assert_eq!(Digest::new().to_hex(), "0".repeat(64));
        let mut folded = a.clone();
        folded.add("https://a.test/users/1");
        folded.add("https://a.test/users/2");
        assert!(folded.is_zero());
        assert_eq!(Digest::from_hex(&a.to_hex()), Some(a));
        assert_eq!(Digest::from_hex("zz"), None);
    }

    #[test]
    fn the_digest_of_one_id_is_its_sha256() {
        // SHA-256 of "a".
        assert_eq!(
            Digest::of(["a"]).to_hex(),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
    }

    #[test]
    fn a_header_is_written_and_read_as_mastodon_does() {
        let header = CollectionSynchronization {
            collection_id: "https://a.test/users/alice/followers".into(),
            url: "https://a.test/users/alice/followers_synchronization".into(),
            digest: "ab".repeat(32),
        };
        let written = header.to_header();
        assert_eq!(
            written,
            format!(
                "collectionId=\"https://a.test/users/alice/followers\", digest=\"{}\", \
                 url=\"https://a.test/users/alice/followers_synchronization\"",
                "ab".repeat(32)
            )
        );
        assert_eq!(CollectionSynchronization::parse(&written), Some(header));
        assert_eq!(
            CollectionSynchronization::parse("collectionId=\"x\", url=\"y\""),
            None,
            "a digest is needed"
        );
        assert_eq!(
            CollectionSynchronization::parse("collectionId=\"x\", collectionId=\"x\""),
            None
        );
        assert_eq!(CollectionSynchronization::parse("nonsense"), None);
    }
}
