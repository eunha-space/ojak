//! Digests of a request's body: the `Digest` header (RFC 3230) draft-cavage
//! signatures cover, and the `Content-Digest` field (RFC 9530) RFC 9421 ones
//! do.
//!
//! Either may list several algorithms. Every one listed that is known here,
//! SHA-256 or SHA-512, has to match the body, and at least one has to be
//! there; the rest are ignored, as neither RFC lets a recipient check what it
//! does not know.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest as _, Sha256, Sha512};

/// The body's digest under the algorithm named `algorithm`, in any case, or
/// `None` for an algorithm not known here.
fn digest(algorithm: &str, body: &[u8]) -> Option<Vec<u8>> {
    match algorithm.to_ascii_lowercase().as_str() {
        "sha-256" => Some(Sha256::digest(body).to_vec()),
        "sha-512" => Some(Sha512::digest(body).to_vec()),
        _ => None,
    }
}

/// Whether every known member of `digests`, each an algorithm and the digest
/// it names, matches `body`, and there is one.
fn all_known_match<'a>(
    digests: impl IntoIterator<Item = (&'a str, Option<Vec<u8>>)>,
    body: &[u8],
) -> bool {
    let mut known = false;
    for (algorithm, sent) in digests {
        let Some(expected) = digest(algorithm, body) else {
            continue;
        };
        if sent.as_deref() != Some(expected.as_slice()) {
            return false;
        }
        known = true;
    }
    known
}

/// Whether a `Digest` header holds the body's digest: `SHA-256=…`, possibly
/// beside `SHA-512=…` or algorithms not known here, each base64.
#[must_use]
pub fn digest_matches(header: &str, body: &[u8]) -> bool {
    all_known_match(
        header.split(',').filter_map(|member| {
            let (algorithm, value) = member.trim().split_once('=')?;
            Some((algorithm.trim(), BASE64.decode(value.trim()).ok()))
        }),
        body,
    )
}

/// Whether a `Content-Digest` field holds the body's digest: a
/// structured-field dictionary of algorithms to byte sequences.
#[must_use]
pub fn content_digest_matches(header: &str, body: &[u8]) -> bool {
    let Ok(dictionary) = sfv::Parser::new(header).parse::<sfv::Dictionary>() else {
        return false;
    };
    all_known_match(
        dictionary.iter().map(|(algorithm, member)| {
            let sent = match member {
                sfv::ListEntry::Item(item) => item.bare_item.as_byte_sequence().map(<[u8]>::to_vec),
                sfv::ListEntry::InnerList(_) => None,
            };
            (algorithm.as_str(), sent)
        }),
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"{\"hello\": \"world\"}";

    fn sha256() -> String {
        BASE64.encode(Sha256::digest(BODY))
    }

    fn sha512() -> String {
        BASE64.encode(Sha512::digest(BODY))
    }

    #[test]
    fn a_digest_header_may_list_several_algorithms_in_any_case() {
        let (sha256, sha512) = (sha256(), sha512());
        assert!(digest_matches(&format!("SHA-256={sha256}"), BODY));
        assert!(digest_matches(&format!("sha-256={sha256}"), BODY));
        assert!(digest_matches(&format!("SHA-512={sha512}"), BODY));
        assert!(digest_matches(
            &format!("SHA-256={sha256}, SHA-512={sha512}"),
            BODY
        ));
        assert!(digest_matches(&format!("MD5=abc,SHA-256={sha256}"), BODY));
    }

    #[test]
    fn every_known_digest_has_to_match_and_one_has_to_be_there() {
        let (sha256, sha512) = (sha256(), sha512());
        assert!(!digest_matches(&format!("SHA-256={sha512}"), BODY));
        assert!(!digest_matches(
            &format!("SHA-256={sha256},SHA-512={sha256}"),
            BODY
        ));
        assert!(!digest_matches("MD5=abc", BODY));
        assert!(!digest_matches("", BODY));
    }

    #[test]
    fn a_content_digest_is_a_structured_field_dictionary() {
        let (sha256, sha512) = (sha256(), sha512());
        assert!(content_digest_matches(&format!("sha-256=:{sha256}:"), BODY));
        // The digest RFC 9421's examples send, which is SHA-512.
        assert!(content_digest_matches(
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            BODY
        ));
        assert!(content_digest_matches(
            &format!("sha-256=:{sha256}:, sha-512=:{sha512}:"),
            BODY
        ));
        assert!(!content_digest_matches(&format!("sha-256={sha256}"), BODY));
        assert!(!content_digest_matches(
            &format!("sha-256=:{sha256}:, sha-512=:{sha256}:"),
            BODY
        ));
        assert!(!content_digest_matches("unixsum=:AAAA:", BODY));
    }
}
