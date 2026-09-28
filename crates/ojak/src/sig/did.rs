//! `did:key`, the DID method every portable object (FEP-ef61) can be
//! verified with, because it needs no resolution: the DID is the key.
//!
//! `did:key:z6Mk…` is the multibase of a Multikey, and its one verification
//! method is `did:key:z6Mk…#z6Mk…`. FEP-ef61 asks for base58btc only, so
//! that one key has one DID; a DID in any other multibase is not read.

use crate::sig::integrity::{PublicKey, decode_multikey, encode_ed25519_multikey};
use anyhow::{Result, anyhow};

/// The `did:key` of an Ed25519 public key.
#[must_use]
pub fn did_key(public_key: &[u8; 32]) -> String {
    format!("did:key:{}", encode_ed25519_multikey(public_key))
}

/// The verification method of a `did:key`: the DID, and its multibase as the
/// fragment.
#[must_use]
pub fn did_key_method(did: &str) -> String {
    let multibase = did.strip_prefix("did:key:").unwrap_or(did);
    format!("{did}#{multibase}")
}

/// The key a `did:key` DID URL names: the DID's own key, when the fragment is
/// absent or is the DID's multibase, as the method defines its one
/// verification method.
///
/// # Errors
///
/// When `did_url` is not a `did:key` DID URL in base58btc, names another
/// verification method, or carries a key type the integrity module cannot
/// verify with.
pub fn resolve_did_key(did_url: &str) -> Result<PublicKey> {
    let rest = did_url
        .strip_prefix("did:key:")
        .ok_or_else(|| anyhow!("{did_url} is not a did:key"))?;
    let (multibase, fragment) = match rest.split_once('#') {
        Some((multibase, fragment)) => (multibase, Some(fragment)),
        None => (rest, None),
    };
    if multibase.contains(['/', '?']) {
        return Err(anyhow!("{did_url} has a path or query"));
    }
    if !multibase.starts_with('z') {
        return Err(anyhow!("{did_url} is not base58btc"));
    }
    if fragment.is_some_and(|fragment| fragment != multibase) {
        return Err(anyhow!("{did_url} names no verification method of its DID"));
    }
    decode_multikey(multibase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_key_resolves_to_itself() {
        let public = [7u8; 32];
        let did = did_key(&public);
        assert!(did.starts_with("did:key:z6Mk"), "{did}");
        let method = did_key_method(&did);
        for url in [did.as_str(), method.as_str()] {
            let PublicKey::Ed25519(key) = resolve_did_key(url).unwrap() else {
                panic!("an Ed25519 key");
            };
            assert_eq!(*key, public);
        }
    }

    #[test]
    fn nothing_else_resolves() {
        let did = did_key(&[7u8; 32]);
        for url in [
            format!("{did}#other"),
            format!("{did}/path"),
            "did:web:a.example".to_owned(),
            "did:key:u7QEHBwcH".to_owned(),
            "did:key:z".to_owned(),
        ] {
            assert!(resolve_did_key(&url).is_err(), "{url}");
        }
    }
}
