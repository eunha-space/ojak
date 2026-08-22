//! FEP-8b32 Object Integrity Proof verification (`eddsa-jcs-2022` and
//! `mldsa44-jcs-2024`).
//!
//! Fedify-based servers (GoToSocial, hackers.pub, …) attach a Data Integrity
//! `proof` to the activities they deliver, authenticating the activity itself
//! rather than the HTTP transport. This lets a recipient accept an activity
//! whose HTTP Signature it can't verify (a different signature spec, a shared
//! inbox, or a forwarded/relayed delivery) as long as the author's proof holds.
//!
//! The algorithm mirrors Fedify's `verifyProof`
//! (`packages/fedify/src/sig/proof.ts`) and the W3C "Data Integrity EdDSA
//! Cryptosuites" `eddsa-jcs-2022` suite:
//!
//! 1. `proofConfig` = the document's `@context` plus the fixed proof metadata
//!    (`type`, `cryptosuite`, `verificationMethod`, `proofPurpose`, `created`).
//! 2. `unsecuredDocument` = the activity with every `proof` form removed.
//! 3. `hashData` = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsecuredDocument)).
//! 4. Verify the `proofValue` over `hashData` with the key resolved from the
//!    proof's `verificationMethod`.
//!
//! `mldsa44-jcs-2024` (W3C "Verifiable Credential Data Integrity — Quantum
//! Resistant Cryptosuites") is the same algorithm over ML-DSA-44 instead of
//! Ed25519, with one deliberate difference in step 1 that the specification
//! itself calls out: the proof configuration always takes the document's
//! `@context`, rather than keeping whatever the proof carried.

use anyhow::{Context as _, Result, anyhow};
use ed25519_dalek::Verifier as _;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Multicodec header for an `ed25519-pub` key inside a Multikey.
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Multicodec header for an `mldsa-44-pub` key inside a Multikey: code `0x1210`
/// as an unsigned varint.
const MLDSA44_PUB_MULTICODEC: [u8; 2] = [0x90, 0x24];

/// The cryptosuites this module can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cryptosuite {
    /// Ed25519 over JCS, the suite Fedify-based servers sign with.
    EddsaJcs2022,
    /// ML-DSA-44 over JCS, the post-quantum suite Mastodon 4.7 added.
    Mldsa44Jcs2024,
}

impl Cryptosuite {
    /// The `cryptosuite` string as it appears in a proof.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EddsaJcs2022 => "eddsa-jcs-2022",
            Self::Mldsa44Jcs2024 => "mldsa44-jcs-2024",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "eddsa-jcs-2022" => Some(Self::EddsaJcs2022),
            "mldsa44-jcs-2024" => Some(Self::Mldsa44Jcs2024),
            _ => None,
        }
    }
}

/// A public key resolved from a proof's `verificationMethod`.
pub enum PublicKey {
    Ed25519(Box<[u8; 32]>),
    /// An ML-DSA-44 key, as the 1312 bytes FIPS 204 encodes it in.
    MlDsa44(Box<[u8]>),
}

/// Find a usable assertion-method integrity proof on `document`, if present.
///
/// Returns the proof object, its cryptosuite, and its `verificationMethod` id.
/// The caller resolves that id to a key of the matching type and passes both
/// back to [`verify_object_integrity_proof`]. `proof` may be a single object or
/// an array (only the first usable one is returned).
#[must_use]
pub fn extract_integrity_proof(
    document: &Value,
) -> Option<(Map<String, Value>, Cryptosuite, String)> {
    let candidates = match document.get("proof")? {
        Value::Array(arr) => arr.clone(),
        obj @ Value::Object(_) => alloc_one(obj.clone()),
        _ => return None,
    };
    for candidate in candidates {
        let Value::Object(obj) = candidate else {
            continue;
        };
        let Some(suite) = obj
            .get("cryptosuite")
            .and_then(Value::as_str)
            .and_then(Cryptosuite::from_str)
        else {
            continue;
        };
        let usable = obj.get("proofPurpose").and_then(Value::as_str) == Some("assertionMethod")
            && obj.get("proofValue").and_then(Value::as_str).is_some()
            && obj.get("created").and_then(Value::as_str).is_some();
        if !usable {
            continue;
        }
        // A proof that has expired is not a proof, and the expiry is covered by
        // the signature, so it cannot have been added by anyone else.
        if let Some(expires) = obj.get("expires").and_then(Value::as_str) {
            match chrono::DateTime::parse_from_rfc3339(expires) {
                Ok(deadline) if deadline < chrono::Utc::now() => continue,
                Err(_) => continue,
                Ok(_) => {}
            }
        }
        if let Some(vm) = obj.get("verificationMethod").and_then(Value::as_str) {
            let vm = vm.to_string();
            return Some((obj, suite, vm));
        }
    }
    None
}

fn alloc_one(value: Value) -> Vec<Value> {
    vec![value]
}

/// Verify an integrity `proof` on `document` against `public_key`, the key
/// resolved from the proof's `verificationMethod`.
///
/// # Errors
/// Returns an error if the proof is malformed, the key does not match the
/// cryptosuite, or the signature does not verify.
pub fn verify_object_integrity_proof(
    document: &Value,
    proof: &Map<String, Value>,
    public_key: &PublicKey,
) -> Result<()> {
    let suite = proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .and_then(Cryptosuite::from_str)
        .ok_or_else(|| anyhow!("unsupported or missing cryptosuite"))?;
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proof missing proofValue"))?;

    // The proof configuration is the proof as it was signed: everything the
    // proof carries except the signature itself. Rebuilding it from a fixed
    // field list would drop anything else the signer covered — `expires`, or a
    // suite-specific term — and verification would fail on a valid proof.
    let mut proof_config = proof.clone();
    proof_config.remove("proofValue");
    let document_context = document.get("@context").cloned();

    match suite {
        Cryptosuite::EddsaJcs2022 => {
            // The proof may restate `@context` to add vocabulary the suite
            // needs. It is only honoured when it is a prefix of the document's,
            // so a signer cannot claim a context the document never had.
            if let Some(Value::Array(proof_context)) = proof_config.get("@context").cloned() {
                let Some(Value::Array(doc_context)) = document_context.clone() else {
                    return Err(anyhow!("proof declares @context but the document does not"));
                };
                if doc_context.len() < proof_context.len()
                    || doc_context[..proof_context.len()] != proof_context[..]
                {
                    return Err(anyhow!("proof @context is not a prefix of the document's"));
                }
            } else {
                proof_config.insert(
                    "@context".to_string(),
                    document_context.clone().unwrap_or(Value::Null),
                );
            }
        }
        Cryptosuite::Mldsa44Jcs2024 => {
            // Deliberately unlike eddsa-jcs-2022, and called out as such by the
            // specification: the configuration always takes the document's
            // `@context`, whatever the proof carried.
            proof_config.insert(
                "@context".to_string(),
                document_context.clone().unwrap_or(Value::Null),
            );
        }
    }

    let proof_canon =
        serde_jcs::to_string(&Value::Object(proof_config)).context("canonicalize proof config")?;
    let proof_hash = Sha256::digest(proof_canon.as_bytes());

    let signature_bytes = decode_multibase(proof_value).context("decode proofValue")?;

    // The document to hash is the activity with every proof form stripped.
    let mut unsecured = document
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("document is not a JSON object"))?;
    unsecured.remove("proof");
    unsecured.remove("https://w3id.org/security#proof");

    // For eddsa-jcs-2022 the signer may have replaced the document's `@context`
    // with the proof's before canonicalizing; the prefix check above bounds what
    // that can be.
    if let (Cryptosuite::EddsaJcs2022, Some(proof_context)) = (suite, proof.get("@context")) {
        unsecured.insert("@context".to_string(), proof_context.clone());
    }

    // Candidate documents to hash. The on-wire form is tried first; if the
    // activity also carries a legacy RsaSignature2017 `signature` (which servers
    // add *after* the integrity proof, so it isn't covered), retry without it.
    // Fedify reaches the same document via JSON-LD normalization; stripping the
    // field directly avoids pulling in a full JSON-LD processor.
    let mut candidates = vec![unsecured.clone()];
    if unsecured.contains_key("signature") {
        let mut without_sig = unsecured;
        without_sig.remove("signature");
        candidates.push(without_sig);
    }

    for candidate in candidates {
        let doc_canon = match serde_jcs::to_string(&Value::Object(candidate)) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut hash_data = [0u8; 64];
        hash_data[..32].copy_from_slice(&proof_hash);
        hash_data[32..].copy_from_slice(&Sha256::digest(doc_canon.as_bytes()));

        if verify_signature(suite, public_key, &hash_data, &signature_bytes)? {
            return Ok(());
        }
    }
    Err(anyhow!("integrity proof verification failed"))
}

/// Check one signature, with the key the cryptosuite calls for.
fn verify_signature(
    suite: Cryptosuite,
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    match (suite, public_key) {
        (Cryptosuite::EddsaJcs2022, PublicKey::Ed25519(key)) => {
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|e| anyhow!("invalid Ed25519 signature: {e}"))?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(key)
                .map_err(|e| anyhow!("invalid Ed25519 public key: {e}"))?;
            Ok(verifying_key.verify(message, &signature).is_ok())
        }
        (Cryptosuite::Mldsa44Jcs2024, PublicKey::MlDsa44(key)) => {
            let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(&key[..])
                .map_err(|_| anyhow!("ML-DSA-44 key must be {} bytes", key.len()))?;
            let verifying_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded);
            let Ok(encoded_signature) =
                ml_dsa::EncodedSignature::<ml_dsa::MlDsa44>::try_from(signature)
            else {
                return Ok(false);
            };
            let Some(signature) = ml_dsa::Signature::<ml_dsa::MlDsa44>::decode(&encoded_signature)
            else {
                return Ok(false);
            };
            // Empty context string, as the cryptosuite specifies.
            Ok(verifying_key.verify_with_context(message, b"", &signature))
        }
        (suite, _) => Err(anyhow!(
            "key type does not match cryptosuite {}",
            suite.as_str()
        )),
    }
}

/// Decode a Multikey `publicKeyMultibase` value into a raw 32-byte Ed25519 key.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping an
/// `ed25519-pub` multicodec key.
pub fn decode_ed25519_multikey(multibase: &str) -> Result<[u8; 32]> {
    let bytes = decode_multibase(multibase).context("decode multikey")?;
    let key = bytes
        .strip_prefix(&ED25519_PUB_MULTICODEC)
        .ok_or_else(|| anyhow!("multikey is not ed25519-pub"))?;
    key.try_into()
        .map_err(|_| anyhow!("ed25519 key must be 32 bytes, got {}", key.len()))
}

/// Decode a Multikey `publicKeyMultibase` value into an ML-DSA-44 public key.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping
/// an `mldsa-44-pub` multicodec key.
pub fn decode_mldsa44_multikey(multibase: &str) -> Result<Vec<u8>> {
    let bytes = decode_multibase(multibase).context("decode multikey")?;
    let key = bytes
        .strip_prefix(&MLDSA44_PUB_MULTICODEC)
        .ok_or_else(|| anyhow!("multikey is not mldsa-44-pub"))?;
    Ok(key.to_vec())
}

/// Decode whichever key type a Multikey carries.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping a
/// key type this module can verify with.
pub fn decode_multikey(multibase: &str) -> Result<PublicKey> {
    let bytes = decode_multibase(multibase).context("decode multikey")?;
    if let Some(key) = bytes.strip_prefix(&ED25519_PUB_MULTICODEC) {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow!("ed25519 key must be 32 bytes, got {}", key.len()))?;
        return Ok(PublicKey::Ed25519(Box::new(key)));
    }
    if let Some(key) = bytes.strip_prefix(&MLDSA44_PUB_MULTICODEC) {
        return Ok(PublicKey::MlDsa44(key.to_vec().into_boxed_slice()));
    }
    Err(anyhow!("unsupported multikey type"))
}

/// Decode a multibase value into bytes.
///
/// Multibase names its own encoding in the first character. Two appear in this
/// corner of the fediverse: `z` (base58btc), which Fedify and Mastodon write,
/// and `u` (base64url, unpadded), which the W3C quantum-resistant cryptosuite
/// examples use.
fn decode_multibase(value: &str) -> Result<Vec<u8>> {
    let mut chars = value.chars();
    match chars.next() {
        Some('z') => bs58::decode(chars.as_str())
            .into_vec()
            .map_err(|e| anyhow!("base58btc decode: {e}")),
        Some('u') => base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            chars.as_str(),
        )
        .map_err(|e| anyhow!("base64url decode: {e}")),
        Some(other) => Err(anyhow!("unsupported multibase encoding {other:?}")),
        None => Err(anyhow!("empty multibase value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Worked example from the W3C "Data Integrity EdDSA Cryptosuites"
    // specification (§ "Representation: eddsa-jcs-2022"). Verifying it end to end
    // exercises JCS canonicalization, the SHA-256 hash ordering, multibase
    // decoding, and Ed25519 verification against a spec-authoritative vector —
    // the same algorithm Fedify (hence hackers.pub) uses to sign.
    fn w3c_signed_credential() -> Value {
        serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
          ],
          "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
          "type": ["VerifiableCredential", "AlumniCredential"],
          "name": "Alumni Credential",
          "description": "A minimum viable example of an Alumni Credential.",
          "issuer": "https://vc.example/issuers/5678",
          "validFrom": "2023-01-01T00:00:00Z",
          "credentialSubject": {
            "id": "did:example:abcdefgh",
            "alumniOf": "The School of Examples"
          },
          "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "proofPurpose": "assertionMethod",
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "proofValue": "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
          }
        })
    }

    #[test]
    fn verifies_w3c_eddsa_jcs_2022_vector() {
        let doc = w3c_signed_credential();
        let (proof, suite, vm) = extract_integrity_proof(&doc).expect("proof present");
        assert_eq!(suite, Cryptosuite::EddsaJcs2022);
        assert!(vm.starts_with("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"));

        // The verification method's fragment is the publicKeyMultibase.
        let key = decode_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
            .expect("decode multikey");

        verify_object_integrity_proof(&doc, &proof, &key).expect("valid proof must verify");
    }

    #[test]
    fn rejects_tampered_document() {
        let mut doc = w3c_signed_credential();
        doc["issuer"] = serde_json::json!("https://vc.example/issuers/evil");
        let (proof, _, _) = extract_integrity_proof(&doc).expect("proof present");
        let key = decode_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
            .expect("decode multikey");
        assert!(verify_object_integrity_proof(&doc, &proof, &key).is_err());
    }

    /// Worked example from the W3C "Verifiable Credential Data Integrity —
    /// Quantum Resistant Cryptosuites" specification (Example 22, signed
    /// credential `mldsa44-jcs-2024`). It exercises the parts that differ from
    /// the Ed25519 suite: the `mldsa-44-pub` multicodec, base64url multibase,
    /// the proof configuration always taking the document's `@context`, and
    /// ML-DSA-44 verification itself.
    #[test]
    fn verifies_w3c_mldsa44_jcs_2024_vector() {
        let doc: Value =
            serde_json::from_str(include_str!("../tests/fixtures/w3c_mldsa44_jcs_2024.json"))
                .expect("parse vector");

        let (proof, suite, vm) = extract_integrity_proof(&doc).expect("proof present");
        assert_eq!(suite, Cryptosuite::Mldsa44Jcs2024);

        // did:key:<multibase>#<multibase> — the key is the method-specific id.
        let multibase = vm
            .strip_prefix("did:key:")
            .and_then(|rest| rest.split('#').next())
            .expect("did:key verification method");
        let key = decode_multikey(multibase).expect("decode multikey");
        assert!(
            matches!(&key, PublicKey::MlDsa44(bytes) if bytes.len() == 1312),
            "expected a 1312-byte ML-DSA-44 key"
        );

        verify_object_integrity_proof(&doc, &proof, &key).expect("valid proof must verify");
    }

    #[test]
    fn rejects_a_tampered_mldsa44_document() {
        let mut doc: Value =
            serde_json::from_str(include_str!("../tests/fixtures/w3c_mldsa44_jcs_2024.json"))
                .expect("parse vector");
        doc["issuer"] = serde_json::json!("did:example:evil");

        let (proof, _, vm) = extract_integrity_proof(&doc).expect("proof present");
        let multibase = vm
            .strip_prefix("did:key:")
            .and_then(|rest| rest.split('#').next())
            .unwrap();
        let key = decode_multikey(multibase).unwrap();
        assert!(verify_object_integrity_proof(&doc, &proof, &key).is_err());
    }

    /// An Ed25519 key cannot stand in for an ML-DSA proof, or the other way
    /// round: the cryptosuite names the key type, and a mismatch is an error
    /// rather than a verification failure to retry.
    #[test]
    fn refuses_a_key_of_the_wrong_type() {
        let doc: Value =
            serde_json::from_str(include_str!("../tests/fixtures/w3c_mldsa44_jcs_2024.json"))
                .expect("parse vector");
        let (proof, _, _) = extract_integrity_proof(&doc).expect("proof present");

        let ed25519 = decode_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2").unwrap();
        let err = verify_object_integrity_proof(&doc, &proof, &ed25519).unwrap_err();
        assert!(err.to_string().contains("key type"), "{err}");
    }

    #[test]
    fn decodes_both_multibase_encodings() {
        // "hello" in base58btc and base64url, as multibase writes them.
        assert_eq!(decode_multibase("zCn8eVZg").unwrap(), b"hello");
        assert_eq!(decode_multibase("uaGVsbG8").unwrap(), b"hello");
        assert!(decode_multibase("Qhello").is_err());
        assert!(decode_multibase("").is_err());
    }

    #[test]
    fn ignores_an_expired_proof() {
        let mut doc = w3c_signed_credential();
        doc["proof"]["expires"] = serde_json::json!("2020-01-01T00:00:00Z");
        assert!(
            extract_integrity_proof(&doc).is_none(),
            "an expired proof must not be offered for verification"
        );

        doc["proof"]["expires"] = serde_json::json!("2999-01-01T00:00:00Z");
        assert!(extract_integrity_proof(&doc).is_some());
    }

    #[test]
    fn missing_proof_is_none() {
        let doc = serde_json::json!({ "type": "Note", "content": "hi" });
        assert!(extract_integrity_proof(&doc).is_none());
    }
}
