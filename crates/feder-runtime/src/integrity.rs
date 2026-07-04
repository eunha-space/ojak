//! FEP-8b32 Object Integrity Proof verification (cryptosuite `eddsa-jcs-2022`).
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
//! 4. Verify the Ed25519 `proofValue` over `hashData` with the key resolved from
//!    the proof's `verificationMethod`.

use anyhow::{anyhow, Context as _, Result};
use ed25519_dalek::Verifier as _;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

/// Multicodec header for an `ed25519-pub` key inside a Multikey.
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Find the `eddsa-jcs-2022` assertion-method proof on `document`, if present.
///
/// Returns the proof object and its `verificationMethod` id. The caller resolves
/// that id to an Ed25519 key and passes both back to
/// [`verify_object_integrity_proof`]. `proof` may be a single object or an array
/// (only the first usable one is returned).
#[must_use]
pub fn extract_integrity_proof(document: &Value) -> Option<(Map<String, Value>, String)> {
    let candidates = match document.get("proof")? {
        Value::Array(arr) => arr.clone(),
        obj @ Value::Object(_) => alloc_one(obj.clone()),
        _ => return None,
    };
    for candidate in candidates {
        let Value::Object(obj) = candidate else {
            continue;
        };
        let usable = obj.get("cryptosuite").and_then(Value::as_str) == Some("eddsa-jcs-2022")
            && obj.get("proofPurpose").and_then(Value::as_str) == Some("assertionMethod")
            && obj.get("proofValue").and_then(Value::as_str).is_some()
            && obj.get("created").and_then(Value::as_str).is_some();
        if !usable {
            continue;
        }
        if let Some(vm) = obj.get("verificationMethod").and_then(Value::as_str) {
            let vm = vm.to_string();
            return Some((obj, vm));
        }
    }
    None
}

fn alloc_one(value: Value) -> Vec<Value> {
    vec![value]
}

/// Verify an `eddsa-jcs-2022` [`proof`] on `document` against `public_key` (the
/// raw 32-byte Ed25519 key resolved from the proof's `verificationMethod`).
///
/// # Errors
/// Returns an error if the proof is malformed, the cryptosuite is unsupported,
/// or the signature does not verify.
pub fn verify_object_integrity_proof(
    document: &Value,
    proof: &Map<String, Value>,
    public_key: &[u8; 32],
) -> Result<()> {
    if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
        return Err(anyhow!("unsupported or missing cryptosuite"));
    }
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proof missing verificationMethod"))?;
    let created = proof
        .get("created")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proof missing created"))?;
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proof missing proofValue"))?;

    // Reconstruct the proof configuration exactly as the signer did: the
    // document's `@context` followed by the fixed metadata fields — never the
    // proof's own `@context` or any extra fields it may carry on the wire.
    let proof_config = json!({
        "@context": document.get("@context").cloned().unwrap_or(Value::Null),
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "created": created,
    });

    // The document to hash is the activity with every proof form stripped.
    let mut unsecured = document
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("document is not a JSON object"))?;
    unsecured.remove("proof");
    unsecured.remove("https://w3id.org/security#proof");
    let unsecured = Value::Object(unsecured);

    let proof_canon = serde_jcs::to_string(&proof_config).context("canonicalize proof config")?;
    let doc_canon = serde_jcs::to_string(&unsecured).context("canonicalize document")?;

    let mut hash_data = [0u8; 64];
    hash_data[..32].copy_from_slice(&Sha256::digest(proof_canon.as_bytes()));
    hash_data[32..].copy_from_slice(&Sha256::digest(doc_canon.as_bytes()));

    let signature_bytes = decode_multibase_base58btc(proof_value).context("decode proofValue")?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("invalid Ed25519 signature: {e}"))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| anyhow!("invalid Ed25519 public key: {e}"))?;

    verifying_key
        .verify(&hash_data, &signature)
        .map_err(|e| anyhow!("integrity proof verification failed: {e}"))
}

/// Decode a Multikey `publicKeyMultibase` value into a raw 32-byte Ed25519 key.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping an
/// `ed25519-pub` multicodec key.
pub fn decode_ed25519_multikey(multibase: &str) -> Result<[u8; 32]> {
    let bytes = decode_multibase_base58btc(multibase).context("decode multikey")?;
    let key = bytes
        .strip_prefix(&ED25519_PUB_MULTICODEC)
        .ok_or_else(|| anyhow!("multikey is not ed25519-pub"))?;
    key.try_into()
        .map_err(|_| anyhow!("ed25519 key must be 32 bytes, got {}", key.len()))
}

/// Decode a base58btc multibase value (the `z` prefix) into bytes.
fn decode_multibase_base58btc(value: &str) -> Result<Vec<u8>> {
    let encoded = value
        .strip_prefix('z')
        .ok_or_else(|| anyhow!("expected base58btc multibase ('z' prefix)"))?;
    bs58::decode(encoded)
        .into_vec()
        .map_err(|e| anyhow!("base58btc decode: {e}"))
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
        let (proof, vm) = extract_integrity_proof(&doc).expect("proof present");
        assert!(vm.starts_with("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"));

        // The verification method's fragment is the publicKeyMultibase.
        let key = decode_ed25519_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
            .expect("decode multikey");

        verify_object_integrity_proof(&doc, &proof, &key).expect("valid proof must verify");
    }

    #[test]
    fn rejects_tampered_document() {
        let mut doc = w3c_signed_credential();
        doc["issuer"] = serde_json::json!("https://vc.example/issuers/evil");
        let (proof, _) = extract_integrity_proof(&doc).expect("proof present");
        let key = decode_ed25519_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
            .expect("decode multikey");
        assert!(verify_object_integrity_proof(&doc, &proof, &key).is_err());
    }

    #[test]
    fn missing_proof_is_none() {
        let doc = serde_json::json!({ "type": "Note", "content": "hi" });
        assert!(extract_integrity_proof(&doc).is_none());
    }
}
