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

use crate::{CryptoRngCore, Error};
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(Box<[u8; 32]>),
    /// An ML-DSA-44 key, as the 1312 bytes FIPS 204 encodes it in.
    MlDsa44(Box<[u8]>),
}

/// The DER of an Ed25519 `SubjectPublicKeyInfo` before its 32 key bytes
/// (RFC 8410): the algorithm identifier `1.3.101.112` and the bit string's
/// header.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The DER of an ML-DSA-44 `SubjectPublicKeyInfo` before its 1312 key bytes
/// (`id-ml-dsa-44`, as X.509 carries it): the algorithm identifier
/// `2.16.840.1.101.3.4.3.17` and the bit string's header.
const MLDSA44_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x11, 0x03, 0x82, 0x05, 0x21, 0x00,
];

/// How long an ML-DSA-44 public key is.
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;

impl PublicKey {
    /// The key as a DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    /// Returns an error if an ML-DSA-44 key is not 1312 bytes long.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Ed25519(key) => Ok([ED25519_SPKI_PREFIX.as_slice(), key.as_slice()].concat()),
            Self::MlDsa44(key) if key.len() == MLDSA44_PUBLIC_KEY_BYTES => {
                Ok([MLDSA44_SPKI_PREFIX.as_slice(), key].concat())
            }
            Self::MlDsa44(key) => Err(Error::Key(format!(
                "an ML-DSA-44 key of {} bytes",
                key.len()
            ))),
        }
    }

    /// The key as an SPKI PEM, as OpenSSL's `public_to_pem` writes it: a
    /// `PUBLIC KEY` block, base64 in lines of 64, each ending in LF. This is
    /// what Mastodon stores a remote actor's Multikey as, and a FASP's key.
    ///
    /// # Errors
    /// As [`PublicKey::to_spki_der`].
    pub fn to_spki_pem(&self) -> Result<String, Error> {
        use base64::Engine as _;

        let encoded = base64::engine::general_purpose::STANDARD.encode(self.to_spki_der()?);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(core::str::from_utf8(line).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        Ok(pem)
    }

    /// The Ed25519 or ML-DSA-44 key of a DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    /// Returns an error if `der` is not an SPKI of either.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        if let Some(key) = der.strip_prefix(&ED25519_SPKI_PREFIX) {
            return Ok(Self::Ed25519(Box::new(ed25519_bytes(key)?)));
        }
        if let Some(key) = der.strip_prefix(&MLDSA44_SPKI_PREFIX)
            && key.len() == MLDSA44_PUBLIC_KEY_BYTES
        {
            return Ok(Self::MlDsa44(key.to_vec().into_boxed_slice()));
        }
        Err(Error::Key(
            "not an Ed25519 or ML-DSA-44 public key in SPKI".into(),
        ))
    }

    /// The Ed25519 or ML-DSA-44 key of an SPKI PEM: the base64 between its
    /// armour lines, however it is wrapped.
    ///
    /// # Errors
    /// Returns an error if `pem` is not base64 armour around an SPKI of
    /// either.
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        use base64::Engine as _;

        let body: String = pem
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| Error::Key("the public key is not base64".into()))?;
        Self::from_spki_der(&der)
    }
}

/// Find a usable assertion-method integrity proof on `document`, if present,
/// and not expired at `now`, in seconds since the Unix epoch.
///
/// Returns the proof object, its cryptosuite, and its `verificationMethod` id.
/// The caller resolves that id to a key of the matching type and passes both
/// back to [`verify_object_integrity_proof`]. `proof` may be a single object or
/// an array (only the first usable one is returned; [`integrity_proofs`] has
/// them all).
#[must_use]
pub fn extract_integrity_proof(
    document: &Value,
    now: i64,
) -> Option<(Map<String, Value>, Cryptosuite, String)> {
    integrity_proofs(document, now).into_iter().next()
}

/// Every usable assertion-method integrity proof on `document`, in order, as
/// [`extract_integrity_proof`] returns one. A document may carry several, in
/// different suites or by different keys, and one that does not verify says
/// nothing about the others.
#[must_use]
pub fn integrity_proofs(
    document: &Value,
    now: i64,
) -> Vec<(Map<String, Value>, Cryptosuite, String)> {
    let candidates = match document.get("proof") {
        Some(Value::Array(arr)) => arr.clone(),
        Some(obj @ Value::Object(_)) => alloc_one(obj.clone()),
        _ => return Vec::new(),
    };
    let mut proofs = Vec::new();
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
                Ok(deadline) if deadline.timestamp() < now => continue,
                Err(_) => continue,
                Ok(_) => {}
            }
        }
        if let Some(vm) = obj.get("verificationMethod").and_then(Value::as_str) {
            let vm = vm.to_string();
            proofs.push((obj, suite, vm));
        }
    }
    proofs
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
) -> Result<(), Error> {
    let suite = proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .and_then(Cryptosuite::from_str)
        .ok_or_else(|| Error::Unsupported("or missing cryptosuite".into()))?;
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Malformed("proof has no proofValue".into()))?;

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
                    return Err(Error::Malformed(
                        "proof declares @context but the document does not".into(),
                    ));
                };
                if doc_context.len() < proof_context.len()
                    || doc_context[..proof_context.len()] != proof_context[..]
                {
                    return Err(Error::Malformed(
                        "proof @context is not a prefix of the document's".into(),
                    ));
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

    let proof_canon = canonical(&Value::Object(proof_config))?;
    let proof_hash = Sha256::digest(proof_canon.as_bytes());

    let signature_bytes = decode_multibase(proof_value)?;

    // The document to hash is the activity with every proof form stripped.
    let mut unsecured = document
        .as_object()
        .cloned()
        .ok_or_else(|| Error::Malformed("document is not a JSON object".into()))?;
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
        let doc_canon = match serde_json_canonicalizer::to_string(&Value::Object(candidate)) {
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
    Err(Error::Invalid)
}

/// `value` as JCS (RFC 8785) writes it.
fn canonical(value: &Value) -> Result<String, Error> {
    serde_json_canonicalizer::to_string(value)
        .map_err(|error| Error::Malformed(format!("cannot canonicalize: {error}")))
}

/// Generate an Ed25519 signing key, returned as a PKCS#8 PEM.
///
/// PEM rather than raw bytes because that is what other implementations expect
/// to find in a stored private key — Mastodon reads its `keypairs.private_key`
/// with `OpenSSL::PKey.read` — so a key written here stays readable by a server
/// pointed at the same database.
///
/// # Errors
/// Returns an error if the key cannot be encoded.
pub fn generate_ed25519_key(rng: &mut impl CryptoRngCore) -> Result<String, Error> {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    let key = ed25519_dalek::SigningKey::generate(rng);
    Ok(key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|error| Error::Key(format!("Ed25519 key as PKCS#8: {error}")))?
        .to_string())
}

/// The raw 32-byte seed and public key of a PKCS#8 PEM Ed25519 key.
///
/// # Errors
/// Returns an error if the PEM is not a PKCS#8 Ed25519 private key.
pub fn parse_ed25519_key(pem: &str) -> Result<([u8; 32], [u8; 32]), Error> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;

    let key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
        .map_err(|_| Error::Key("not an Ed25519 private key in PKCS#8 PEM".into()))?;
    Ok((key.to_bytes(), key.verifying_key().to_bytes()))
}

/// The public key of a raw 32-byte Ed25519 seed.
#[must_use]
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// A fresh raw 32-byte Ed25519 seed.
#[must_use]
pub fn generate_ed25519_seed(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    ed25519_dalek::SigningKey::generate(rng).to_bytes()
}

/// Attach an `eddsa-jcs-2022` integrity proof to `document`.
///
/// The inverse of [`verify_object_integrity_proof`], and deliberately written
/// to be verified by it: the proof configuration is hashed, then the document
/// without its proof, and the Ed25519 signature covers both hashes in that
/// order.
///
/// A proof authenticates the activity rather than the transport that carried
/// it, which is what lets a relayed or forwarded activity still be attributed.
/// Mastodon 4.7 verifies these but does not produce them.
///
/// # Arguments
/// * `document`            – the activity to sign; must be a JSON object
/// * `verification_method` – the id of the key, as published in the actor's
///   `assertionMethod`
/// * `signing_key`         – the raw 32-byte Ed25519 seed
/// * `now`                 – the time, in seconds since the Unix epoch, which
///   becomes the proof's `created`
///
/// # Errors
/// Returns an error if the document is not an object or cannot be canonicalized.
pub fn sign_object_integrity_proof(
    document: &Value,
    verification_method: &str,
    signing_key: &[u8; 32],
    now: i64,
) -> Result<Value, Error> {
    use ed25519_dalek::Signer as _;

    let mut unsecured = document
        .as_object()
        .cloned()
        .ok_or_else(|| Error::Malformed("document is not a JSON object".into()))?;
    unsecured.remove("proof");
    unsecured.remove("https://w3id.org/security#proof");

    let created = chrono::DateTime::from_timestamp(now, 0)
        .ok_or_else(|| Error::Malformed(format!("{now} is not a time")))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // The configuration carries the document's `@context`, as the verifier
    // reconstructs it. Field order is irrelevant: JCS sorts keys.
    let mut proof_config = Map::new();
    proof_config.insert(
        "@context".to_string(),
        unsecured.get("@context").cloned().unwrap_or(Value::Null),
    );
    proof_config.insert("type".to_string(), Value::from("DataIntegrityProof"));
    proof_config.insert(
        "cryptosuite".to_string(),
        Value::from(Cryptosuite::EddsaJcs2022.as_str()),
    );
    proof_config.insert(
        "verificationMethod".to_string(),
        Value::from(verification_method),
    );
    proof_config.insert("proofPurpose".to_string(), Value::from("assertionMethod"));
    proof_config.insert("created".to_string(), Value::from(created));

    let proof_canon = canonical(&Value::Object(proof_config.clone()))?;
    let doc_canon = canonical(&Value::Object(unsecured.clone()))?;

    let mut hash_data = [0u8; 64];
    hash_data[..32].copy_from_slice(&Sha256::digest(proof_canon.as_bytes()));
    hash_data[32..].copy_from_slice(&Sha256::digest(doc_canon.as_bytes()));

    let signature = ed25519_dalek::SigningKey::from_bytes(signing_key).sign(&hash_data);

    let mut proof = proof_config;
    proof.insert(
        "proofValue".to_string(),
        Value::from(encode_multibase_base58btc(&signature.to_bytes())),
    );

    let mut signed = unsecured;
    signed.insert("proof".to_string(), Value::Object(proof));
    Ok(Value::Object(signed))
}

/// The Multikey `publicKeyMultibase` for an Ed25519 public key: the
/// `ed25519-pub` multicodec header, base58btc, with multibase's `z` prefix.
#[must_use]
pub fn encode_ed25519_multikey(public_key: &[u8; 32]) -> String {
    let mut bytes = ED25519_PUB_MULTICODEC.to_vec();
    bytes.extend_from_slice(public_key);
    encode_multibase_base58btc(&bytes)
}

fn encode_multibase_base58btc(bytes: &[u8]) -> String {
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Check one signature, with the key the cryptosuite calls for.
fn verify_signature(
    suite: Cryptosuite,
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    match (suite, public_key) {
        (Cryptosuite::EddsaJcs2022, PublicKey::Ed25519(key)) => {
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|e| Error::Malformed(format!("Ed25519 signature: {e}")))?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(key)
                .map_err(|e| Error::Key(format!("Ed25519 public key: {e}")))?;
            Ok(verifying_key.verify(message, &signature).is_ok())
        }
        (Cryptosuite::Mldsa44Jcs2024, PublicKey::MlDsa44(key)) => {
            let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(&key[..])
                .map_err(|_| Error::Key(format!("an ML-DSA-44 key of {} bytes", key.len())))?;
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
        (suite, _) => Err(Error::WrongKey(format!(
            "key type does not match cryptosuite {}",
            suite.as_str()
        ))),
    }
}

/// Decode a Multikey `publicKeyMultibase` value into a raw 32-byte Ed25519 key.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping an
/// `ed25519-pub` multicodec key.
pub fn decode_ed25519_multikey(multibase: &str) -> Result<[u8; 32], Error> {
    let bytes = decode_multibase(multibase)?;
    let key = bytes
        .strip_prefix(&ED25519_PUB_MULTICODEC)
        .ok_or_else(|| Error::Key("multikey is not ed25519-pub".into()))?;
    ed25519_bytes(key)
}

fn ed25519_bytes(key: &[u8]) -> Result<[u8; 32], Error> {
    key.try_into()
        .map_err(|_| Error::Key(format!("an Ed25519 key of {} bytes", key.len())))
}

/// Decode a Multikey `publicKeyMultibase` value into an ML-DSA-44 public key.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping
/// an `mldsa-44-pub` multicodec key.
pub fn decode_mldsa44_multikey(multibase: &str) -> Result<Vec<u8>, Error> {
    let bytes = decode_multibase(multibase)?;
    let key = bytes
        .strip_prefix(&MLDSA44_PUB_MULTICODEC)
        .ok_or_else(|| Error::Key("multikey is not mldsa-44-pub".into()))?;
    Ok(key.to_vec())
}

/// Decode whichever key type a Multikey carries.
///
/// # Errors
/// Returns an error if the value is not a base58btc multibase string wrapping a
/// key type this module can verify with.
pub fn decode_multikey(multibase: &str) -> Result<PublicKey, Error> {
    let bytes = decode_multibase(multibase)?;
    if let Some(key) = bytes.strip_prefix(&ED25519_PUB_MULTICODEC) {
        return Ok(PublicKey::Ed25519(Box::new(ed25519_bytes(key)?)));
    }
    if let Some(key) = bytes.strip_prefix(&MLDSA44_PUB_MULTICODEC) {
        return Ok(PublicKey::MlDsa44(key.to_vec().into_boxed_slice()));
    }
    Err(Error::Unsupported("multikey type".into()))
}

/// Decode a multibase value into bytes.
///
/// Multibase names its own encoding in the first character. Two appear in this
/// corner of the fediverse: `z` (base58btc), which Fedify and Mastodon write,
/// and `u` (base64url, unpadded), which the W3C quantum-resistant cryptosuite
/// examples use.
fn decode_multibase(value: &str) -> Result<Vec<u8>, Error> {
    let mut chars = value.chars();
    match chars.next() {
        Some('z') => bs58::decode(chars.as_str())
            .into_vec()
            .map_err(|e| Error::Malformed(format!("base58btc: {e}"))),
        Some('u') => base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            chars.as_str(),
        )
        .map_err(|e| Error::Malformed(format!("base64url: {e}"))),
        Some(other) => Err(Error::Unsupported(format!("multibase encoding {other:?}"))),
        None => Err(Error::Malformed("empty multibase value".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8410 §10.1's example public key.
    #[test]
    fn reads_and_writes_the_rfc_8410_public_key() {
        let pem = "-----BEGIN PUBLIC KEY-----\n\
                   MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
                   -----END PUBLIC KEY-----\n";
        let key = PublicKey::from_spki_pem(pem).unwrap();
        let PublicKey::Ed25519(raw) = &key else {
            panic!("{key:?}");
        };
        assert_eq!(raw[..4], [0x19, 0xbf, 0x44, 0x09]);
        assert_eq!(key.to_spki_pem().unwrap(), pem);
    }

    /// An ML-DSA-44 key is wrapped in lines of 64, as OpenSSL writes it, and
    /// read back however it is wrapped.
    #[test]
    fn an_ml_dsa_44_key_round_trips_through_pem() {
        let key = PublicKey::MlDsa44(vec![7; 1312].into_boxed_slice());
        let pem = key.to_spki_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\nMIIFMjALBglghkgBZQMEAxEDggUhAA"));
        assert!(pem.lines().all(|line| line.len() <= 64));
        assert_eq!(PublicKey::from_spki_pem(&pem).unwrap(), key);
        let unwrapped: String = pem.lines().collect::<Vec<_>>().join("");
        let unwrapped = unwrapped
            .replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n")
            .replace("-----END", "\n-----END");
        assert_eq!(PublicKey::from_spki_pem(&unwrapped).unwrap(), key);
        assert!(
            PublicKey::MlDsa44(vec![7; 10].into_boxed_slice())
                .to_spki_pem()
                .is_err()
        );
    }

    #[test]
    fn what_is_not_an_ed25519_or_ml_dsa_44_key_is_refused() {
        let rsa = include_str!("../../ojak/tests/fixtures/rfc9421_test_key_rsa_public.pem");
        assert!(PublicKey::from_spki_pem(rsa).is_err());
        assert!(PublicKey::from_spki_pem("not base64!").is_err());
    }

    /// When the tests read and sign proofs: after the W3C vectors were
    /// made, and before the far expiry `ignores_an_expired_proof` sets.
    const NOW: i64 = 1_759_000_000;

    /// FEP-8b32's own test vector (fep-8b32.feature): a proof that restates
    /// the document's `@context`, over a document with decimals, which JCS
    /// has to write as ECMAScript does.
    #[test]
    fn verifies_the_fep_8b32_test_vector() {
        let document = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v2"
            ],
            "id": "https://server.example/activities/1",
            "type": "Create",
            "actor": "https://server.example/users/alice",
            "object": {
                "id": "https://server.example/objects/1",
                "type": "Note",
                "attributedTo": "https://server.example/users/alice",
                "content": "Hello world",
                "location": {
                    "type": "Place",
                    "longitude": -71.184902,
                    "latitude": 25.273962
                }
            },
            "proof": {
                "@context": [
                    "https://www.w3.org/ns/activitystreams",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "https://server.example/users/alice#ed25519-key",
                "proofPurpose": "assertionMethod",
                "proofValue": "z42ffGu6AUKPCFcFPiabmUvnGLPJzC7e4DGWC52NUasSSH37UMa9c58tdgVszUcZfytxa4fQ5TYHaJENCxUDe9SdL",
                "created": "2023-02-24T23:36:38Z"
            }
        });
        let key = decode_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2").unwrap();
        let (proof, suite, method) = extract_integrity_proof(&document, NOW).unwrap();
        assert_eq!(suite, Cryptosuite::EddsaJcs2022);
        assert_eq!(method, "https://server.example/users/alice#ed25519-key");
        verify_object_integrity_proof(&document, &proof, &key).unwrap();

        let mut moved = document.clone();
        moved["object"]["location"]["latitude"] = serde_json::json!(25.273963);
        assert!(verify_object_integrity_proof(&moved, &proof, &key).is_err());
    }

    /// RFC 8785 §3.2.3: keys are sorted by their UTF-16 code units, which is
    /// how a JavaScript signer sorts them, not by their UTF-8 bytes, and
    /// unescaped. Sorted by bytes, U+FB33 would come before the emoji and
    /// `\r` after `1`.
    #[test]
    fn canonical_json_sorts_keys_as_rfc_8785_does() {
        let object = serde_json::json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis"
        });
        let canonical = serde_json_canonicalizer::to_string(&object).unwrap();
        let order: Vec<&str> = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ]
        .into_iter()
        .collect();
        let mut positions: Vec<usize> = order
            .iter()
            .map(|value| canonical.find(value).unwrap())
            .collect();
        let sorted = {
            let mut sorted = positions.clone();
            sorted.sort_unstable();
            sorted
        };
        assert_eq!(positions, sorted, "{canonical}");
        positions.dedup();
        assert_eq!(positions.len(), order.len());
    }

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
        let (proof, suite, vm) = extract_integrity_proof(&doc, NOW).expect("proof present");
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
        let (proof, _, _) = extract_integrity_proof(&doc, NOW).expect("proof present");
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

        let (proof, suite, vm) = extract_integrity_proof(&doc, NOW).expect("proof present");
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

        let (proof, _, vm) = extract_integrity_proof(&doc, NOW).expect("proof present");
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
        let (proof, _, _) = extract_integrity_proof(&doc, NOW).expect("proof present");

        let ed25519 = decode_multikey("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2").unwrap();
        let err = verify_object_integrity_proof(&doc, &proof, &ed25519).unwrap_err();
        assert!(matches!(err, Error::WrongKey(_)), "{err}");
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
            extract_integrity_proof(&doc, NOW).is_none(),
            "an expired proof must not be offered for verification"
        );

        doc["proof"]["expires"] = serde_json::json!("2999-01-01T00:00:00Z");
        assert!(extract_integrity_proof(&doc, NOW).is_some());
    }

    /// A proof this module produces is one it accepts. Round-tripping is weak
    /// evidence on its own, but the verifier is itself pinned to the W3C
    /// vector, so agreeing with it means agreeing with the specification.
    #[test]
    fn signs_a_proof_its_own_verifier_accepts() {
        use ed25519_dalek::SigningKey;

        let seed = [7u8; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let multikey = encode_ed25519_multikey(&public);

        let document = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://local.example/activities/1",
            "type": "Create",
            "actor": "https://local.example/users/alice",
            "object": {"id": "https://local.example/notes/1", "type": "Note", "content": "hi"},
        });

        let vm = "https://local.example/users/alice#ed25519-key";
        let signed = sign_object_integrity_proof(&document, vm, &seed, NOW).unwrap();

        let (proof, suite, found_vm) =
            extract_integrity_proof(&signed, NOW).expect("proof attached");
        assert_eq!(suite, Cryptosuite::EddsaJcs2022);
        assert_eq!(found_vm, vm);

        let key = decode_multikey(&multikey).unwrap();
        verify_object_integrity_proof(&signed, &proof, &key).expect("own proof must verify");
    }

    /// The proof covers the document: change anything under it and the proof
    /// stops holding.
    #[test]
    fn a_signed_document_cannot_be_altered() {
        use ed25519_dalek::SigningKey;

        let seed = [9u8; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let multikey = encode_ed25519_multikey(&public);

        let document = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://local.example/activities/2",
            "type": "Create",
            "actor": "https://local.example/users/alice",
        });
        let mut signed = sign_object_integrity_proof(
            &document,
            "https://local.example/users/alice#k",
            &seed,
            NOW,
        )
        .unwrap();
        signed["actor"] = serde_json::json!("https://local.example/users/mallory");

        let (proof, _, _) = extract_integrity_proof(&signed, NOW).unwrap();
        let key = decode_multikey(&multikey).unwrap();
        assert!(verify_object_integrity_proof(&signed, &proof, &key).is_err());
    }

    /// The published key decodes back to the bytes it was made from, with the
    /// multicodec header the W3C vector uses.
    /// A generated key is a PKCS#8 PEM — the form other implementations read
    /// a stored private key from — and parses back to the bytes that sign.
    #[test]
    fn generates_a_pem_key_that_parses_back() {
        let pem = generate_ed25519_key(&mut rand::rngs::OsRng).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        let (seed, public) = parse_ed25519_key(&pem).unwrap();
        assert_eq!(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
            public,
            "the public half must belong to the seed"
        );

        // And it is usable end to end.
        let document = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Create",
        });
        let signed =
            sign_object_integrity_proof(&document, "https://x.test/a#k", &seed, NOW).unwrap();
        let (proof, _, _) = extract_integrity_proof(&signed, NOW).unwrap();
        let key = decode_multikey(&encode_ed25519_multikey(&public)).unwrap();
        verify_object_integrity_proof(&signed, &proof, &key).unwrap();

        assert_ne!(
            pem,
            generate_ed25519_key(&mut rand::rngs::OsRng).unwrap(),
            "keys must differ"
        );
    }

    #[test]
    fn a_published_multikey_round_trips() {
        let public = [3u8; 32];
        let multikey = encode_ed25519_multikey(&public);
        assert!(multikey.starts_with('z'));
        assert_eq!(decode_ed25519_multikey(&multikey).unwrap(), public);

        match decode_multikey(&multikey).unwrap() {
            PublicKey::Ed25519(bytes) => assert_eq!(*bytes, public),
            PublicKey::MlDsa44(_) => panic!("decoded as the wrong key type"),
        }
    }

    #[test]
    fn missing_proof_is_none() {
        let doc = serde_json::json!({ "type": "Note", "content": "hi" });
        assert!(extract_integrity_proof(&doc, NOW).is_none());
    }
}
