//! Linked Data Signatures: `RsaSignature2017`, as Mastodon makes and checks
//! them (`ActivityPub::LinkedDataSignature`).
//!
//! The signature sits in the document it signs, under `signature`, and covers
//! two SHA-256 hashes: one of the signature's own options (`creator`,
//! `created`, `expires`) read against the identity context, and one of the
//! document without its `signature`. Each hash is of the canonical N-Quads
//! of what the JSON-LD means ([`ojak_jsonld::rdf`]), so a server that passes
//! the document on — a relay, or a server forwarding a reply — cannot change
//! what it says without the signature failing, while the signature still says
//! who wrote it.
//!
//! That cuts both ways. What verifies is the graph, not the tree: a document
//! can be rewritten into one that reads differently to a reader of JSON keys
//! and still verify. A caller that takes a document on the strength of this
//! signature should read it as JSON-LD processing gives it, not as it was
//! written; ojak's inbox does.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use ojak_jsonld::Registry;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::Error;
use crate::signature::{PrivateKey, rsa_verify_pkcs1v15};

/// The one Linked Data Signature suite the fediverse uses.
pub const RSA_SIGNATURE_2017: &str = "RsaSignature2017";

/// What the signature's options are read against.
pub const IDENTITY_CONTEXT: &str = "https://w3id.org/identity/v1";

/// What a signed document's `@context` gains, so that `signature` means
/// something to a JSON-LD reader.
pub const SECURITY_CONTEXT: &str = "https://w3id.org/security/v1";

/// How long Mastodon's signatures last.
pub const DEFAULT_LIFETIME_SECONDS: i64 = 2 * 24 * 60 * 60;

/// The key an `RsaSignature2017` on `document` says made it: its `creator`.
///
/// Says nothing about whether it verifies.
#[must_use]
pub fn creator(document: &Value) -> Option<&str> {
    let signature = document.get("signature")?;
    if signature.get("type").and_then(Value::as_str) != Some(RSA_SIGNATURE_2017) {
        return None;
    }
    signature.get("creator").and_then(Value::as_str)
}

/// Sign `document` as `key_id`, which `private_key` is the key of: the
/// document with an `RsaSignature2017` made at `created` and good until
/// `expires` (Unix seconds), and the security context added to its
/// `@context`, as `ActivityPub::LinkedDataSignature#sign!` gives it.
///
/// A `signature` the document already carries is replaced.
///
/// # Errors
///
/// When the document, or the options, cannot be turned into RDF: a context
/// ojak does not ship, or a JSON-LD feature ojak does not turn into RDF.
pub fn sign(
    registry: &Registry,
    document: &Value,
    key_id: &str,
    private_key: &PrivateKey,
    created: i64,
    expires: i64,
) -> Result<Value, Error> {
    let Value::Object(members) = document else {
        return Err(Error::Malformed(
            "a document to sign is a JSON object".into(),
        ));
    };
    let mut options = Map::new();
    options.insert("type".into(), Value::from(RSA_SIGNATURE_2017));
    options.insert("creator".into(), Value::from(key_id));
    options.insert("created".into(), Value::from(timestamp(created)?));
    options.insert("expires".into(), Value::from(timestamp(expires)?));

    let message = message(registry, &options, members)?;
    let signature_value = private_key.sign(message.as_bytes());
    options.insert("signatureValue".into(), Value::from(signature_value));

    let mut signed = members.clone();
    signed.insert("signature".into(), Value::Object(options));
    signed.insert(
        "@context".into(),
        with_security_context(members.get("@context")),
    );
    Ok(Value::Object(signed))
}

/// Check the `RsaSignature2017` on `document` against `public_key_pem`, the
/// key its [`creator`] names, at `now` (Unix seconds).
///
/// The caller has found that key, and knows whose it is; the signature says
/// that its holder signed this document, not who the holder is.
///
/// # Errors
///
/// [`Error::Missing`] when there is no `RsaSignature2017`,
/// [`Error::Invalid`] when it has expired or does not verify, and
/// otherwise why the document could not be read.
pub fn verify(
    registry: &Registry,
    document: &Value,
    public_key_pem: &str,
    now: i64,
) -> Result<(), Error> {
    Signed::read(registry, document, now)?.verify(public_key_pem)
}

/// An `RsaSignature2017` read and hashed, its key not yet tried.
///
/// Reading is the expensive half — both hashes are of canonical RDF — so a
/// caller trying more than one copy of a key, a stored one and then a fresh
/// one, reads once.
#[derive(Clone, Debug)]
pub struct Signed {
    creator: String,
    message: String,
    signature_value: String,
}

impl Signed {
    /// Read the signature on `document`, refusing it at `now` (Unix seconds)
    /// if it has expired.
    ///
    /// # Errors
    ///
    /// As [`verify`], short of trying the key.
    pub fn read(registry: &Registry, document: &Value, now: i64) -> Result<Self, Error> {
        let Value::Object(members) = document else {
            return Err(Error::Malformed(
                "a signed document is a JSON object".into(),
            ));
        };
        let Some(Value::Object(signature)) = members.get("signature") else {
            return Err(Error::Missing("signature".into()));
        };
        if signature.get("type").and_then(Value::as_str) != Some(RSA_SIGNATURE_2017) {
            return Err(Error::Unsupported("Linked Data Signature type".into()));
        }
        let Some(creator) = signature.get("creator").and_then(Value::as_str) else {
            return Err(Error::Missing("creator".into()));
        };
        let Some(signature_value) = signature.get("signatureValue").and_then(Value::as_str) else {
            return Err(Error::Missing("signatureValue".into()));
        };
        if let Some(expires) = signature.get("expires") {
            let expires = expires
                .as_str()
                .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
                .ok_or_else(|| Error::Malformed("expires".into()))?;
            if expires.timestamp() < now {
                return Err(Error::Invalid);
            }
        }
        let mut options = signature.clone();
        for key in ["type", "id", "signatureValue"] {
            options.remove(key);
        }
        Ok(Self {
            creator: creator.into(),
            message: message(registry, &options, members)?,
            // Mastodon decodes leniently (`Base64.decode64`), skipping line
            // breaks.
            signature_value: signature_value
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect(),
        })
    }

    /// The key the signature says made it.
    #[must_use]
    pub fn creator(&self) -> &str {
        &self.creator
    }

    /// Whether the key `public_key_pem` made the signature.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] for a key that is not an RSA public key, and
    /// [`Error::Invalid`] when it did not.
    pub fn verify(&self, public_key_pem: &str) -> Result<(), Error> {
        rsa_verify_pkcs1v15(
            public_key_pem,
            self.message.as_bytes(),
            &self.signature_value,
        )
        .map_err(|error| match error {
            Error::Key(_) => error,
            _ => Error::Invalid,
        })
    }
}

/// What is signed: the hex SHA-256 of the options' canonical form, then of
/// the document's without its `signature`.
fn message(
    registry: &Registry,
    options: &Map<String, Value>,
    document: &Map<String, Value>,
) -> Result<String, Error> {
    let mut options = options.clone();
    options.insert("@context".into(), Value::from(IDENTITY_CONTEXT));
    let mut document = document.clone();
    document.remove("signature");
    let mut message = hash(registry, &Value::Object(options))?;
    message.push_str(&hash(registry, &Value::Object(document))?);
    Ok(message)
}

fn hash(registry: &Registry, document: &Value) -> Result<String, Error> {
    let canonical = ojak_jsonld::rdf::canonize(registry, document)
        .map_err(|error| Error::Unsupported(format!("JSON-LD: {error}")))?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// `Time#iso8601` in UTC: whole seconds, `Z`.
fn timestamp(seconds: i64) -> Result<String, Error> {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .ok_or_else(|| Error::Malformed("a time out of range".into()))
}

/// `@context` with the security context added once at the end, a single
/// entry written as itself.
fn with_security_context(context: Option<&Value>) -> Value {
    let mut entries: Vec<Value> = match context {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(entries)) => entries.clone(),
        Some(single) => Vec::from([single.clone()]),
    };
    entries.push(Value::from(SECURITY_CONTEXT));
    let mut unique: Vec<Value> = Vec::with_capacity(entries.len());
    for entry in entries {
        if !unique.contains(&entry) {
            unique.push(entry);
        }
    }
    if unique.len() == 1 {
        unique.pop().unwrap_or(Value::Null)
    } else {
        Value::Array(unique)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_security_context_is_added_once() {
        assert_eq!(
            with_security_context(Some(&json!("https://www.w3.org/ns/activitystreams"))),
            json!(["https://www.w3.org/ns/activitystreams", SECURITY_CONTEXT])
        );
        assert_eq!(
            with_security_context(Some(&json!([
                "https://www.w3.org/ns/activitystreams",
                SECURITY_CONTEXT
            ]))),
            json!(["https://www.w3.org/ns/activitystreams", SECURITY_CONTEXT])
        );
        assert_eq!(with_security_context(None), json!(SECURITY_CONTEXT));
    }

    #[test]
    fn times_are_written_as_mastodon_writes_them() {
        assert_eq!(timestamp(0).unwrap(), "1970-01-01T00:00:00Z");
    }
}
