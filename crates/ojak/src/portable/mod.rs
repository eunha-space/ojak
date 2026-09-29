//! Portable objects (FEP-ef61): verifying them, and signing them.
//!
//! A portable object is authentic when an FEP-8b32 integrity proof on it was
//! made with a key under the DID of its `id`, and by nothing else: not where
//! it was fetched from, and not the HTTP signature it arrived under.
//! *docs/design/portable.md* has the reasoning.
//!
//! `did:key` is resolved here, since the DID is the key. Any other method
//! needs a [`DidResolver`] from the application.

mod uri;

pub use uri::*;

use crate::sig::did::{did_key, did_key_method, resolve_did_key};
use crate::sig::integrity::{self, PublicKey};
use serde_json::Value;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// An error from the application's resolver or signer.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves the DID URLs of methods other than `did:key` to keys.
pub trait DidResolver: Send + Sync + 'static {
    /// The key `did_url` names, or `None` when this resolver does not know
    /// it.
    fn resolve<'a>(&'a self, did_url: &'a str) -> BoxFuture<'a, Result<Option<PublicKey>, Error>>;
}

/// Why a portable document is not authentic.
#[derive(Debug)]
pub enum PortableError {
    /// Its `id` is not an `ap` URI, or it has none.
    NotPortable,
    /// It has no usable integrity proof.
    NoProof,
    /// The proof's verification method is not under the DID it has to be.
    ForeignMethod { method: String, did: String },
    /// The verification method did not resolve to a key.
    Unresolved { method: String, why: String },
    /// The proof does not verify.
    Invalid(String),
    /// It is an actor and lists no gateway.
    NoGateways,
}

impl fmt::Display for PortableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPortable => f.write_str("not a portable object"),
            Self::NoProof => f.write_str("no usable integrity proof"),
            Self::ForeignMethod { method, did } => {
                write!(f, "proof key {method} is not under {did}")
            }
            Self::Unresolved { method, why } => write!(f, "{method} did not resolve: {why}"),
            Self::Invalid(why) => write!(f, "proof does not verify: {why}"),
            Self::NoGateways => f.write_str("portable actor lists no gateways"),
        }
    }
}

impl std::error::Error for PortableError {}

/// The key `did_url` names: a `did:key`'s own, or what `resolver` says.
///
/// # Errors
///
/// When it does not resolve.
pub async fn resolve(
    did_url: &str,
    resolver: Option<&dyn DidResolver>,
) -> Result<PublicKey, PortableError> {
    let unresolved = |why: String| PortableError::Unresolved {
        method: did_url.to_owned(),
        why,
    };
    if did_url.starts_with("did:key:") {
        return resolve_did_key(did_url).map_err(|error| unresolved(error.to_string()));
    }
    let resolver = resolver.ok_or_else(|| unresolved("no resolver for its method".into()))?;
    match resolver.resolve(did_url).await {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(unresolved("unknown to the resolver".into())),
        Err(error) => Err(unresolved(error.to_string())),
    }
}

/// Verify that `document` carries a proof made with a key under `did`: any
/// of its proofs, tried in order.
///
/// # Errors
///
/// When none is, with why the last one tried was not.
pub async fn verify_by(
    document: &Value,
    did: &str,
    resolver: Option<&dyn DidResolver>,
) -> Result<(), PortableError> {
    let mut last = PortableError::NoProof;
    for (proof, _, method) in integrity::integrity_proofs(document) {
        if did_of(&method) != Some(did) {
            last = PortableError::ForeignMethod {
                method,
                did: did.to_owned(),
            };
            continue;
        }
        let key = match resolve(&method, resolver).await {
            Ok(key) => key,
            Err(error) => {
                last = error;
                continue;
            }
        };
        match integrity::verify_object_integrity_proof(document, &proof, &key) {
            Ok(()) => return Ok(()),
            Err(error) => last = PortableError::Invalid(error.to_string()),
        }
    }
    Err(last)
}

/// Verify a portable document: its `id` is an `ap` URI, a proof by the
/// `id`'s DID verifies, and an actor lists at least one gateway. Returns the
/// `id`.
///
/// # Errors
///
/// When any of that does not hold.
pub async fn verify(
    document: &Value,
    resolver: Option<&dyn DidResolver>,
) -> Result<ApUri, PortableError> {
    let id = document
        .get("id")
        .and_then(Value::as_str)
        .and_then(ApUri::parse)
        .ok_or(PortableError::NotPortable)?;
    verify_by(document, id.did(), resolver).await?;
    if is_actor(document) && gateways(document).is_empty() {
        return Err(PortableError::NoGateways);
    }
    Ok(id)
}

/// The gateways an actor document lists, in order.
#[must_use]
pub fn gateways(actor: &Value) -> Vec<String> {
    let items = match actor.get("gateways") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Object(list)) => match list.get("@list") {
            Some(Value::Array(items)) => items.iter().collect(),
            _ => Vec::new(),
        },
        Some(item) => vec![item],
        None => Vec::new(),
    };
    items
        .into_iter()
        .filter_map(Value::as_str)
        .filter(|gateway| gateway.starts_with("https://") || gateway.starts_with("http://"))
        .map(str::to_owned)
        .collect()
}

fn is_actor(document: &Value) -> bool {
    const ACTORS: [&str; 5] = ["Application", "Group", "Organization", "Person", "Service"];
    match document.get("type") {
        Some(Value::String(kind)) => ACTORS.contains(&kind.as_str()),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .any(|kind| ACTORS.contains(&kind)),
        _ => false,
    }
}

/// Where a proof comes from: a key the server holds, or one it reaches
/// through a signing service or the user's device. What is signed is a whole
/// document, and what comes back is that document with its proof.
pub trait ProofSigner: Send + Sync + 'static {
    /// The DID URL of the key, which a proof names as its
    /// `verificationMethod`.
    fn verification_method(&self) -> &str;

    /// `document` with an integrity proof attached.
    fn prove<'a>(&'a self, document: &'a Value) -> BoxFuture<'a, Result<Value, Error>>;
}

impl<S: ProofSigner + ?Sized> ProofSigner for Arc<S> {
    fn verification_method(&self) -> &str {
        (**self).verification_method()
    }

    fn prove<'a>(&'a self, document: &'a Value) -> BoxFuture<'a, Result<Value, Error>> {
        (**self).prove(document)
    }
}

/// An Ed25519 key held in memory, signing as its `did:key`.
#[derive(Clone)]
pub struct Ed25519Signer {
    seed: [u8; 32],
    did: String,
    method: String,
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}

impl Ed25519Signer {
    /// A signer for the raw 32-byte seed `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        let did = did_key(&integrity::ed25519_public_key(&seed));
        let method = did_key_method(&did);
        Self { seed, did, method }
    }

    /// A signer with a fresh key.
    #[must_use]
    pub fn generate() -> Self {
        Self::new(integrity::generate_ed25519_seed())
    }

    /// A signer for a PKCS#8 PEM Ed25519 private key.
    ///
    /// # Errors
    ///
    /// When `pem` is not one.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let (seed, _) = integrity::parse_ed25519_key(pem).map_err(|error| error.to_string())?;
        Ok(Self::new(seed))
    }

    /// The `did:key` the key is: the authority of the `ap` URIs it controls.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }
}

impl ProofSigner for Ed25519Signer {
    fn verification_method(&self) -> &str {
        &self.method
    }

    fn prove<'a>(&'a self, document: &'a Value) -> BoxFuture<'a, Result<Value, Error>> {
        Box::pin(async move {
            integrity::sign_object_integrity_proof(document, &self.method, &self.seed)
                .map_err(|error| error.to_string().into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn actor(signer: &Ed25519Signer) -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1",
                "https://w3id.org/fep/ef61"
            ],
            "type": "Person",
            "id": format!("ap://{}/actor", signer.did()),
            "inbox": format!("ap://{}/actor/inbox", signer.did()),
            "gateways": ["https://server1.example"]
        })
    }

    #[tokio::test]
    async fn what_its_key_signed_is_authentic() {
        let signer = Ed25519Signer::generate();
        let signed = signer.prove(&actor(&signer)).await.unwrap();
        let id = verify(&signed, None).await.unwrap();
        assert_eq!(id.did(), signer.did());
        assert_eq!(gateways(&signed), ["https://server1.example"]);
    }

    #[tokio::test]
    async fn a_proof_that_verifies_is_found_among_ones_that_do_not() {
        let owner = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let unsigned = actor(&owner);
        let by_owner = owner.prove(&unsigned).await.unwrap();
        let by_other = other.prove(&unsigned).await.unwrap();
        let mut tampered = by_owner["proof"].clone();
        tampered["created"] = json!("2000-01-01T00:00:00Z");
        let mut signed = unsigned;
        signed["proof"] = json!([by_other["proof"], tampered, by_owner["proof"]]);
        assert_eq!(integrity::integrity_proofs(&signed).len(), 3);

        let id = verify(&signed, None).await.unwrap();
        assert_eq!(id.did(), owner.did());

        signed["proof"] = json!([by_other["proof"], tampered]);
        assert!(matches!(
            verify(&signed, None).await,
            Err(PortableError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn another_key_does_not_vouch_for_it() {
        let owner = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let signed = other.prove(&actor(&owner)).await.unwrap();
        assert!(matches!(
            verify(&signed, None).await,
            Err(PortableError::ForeignMethod { .. })
        ));
    }

    #[tokio::test]
    async fn a_changed_document_does_not_verify() {
        let signer = Ed25519Signer::generate();
        let mut signed = signer.prove(&actor(&signer)).await.unwrap();
        signed["gateways"] = json!(["https://attacker.example"]);
        assert!(matches!(
            verify(&signed, None).await,
            Err(PortableError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn an_actor_needs_a_gateway_and_a_proof() {
        let signer = Ed25519Signer::generate();
        let mut unsigned = actor(&signer);
        assert!(matches!(
            verify(&unsigned, None).await,
            Err(PortableError::NoProof)
        ));
        unsigned.as_object_mut().unwrap().remove("gateways");
        let signed = signer.prove(&unsigned).await.unwrap();
        assert!(matches!(
            verify(&signed, None).await,
            Err(PortableError::NoGateways)
        ));
        let https = json!({"id": "https://a.example/users/alice", "type": "Person"});
        assert!(matches!(
            verify(&https, None).await,
            Err(PortableError::NotPortable)
        ));
    }

    #[tokio::test]
    async fn other_methods_need_a_resolver() {
        struct Web(PublicKeyBytes);
        struct PublicKeyBytes([u8; 32]);
        impl DidResolver for Web {
            fn resolve<'a>(
                &'a self,
                did_url: &'a str,
            ) -> BoxFuture<'a, Result<Option<PublicKey>, Error>> {
                let key = (did_url == "did:web:a.example#key")
                    .then(|| PublicKey::Ed25519(Box::new(self.0.0)));
                Box::pin(async move { Ok(key) })
            }
        }

        let seed = [9u8; 32];
        let public = integrity::ed25519_public_key(&seed);
        let document = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "ap://did:web:a.example/objects/1",
            "type": "Note"
        });
        let signed =
            integrity::sign_object_integrity_proof(&document, "did:web:a.example#key", &seed)
                .unwrap();
        assert!(matches!(
            verify(&signed, None).await,
            Err(PortableError::Unresolved { .. })
        ));
        let resolver = Web(PublicKeyBytes(public));
        verify(&signed, Some(&resolver)).await.unwrap();
    }
}
