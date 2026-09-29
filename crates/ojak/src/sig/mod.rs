//! Signatures and proofs: HTTP Signatures (draft-cavage, and RFC 9421 with
//! RSA or Ed25519) and the policy an inbox holds them to, FEP-8b32 Object
//! Integrity Proofs (`eddsa-jcs-2022`, and the post-quantum
//! `mldsa44-jcs-2024`), and `did:key`.
//!
//! They do no I/O: callers supply byte slices, header pairs and keys, and
//! the rest of Ojak fetches keys and sends requests with them.

use std::sync::Arc;

pub mod did;
pub mod digest;
pub mod integrity;
pub mod rfc9421;
pub mod signature;
pub mod verification;

/// An RSA private key, parsed once; what a [`SenderKey`] signs with.
pub use signature::PrivateKey;

/// An HTTP signature scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    /// draft-cavage-http-signatures-12, which most of the network verifies.
    DraftCavage,
    /// RFC 9421 HTTP Message Signatures.
    Rfc9421,
}

impl Scheme {
    /// The scheme a refused request is retried in.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::DraftCavage => Self::Rfc9421,
            Self::Rfc9421 => Self::DraftCavage,
        }
    }
}

/// The key an actor signs deliveries with.
#[derive(Clone, Debug)]
pub struct SenderKey {
    /// The key's IRI, as its actor document publishes it.
    pub key_id: String,
    pub private_key: Arc<PrivateKey>,
}
