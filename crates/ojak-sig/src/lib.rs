//! Signatures and proofs: HTTP Signatures (draft-cavage, and RFC 9421 with
//! RSA or Ed25519) and the policy an inbox holds them to, FEP-8b32 Object
//! Integrity Proofs (`eddsa-jcs-2022`, and the post-quantum
//! `mldsa44-jcs-2024`), Linked Data Signatures (`RsaSignature2017`), and
//! `did:key`.
//!
//! They do no I/O: callers supply byte slices, header pairs, keys, the time
//! and, to make a key, randomness. Ojak fetches keys and sends requests with
//! them, and re-exports this crate as `ojak::sig`.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;

pub mod did;
pub mod digest;
pub mod integrity;
pub mod linked_data;
pub mod rfc9421;
pub mod signature;
pub mod verification;

/// An RSA private key, parsed once; what a [`SenderKey`] signs with.
pub use signature::PrivateKey;

/// The randomness keys are made with, which the caller supplies: `OsRng`
/// from `rand_core` with its `getrandom` feature, or a device's own.
pub use rand_core::CryptoRngCore;

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

/// Why something could not be signed or verified.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A key that cannot be read or made: a PEM, a Multikey, or a DID URL.
    Key(String),
    /// A signature, proof, header or URL that cannot be read.
    Malformed(String),
    /// Something a signature covers that the request does not carry.
    Missing(String),
    /// An algorithm, cryptosuite or component this crate does not know.
    Unsupported(String),
    /// A key of one kind, offered for a signature or proof of another.
    WrongKey(String),
    /// The body is not the one its digest describes.
    DigestMismatch,
    /// The signature or proof does not verify.
    Invalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(why) => write!(f, "unusable key: {why}"),
            Self::Malformed(why) => write!(f, "malformed: {why}"),
            Self::Missing(what) => write!(f, "{what} is covered but was not sent"),
            Self::Unsupported(what) => write!(f, "unsupported {what}"),
            Self::WrongKey(why) => write!(f, "wrong key: {why}"),
            Self::DigestMismatch => f.write_str("the body does not match its digest"),
            Self::Invalid => f.write_str("the signature does not verify"),
        }
    }
}

impl core::error::Error for Error {}
