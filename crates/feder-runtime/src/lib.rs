//! Standard `std` runtime building blocks for ActivityPub servers.
//!
//! These are the platform/IO pieces that sit outside Feder's portable, no_std
//! protocol core: HTTP Signatures (draft-cavage, and RFC 9421 with RSA or
//! Ed25519), FEP-8b32 Object Integrity Proofs (`eddsa-jcs-2022` and the
//! post-quantum `mldsa44-jcs-2024`), and WebFinger discovery. They are
//! framework-agnostic — callers supply byte slices, header pairs, and a
//! [`reqwest::Client`].

pub mod delivery;
pub mod integrity;
pub mod rfc9421;
pub mod signature;
pub mod verification;
pub mod webfinger;
