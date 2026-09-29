//! Ojak: an ActivityPub application framework.
//!
//! The application owns its data, and Ojak does the protocol around it; see
//! *docs/design/framework.md*. It has the guarded HTTP client every
//! outgoing request goes through ([`client`]), signatures and proofs
//! ([`sig`]), delivery of activities through a queue the application
//! provides ([`deliverer`]), fetching documents from other servers
//! ([`fetch`]), the key-value store Ojak keeps its caches in ([`kv`]),
//! serving actors, objects, collections, WebFinger and NodeInfo and
//! receiving activities ([`federation`]), portable objects (FEP-ef61) at
//! gateways ([`portable`]), and finding an actor by its handle
//! ([`webfinger`]).

extern crate alloc;

pub mod client;
pub mod deliverer;
pub mod federation;
pub mod fetch;
pub mod kv;
pub mod origin;
pub mod portable;
pub mod queue;
pub use ojak_sig as sig;
pub mod template;
#[cfg(feature = "testing")]
pub mod testing;
pub mod webfinger;
