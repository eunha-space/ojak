//! Feder: an ActivityPub application framework.
//!
//! The application owns its data, and Feder does the protocol around it; see
//! *docs/design/framework.md*. This crate is being built a piece at a time,
//! in the order the design record gives: so far, the guarded HTTP client
//! every outgoing request goes through, delivery of activities through a
//! queue the application provides, fetching documents from other servers,
//! the key-value store Feder keeps its caches in, and serving actors,
//! objects, collections, WebFinger and NodeInfo.

pub mod client;
pub mod deliverer;
pub mod delivery;
pub mod federation;
pub mod fetch;
pub mod kv;
pub mod queue;
pub mod template;
#[cfg(feature = "testing")]
pub mod testing;
