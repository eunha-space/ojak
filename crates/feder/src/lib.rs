//! Feder: an ActivityPub application framework.
//!
//! The application owns its data, and Feder does the protocol around it; see
//! *docs/design/framework.md*. This crate is being built a piece at a time,
//! in the order the design record gives: so far, the guarded HTTP client
//! every outgoing request goes through, and delivery of activities through a
//! queue the application provides.

pub mod client;
pub mod deliverer;
pub mod delivery;
pub mod queue;
#[cfg(feature = "testing")]
pub mod testing;
