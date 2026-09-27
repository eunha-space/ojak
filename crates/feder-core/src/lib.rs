//! Portable ActivityPub decisions for Feder: pure functions over the
//! vocabulary, with no I/O and no state of their own.
#![no_std]
//!
//! The application owns its data; these decide what the protocol says should
//! happen to it. Addressing and visibility ([`addressing`]), what to do with
//! a Follow ([`inbound`]), what a post or reaction means where the fediverse
//! says it several ways ([`meaning`]), where an identifier's authority
//! comes from ([`origin`]), portable objects' identifiers ([`portable`]),
//! and subscribing to relays ([`relay`]).

extern crate alloc;

pub use feder_vocab as vocab;

pub mod addressing;
pub mod inbound;
pub mod meaning;
pub mod origin;
pub mod portable;
pub mod relay;
