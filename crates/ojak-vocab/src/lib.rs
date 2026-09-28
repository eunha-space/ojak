//! The Activity Vocabulary, for Ojak.
#![no_std]
//!
//! Every ActivityStreams type and the extensions the fediverse uses, from
//! Fedify's vocabulary schemas and Ojak's own additions to them (see
//! `schemas/` and `extensions/`), generated into [`generated`] and exported
//! here: `ojak_vocab::Note`, `ojak_vocab::Follow`, `ojak_vocab::AnyObject`.
//!
//! A document is read by what it means: [`read`] normalises it over the
//! contexts Ojak ships and reads it into a type, and [`read_reporting`] says
//! what the type did not keep. [`write()`] writes a value in Ojak's spelling,
//! under Ojak's context.
//!
//! This crate models protocol data only. It does not fetch, store, deliver,
//! or decide anything.

extern crate alloc;

use alloc::boxed::Box;
use iri_string::types::IriString;
use serde::{Deserialize, Serialize};

pub mod generated;
pub mod json;
pub mod loss;
pub mod meaning;
mod read;

pub use generated::*;
pub use loss::Loss;
pub use read::{Read, ReadError, Registry, read, read_reporting, write};

/// The canonical Activity Streams JSON-LD context URL.
pub const ACTIVITYSTREAMS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";

/// The special collection addressing every actor (public posts).
pub const ACTIVITYSTREAMS_PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

/// An absolute ActivityPub/ActivityStreams identifier.
pub type Iri = IriString;

/// A value that is either an object's IRI or the object itself.
///
/// ActivityStreams properties can hold either, and Ojak keeps the two
/// apart rather than dereferencing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Reference<T> {
    Id(Iri),
    Object(Box<T>),
}

impl<T> Reference<T> {
    #[must_use]
    pub fn id(id: Iri) -> Self {
        Self::Id(id)
    }

    #[must_use]
    pub fn object(object: T) -> Self {
        Self::Object(Box::new(object))
    }
}
