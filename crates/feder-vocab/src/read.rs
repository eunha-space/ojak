//! Reading documents written by other servers, and writing Feder's own.

use alloc::{string::String, vec::Vec};
use core::fmt;
use serde::de::DeserializeOwned;

use crate::json::ToJson;
use serde_json::Value;

pub use feder_jsonld::Registry;

/// A document read into a vocabulary type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Read<T> {
    value: T,
    unresolved_contexts: Vec<String>,
}

impl<T> Read<T> {
    /// The value that was read.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The value that was read, by value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Context IRIs the document named that Feder does not ship.
    ///
    /// Not an error, but what they define was not resolved: a key relying on
    /// them keeps the sender's spelling, so no field of Feder's types reads
    /// it. Worth logging when a peer's documents read emptier than expected.
    #[must_use]
    pub fn unresolved_contexts(&self) -> &[String] {
        &self.unresolved_contexts
    }
}

/// Why a document could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// The document is not JSON-LD Feder will process.
    JsonLd(feder_jsonld::Error),
    /// The document was processed but is not the shape of the type asked for.
    Shape(serde_json::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonLd(error) => write!(f, "cannot process the document: {error}"),
            Self::Shape(error) => write!(f, "the document is not the expected shape: {error}"),
        }
    }
}

impl core::error::Error for ReadError {}

/// Read a document from another server into a vocabulary type.
///
/// The document is normalised first, so it is read by what its keys mean
/// rather than how the sender spelled them: `"as:sensitive"`, a term aliased
/// to it, and `"sensitive"` all arrive in the same field, and a type written
/// with a prefix, such as `"fep:QuoteRequest"`, arrives as the type it names.
/// Only the contexts `registry` holds are resolved; nothing is fetched.
///
/// Verify signatures and proofs on `document` before reading it, not on the
/// value this returns. Normalising rewrites the document, and a signature
/// covers the bytes that were signed.
///
/// # Errors
///
/// [`ReadError::JsonLd`] when the document cannot be processed — it uses
/// `@graph`, `@included` or `@reverse`, or exceeds a processing limit — and
/// [`ReadError::Shape`] when it is not the shape of `T`.
pub fn read<T: DeserializeOwned>(
    registry: &Registry,
    document: &Value,
) -> Result<Read<T>, ReadError> {
    let processed = feder_jsonld::normalize(registry, document).map_err(ReadError::JsonLd)?;
    let unresolved_contexts = processed.unresolved_contexts().to_vec();
    let mut normalized = processed.into_document();
    // The context is now Feder's own, whatever the sender wrote. The types
    // carry their own and must not be handed this one.
    if let Value::Object(members) = &mut normalized {
        members.remove("@context");
    }
    let value = serde_json::from_value(normalized).map_err(ReadError::Shape)?;
    Ok(Read {
        value,
        unresolved_contexts,
    })
}

/// Write a vocabulary value as a document: in Feder's spelling, under Feder's
/// context.
///
/// This is the counterpart of [`read`], and only for the top of a document.
/// A value's own [`ToJson`] writes no `@context`, because an object embedded
/// in another takes its context from the document around it.
#[must_use]
pub fn write<T: ToJson>(value: &T) -> Value {
    let mut document = value.to_json();
    if let Value::Object(members) = &mut document {
        members.insert("@context".into(), feder_jsonld::feder_context());
    }
    document
}
