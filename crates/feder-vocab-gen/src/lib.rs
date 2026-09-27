//! Generates *feder-vocab*'s types from the vendored vocabulary schemas.
//!
//! The schemas are Fedify's; see *crates/feder-vocab/schemas/README.md*.
//! Feder's own additions to them are in *crates/feder-vocab/extensions*. This
//! crate reads them, works out what each property is in Feder's terms, and
//! writes Rust. It runs on a developer's machine, not in a build: the output
//! is committed, and a test fails when it is stale.

pub mod emit;
pub mod model;
pub mod schema;

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Where the vendored schemas are.
#[must_use]
pub fn schemas_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../feder-vocab/schemas")
}

/// Where Feder's additions to the vocabulary are.
#[must_use]
pub fn additions_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../feder-vocab/extensions/additions.yaml")
}

/// Where the generated code goes.
#[must_use]
pub fn output_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../feder-vocab/src/generated.rs")
}

/// The generated code for the vendored schemas, formatted.
///
/// # Errors
///
/// When a schema cannot be read or represented, or `rustfmt` fails.
pub fn render() -> Result<String> {
    let mut schemas = schema::load_dir(&schemas_dir())?;
    schema::apply(&mut schemas, &schema::load_additions(&additions_path())?)?;
    let vocabulary = model::Vocabulary::from_schemas(&schemas, &feder_jsonld::Registry::bundled())?;
    emit::render(&vocabulary)
}
