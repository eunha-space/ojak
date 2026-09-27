//! Generates *feder-vocab*'s types from the vendored vocabulary schemas.
//!
//! The schemas are Fedify's; see *crates/feder-vocab/schemas/README.md*. This
//! crate reads them, works out what each property is in Feder's terms, and
//! writes Rust. It runs on a developer's machine, not in a build: the output
//! is committed, and a test fails when it is stale.

pub mod model;
pub mod schema;
