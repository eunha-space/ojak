//! JSON-LD term expansion for ActivityPub documents, over bundled contexts.
#![no_std]
//!
//! ActivityPub is JSON-LD, which means a key is not a name but an abbreviation
//! for an IRI, and the `@context` says which. Two servers can describe the same
//! thing with different keys — `sensitive`, `as:sensitive`, or any term aliased
//! to either — and a reader that matches on spelling reads one and drops the
//! other. This crate resolves keys to the IRIs they stand for, and puts them
//! back into ojak's own spelling.
//!
//! ~~~~
//! use ojak_jsonld::{Registry, normalize};
//! use serde_json::json;
//!
//! let registry = Registry::bundled();
//! let document = json!({
//!     "@context": ["https://www.w3.org/ns/activitystreams", {"s": "as:sensitive"}],
//!     "type": "Note",
//!     "id": "https://remote.example/notes/1",
//!     "s": true
//! });
//! let normalized = normalize(&registry, &document).expect("normalize");
//! // The alias is gone; the term ojak reads is there.
//! assert_eq!(normalized.document()["sensitive"], json!(true));
//! ~~~~
//!
//! # What this is not
//!
//! It is not a general JSON-LD processor, and does not try to be. It resolves
//! only the contexts in `contexts/`, because resolution happens on inbound
//! attacker-controlled documents and a loader that fetches what they name is a
//! request-forgery primitive; see `contexts/README.md`. A context it does not
//! ship is read as ActivityStreams, which every context the fediverse serves
//! extends, so its standard terms mean what they always do and only the
//! sender's own additions go unread; [`Processed::unresolved_contexts`] says
//! which contexts those were. It rejects `@graph`,
//! `@included` and `@reverse` outright, for reasons recorded on
//! [`Error::RestructuringKeyword`]. It has no flattening, no framing, and no
//! `@nest`, `@index` maps, `@id` maps or `@type` maps — none of which appear
//! in ActivityPub traffic.
//!
//! It does turn a document into RDF and canonicalise it ([`rdf`]), because
//! that is what a Linked Data Signature signs; see that module for how it is
//! stricter than the reading path. A caller checking such a signature over a
//! context it fetched, as Mastodon does, adds the fetched document to a
//! registry ([`Registry::with`]); the fetching itself, and its rules, are the
//! caller's.
//!
//! What it does cover is the JSON-LD 1.1 needed by the contexts the fediverse
//! actually serves: term and compact-IRI expansion, `@vocab`, `@base`,
//! `@language` and language maps, `@container` sets and lists, type coercion,
//! and property- and type-scoped contexts. The last of those is not optional:
//! `security/data-integrity/v1` hangs `proofValue` and `cryptosuite` off a
//! scoped context on `DataIntegrityProof`, and those are the fields ojak
//! verifies integrity proofs with.
//!
//! One simplification is worth knowing about when reading compacted output.
//! JSON-LD compaction may split a single property across two terms, writing an
//! untagged value under `content` and language-tagged ones under `contentMap`.
//! Ojak picks one term for a property and writes every value under it. The
//! result is valid JSON-LD carrying every value, and re-expands to the same
//! thing, but it is not always the term a given server would have chosen.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;
use serde_json::Value;

mod compact;
mod context;
mod expand;
pub mod rdf;
mod registry;

pub use context::{ContextCache, NoCache, ProcessedContext};
pub use registry::Registry;

use alloc::sync::Arc;
use context::{ActiveContext, Session};

/// The context ojak compacts to, and emits.
const OJAK_CONTEXT: &str = include_str!("../contexts/ojak.jsonld");

/// Ceilings on the work one document may cause.
///
/// A document arrives from anyone who can reach an inbox, and every one of
/// these bounds an amount of work that is otherwise a function of what the
/// sender wrote. The defaults are generous for real traffic: the largest
/// Mastodon actor observed uses a depth of 5 and some 60 nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// How deeply values may nest. Matches Fedify's traversal limit.
    pub max_depth: usize,
    /// How many JSON objects one document may contain.
    pub max_nodes: usize,
    /// How many `@context` entries one document may cause to be processed,
    /// counting each element of every array and each bundled document reached.
    pub max_contexts: usize,
    /// How many terms one active context may define.
    pub max_terms: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_nodes: 10_000,
            max_contexts: 64,
            max_terms: 4_096,
        }
    }
}

/// Why a document could not be processed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Nesting past [`Limits::max_depth`].
    DepthExceeded,
    /// More objects than [`Limits::max_nodes`].
    NodeBudgetExceeded,
    /// More context entries than [`Limits::max_contexts`].
    ContextBudgetExceeded,
    /// More terms in one context than [`Limits::max_terms`].
    TermBudgetExceeded,
    /// A context, or a term definition, that refers back to itself.
    CyclicContext(String),
    /// A `@context` value that is not an IRI, a term map, an array of those,
    /// or null.
    InvalidContext,
    /// A term definition JSON-LD does not allow.
    InvalidTermDefinition(String),
    /// A document using `@graph`, `@included` or `@reverse`, or a term aliased
    /// to one of them.
    ///
    /// These let a single RDF graph be written as several different trees.
    /// Because a Linked Data Signature covers the graph rather than the tree,
    /// a signed activity can be restructured — its `object` promoted to the top
    /// level under `@graph`, or properties hidden behind `@included` — so that
    /// every tree-reading implementation reads something the signer did not
    /// say, with the signature still verifying. That is GHSA-9rfg-v8g9-9367,
    /// disclosed across several fediverse projects in 2025 with the
    /// recommendation that implementations reject all three; ojak does.
    RestructuringKeyword(String),
    /// A context the registry does not hold — one ojak does not ship, and
    /// the caller did not add — met where guessing is not good enough:
    /// turning a document into RDF ([`rdf`]), which a signature covers.
    UnresolvedContext(String),
    /// Something JSON-LD allows that ojak does not turn into RDF.
    Unsupported(String),
    /// Labelling the blank nodes of a dataset took more work than
    /// [`rdf::canonicalize`] allows one dataset.
    CanonicalizationBudgetExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DepthExceeded => f.write_str("document nests too deeply"),
            Self::NodeBudgetExceeded => f.write_str("document has too many objects"),
            Self::ContextBudgetExceeded => f.write_str("document processes too many contexts"),
            Self::TermBudgetExceeded => f.write_str("context defines too many terms"),
            Self::CyclicContext(name) => write!(f, "cyclic JSON-LD context or term: {name}"),
            Self::InvalidContext => f.write_str("invalid @context value"),
            Self::InvalidTermDefinition(term) => write!(f, "invalid term definition: {term}"),
            Self::RestructuringKeyword(keyword) => {
                write!(f, "refusing graph-restructuring keyword: {keyword}")
            }
            Self::UnresolvedContext(iri) => write!(f, "context not resolved: {iri}"),
            Self::Unsupported(what) => write!(f, "not supported in RDF: {what}"),
            Self::CanonicalizationBudgetExceeded => {
                f.write_str("canonicalizing the dataset takes too much work")
            }
        }
    }
}

impl core::error::Error for Error {}

/// A processed document, and what could not be resolved while processing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Processed {
    document: Value,
    unresolved: Vec<String>,
}

impl Processed {
    /// The processed document.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// The processed document, by value.
    #[must_use]
    pub fn into_document(self) -> Value {
        self.document
    }

    /// Context IRIs the document named that ojak does not ship.
    ///
    /// Not an error: their terms simply did not expand, and any key relying on
    /// them was dropped. Worth logging when a peer's documents come back
    /// emptier than expected — it usually means a new extension context.
    #[must_use]
    pub fn unresolved_contexts(&self) -> &[String] {
        &self.unresolved
    }
}

/// Expand a document: every key becomes the IRI it stands for.
///
/// The result is the JSON-LD expanded form — an array of node objects, with
/// every value wrapped as `{"@value": …}` or `{"@id": …}`. This is the form to
/// compare two documents in, and the form [`compact`] reads.
pub fn expand(registry: &Registry, document: &Value) -> Result<Processed, Error> {
    expand_with(registry, document, Limits::default())
}

/// [`expand`], with limits of the caller's choosing.
pub fn expand_with(
    registry: &Registry,
    document: &Value,
    limits: Limits,
) -> Result<Processed, Error> {
    let mut session = Session::new(registry, limits);
    let expanded = expand::expand_document(&ActiveContext::default(), document, &mut session)?;
    Ok(Processed {
        document: expanded,
        unresolved: session.unresolved,
    })
}

/// Compact an expanded document against `context`.
///
/// `context` is a `@context` value — an IRI the registry knows, a term map, or
/// an array of those.
pub fn compact(registry: &Registry, expanded: &Value, context: &Value) -> Result<Processed, Error> {
    compact_with(registry, expanded, context, Limits::default())
}

/// [`compact`], with limits of the caller's choosing.
pub fn compact_with(
    registry: &Registry,
    expanded: &Value,
    context: &Value,
    limits: Limits,
) -> Result<Processed, Error> {
    let mut session = Session::new(registry, limits);
    let active = context::process(
        &ActiveContext::default(),
        context,
        &mut session,
        &mut Vec::new(),
    )?;
    let compacted = compact::compact_document(&active, expanded, context, &mut session)?;
    Ok(Processed {
        document: compacted,
        unresolved: session.unresolved,
    })
}

/// Read a document however it was written, and hand it back in ojak's own
/// spelling.
///
/// This is expansion followed by compaction against ojak's context: whatever
/// aliases, prefixes and extension vocabularies the sender used are resolved to
/// IRIs and then written back with the terms ojak's vocabulary types expect.
/// A term from a context ojak does not ship survives as its full IRI rather
/// than as the sender's abbreviation, so nothing is silently renamed.
pub fn normalize(registry: &Registry, document: &Value) -> Result<Processed, Error> {
    normalize_with(registry, document, Limits::default())
}

/// [`normalize`], with limits of the caller's choosing.
pub fn normalize_with(
    registry: &Registry,
    document: &Value,
    limits: Limits,
) -> Result<Processed, Error> {
    normalize_with_cache(registry, document, limits, &NoCache)
}

/// [`normalize_with`], keeping processed contexts in `cache`.
///
/// The result is the same as without one. What changes is the cost: a
/// document whose `@context` has been seen before, as nearly every one a
/// server receives has, is not made to process it again, and nor is ojak's
/// own context, which every document is compacted against.
pub fn normalize_with_cache(
    registry: &Registry,
    document: &Value,
    limits: Limits,
    cache: &dyn ContextCache,
) -> Result<Processed, Error> {
    let mut session = Session::with_cache(registry, cache, limits);
    let expanded = expand::expand_document(&ActiveContext::default(), document, &mut session)?;
    let unresolved = session.unresolved;

    let ojak = ojak_context_processed(registry, limits, cache)?;
    let mut session = Session::with_cache(registry, cache, limits);
    session.contexts = ojak.charged;
    let context = ojak
        .source
        .as_ref()
        .expect("ojak's context is kept with its source");
    let compacted = compact::compact_document(&ojak.active, &expanded, context, &mut session)?;
    Ok(Processed {
        document: compacted,
        unresolved,
    })
}

/// Ojak's own context, processed: from `cache` when it has been before.
fn ojak_context_processed(
    registry: &Registry,
    limits: Limits,
    cache: &dyn ContextCache,
) -> Result<Arc<ProcessedContext>, Error> {
    let key = alloc::format!(
        "\u{0}ojak\u{0}{}\u{0}{}",
        limits.max_contexts,
        limits.max_terms
    );
    if let Some(cached) = cache.get(&key) {
        return Ok(cached);
    }
    let context = ojak_context();
    let mut session = Session::new(registry, limits);
    let active = context::process(
        &ActiveContext::default(),
        &context,
        &mut session,
        &mut Vec::new(),
    )?;
    let processed = Arc::new(ProcessedContext {
        active,
        charged: session.contexts,
        unresolved: session.unresolved,
        source: Some(context),
    });
    cache.put(key, processed.clone());
    Ok(processed)
}

/// The `@context` value ojak emits and compacts to.
#[must_use]
pub fn ojak_context() -> Value {
    let document: Value =
        serde_json::from_str(OJAK_CONTEXT).expect("bundled ojak context is valid JSON");
    document
        .get("@context")
        .cloned()
        .expect("bundled ojak context has an @context member")
}
