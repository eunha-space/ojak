//! Context processing: turning `@context` values into an active context.
//!
//! This follows the JSON-LD 1.1 "Context Processing" and "Create Term
//! Definition" algorithms closely enough for the contexts the fediverse
//! actually serves, which is the set in `contexts/`. Those need more than
//! JSON-LD 1.0: `security/data-integrity/v1` and `cid/v1` define
//! `DataIntegrityProof` and `Multikey` with *type-scoped* contexts, so a
//! processor that ignored scoped contexts would fail to expand `proofValue`
//! and `publicKeyMultibase` — the two fields feder verifies proofs with.
//!
//! What is deliberately left out is recorded in the crate documentation.

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use serde_json::{Map, Value};

use crate::{Error, Limits, Registry};

/// Every JSON-LD keyword, including the ones feder refuses to process.
const KEYWORDS: &[&str] = &[
    "@base",
    "@container",
    "@context",
    "@direction",
    "@graph",
    "@id",
    "@import",
    "@included",
    "@index",
    "@json",
    "@language",
    "@list",
    "@nest",
    "@none",
    "@prefix",
    "@propagate",
    "@protected",
    "@reverse",
    "@set",
    "@type",
    "@value",
    "@version",
    "@vocab",
];

/// Whether `value` is a JSON-LD keyword.
#[must_use]
pub(crate) fn is_keyword(value: &str) -> bool {
    KEYWORDS.contains(&value)
}

/// Whether a simple-string term definition ends in a generic delimiter, which
/// is what makes it usable as a compact-IRI prefix (`"as"`, `"toot"`, `"gts"`).
fn ends_with_gen_delim(value: &str) -> bool {
    matches!(
        value.chars().next_back(),
        Some(':' | '/' | '?' | '#' | '[' | ']' | '@')
    )
}

/// How a term's values are to be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TypeMapping {
    /// `@type: "@id"` — the value is an IRI, not a string.
    Id,
    /// `@type: "@vocab"` — the value is an IRI read against `@vocab`.
    Vocab,
    /// `@type: "@json"` — the value is a JSON literal, left untouched.
    Json,
    /// `@type: "@none"`.
    None,
    /// A datatype IRI such as `xsd:dateTime`.
    Datatype(String),
}

/// The `@container` flags of a term definition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Container {
    pub list: bool,
    pub set: bool,
    pub language: bool,
    pub index: bool,
    pub id: bool,
    pub kind: bool,
    pub graph: bool,
}

impl Container {
    fn add(&mut self, value: &str) {
        match value {
            "@list" => self.list = true,
            "@set" => self.set = true,
            "@language" => self.language = true,
            "@index" => self.index = true,
            "@id" => self.id = true,
            "@type" => self.kind = true,
            "@graph" => self.graph = true,
            _ => {}
        }
    }
}

/// What one term in an active context means.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TermDefinition {
    /// The IRI (or keyword) the term expands to. `None` means the term was
    /// mapped to `null` and any key using it is dropped.
    pub iri: Option<String>,
    pub type_mapping: Option<TypeMapping>,
    pub container: Container,
    /// `Some(None)` is `@language: null`, which clears an inherited language.
    pub language: Option<Option<String>>,
    pub reverse: bool,
    pub prefix: bool,
    pub protected: bool,
    /// A term-scoped `@context`, applied to this term's values (for a property)
    /// or to the node carrying it (for a type).
    pub scoped: Option<Box<Value>>,
}

/// The context in force at one point in a document.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveContext {
    terms: BTreeMap<String, TermDefinition>,
    base: Option<String>,
    vocab: Option<String>,
    language: Option<String>,
}

impl ActiveContext {
    pub(crate) fn term(&self, name: &str) -> Option<&TermDefinition> {
        self.terms.get(name)
    }

    pub(crate) fn vocab(&self) -> Option<&str> {
        self.vocab.as_deref()
    }

    pub(crate) fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    pub(crate) fn base(&self) -> Option<&str> {
        self.base.as_deref()
    }

    /// Every term, for building the inverse map compaction needs.
    pub(crate) fn terms(&self) -> impl Iterator<Item = (&String, &TermDefinition)> {
        self.terms.iter()
    }
}

/// Mutable state shared across one document's processing: the budgets, the
/// registry, and the contexts that could not be resolved.
pub(crate) struct Session<'a> {
    pub registry: &'a Registry,
    pub limits: Limits,
    pub contexts: usize,
    pub nodes: usize,
    pub unresolved: Vec<String>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(registry: &'a Registry, limits: Limits) -> Self {
        Self {
            registry,
            limits,
            contexts: 0,
            nodes: 0,
            unresolved: Vec::new(),
        }
    }

    pub(crate) fn charge_node(&mut self) -> Result<(), Error> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(Error::NodeBudgetExceeded);
        }
        Ok(())
    }

    fn charge_context(&mut self) -> Result<(), Error> {
        self.contexts += 1;
        if self.contexts > self.limits.max_contexts {
            return Err(Error::ContextBudgetExceeded);
        }
        Ok(())
    }

    fn note_unresolved(&mut self, iri: &str) {
        if !self.unresolved.iter().any(|seen| seen == iri) {
            self.unresolved.push(iri.to_owned());
        }
    }
}

/// Process a `@context` value against `active`, returning the new context.
///
/// `remote` is the stack of context IRIs currently being resolved, which is how
/// a context that refers back to itself is caught rather than recursed into.
/// The ActivityStreams context, which an unknown context is read as.
const ACTIVITYSTREAMS: &str = "https://www.w3.org/ns/activitystreams";

pub(crate) fn process(
    active: &ActiveContext,
    local: &Value,
    session: &mut Session<'_>,
    remote: &mut Vec<String>,
) -> Result<ActiveContext, Error> {
    let mut result = active.clone();
    let entries: Vec<&Value> = match local {
        Value::Array(items) => items.iter().collect(),
        other => Vec::from([other]),
    };

    for entry in entries {
        session.charge_context()?;
        match entry {
            // A null context wipes the slate, keeping only the document base.
            Value::Null => {
                let base = result.base.clone();
                result = ActiveContext {
                    base,
                    ..ActiveContext::default()
                };
            }
            Value::String(iri) => {
                let resolved = resolve_context_iri(&result, iri);
                let document = match session.registry.resolve(&resolved) {
                    Some(document) => document.clone(),
                    // Tolerant on purpose: a context feder does not ship does
                    // not fail the whole document, and the caller is told
                    // which ones there were. It is read as ActivityStreams:
                    // every context the fediverse serves extends it (Mbin's
                    // and Lemmy's own, Pleroma's per-instance LitePub), and
                    // the sender's own additions, which are all it could add,
                    // are left unread. Otherwise a document naming only its
                    // server's context, as Mbin's do, would read as nothing.
                    None => {
                        session.note_unresolved(&resolved);
                        match session.registry.resolve(ACTIVITYSTREAMS) {
                            Some(document) if resolved != ACTIVITYSTREAMS => document.clone(),
                            _ => continue,
                        }
                    }
                };
                if remote.iter().any(|seen| seen == &resolved) {
                    return Err(Error::CyclicContext(resolved));
                }
                remote.push(resolved);
                let outcome = process(&result, &document, session, remote);
                remote.pop();
                result = outcome?;
            }
            Value::Object(map) => apply_term_map(&mut result, map, session)?,
            _ => return Err(Error::InvalidContext),
        }
    }

    Ok(result)
}

/// Resolve a context reference that may be relative to the active base.
fn resolve_context_iri(active: &ActiveContext, iri: &str) -> String {
    if is_absolute_iri(iri) {
        return iri.to_owned();
    }
    match active.base() {
        Some(base) => resolve_against(base, iri),
        None => iri.to_owned(),
    }
}

/// Apply one inline term map to the context being built.
fn apply_term_map(
    result: &mut ActiveContext,
    map: &Map<String, Value>,
    session: &mut Session<'_>,
) -> Result<(), Error> {
    if let Some(base) = map.get("@base") {
        match base {
            Value::Null => result.base = None,
            Value::String(value) => result.base = Some(value.clone()),
            _ => return Err(Error::InvalidContext),
        }
    }
    if let Some(vocab) = map.get("@vocab") {
        match vocab {
            Value::Null => result.vocab = None,
            // `@vocab` may itself be a term or a compact IRI; the
            // ActivityStreams context uses the blank-node prefix `_:`.
            Value::String(value) => {
                result.vocab = expand_iri(result, value, true, true);
            }
            _ => return Err(Error::InvalidContext),
        }
    }
    if let Some(language) = map.get("@language") {
        match language {
            Value::Null => result.language = None,
            Value::String(value) => result.language = Some(value.to_lowercase()),
            _ => return Err(Error::InvalidContext),
        }
    }

    let protected = map
        .get("@protected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut defined = BTreeMap::new();
    for key in map.keys() {
        if is_keyword(key) {
            continue;
        }
        create_term_definition(result, map, key, &mut defined, protected, session)?;
    }
    Ok(())
}

/// The JSON-LD "Create Term Definition" algorithm.
///
/// `defined` tracks terms already built and terms currently being built, which
/// is what lets a term map define `"Emoji": "toot:Emoji"` *before* it defines
/// `"toot"` — as litepub's context does — without depending on key order.
fn create_term_definition(
    active: &mut ActiveContext,
    local: &Map<String, Value>,
    term: &str,
    defined: &mut BTreeMap<String, bool>,
    protected: bool,
    session: &mut Session<'_>,
) -> Result<(), Error> {
    match defined.get(term) {
        Some(true) => return Ok(()),
        Some(false) => return Err(Error::CyclicContext(term.to_owned())),
        None => {}
    }
    if active.terms.len() >= session.limits.max_terms {
        return Err(Error::TermBudgetExceeded);
    }
    defined.insert(term.to_owned(), false);

    let value = local.get(term).unwrap_or(&Value::Null);
    let mut definition = TermDefinition {
        protected,
        ..TermDefinition::default()
    };

    match value {
        // `"term": null` removes the term; keys using it are dropped.
        Value::Null => {}
        Value::String(iri) => {
            definition.iri =
                expand_iri_while_defining(active, local, iri, defined, protected, session)?;
            definition.prefix = ends_with_gen_delim(iri);
        }
        Value::Object(map) => {
            if map.get("@id").is_some_and(Value::is_null) {
                // An explicit null `@id` is the object form of removing a term.
                active.terms.insert(term.to_owned(), definition);
                defined.insert(term.to_owned(), true);
                return Ok(());
            }
            if let Some(Value::Bool(flag)) = map.get("@protected") {
                definition.protected = *flag;
            }
            if let Some(reverse) = map.get("@reverse") {
                let Value::String(iri) = reverse else {
                    return Err(Error::InvalidTermDefinition(term.to_owned()));
                };
                definition.iri =
                    expand_iri_while_defining(active, local, iri, defined, protected, session)?;
                definition.reverse = true;
            } else if let Some(id) = map.get("@id") {
                let Value::String(iri) = id else {
                    return Err(Error::InvalidTermDefinition(term.to_owned()));
                };
                definition.iri =
                    expand_iri_while_defining(active, local, iri, defined, protected, session)?;
            } else {
                // No `@id`: the term expands on its own, as a compact IRI if it
                // looks like one, otherwise against `@vocab`.
                definition.iri =
                    expand_iri_while_defining(active, local, term, defined, protected, session)?;
            }

            if let Some(kind) = map.get("@type") {
                let Value::String(value) = kind else {
                    return Err(Error::InvalidTermDefinition(term.to_owned()));
                };
                definition.type_mapping = Some(match value.as_str() {
                    "@id" => TypeMapping::Id,
                    "@vocab" => TypeMapping::Vocab,
                    "@json" => TypeMapping::Json,
                    "@none" => TypeMapping::None,
                    other => TypeMapping::Datatype(
                        expand_iri_while_defining(
                            active, local, other, defined, protected, session,
                        )?
                        .unwrap_or_else(|| other.to_owned()),
                    ),
                });
            }

            match map.get("@container") {
                Some(Value::String(value)) => definition.container.add(value),
                Some(Value::Array(values)) => {
                    for value in values {
                        let Value::String(value) = value else {
                            return Err(Error::InvalidTermDefinition(term.to_owned()));
                        };
                        definition.container.add(value);
                    }
                }
                Some(_) => return Err(Error::InvalidTermDefinition(term.to_owned())),
                None => {}
            }

            match map.get("@language") {
                Some(Value::Null) => definition.language = Some(None),
                Some(Value::String(value)) => {
                    definition.language = Some(Some(value.to_lowercase()));
                }
                Some(_) => return Err(Error::InvalidTermDefinition(term.to_owned())),
                None => {}
            }

            if let Some(Value::Bool(flag)) = map.get("@prefix") {
                definition.prefix = *flag;
            }
            if let Some(scoped) = map.get("@context") {
                definition.scoped = Some(Box::new(scoped.clone()));
            }
        }
        _ => return Err(Error::InvalidTermDefinition(term.to_owned())),
    }

    active.terms.insert(term.to_owned(), definition);
    defined.insert(term.to_owned(), true);
    Ok(())
}

/// The JSON-LD "IRI Expansion" algorithm, as used while *building* a context.
///
/// This is the variant that may define other terms as a side effect: a term map
/// is a set of mutually referring definitions, not an ordered list, so
/// `"Emoji": "toot:Emoji"` must work even though litepub's context defines
/// `"toot"` several lines further down.
fn expand_iri_while_defining(
    active: &mut ActiveContext,
    local: &Map<String, Value>,
    value: &str,
    defined: &mut BTreeMap<String, bool>,
    protected: bool,
    session: &mut Session<'_>,
) -> Result<Option<String>, Error> {
    if is_keyword(value) {
        return Ok(Some(value.to_owned()));
    }
    if value.starts_with('@') {
        return Ok(None);
    }

    if local.contains_key(value) && defined.get(value) != Some(&true) {
        create_term_definition(active, local, value, defined, protected, session)?;
    }
    if let Some(definition) = active.term(value) {
        return Ok(definition.iri.clone());
    }

    if let Some(index) = value.find(':')
        && index > 0
    {
        let (prefix, rest) = value.split_at(index);
        let suffix = &rest[1..];
        if prefix == "_" || suffix.starts_with("//") {
            return Ok(Some(value.to_owned()));
        }
        if local.contains_key(prefix) && defined.get(prefix) != Some(&true) {
            create_term_definition(active, local, prefix, defined, protected, session)?;
        }
        if let Some(definition) = active.term(prefix)
            && definition.prefix
            && let Some(iri) = &definition.iri
        {
            let mut expanded = iri.clone();
            expanded.push_str(suffix);
            return Ok(Some(expanded));
        }
        return Ok(Some(value.to_owned()));
    }

    if let Some(prefix) = active.vocab() {
        let mut expanded = prefix.to_owned();
        expanded.push_str(value);
        return Ok(Some(expanded));
    }
    Ok(Some(value.to_owned()))
}

/// The JSON-LD "IRI Expansion" algorithm, as used while *reading* a document.
///
/// Returns `None` when the value expands to nothing: a term mapped to null, or
/// an unrecognised `@`-prefixed key. Both are dropped rather than carried
/// through, so an invented keyword cannot arrive as data.
pub(crate) fn expand_iri(
    active: &ActiveContext,
    value: &str,
    vocab: bool,
    document_relative: bool,
) -> Option<String> {
    if is_keyword(value) {
        return Some(value.to_owned());
    }
    if value.starts_with('@') {
        return None;
    }

    if vocab && let Some(definition) = active.term(value) {
        return definition.iri.clone();
    }

    if let Some(index) = value.find(':')
        && index > 0
    {
        let (prefix, rest) = value.split_at(index);
        let suffix = &rest[1..];
        if prefix == "_" || suffix.starts_with("//") {
            return Some(value.to_owned());
        }
        if let Some(definition) = active.term(prefix)
            && definition.prefix
            && let Some(iri) = &definition.iri
        {
            let mut expanded = iri.clone();
            expanded.push_str(suffix);
            return Some(expanded);
        }
        return Some(value.to_owned());
    }

    if vocab && let Some(prefix) = active.vocab() {
        let mut expanded = prefix.to_owned();
        expanded.push_str(value);
        return Some(expanded);
    }
    if document_relative && let Some(base) = active.base() {
        return Some(resolve_against(base, value));
    }
    Some(value.to_owned())
}

/// Whether `value` has a scheme, i.e. is not a relative reference.
pub(crate) fn is_absolute_iri(value: &str) -> bool {
    let Some(index) = value.find(':') else {
        return false;
    };
    if index == 0 {
        return false;
    }
    let scheme = &value[..index];
    scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Resolve `reference` against `base` per RFC 3986, falling back to the
/// reference itself when either side is not a usable IRI.
pub(crate) fn resolve_against(base: &str, reference: &str) -> String {
    use iri_string::types::{IriAbsoluteStr, IriReferenceStr};

    let Ok(base) = IriAbsoluteStr::new(base) else {
        return reference.to_owned();
    };
    let Ok(reference) = IriReferenceStr::new(reference) else {
        return reference.to_owned();
    };
    reference.resolve_against(base).to_string()
}
