//! Compaction: writing an expanded document back out in a chosen vocabulary.
//!
//! Expansion answers what a document says. Compaction answers how feder says
//! it: every IRI that feder's context has a term for comes back as that term,
//! so [`crate::normalize`] hands the vocabulary types a document spelled the
//! way they expect regardless of how it arrived.
//!
//! An IRI the context has no term for is left as an IRI rather than guessed at.
//! A document that arrives using a context feder does not ship therefore comes
//! back with those keys visibly unresolved, which is a better outcome than a
//! plausible-looking key that means something else.

use core::cmp::Reverse;

use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, vec::Vec};
use serde_json::{Map, Value};

use crate::{
    Error,
    context::{ActiveContext, Session, TermDefinition, TypeMapping, process},
};

/// The terms of an active context, indexed by the IRI they expand to.
struct Inverse<'a> {
    by_iri: BTreeMap<&'a str, Vec<(&'a str, &'a TermDefinition)>>,
}

impl<'a> Inverse<'a> {
    fn build(active: &'a ActiveContext) -> Self {
        let mut by_iri: BTreeMap<&str, Vec<(&str, &TermDefinition)>> = BTreeMap::new();
        for (name, definition) in active.terms() {
            let Some(iri) = definition.iri.as_deref() else {
                continue;
            };
            by_iri
                .entry(iri)
                .or_default()
                .push((name.as_str(), definition));
        }
        Self { by_iri }
    }

    fn candidates(&self, iri: &str) -> &[(&'a str, &'a TermDefinition)] {
        self.by_iri.get(iri).map_or(&[], Vec::as_slice)
    }

    /// The term to write `iri` as, given the values it carries.
    ///
    /// Highest-scoring definition wins; ties go to the shorter term and then
    /// the lexicographically smaller one, so the same document always compacts
    /// the same way.
    fn select(&self, iri: &str, values: &[Value]) -> Option<(&'a str, &'a TermDefinition)> {
        self.candidates(iri)
            .iter()
            .filter(|(_, definition)| !definition.reverse)
            .max_by_key(|(name, definition)| {
                (
                    score(definition, values),
                    Reverse(name.len()),
                    Reverse(*name),
                )
            })
            .map(|(name, definition)| (*name, *definition))
    }
}

/// How well a term definition fits the values it would carry.
fn score(definition: &TermDefinition, values: &[Value]) -> i32 {
    if values.is_empty() {
        return i32::from(definition.type_mapping.is_none());
    }
    let mut score = 0;
    let all_node_refs = values.iter().all(is_node_reference);
    let all_lists = values.iter().all(|value| value.get("@list").is_some());
    // Note the asymmetry: a `@language` container is the right term precisely
    // when the values are in *different* languages, so it is chosen on every
    // value being tagged rather than on them sharing a tag.
    let all_tagged = values.iter().all(|value| value.get("@language").is_some());
    let datatype = common_datatype(values);
    let language = common_language(values);

    if all_lists && definition.container.list {
        score += 4;
    }
    if all_node_refs
        && matches!(
            definition.type_mapping,
            Some(TypeMapping::Id | TypeMapping::Vocab)
        )
    {
        score += 4;
    }
    if let Some(datatype) = datatype
        && matches!(&definition.type_mapping, Some(TypeMapping::Datatype(mapped)) if mapped == datatype)
    {
        score += 4;
    }
    if let Some(language) = language
        && matches!(&definition.language, Some(Some(mapped)) if mapped == language)
    {
        score += 3;
    } else if all_tagged && definition.container.language {
        score += 2;
    }
    if datatype.is_none()
        && !all_tagged
        && !all_node_refs
        && !all_lists
        && definition.type_mapping.is_none()
    {
        score += 1;
    }
    score
}

fn is_node_reference(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.contains_key("@id"))
}

/// The `@type` shared by every value, if they share one.
fn common_datatype(values: &[Value]) -> Option<&str> {
    let first = values.first()?.get("@type")?.as_str()?;
    values
        .iter()
        .all(|value| value.get("@type").and_then(Value::as_str) == Some(first))
        .then_some(first)
}

/// The `@language` shared by every value, if they share one.
fn common_language(values: &[Value]) -> Option<&str> {
    let first = values.first()?.get("@language")?.as_str()?;
    values
        .iter()
        .all(|value| value.get("@language").and_then(Value::as_str) == Some(first))
        .then_some(first)
}

/// The term `keyword` is aliased to in `active`, or the keyword itself.
fn keyword_alias<'a>(inverse: &Inverse<'a>, keyword: &'a str) -> &'a str {
    inverse
        .candidates(keyword)
        .iter()
        .map(|(name, _)| *name)
        .min_by_key(|name| (name.len(), *name))
        .unwrap_or(keyword)
}

/// Compact an expanded document against `active`, attaching `context`.
pub(crate) fn compact_document(
    active: &ActiveContext,
    expanded: &Value,
    context: &Value,
    session: &mut Session<'_>,
) -> Result<Value, Error> {
    let inverse = Inverse::build(active);
    let nodes = match expanded {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        other => Vec::from([other.clone()]),
    };

    let mut compacted = Vec::with_capacity(nodes.len());
    for node in &nodes {
        compacted.push(compact_element(active, &inverse, None, node, session, 0)?);
    }

    // ActivityPub documents are single nodes. More than one top-level node
    // could only be written back as a `@graph`, which feder refuses, so the
    // array is handed back as it is rather than restructured.
    match compacted.len() {
        0 => {
            let mut object = Map::new();
            object.insert("@context".to_owned(), context.clone());
            Ok(Value::Object(object))
        }
        1 => {
            let mut node = match compacted.remove_first() {
                Value::Object(object) => object,
                other => return Ok(other),
            };
            node.insert("@context".to_owned(), context.clone());
            Ok(Value::Object(node))
        }
        _ => Ok(Value::Array(compacted)),
    }
}

/// `Vec::remove(0)` under a name that says what it is doing.
trait RemoveFirst {
    fn remove_first(self) -> Value;
}

impl RemoveFirst for Vec<Value> {
    fn remove_first(mut self) -> Value {
        self.remove(0)
    }
}

/// Compact one expanded value.
fn compact_element(
    active: &ActiveContext,
    inverse: &Inverse<'_>,
    property: Option<&TermDefinition>,
    value: &Value,
    session: &mut Session<'_>,
    depth: usize,
) -> Result<Value, Error> {
    if depth > session.limits.max_depth {
        return Err(Error::DepthExceeded);
    }
    match value {
        Value::Array(items) => {
            let mut compacted = Vec::with_capacity(items.len());
            for item in items {
                compacted.push(compact_element(
                    active,
                    inverse,
                    property,
                    item,
                    session,
                    depth + 1,
                )?);
            }
            Ok(Value::Array(compacted))
        }
        Value::Object(object) if object.contains_key("@value") => {
            Ok(compact_value(active, inverse, property, object))
        }
        Value::Object(object) if object.contains_key("@list") => {
            let items = object["@list"].clone();
            compact_element(active, inverse, property, &items, session, depth + 1)
        }
        Value::Object(object) => {
            // A bare node reference under an `@id`-typed term is just its IRI,
            // and under a `@vocab`-typed one it is the term the IRI has, which
            // is how `proofPurpose` says `assertionMethod`.
            if is_node_reference(value) {
                match property.and_then(|d| d.type_mapping.as_ref()) {
                    Some(TypeMapping::Id) => return Ok(object["@id"].clone()),
                    Some(TypeMapping::Vocab) => {
                        if let Some(iri) = object["@id"].as_str() {
                            return Ok(Value::String(compact_iri(active, inverse, iri)));
                        }
                    }
                    _ => {}
                }
            }
            compact_node(active, inverse, object, session, depth)
        }
        other => Ok(other.clone()),
    }
}

/// The context `node`'s types scope to it, if any of them scope one.
///
/// The mirror of expansion's type-scoped contexts: `DataIntegrityProof` is
/// what gives `proofValue` and `cryptosuite` their terms, so a proof compacted
/// without it would come back as `sec:proofValue` wrapped in a typed value.
/// Types are compacted against the enclosing context to find their terms, and
/// scoped contexts are applied in lexicographic order of those terms, as
/// expansion applies them.
fn type_scoped_context(
    active: &ActiveContext,
    inverse: &Inverse<'_>,
    node: &Map<String, Value>,
    session: &mut Session<'_>,
) -> Result<Option<ActiveContext>, Error> {
    let mut terms: Vec<String> = match node.get("@type") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|iri| compact_iri(active, inverse, iri))
            .collect(),
        Some(Value::String(iri)) => Vec::from([compact_iri(active, inverse, iri)]),
        _ => return Ok(None),
    };
    terms.sort_unstable();
    let mut scoped: Option<ActiveContext> = None;
    for term in &terms {
        let Some(local) = active.term(term).and_then(|d| d.scoped.as_deref()) else {
            continue;
        };
        let base = scoped.as_ref().unwrap_or(active);
        scoped = Some(process(base, local, session, &mut Vec::new())?);
    }
    Ok(scoped)
}

/// Compact an expanded node object.
fn compact_node(
    active: &ActiveContext,
    inverse: &Inverse<'_>,
    node: &Map<String, Value>,
    session: &mut Session<'_>,
    depth: usize,
) -> Result<Value, Error> {
    session.charge_node()?;

    // A type-scoped context applies to the node carrying the type, and to
    // what is nested in it, exactly as in expansion.
    let type_scoped = type_scoped_context(active, inverse, node, session)?;
    let type_scoped_inverse = type_scoped.as_ref().map(Inverse::build);
    let (active, inverse) = match (&type_scoped, &type_scoped_inverse) {
        (Some(scoped), Some(scoped_inverse)) => (scoped, scoped_inverse),
        _ => (active, inverse),
    };

    let mut result = Map::new();

    for (key, value) in node {
        match key.as_str() {
            "@id" => {
                result.insert(keyword_alias(inverse, "@id").to_owned(), value.clone());
            }
            "@type" => {
                let types: Vec<Value> = match value {
                    Value::Array(items) => items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|iri| Value::String(compact_iri(active, inverse, iri)))
                        .collect(),
                    Value::String(iri) => {
                        Vec::from([Value::String(compact_iri(active, inverse, iri))])
                    }
                    _ => Vec::new(),
                };
                let types = if types.len() == 1 {
                    types.into_iter().next().expect("length checked")
                } else {
                    Value::Array(types)
                };
                result.insert(keyword_alias(inverse, "@type").to_owned(), types);
            }
            iri => {
                let items: Vec<Value> = match value {
                    Value::Array(items) => items.clone(),
                    other => Vec::from([other.clone()]),
                };
                let selected = inverse.select(iri, &items);
                let name = selected
                    .map(|(name, _)| name.to_owned())
                    .unwrap_or_else(|| compact_iri(active, inverse, iri));
                let definition = selected.map(|(_, definition)| definition);

                // A `@container: @language` term is written as a map keyed by
                // language, not as a list of language-tagged values.
                if definition.is_some_and(|d| d.container.language)
                    && items.iter().all(|item| item.get("@language").is_some())
                {
                    result.insert(name, language_map(&items));
                    continue;
                }

                // A property-scoped context applies to this property's values
                // only, again as in expansion.
                let property_scoped = match definition.and_then(|d| d.scoped.as_deref()) {
                    Some(local) => Some(process(active, local, session, &mut Vec::new())?),
                    None => None,
                };
                let property_scoped_inverse = property_scoped.as_ref().map(Inverse::build);
                let (value_active, value_inverse) =
                    match (&property_scoped, &property_scoped_inverse) {
                        (Some(scoped), Some(scoped_inverse)) => (scoped, scoped_inverse),
                        _ => (active, inverse),
                    };

                let is_list = items.len() == 1 && items[0].get("@list").is_some();
                let mut compacted = Vec::with_capacity(items.len());
                for item in &items {
                    compacted.push(compact_element(
                        value_active,
                        value_inverse,
                        definition,
                        item,
                        session,
                        depth + 1,
                    )?);
                }

                let value = if is_list && definition.is_some_and(|d| d.container.list) {
                    // The list *is* the value; its wrapper was the container.
                    compacted.into_iter().next().expect("one list")
                } else if compacted.len() == 1 && !definition.is_some_and(|d| d.container.set) {
                    compacted.into_iter().next().expect("length checked")
                } else {
                    Value::Array(compacted)
                };
                result.insert(name, value);
            }
        }
    }

    Ok(Value::Object(result))
}

/// Write language-tagged values back as a language map.
fn language_map(items: &[Value]) -> Value {
    let mut map: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for item in items {
        let language = item
            .get("@language")
            .and_then(Value::as_str)
            .unwrap_or("@none")
            .to_owned();
        let value = item.get("@value").cloned().unwrap_or(Value::Null);
        map.entry(language).or_default().push(value);
    }
    let mut result = Map::new();
    for (language, mut values) in map {
        let value = if values.len() == 1 {
            values.remove(0)
        } else {
            Value::Array(values)
        };
        result.insert(language, value);
    }
    Value::Object(result)
}

/// Compact an expanded value object down to a scalar where the term allows it.
fn compact_value(
    active: &ActiveContext,
    inverse: &Inverse<'_>,
    property: Option<&TermDefinition>,
    object: &Map<String, Value>,
) -> Value {
    let value = object.get("@value").cloned().unwrap_or(Value::Null);
    let datatype = object.get("@type").and_then(Value::as_str);
    let language = object.get("@language").and_then(Value::as_str);

    // A JSON literal is its own value.
    if datatype == Some("@json") {
        return value;
    }
    // The term already says what type these values have, so the wrapper adds
    // nothing.
    if let Some(datatype) = datatype
        && matches!(property.and_then(|d| d.type_mapping.as_ref()), Some(TypeMapping::Datatype(mapped)) if mapped == datatype)
    {
        return value;
    }
    if let Some(language) = language {
        let matches_term = matches!(property.and_then(|d| d.language.as_ref()), Some(Some(mapped)) if mapped == language);
        let matches_context =
            active.language() == Some(language) && property.is_none_or(|d| d.language.is_none());
        if matches_term || matches_context {
            return value;
        }
    }
    if datatype.is_none() && language.is_none() {
        let default_language_applies = active.language().is_some()
            && value.is_string()
            && property.is_none_or(|d| d.language.is_none());
        if !default_language_applies {
            return value;
        }
    }

    // Otherwise the wrapper is load-bearing; keep it, with aliases applied.
    // The keywords are left as keywords here. Aliasing `@type` to
    // ActivityStreams' `type` would be legal JSON-LD and would read, to
    // anything less than a full processor, as the type of an object rather than
    // the datatype of a value.
    let mut result = Map::new();
    result.insert("@value".to_owned(), value);
    if let Some(datatype) = datatype {
        result.insert(
            "@type".to_owned(),
            Value::String(compact_iri(active, inverse, datatype)),
        );
    }
    if let Some(language) = language {
        result.insert("@language".to_owned(), Value::String(language.to_owned()));
    }
    Value::Object(result)
}

/// Write an IRI in the shortest form the active context gives it.
fn compact_iri(active: &ActiveContext, inverse: &Inverse<'_>, iri: &str) -> String {
    if let Some(name) = inverse
        .candidates(iri)
        .iter()
        .filter(|(_, definition)| !definition.reverse && definition.type_mapping.is_none())
        .map(|(name, _)| *name)
        .min_by_key(|name| (name.len(), *name))
    {
        return name.to_owned();
    }
    if let Some(name) = inverse
        .candidates(iri)
        .iter()
        .map(|(name, _)| *name)
        .min_by_key(|name| (name.len(), *name))
    {
        return name.to_owned();
    }

    // A compact IRI, using the longest prefix the context defines.
    let mut best: Option<(usize, String)> = None;
    for (name, definition) in active.terms() {
        if !definition.prefix {
            continue;
        }
        let Some(prefix) = definition.iri.as_deref() else {
            continue;
        };
        if prefix.is_empty() || !iri.starts_with(prefix) || iri.len() == prefix.len() {
            continue;
        }
        let candidate = alloc::format!("{name}:{}", &iri[prefix.len()..]);
        if best
            .as_ref()
            .is_none_or(|(length, _)| prefix.len() > *length)
        {
            best = Some((prefix.len(), candidate));
        }
    }
    if let Some((_, candidate)) = best {
        return candidate;
    }

    // Terms the context has no name for expand against `@vocab`, which for
    // ActivityStreams is the blank-node prefix `_:`; stripping it back off is
    // what lets an unrecognised key survive a round trip under its own name.
    if let Some(vocab) = active.vocab()
        && let Some(rest) = iri.strip_prefix(vocab)
    {
        // Unless doing so would collide with a keyword alias, which would
        // let an inbound `_:id` arrive as this document's `id`.
        let collides = active
            .term(rest)
            .and_then(|definition| definition.iri.as_deref())
            .is_some_and(|mapped| mapped.starts_with('@'));
        if !rest.is_empty() && !collides {
            return rest.to_owned();
        }
    }

    iri.to_owned()
}
