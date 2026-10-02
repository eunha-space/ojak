//! Expansion: rewriting a document so every key is the IRI it means.
//!
//! Expansion is what makes two documents comparable. `sensitive`,
//! `as:sensitive` and a term aliased to either all become
//! `https://www.w3.org/ns/activitystreams#sensitive`, so a reader can ask what
//! a document says without also knowing how the sender chose to spell it.

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use serde_json::{Map, Value};

use crate::{
    Error,
    context::{ActiveContext, Session, TermDefinition, TypeMapping, expand_iri, process},
};

/// Keywords ojak refuses to process, in either their own name or an alias.
///
/// These are the JSON-LD features that let one RDF graph be written as several
/// different trees. A Linked Data Signature covers the graph, so an attacker
/// who receives a signed activity can restructure the tree — moving the
/// activity under `@graph` and promoting its `object` to the top level, or
/// hiding properties behind `@included` — and every tree-reading ActivityPub
/// implementation then reads something the signer never said, with the
/// signature still valid. That is GHSA-9rfg-v8g9-9367, coordinated across
/// several fediverse projects in 2025, whose reporter recommended every
/// implementation reject these three.
///
/// Ojak has no reason to accept them on its own account: its FEP-8b32 proofs
/// are JCS over the JSON rather than over the canonical graph, so the
/// signature bypass does not apply. The ambiguity does. A document whose
/// meaning depends on whether the reader walks trees or graphs is a document
/// ojak would rather not have an opinion about.
///
/// Aliases are covered because this check runs *after* IRI expansion has
/// already resolved a term to the keyword it was defined as.
const RESTRUCTURING_KEYWORDS: &[&str] = &["@graph", "@included", "@reverse"];

/// Expand `document` against `active`, returning the expanded array form.
pub(crate) fn expand_document(
    active: &ActiveContext,
    document: &Value,
    session: &mut Session<'_>,
) -> Result<Value, Error> {
    let expanded = expand_element(active, None, None, document, session, 0)?;
    Ok(match expanded {
        Value::Array(items) => Value::Array(items),
        Value::Null => Value::Array(Vec::new()),
        other => Value::Array(Vec::from([other])),
    })
}

/// The JSON-LD "Expansion" algorithm for one element.
fn expand_element(
    active: &ActiveContext,
    active_property: Option<&str>,
    property: Option<&TermDefinition>,
    element: &Value,
    session: &mut Session<'_>,
    depth: usize,
) -> Result<Value, Error> {
    if depth > session.limits.max_depth {
        return Err(Error::DepthExceeded);
    }

    match element {
        Value::Null => Ok(Value::Null),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            // A scalar with no property to belong to is not a statement about
            // anything, and JSON-LD drops it.
            if active_property.is_none() {
                return Ok(Value::Null);
            }
            Ok(expand_value(active, property, element))
        }
        Value::Array(items) => {
            let mut expanded = Vec::with_capacity(items.len());
            for item in items {
                match expand_element(active, active_property, property, item, session, depth + 1)? {
                    Value::Null => {}
                    Value::Array(inner) => expanded.extend(inner),
                    other => expanded.push(other),
                }
            }
            Ok(Value::Array(expanded))
        }
        Value::Object(map) => expand_object(active, map, session, depth),
    }
}

/// Expand one JSON object: a node object, a value object, or a list.
fn expand_object(
    active: &ActiveContext,
    map: &Map<String, Value>,
    session: &mut Session<'_>,
    depth: usize,
) -> Result<Value, Error> {
    session.charge_node()?;

    // A local `@context` applies to this node and everything under it.
    let mut active = match map.get("@context") {
        Some(local) => process(active, local, session, &mut Vec::new())?,
        None => active.clone(),
    };

    // A type-scoped context applies to the node carrying the type, which is why
    // it has to be found before the other keys are read: `DataIntegrityProof`
    // is what gives `proofValue` and `cryptosuite` their meaning.
    apply_type_scoped_contexts(&mut active, map, session)?;

    let mut result = Map::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();

    for key in keys {
        if key == "@context" {
            continue;
        }
        let value = &map[key];
        let Some(expanded_key) = expand_iri(&active, key, true, false) else {
            continue;
        };

        if RESTRUCTURING_KEYWORDS.contains(&expanded_key.as_str()) {
            return Err(Error::RestructuringKeyword(expanded_key));
        }

        if crate::context::is_keyword(&expanded_key) {
            expand_keyword(&active, &expanded_key, value, &mut result, session, depth)?;
            continue;
        }
        if !expanded_key.contains(':') {
            // Not a keyword and not an IRI: nothing in the active context gives
            // this key a meaning, so it is not a statement ojak can read.
            continue;
        }

        let definition = active.term(key).cloned();
        if definition.as_ref().is_some_and(|d| d.reverse) {
            // A term defined with `@reverse` is the same graph-restructuring
            // device as the keyword, wearing a different hat.
            return Err(Error::RestructuringKeyword("@reverse".to_owned()));
        }

        // A property-scoped context applies to this property's values only.
        let scoped = match definition.as_ref().and_then(|d| d.scoped.as_ref()) {
            Some(local) => process(&active, local, session, &mut Vec::new())?,
            None => active.clone(),
        };

        let expanded_value =
            if definition.as_ref().is_some_and(|d| d.container.language) && value.is_object() {
                expand_language_map(value.as_object().expect("checked is_object"))
            } else {
                let expanded = expand_element(
                    &scoped,
                    Some(key),
                    definition.as_ref(),
                    value,
                    session,
                    depth + 1,
                )?;
                if definition.as_ref().is_some_and(|d| d.container.list) {
                    wrap_list(expanded)
                } else if session.rdf && definition.as_ref().is_some_and(|d| d.container.graph) {
                    wrap_graphs(expanded)
                } else {
                    expanded
                }
            };

        let expanded_value = match expanded_value {
            Value::Null => continue,
            Value::Array(items) => Value::Array(items),
            other => Value::Array(Vec::from([other])),
        };
        merge(&mut result, expanded_key, expanded_value);
    }

    finish_node(result, session.rdf)
}

/// Apply the scoped context of every type the node declares.
fn apply_type_scoped_contexts(
    active: &mut ActiveContext,
    map: &Map<String, Value>,
    session: &mut Session<'_>,
) -> Result<(), Error> {
    let mut type_terms: Vec<&str> = Vec::new();
    for (key, value) in map {
        if expand_iri(active, key, true, false).as_deref() != Some("@type") {
            continue;
        }
        match value {
            Value::String(term) => type_terms.push(term),
            Value::Array(items) => {
                for item in items {
                    if let Value::String(term) = item {
                        type_terms.push(term);
                    }
                }
            }
            _ => {}
        }
    }
    // Lexicographic order, so a node with two scoped types processes them the
    // same way everywhere.
    type_terms.sort_unstable();
    for term in type_terms {
        let Some(local) = active.term(term).and_then(|d| d.scoped.clone()) else {
            continue;
        };
        *active = process(active, &local, session, &mut Vec::new())?;
    }
    Ok(())
}

/// Expand a keyword entry into `result`.
fn expand_keyword(
    active: &ActiveContext,
    keyword: &str,
    value: &Value,
    result: &mut Map<String, Value>,
    session: &mut Session<'_>,
    depth: usize,
) -> Result<(), Error> {
    match keyword {
        "@id" => {
            if let Value::String(iri) = value
                && let Some(expanded) = expand_iri(active, iri, false, true)
            {
                result.insert("@id".to_owned(), Value::String(expanded));
            }
        }
        "@type" => {
            let mut types = Vec::new();
            match value {
                Value::String(kind) => {
                    if let Some(expanded) = expand_iri(active, kind, true, true) {
                        types.push(Value::String(expanded));
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        if let Value::String(kind) = item
                            && let Some(expanded) = expand_iri(active, kind, true, true)
                        {
                            types.push(Value::String(expanded));
                        }
                    }
                }
                _ => {}
            }
            if !types.is_empty() {
                result.insert("@type".to_owned(), Value::Array(types));
            }
        }
        "@value" => {
            result.insert("@value".to_owned(), value.clone());
        }
        "@language" => {
            if let Value::String(language) = value {
                result.insert(
                    "@language".to_owned(),
                    Value::String(language.to_lowercase()),
                );
            }
        }
        "@list" => {
            let expanded = expand_element(active, Some("@list"), None, value, session, depth + 1)?;
            result.insert("@list".to_owned(), as_array(expanded));
        }
        "@set" => {
            let expanded = expand_element(active, Some("@set"), None, value, session, depth + 1)?;
            result.insert("@set".to_owned(), as_array(expanded));
        }
        // `@index`, `@direction`, `@nest`, `@version` and the context keywords
        // carry no statement ojak acts on, and are dropped.
        _ => {}
    }
    Ok(())
}

/// Expand a `@container: @language` map into language-tagged value objects.
fn expand_language_map(map: &Map<String, Value>) -> Value {
    let mut values = Vec::new();
    let mut languages: Vec<&String> = map.keys().collect();
    languages.sort();
    for language in languages {
        let entries = match &map[language] {
            Value::Array(items) => items.clone(),
            other => Vec::from([other.clone()]),
        };
        for entry in entries {
            let Value::String(text) = entry else {
                continue;
            };
            let mut object = Map::new();
            object.insert("@value".to_owned(), Value::String(text));
            if language != "@none" {
                object.insert(
                    "@language".to_owned(),
                    Value::String(language.to_lowercase()),
                );
            }
            values.push(Value::Object(object));
        }
    }
    Value::Array(values)
}

/// The JSON-LD "Value Expansion" algorithm.
fn expand_value(active: &ActiveContext, property: Option<&TermDefinition>, value: &Value) -> Value {
    let mapping = property.and_then(|d| d.type_mapping.as_ref());

    if let (Some(TypeMapping::Id), Value::String(text)) = (mapping, value)
        && let Some(iri) = expand_iri(active, text, false, true)
    {
        let mut object = Map::new();
        object.insert("@id".to_owned(), Value::String(iri));
        return Value::Object(object);
    }
    if let (Some(TypeMapping::Vocab), Value::String(text)) = (mapping, value)
        && let Some(iri) = expand_iri(active, text, true, true)
    {
        let mut object = Map::new();
        object.insert("@id".to_owned(), Value::String(iri));
        return Value::Object(object);
    }

    let mut object = Map::new();
    object.insert("@value".to_owned(), value.clone());
    match mapping {
        Some(TypeMapping::Json) => {
            object.insert("@type".to_owned(), Value::String("@json".to_owned()));
        }
        Some(TypeMapping::Datatype(datatype)) => {
            object.insert("@type".to_owned(), Value::String(datatype.clone()));
        }
        _ => {
            if value.is_string() {
                let language = match property.and_then(|d| d.language.as_ref()) {
                    // `@language: null` on the term clears the default.
                    Some(None) => None,
                    Some(Some(language)) => Some(language.clone()),
                    None => active.language().map(ToString::to_string),
                };
                if let Some(language) = language {
                    object.insert("@language".to_owned(), Value::String(language));
                }
            }
        }
    }
    Value::Object(object)
}

/// Wrap each node object of an expanded value in a graph object, as a term
/// whose `@container` is `@graph` asks: what it holds is a graph of its own.
fn wrap_graphs(expanded: Value) -> Value {
    let wrap = |item: Value| {
        let is_node = item
            .as_object()
            .is_some_and(|object| !object.contains_key("@value") && !object.contains_key("@list"));
        if !is_node {
            return item;
        }
        let mut object = Map::new();
        object.insert("@graph".to_owned(), Value::Array(Vec::from([item])));
        Value::Object(object)
    };
    match expanded {
        Value::Array(items) => Value::Array(items.into_iter().map(wrap).collect()),
        Value::Null => Value::Null,
        other => wrap(other),
    }
}

/// Wrap an expanded value in a `@list` unless it already is one.
fn wrap_list(expanded: Value) -> Value {
    if expanded
        .as_object()
        .is_some_and(|object| object.contains_key("@list"))
    {
        return expanded;
    }
    let mut object = Map::new();
    object.insert("@list".to_owned(), as_array(expanded));
    Value::Object(object)
}

fn as_array(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items),
        Value::Null => Value::Array(Vec::new()),
        other => Value::Array(Vec::from([other])),
    }
}

/// Add an expanded property to the node, concatenating when two source keys
/// expanded to the same IRI (`sensitive` and `as:sensitive` in one document).
fn merge(result: &mut Map<String, Value>, key: String, value: Value) {
    match result.get_mut(&key) {
        Some(Value::Array(existing)) => {
            if let Value::Array(items) = value {
                existing.extend(items);
            }
        }
        _ => {
            result.insert(key, value);
        }
    }
}

/// Tidy a finished node object, dropping what says nothing — to a tree
/// reader. In RDF (`rdf`) a node with nothing in it is still a blank node.
fn finish_node(mut result: Map<String, Value>, rdf: bool) -> Result<Value, Error> {
    if result.contains_key("@value") {
        // A value object is only its value; `{"@value": null}` says nothing.
        if result.get("@value").is_some_and(Value::is_null) {
            return Ok(Value::Null);
        }
        // A node's `@type` is a list of types; a value's `@type` is the one
        // datatype it has, and must stay a string or a reader looking for a
        // datatype will not find one.
        if let Some(Value::Array(types)) = result.get("@type") {
            let datatype = types.first().cloned();
            match datatype {
                Some(datatype) => result.insert("@type".to_owned(), datatype),
                None => result.remove("@type"),
            };
        }
        return Ok(Value::Object(result));
    }
    if let Some(set) = result.get("@set") {
        return Ok(set.clone());
    }
    if result.is_empty() && !rdf {
        return Ok(Value::Null);
    }
    Ok(Value::Object(result))
}
