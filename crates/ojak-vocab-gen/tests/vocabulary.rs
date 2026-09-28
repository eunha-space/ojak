//! The vendored schemas, as the generator reads them.

use ojak_jsonld::Registry;
use ojak_vocab_gen::{
    model::{Literal, Range, Vocabulary},
    schema,
};
use std::path::Path;

fn vocabulary() -> Vocabulary {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ojak-vocab/schemas");
    let schemas = schema::load_dir(&dir).expect("load schemas");
    Vocabulary::from_schemas(&schemas, &Registry::bundled()).expect("analyse schemas")
}

fn find<'a>(vocabulary: &'a Vocabulary, name: &str) -> &'a ojak_vocab_gen::model::Type {
    vocabulary
        .types
        .values()
        .find(|t| t.name == name)
        .unwrap_or_else(|| panic!("no type {name}"))
}

#[test]
fn every_schema_is_understood() {
    assert_eq!(vocabulary().types.len(), 81);
}

#[test]
fn note_has_what_object_has() {
    let vocabulary = vocabulary();
    let note = find(&vocabulary, "Note");
    assert_eq!(note.type_term.as_deref(), Some("Note"));
    let content = note
        .properties
        .iter()
        .find(|p| p.field == "content")
        .expect("content");
    assert_eq!(content.key, "content");
    assert_eq!(
        content.ranges,
        vec![
            Range::Literal(Literal::String),
            Range::Literal(Literal::LangString)
        ]
    );
    assert_eq!(content.declared_by, "Object");
    let attribution = note
        .properties
        .iter()
        .find(|p| p.key == "attributedTo")
        .expect("attributedTo");
    assert!(!attribution.functional);
}

/// Not an assertion, a report: the properties whose key is not a term in
/// Ojak's context, which is where the context is missing a definition.
#[test]
fn report_keys_outside_ojaks_context() {
    let vocabulary = vocabulary();
    let mut seen = std::collections::BTreeSet::new();
    for t in vocabulary.types.values() {
        if t.type_term
            .as_deref()
            .is_some_and(|term| term.contains(':'))
        {
            seen.insert(format!(
                "type {} -> {}",
                t.name,
                t.type_term.as_deref().unwrap_or("")
            ));
        }
        for p in &t.properties {
            if p.key.contains(':') {
                seen.insert(format!("{}.{} -> {}", p.declared_by, p.field, p.key));
            }
        }
    }
    for line in &seen {
        println!("{line}");
    }
    println!("{} outside", seen.len());
}
