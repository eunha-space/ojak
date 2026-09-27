//! Every document in `tests/corpus`, read into the vocabulary: which type it
//! read as, and what it lost.
//!
//! Lemmy keeps its own documents without the `@context` it sends them with;
//! such a document is read with the context Lemmy sends, or for another
//! server's, the ActivityStreams context every sender puts first, and the
//! report says so.
//!
//! The result is compared with `tests/corpus/losses.txt`, which is checked
//! in, so that a change to what the vocabulary reads shows in review as a
//! change to that file. After a change that is meant to alter it, rewrite it:
//!
//! ~~~~ sh
//! FEDER_BLESS=1 cargo test -p feder-vocab --test corpus
//! ~~~~

use feder_vocab::generated::AnyObject;
use feder_vocab::{Registry, read_reporting};
use serde_json::Value;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus");

fn documents(dir: &Path, found: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("corpus directory")
        .map(|entry| entry.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            documents(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            found.push(path);
        }
    }
}

/// The variant a value read as: `Note`, `Other`, ….
fn variant(value: &AnyObject) -> String {
    let debug = format!("{value:?}");
    debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// `value` with floats to twelve significant digits: how serde_json parses
/// the last digit of a long one depends on a feature another crate in the
/// build may turn on.
fn stable(value: &Value) -> Value {
    match value {
        Value::Number(number) if number.is_f64() => {
            let rounded = format!("{:.11e}", number.as_f64().unwrap_or_default());
            Value::String(rounded)
        }
        Value::Array(values) => Value::Array(values.iter().map(stable).collect()),
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), stable(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn shorten(value: &Value) -> String {
    let text = stable(value).to_string();
    match text.char_indices().nth(100) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

fn report() -> String {
    let registry = Registry::bundled();
    let root = Path::new(CORPUS);
    let mut paths = Vec::new();
    documents(root, &mut paths);
    let mut report = String::new();
    let (mut clean, mut other) = (0, 0);
    let mut unresolved = std::collections::BTreeMap::<String, usize>::new();
    for path in &paths {
        let name = path.strip_prefix(root).unwrap().display().to_string();
        let text = std::fs::read_to_string(path).expect("read");
        let mut document: Value = match serde_json::from_str(&text) {
            Ok(document) => document,
            Err(error) => {
                writeln!(report, "{name}: not JSON: {error}").unwrap();
                continue;
            }
        };
        let mut notes = String::new();
        if let Some(members) = document.as_object_mut()
            && !members.contains_key("@context")
        {
            let context = if name.starts_with("lemmy/lemmy/") {
                serde_json::json!([
                    "https://join-lemmy.org/context.json",
                    "https://www.w3.org/ns/activitystreams"
                ])
            } else {
                "https://www.w3.org/ns/activitystreams".into()
            };
            members.insert("@context".into(), context);
            notes.push_str(" (no @context)");
        }
        let declared = document
            .get("type")
            .map(|t| t.to_string())
            .unwrap_or_else(|| "(no type)".into());
        match read_reporting::<AnyObject>(&registry, &document) {
            Err(error) => writeln!(report, "{name}: {declared} not read: {error}").unwrap(),
            Ok(read) => {
                for context in read.unresolved_contexts() {
                    *unresolved.entry(context.clone()).or_insert(0) += 1;
                }
                let variant = variant(read.value());
                if variant == "Other" {
                    other += 1;
                }
                if read.lost().is_empty() && variant != "Other" {
                    clean += 1;
                    continue;
                }
                writeln!(report, "{name}: {declared} read as {variant}{notes}").unwrap();
                for loss in read.lost() {
                    writeln!(report, "    lost {}: {}", loss.path, shorten(&loss.value)).unwrap();
                }
            }
        }
    }
    let mut contexts = String::new();
    for (context, count) in &unresolved {
        writeln!(contexts, "    {context} ({count})").unwrap();
    }
    format!(
        "{} documents: {clean} read without loss, {other} read as no known type.\n\
         Contexts named and not bundled, which leave their terms unread:\n{contexts}\n{report}",
        paths.len()
    )
}

#[test]
fn the_corpus_reads_as_recorded() {
    let report = report();
    let recorded = Path::new(CORPUS).join("losses.txt");
    if std::env::var_os("FEDER_BLESS").is_some() {
        std::fs::write(&recorded, &report).expect("write losses.txt");
        return;
    }
    let expected = std::fs::read_to_string(&recorded).unwrap_or_default();
    assert!(
        report == expected,
        "the corpus reads differently from tests/corpus/losses.txt; \
         if that is intended, rewrite it with FEDER_BLESS=1.\n\n{report}"
    );
}
