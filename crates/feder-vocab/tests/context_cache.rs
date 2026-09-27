//! Keeping processed contexts changes what normalising costs, never what it
//! produces: every document in `tests/corpus` normalises the same through a
//! cache, whether the cache is cold or has seen every context before.

use feder_jsonld::{ContextCache, Limits, ProcessedContext, normalize, normalize_with_cache};
use feder_vocab::Registry;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus");

#[derive(Default)]
struct MapCache(Mutex<HashMap<String, Arc<ProcessedContext>>>);

impl ContextCache for MapCache {
    fn get(&self, key: &str) -> Option<Arc<ProcessedContext>> {
        self.0.lock().unwrap().get(key).cloned()
    }

    fn put(&self, key: String, context: Arc<ProcessedContext>) {
        self.0.lock().unwrap().insert(key, context);
    }
}

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

fn outcome(result: Result<feder_jsonld::Processed, feder_jsonld::Error>) -> String {
    match result {
        Ok(processed) => format!(
            "{} {:?}",
            processed.document(),
            processed.unresolved_contexts()
        ),
        Err(error) => format!("error: {error}"),
    }
}

#[test]
fn a_cache_changes_nothing_normalize_produces() {
    let registry = Registry::bundled();
    let mut paths = Vec::new();
    documents(Path::new(CORPUS), &mut paths);
    assert!(paths.len() > 100, "the corpus is where it should be");

    let cache = MapCache::default();
    for pass in ["cold", "warm"] {
        for path in &paths {
            let document: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(
                outcome(normalize_with_cache(
                    &registry,
                    &document,
                    Limits::default(),
                    &cache
                )),
                outcome(normalize(&registry, &document)),
                "{} ({pass} cache)",
                path.display()
            );
        }
    }
    let kept = cache.0.lock().unwrap().len();
    assert!(
        kept < paths.len(),
        "{kept} contexts for {} documents: the same ones recur",
        paths.len()
    );
}
