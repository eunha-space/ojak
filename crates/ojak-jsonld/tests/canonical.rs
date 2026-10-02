//! Canonical N-Quads, held to Ruby's: each `tests/canonical/*.json` beside
//! the `*.nq` that the `json-ld` and `rdf-normalize` gems Mastodon 4.7.1
//! locks give it, with Mastodon's preloaded contexts and no fetching.
//!
//! Most are blank-node puzzles (`symmetric*`, `ring`, `shared_label`) that
//! take URDNA2015 past its first-degree hashes, literal escapes, lists and
//! doubles; the rest are real documents from the vocabulary corpus that each
//! once disagreed. `mitra_*` and `fedify_*` carry a data-integrity `proof`,
//! whose context Mastodon does not preload and whose `@graph` container
//! Mastodon's `RDF::Graph` folds into the default graph: theirs are what the
//! same gems give with ojak's bundled contexts loadable and the dataset kept
//! as a dataset, which is what the JSON-LD specification means.

use ojak_jsonld::{Registry, rdf};
use std::path::Path;

#[test]
fn canonical_forms_match_ruby() {
    let registry = Registry::bundled();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/canonical");
    let mut checked = 0;
    for entry in std::fs::read_dir(&directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let expected = std::fs::read_to_string(path.with_extension("nq")).unwrap();
        let canonical = rdf::canonize(&registry, &document)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(canonical, expected, "{}", path.display());
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} documents");
}

#[test]
fn an_unbundled_context_is_an_error() {
    let document = serde_json::json!({
        "@context": ["https://www.w3.org/ns/activitystreams", "https://unknown.example/ns"],
        "id": "https://a.example/1",
        "type": "Note"
    });
    assert_eq!(
        rdf::canonize(&Registry::bundled(), &document),
        Err(ojak_jsonld::Error::UnresolvedContext(
            "https://unknown.example/ns".into()
        ))
    );
}

#[test]
fn blank_node_puzzles_are_bounded() {
    // Twelve indistinguishable blank nodes all pointing at each other: the
    // labelling's worst case, refused rather than worked through.
    let nodes: Vec<serde_json::Value> = (0..12)
        .map(|i| {
            let others: Vec<serde_json::Value> = (0..12)
                .filter(|&j| j != i)
                .map(|j| serde_json::json!({"id": format!("_:n{j}")}))
                .collect();
            serde_json::json!({"id": format!("_:n{i}"), "tag": others})
        })
        .collect();
    let document = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Collection",
        "items": nodes
    });
    assert_eq!(
        rdf::canonize(&Registry::bundled(), &document),
        Err(ojak_jsonld::Error::CanonicalizationBudgetExceeded)
    );
}
