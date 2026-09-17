//! What the crate refuses, and why it refuses it.
//!
//! Everything here is reachable by anyone who can reach an inbox, before any
//! signature has been checked, so each refusal is load-bearing rather than
//! tidiness.

use feder_jsonld::{Error, Limits, Registry, expand, expand_with};
use serde_json::{Value, json};

fn registry() -> Registry {
    Registry::bundled()
}

/// The shape GHSA-9rfg-v8g9-9367 describes: a signed `Undo` whose embedded
/// `Announce` an attacker promotes to the top level by pushing the activity
/// down into `@graph`. The RDF graph — and so the Linked Data Signature over
/// it — is unchanged; what every tree-reading ActivityPub implementation does
/// with the document is not.
fn restructured_activity(graph_key: &str, context: Value) -> Value {
    json!({
        "@context": context,
        "type": "Announce",
        "id": "https://attacker.example/announce/1",
        "actor": "https://victim.example/users/alice",
        graph_key: {
            "type": "Undo",
            "id": "https://victim.example/undo/1",
            "actor": "https://victim.example/users/alice"
        }
    })
}

#[test]
fn graph_restructuring_keywords_are_refused() {
    let registry = registry();
    for keyword in ["@graph", "@included", "@reverse"] {
        let document =
            restructured_activity(keyword, json!("https://www.w3.org/ns/activitystreams"));
        assert_eq!(
            expand(&registry, &document),
            Err(Error::RestructuringKeyword(keyword.to_owned())),
            "{keyword} was not refused"
        );
    }
}

#[test]
fn an_alias_for_a_restructuring_keyword_is_refused_too() {
    // The keyword need not be spelled as itself: a context can name it
    // anything. This is why the check has to happen against the expanded key
    // rather than against the key the sender wrote.
    let registry = registry();
    let document = restructured_activity(
        "payload",
        json!([
            "https://www.w3.org/ns/activitystreams",
            { "payload": "@graph" }
        ]),
    );
    assert_eq!(
        expand(&registry, &document),
        Err(Error::RestructuringKeyword("@graph".to_owned()))
    );
}

#[test]
fn a_term_defined_with_reverse_is_refused() {
    // `@reverse` in a term definition turns a property inside out without ever
    // naming the keyword in the document. Same restructuring, quieter.
    let registry = registry();
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            { "announcedBy": { "@reverse": "as:object" } }
        ],
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "announcedBy": "https://attacker.example/announce/1"
    });
    assert_eq!(
        expand(&registry, &document),
        Err(Error::RestructuringKeyword("@reverse".to_owned()))
    );
}

#[test]
fn an_invented_keyword_never_becomes_data() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "@verified": true,
        "@actor": "https://victim.example/users/alice"
    });
    let expanded = expand(&registry(), &document).expect("expand");
    let node = &expanded.document()[0];
    assert!(node.get("@verified").is_none());
    assert!(node.get("@actor").is_none());
    assert!(node.get("_:@verified").is_none());
}

#[test]
fn a_blank_node_key_cannot_arrive_as_id() {
    // An unrecognised key expands to `_:key` and compacts back under its own
    // name, which is how an extension term survives a round trip. `_:id` would
    // come back as this document's `id` if that were done blindly.
    let registry = registry();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://honest.example/notes/1",
        "_:id": "https://attacker.example/notes/1"
    });
    let normalized = feder_jsonld::normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["id"],
        json!("https://honest.example/notes/1")
    );
}

#[test]
fn nesting_is_bounded() {
    let mut document = json!({ "type": "Note", "id": "https://remote.example/notes/1" });
    for _ in 0..200 {
        document = json!({ "type": "Create", "object": document });
    }
    document["@context"] = json!("https://www.w3.org/ns/activitystreams");

    assert_eq!(
        expand(&registry(), &document),
        Err(Error::DepthExceeded),
        "a deeply nested document must not be walked to the bottom"
    );
}

#[test]
fn object_count_is_bounded() {
    let items: Vec<Value> = (0..5_000)
        .map(|index| json!({ "type": "Note", "id": format!("https://remote.example/n/{index}") }))
        .collect();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "OrderedCollection",
        "id": "https://remote.example/outbox",
        "orderedItems": items
    });

    let limits = Limits {
        max_nodes: 1_000,
        ..Limits::default()
    };
    assert_eq!(
        expand_with(&registry(), &document, limits),
        Err(Error::NodeBudgetExceeded)
    );
}

#[test]
fn context_processing_is_bounded() {
    // Repeating a bundled context is cheap for the sender and not for the
    // receiver, so the count is capped rather than the contexts deduplicated.
    let contexts: Vec<Value> =
        core::iter::repeat_n(json!("https://www.w3.org/ns/activitystreams"), 500).collect();
    let document = json!({
        "@context": contexts,
        "type": "Note",
        "id": "https://remote.example/notes/1"
    });
    assert_eq!(
        expand(&registry(), &document),
        Err(Error::ContextBudgetExceeded)
    );
}

#[test]
fn a_context_referring_to_itself_is_refused() {
    let registry = Registry::empty().with(
        "https://loop.example/ns",
        json!({ "@context": "https://loop.example/ns" }),
    );
    let document = json!({
        "@context": "https://loop.example/ns",
        "type": "Note",
        "id": "https://remote.example/notes/1"
    });
    assert_eq!(
        expand(&registry, &document),
        Err(Error::CyclicContext("https://loop.example/ns".to_owned()))
    );
}

#[test]
fn a_term_map_referring_to_itself_is_refused() {
    let document = json!({
        "@context": { "a": "b:x", "b": "a:y" },
        "type": "Note",
        "id": "https://remote.example/notes/1"
    });
    assert!(matches!(
        expand(&registry(), &document),
        Err(Error::CyclicContext(_))
    ));
}

#[test]
fn nothing_is_fetched_for_a_context_that_is_not_bundled() {
    // The only guarantee worth stating in a test: an empty registry resolves
    // nothing, so a document naming any IRI at all gets its terms dropped
    // rather than dereferenced.
    let registry = Registry::empty();
    let document = json!({
        "@context": "https://attacker.example/ns",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "content": "hello"
    });
    let expanded = expand(&registry, &document).expect("expand");
    assert_eq!(
        expanded.unresolved_contexts(),
        ["https://attacker.example/ns"]
    );
    // Nothing resolved, so nothing survives -- not even `id` and `type`, which
    // are themselves terms the ActivityStreams context defines as aliases for
    // `@id` and `@type`.
    assert_eq!(expanded.document(), &json!([]));

    // Only the keywords themselves still mean anything without a context.
    let keyworded = json!({
        "@context": "https://attacker.example/ns",
        "@type": "https://www.w3.org/ns/activitystreams#Note",
        "@id": "https://remote.example/notes/1"
    });
    let expanded = expand(&registry, &keyworded).expect("expand");
    assert_eq!(
        expanded.document(),
        &json!([{
            "@id": "https://remote.example/notes/1",
            "@type": ["https://www.w3.org/ns/activitystreams#Note"]
        }])
    );
}
