//! What this crate is for: reading documents from the servers feder has to
//! talk to, whatever spelling they arrived in.
//!
//! The documents here are modelled on real captures — a Mastodon actor with
//! its inline term map, a Mitra/Fedify actor carrying Multikeys, a litepub
//! note — rather than on what the specification would let a server send.

use feder_jsonld::{Registry, expand, normalize};
use serde_json::{Value, json};

const AS: &str = "https://www.w3.org/ns/activitystreams#";
const SEC: &str = "https://w3id.org/security#";
const TOOT: &str = "http://joinmastodon.org/ns#";

fn registry() -> Registry {
    Registry::bundled()
}

/// The single expanded node of a document.
fn node(document: &Value) -> &Value {
    &document.as_array().expect("expanded form is an array")[0]
}

/// The first value of an expanded property.
fn first<'a>(node: &'a Value, iri: &str) -> &'a Value {
    &node[iri].as_array().expect("expanded property is an array")[0]
}

#[test]
fn bundled_contexts_all_parse() {
    let registry = registry();
    assert!(registry.known_iris().len() >= 11);
    for iri in [
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
        "https://w3id.org/security/data-integrity/v1",
        "https://w3id.org/security/multikey/v1",
        "https://www.w3.org/ns/did/v1",
        "https://www.w3.org/ns/cid/v1",
        "https://gotosocial.org/ns",
        "https://litepub.social/litepub/context.jsonld",
        "https://purl.archive.org/socialweb/webfinger",
        "https://join-lemmy.org/context.json",
        "http://joinmastodon.org/ns",
    ] {
        assert!(
            registry.known_iris().iter().any(|known| known == iri),
            "{iri} is not bundled"
        );
    }
}

/// A Mastodon actor, with the `@context` Mastodon actually emits.
fn mastodon_actor() -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
            {
                "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
                "toot": "http://joinmastodon.org/ns#",
                "featured": { "@id": "toot:featured", "@type": "@id" },
                "alsoKnownAs": { "@id": "as:alsoKnownAs", "@type": "@id" },
                "schema": "http://schema.org#",
                "PropertyValue": "schema:PropertyValue",
                "value": "schema:value",
                "discoverable": "toot:discoverable",
                "suspended": "toot:suspended"
            }
        ],
        "id": "https://academy.example/users/brauca",
        "type": "Person",
        "inbox": "https://academy.example/users/brauca/inbox",
        "outbox": "https://academy.example/users/brauca/outbox",
        "featured": "https://academy.example/users/brauca/collections/featured",
        "preferredUsername": "brauca",
        "name": "Brauca Darradiul",
        "manuallyApprovesFollowers": false,
        "discoverable": false,
        "published": "2024-09-12T00:00:00Z",
        "publicKey": {
            "id": "https://academy.example/users/brauca#main-key",
            "owner": "https://academy.example/users/brauca",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"
        }
    })
}

#[test]
fn mastodon_actor_expands_to_the_iris_it_means() {
    let expanded = expand(&registry(), &mastodon_actor()).expect("expand");
    let node = node(expanded.document());

    assert_eq!(node["@id"], json!("https://academy.example/users/brauca"));
    assert_eq!(node["@type"], json!([format!("{AS}Person")]));

    // An ActivityStreams term, an aliased one, and a `toot:` compact IRI all
    // land on the IRI they stand for.
    assert_eq!(
        first(node, &format!("{AS}preferredUsername"))["@value"],
        json!("brauca")
    );
    assert_eq!(
        first(node, &format!("{AS}manuallyApprovesFollowers"))["@value"],
        json!(false)
    );
    assert_eq!(
        first(node, &format!("{TOOT}discoverable"))["@value"],
        json!(false)
    );

    // `featured` is `@type: "@id"`, so its string value is an IRI, not a
    // string: a reader must not compare it to text.
    assert_eq!(
        first(node, &format!("{TOOT}featured"))["@id"],
        json!("https://academy.example/users/brauca/collections/featured")
    );

    // `inbox` comes from ActivityPub's own `ldp:` term, not from `as:`.
    assert_eq!(
        first(node, "http://www.w3.org/ns/ldp#inbox")["@id"],
        json!("https://academy.example/users/brauca/inbox")
    );

    // The key is an embedded node, and `publicKeyPem` is a `sec:` term.
    let key = first(node, &format!("{SEC}publicKey"));
    assert_eq!(
        key["@id"],
        json!("https://academy.example/users/brauca#main-key")
    );
    assert!(
        first(key, &format!("{SEC}publicKeyPem"))["@value"]
            .as_str()
            .expect("pem is a string")
            .starts_with("-----BEGIN")
    );
}

#[test]
fn the_same_statement_spelled_three_ways_reads_the_same() {
    let registry = registry();
    let plain = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "content": "hello"
    });
    let compact_iri = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "as:content": "hello"
    });
    let aliased = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            { "body": "as:content", "kind": "@type", "iri": "@id" }
        ],
        "kind": "Note",
        "iri": "https://remote.example/notes/1",
        "body": "hello"
    });

    let expanded: Vec<Value> = [&plain, &compact_iri, &aliased]
        .iter()
        .map(|document| expand(&registry, document).expect("expand").into_document())
        .collect();
    assert_eq!(expanded[0], expanded[1]);
    assert_eq!(expanded[1], expanded[2]);

    // And each comes back in feder's own spelling, keyword aliases undone.
    for document in [&plain, &compact_iri, &aliased] {
        let normalized = normalize(&registry, document).expect("normalize");
        assert_eq!(normalized.document()["type"], json!("Note"));
        assert_eq!(normalized.document()["content"], json!("hello"));
        assert_eq!(
            normalized.document()["id"],
            json!("https://remote.example/notes/1")
        );
    }
}

#[test]
fn a_term_activitystreams_never_defined_is_a_blank_node() {
    // The ActivityStreams context does not define `sensitive`,
    // `manuallyApprovesFollowers` or `Hashtag`, which is why Mastodon inlines
    // all three in every document it sends. Under the bare context they fall
    // through to `@vocab`, which ActivityStreams sets to the blank-node prefix
    // `_:` — so they expand to something that is visibly not an ActivityStreams
    // property, rather than silently to one.
    let registry = registry();
    let bare = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://naive.example/notes/1",
        "sensitive": true
    });
    let declared = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            { "sensitive": "as:sensitive" }
        ],
        "type": "Note",
        "id": "https://mastodon.example/notes/1",
        "sensitive": true
    });

    let bare_node = expand(&registry, &bare).expect("expand").into_document();
    assert!(bare_node[0].get("_:sensitive").is_some());
    assert!(bare_node[0].get(format!("{AS}sensitive")).is_none());

    let declared_node = expand(&registry, &declared)
        .expect("expand")
        .into_document();
    assert!(declared_node[0].get(format!("{AS}sensitive")).is_some());

    // Compaction is deliberately more forgiving than expansion: both come back
    // spelled `sensitive`, because dropping a key over a context the sender
    // forgot to declare would lose a statement they plainly meant to make.
    for document in [&bare, &declared] {
        let normalized = normalize(&registry, document).expect("normalize");
        assert_eq!(normalized.document()["sensitive"], json!(true));
    }
}

/// A Mitra/Fedify-shaped actor: verification methods as Multikeys, whose terms
/// come from a context scoped to the `Multikey` type.
fn multikey_actor() -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/v1",
            "https://w3id.org/security/data-integrity/v1",
            "https://w3id.org/security/multikey/v1",
            { "toot": "http://joinmastodon.org/ns#", "featured": "toot:featured" }
        ],
        "id": "https://wizard.example/users/hong",
        "type": "Person",
        "preferredUsername": "hong",
        "assertionMethod": [{
            "id": "https://wizard.example/users/hong#ed25519-key",
            "type": "Multikey",
            "controller": "https://wizard.example/users/hong",
            "publicKeyMultibase": "z6MkweqJajqa5jRAJTBVxxu47oCdB7HzmYbBKN8VGbFJmKkC"
        }]
    })
}

#[test]
fn a_type_scoped_context_is_what_gives_multikey_its_terms() {
    let expanded = expand(&registry(), &multikey_actor()).expect("expand");
    let node = node(expanded.document());

    let method = first(node, &format!("{SEC}assertionMethod"));
    assert_eq!(method["@type"], json!([format!("{SEC}Multikey")]));
    assert_eq!(
        first(method, &format!("{SEC}publicKeyMultibase"))["@value"],
        json!("z6MkweqJajqa5jRAJTBVxxu47oCdB7HzmYbBKN8VGbFJmKkC")
    );
    assert_eq!(
        first(method, &format!("{SEC}controller"))["@id"],
        json!("https://wizard.example/users/hong")
    );
}

#[test]
fn without_the_type_the_scoped_terms_do_not_apply() {
    // The same document with `Multikey` removed. `publicKeyMultibase` is
    // defined *only* inside that type's scoped context, so it must now fail to
    // resolve rather than quietly expanding as if it had.
    let mut document = multikey_actor();
    document["assertionMethod"][0]["type"] = json!("Person");

    let expanded = expand(&registry(), &document).expect("expand");
    let node = node(expanded.document());
    let method = first(node, &format!("{SEC}assertionMethod"));

    assert!(method.get(format!("{SEC}publicKeyMultibase")).is_none());
    // It falls back to the ActivityStreams `@vocab`, which is the blank-node
    // prefix: an unrecognised term, visibly so.
    assert!(method.get("_:publicKeyMultibase").is_some());
}

#[test]
fn integrity_proof_fields_expand_under_their_scoped_context() {
    // FEP-8b32, which is what feder-runtime verifies. `proofValue` and
    // `cryptosuite` are defined by the context scoped to `DataIntegrityProof`.
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1"
        ],
        "id": "https://remote.example/activities/1",
        "type": "Create",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "https://remote.example/users/bob#ed25519-key",
            "proofValue": "z3sMTQ"
        }
    });

    let expanded = expand(&registry(), &document).expect("expand");
    let node = node(expanded.document());
    let proof = first(node, &format!("{SEC}proof"));

    assert_eq!(proof["@type"], json!([format!("{SEC}DataIntegrityProof")]));
    assert_eq!(
        first(proof, &format!("{SEC}cryptosuite"))["@value"],
        json!("eddsa-jcs-2022")
    );
    assert_eq!(
        first(proof, &format!("{SEC}proofValue"))["@value"],
        json!("z3sMTQ")
    );
    assert_eq!(
        first(proof, &format!("{SEC}verificationMethod"))["@id"],
        json!("https://remote.example/users/bob#ed25519-key")
    );
    // `proofPurpose` is `@type: "@vocab"`, so its value is an IRI too.
    assert_eq!(
        first(proof, &format!("{SEC}proofPurpose"))["@id"],
        json!(format!("{SEC}assertionMethod"))
    );
    // `created` carries the xsd datatype its term coerces to.
    assert_eq!(
        first(proof, "http://purl.org/dc/terms/created")["@type"],
        json!("http://www.w3.org/2001/XMLSchema#dateTime")
    );
}

#[test]
fn an_integrity_proof_normalises_back_to_the_terms_it_was_written_in() {
    // Compaction has to apply the same type-scoped context expansion did, or a
    // proof comes back as `sec:proofValue` wrapped in a typed value object,
    // which is the same statement in a shape no reader expects.
    let proof = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://remote.example/users/bob#ed25519-key",
        "proofValue": "z3sMTQ"
    });
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1"
        ],
        "id": "https://remote.example/activities/1",
        "type": "Create",
        "proof": proof
    });

    let normalized = normalize(&registry(), &document).expect("normalize");

    assert_eq!(normalized.document()["proof"], proof);
}

#[test]
fn a_term_may_be_defined_before_the_prefix_it_uses() {
    // litepub's context defines `"Emoji": "toot:Emoji"` several lines above
    // `"toot"`. A term map is a set, not a sequence, so key order must not
    // decide whether this resolves.
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            { "Emoji": "toot:Emoji", "toot": "http://joinmastodon.org/ns#" }
        ],
        "id": "https://pleroma.example/emoji/1",
        "type": "Emoji"
    });
    let expanded = expand(&registry(), &document).expect("expand");
    assert_eq!(
        node(expanded.document())["@type"],
        json!([format!("{TOOT}Emoji")])
    );
}

#[test]
fn litepub_and_lemmy_documents_resolve_from_the_bundle() {
    let registry = registry();

    let litepub = json!({
        "@context": "https://litepub.social/litepub/context.jsonld",
        "id": "https://akkoma.example/notes/1",
        "type": "Note",
        "content": "hi",
        "sensitive": true,
        "conversation": "https://akkoma.example/contexts/1"
    });
    let expanded = expand(&registry, &litepub).expect("expand litepub");
    assert!(expanded.unresolved_contexts().is_empty());
    let litepub_node = node(expanded.document());
    assert_eq!(
        first(litepub_node, &format!("{AS}sensitive"))["@value"],
        json!(true)
    );
    assert_eq!(
        first(litepub_node, "http://ostatus.org#conversation")["@id"],
        json!("https://akkoma.example/contexts/1")
    );

    let lemmy = json!({
        "@context": "https://join-lemmy.org/context.json",
        "id": "https://lemmy.example/c/rust",
        "type": "Group",
        "postingRestrictedToMods": false
    });
    let expanded = expand(&registry, &lemmy).expect("expand lemmy");
    assert!(expanded.unresolved_contexts().is_empty());
    assert_eq!(
        first(
            node(expanded.document()),
            "https://join-lemmy.org/ns#postingRestrictedToMods"
        )["@value"],
        json!(false)
    );
}

#[test]
fn an_unshipped_context_is_reported_rather_than_fatal() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://example.invalid/ns/whatever"
        ],
        "id": "https://remote.example/notes/1",
        "type": "Note",
        "content": "hello",
        "somethingNobodyShips": "value"
    });

    let expanded = expand(&registry(), &document).expect("expand");
    assert_eq!(
        expanded.unresolved_contexts(),
        ["https://example.invalid/ns/whatever"]
    );
    // What the document says in terms feder knows is still read.
    assert_eq!(
        first(node(expanded.document()), &format!("{AS}content"))["@value"],
        json!("hello")
    );
}
