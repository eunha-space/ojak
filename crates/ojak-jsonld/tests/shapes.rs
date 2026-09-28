//! Containers and value shapes: the parts of a document where JSON-LD decides
//! whether something is one value or a list of them, and in what language.

use ojak_jsonld::{Registry, expand, normalize};
use serde_json::json;

const AS: &str = "https://www.w3.org/ns/activitystreams#";
const TOOT: &str = "http://joinmastodon.org/ns#";

fn registry() -> Registry {
    Registry::bundled()
}

#[test]
fn a_language_map_becomes_language_tagged_values_and_back() {
    let registry = registry();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "contentMap": { "en": "hello", "ko": "안녕하세요" }
    });

    // `content` and `contentMap` are one property; the map form only says what
    // language each value is in.
    let expanded = expand(&registry, &document).expect("expand");
    let content = expanded.document()[0][format!("{AS}content")]
        .as_array()
        .expect("content is an array");
    assert_eq!(content.len(), 2);
    assert!(content.contains(&json!({ "@value": "hello", "@language": "en" })));
    assert!(content.contains(&json!({ "@value": "안녕하세요", "@language": "ko" })));

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["contentMap"],
        json!({ "en": "hello", "ko": "안녕하세요" })
    );
    assert!(normalized.document().get("content").is_none());
}

#[test]
fn tagged_and_untagged_values_of_one_property_share_a_term() {
    // A deliberate simplification. JSON-LD compaction may split one property
    // across two terms, putting the untagged value under `content` and the
    // tagged ones under `contentMap`. Ojak picks one term for the property
    // and writes every value under it: still valid JSON-LD, and every reader
    // gets every value, but less idiomatic than what Mastodon emits.
    let registry = registry();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "content": "hello",
        "contentMap": { "ko": "안녕하세요" }
    });

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["content"],
        json!(["hello", { "@value": "안녕하세요", "@language": "ko" }])
    );
    assert!(normalized.document().get("contentMap").is_none());
}

#[test]
fn an_ordered_collection_keeps_its_order() {
    let registry = registry();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "OrderedCollection",
        "id": "https://remote.example/outbox",
        "orderedItems": [
            "https://remote.example/notes/3",
            "https://remote.example/notes/1",
            "https://remote.example/notes/2"
        ]
    });

    // `orderedItems` is `as:items` with `@container: @list`: the order is part
    // of what the document says, and a set would lose it.
    let expanded = expand(&registry, &document).expect("expand");
    let items = &expanded.document()[0][format!("{AS}items")][0]["@list"];
    assert_eq!(
        items,
        &json!([
            { "@id": "https://remote.example/notes/3" },
            { "@id": "https://remote.example/notes/1" },
            { "@id": "https://remote.example/notes/2" }
        ])
    );

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["orderedItems"],
        json!([
            "https://remote.example/notes/3",
            "https://remote.example/notes/1",
            "https://remote.example/notes/2"
        ]),
        "a list must not come back reordered or renested"
    );
}

#[test]
fn a_focal_point_is_a_list_of_two_numbers() {
    let registry = registry();
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {
                "toot": "http://joinmastodon.org/ns#",
                "focalPoint": { "@container": "@list", "@id": "toot:focalPoint" }
            }
        ],
        "type": "Image",
        "id": "https://remote.example/media/1",
        "focalPoint": [-0.55, 0.43]
    });

    let expanded = expand(&registry, &document).expect("expand");
    assert_eq!(
        expanded.document()[0][format!("{TOOT}focalPoint")][0]["@list"],
        json!([{ "@value": -0.55 }, { "@value": 0.43 }])
    );

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(normalized.document()["focalPoint"], json!([-0.55, 0.43]));
}

#[test]
fn a_set_container_keeps_its_array_around_one_value() {
    // `attributionDomains` is `@container: @set`, so a single domain is still
    // an array. A reader that expects a list must get one.
    let registry = registry();
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {
                "toot": "http://joinmastodon.org/ns#",
                "attributionDomains": { "@id": "toot:attributionDomains", "@container": "@set" }
            }
        ],
        "type": "Person",
        "id": "https://remote.example/users/alice",
        "attributionDomains": ["example.com"]
    });

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["attributionDomains"],
        json!(["example.com"])
    );
}

#[test]
fn one_value_loses_its_array_unless_the_term_asked_for_one() {
    let registry = registry();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "cc": [
            "https://remote.example/users/alice/followers",
            "https://remote.example/users/bob"
        ]
    });

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["to"],
        json!("https://www.w3.org/ns/activitystreams#Public")
    );
    assert_eq!(
        normalized.document()["cc"],
        json!([
            "https://remote.example/users/alice/followers",
            "https://remote.example/users/bob"
        ])
    );
}

#[test]
fn a_typed_value_keeps_the_type_its_term_does_not_imply() {
    let registry = registry();
    // `published` is coerced to `xsd:dateTime` by the term, so the value is a
    // plain string on the wire. `startTime` is too — but a value typed as
    // something the term does not imply has to keep saying so.
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://remote.example/notes/1",
        "published": "2026-05-29T06:30:00Z",
        "summary": { "@value": "text/markdown", "@type": "http://www.w3.org/2001/XMLSchema#string" }
    });

    let normalized = normalize(&registry, &document).expect("normalize");
    assert_eq!(
        normalized.document()["published"],
        json!("2026-05-29T06:30:00Z")
    );
    assert_eq!(
        normalized.document()["summary"],
        json!({ "@value": "text/markdown", "@type": "xsd:string" })
    );
}

#[test]
fn a_ojak_shaped_document_survives_a_round_trip() {
    // What ojak itself emits has to come back unchanged, or normalising
    // inbound traffic would quietly rewrite ojak's own activities.
    let registry = registry();
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Create",
        "id": "https://ojak.example/activities/create/1",
        "actor": "https://ojak.example/users/alice",
        "to": "https://www.w3.org/ns/activitystreams#Public",
        "cc": "https://ojak.example/users/alice/followers",
        "object": {
            "type": "Note",
            "id": "https://ojak.example/notes/1",
            "attributedTo": "https://ojak.example/users/alice",
            "content": "Hello, fediverse.",
            "published": "2026-05-29T06:30:00Z",
            "inReplyTo": "https://remote.example/notes/9",
            "url": "https://ojak.example/@alice/1"
        }
    });

    let normalized = normalize(&registry, &document).expect("normalize");
    let result = normalized.document();
    assert_eq!(result["type"], json!("Create"));
    assert_eq!(result["actor"], json!("https://ojak.example/users/alice"));
    assert_eq!(result["object"]["type"], json!("Note"));
    assert_eq!(result["object"]["content"], json!("Hello, fediverse."));
    assert_eq!(
        result["object"]["inReplyTo"],
        json!("https://remote.example/notes/9")
    );
    assert_eq!(
        result["object"]["url"],
        json!("https://ojak.example/@alice/1")
    );
    // The embedded object does not grow a `@context` of its own.
    assert!(result["object"].get("@context").is_none());
}

#[test]
fn a_quote_authorization_reads_the_same_from_gotosocial_and_mastodon() {
    // Ojak emits FEP-044f quote authorizations with Mastodon's inline terms;
    // GoToSocial sends the same statement through its own hosted context.
    let registry = registry();
    let mastodon_shaped = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {
                "gts": "https://gotosocial.org/ns#",
                "QuoteAuthorization": "https://w3id.org/fep/044f#QuoteAuthorization",
                "interactingObject": { "@id": "gts:interactingObject", "@type": "@id" },
                "interactionTarget": { "@id": "gts:interactionTarget", "@type": "@id" }
            }
        ],
        "type": "QuoteAuthorization",
        "id": "https://b.example/notes/9/approvals/1",
        "attributedTo": "https://b.example/users/bob",
        "interactingObject": "https://a.example/notes/1",
        "interactionTarget": "https://b.example/notes/9"
    });
    let gotosocial_shaped = json!({
        "@context": ["https://www.w3.org/ns/activitystreams", "https://gotosocial.org/ns"],
        "type": "QuoteAuthorization",
        "id": "https://b.example/notes/9/approvals/1",
        "attributedTo": "https://b.example/users/bob",
        "interactingObject": "https://a.example/notes/1",
        "interactionTarget": "https://b.example/notes/9"
    });

    let mastodon = expand(&registry, &mastodon_shaped).expect("expand");
    let gotosocial = expand(&registry, &gotosocial_shaped).expect("expand");

    // The properties agree. The *type* does not, and that is the finding:
    // GoToSocial's hosted context maps `QuoteAuthorization` into its own
    // namespace, while Mastodon maps it to FEP-044f's.
    let gts = "https://gotosocial.org/ns#";
    for property in [
        format!("{gts}interactingObject"),
        format!("{gts}interactionTarget"),
    ] {
        assert_eq!(
            mastodon.document()[0][&property],
            gotosocial.document()[0][&property],
            "{property} differs"
        );
    }
    assert_eq!(
        mastodon.document()[0]["@type"],
        json!(["https://w3id.org/fep/044f#QuoteAuthorization"])
    );
    assert_eq!(
        gotosocial.document()[0]["@type"],
        json!([format!("{gts}QuoteAuthorization")])
    );
}
