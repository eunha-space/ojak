//! Reading documents as other servers write them, through `feder_vocab::read`.

use feder_vocab::{
    ConsentRequest, Create, Follow, Iri, Note, ReadError, Reference, Registry, RequestType, read,
};
use serde_json::{Value, json};

const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

fn public() -> Iri {
    PUBLIC.parse().expect("valid IRI")
}

fn registry() -> Registry {
    Registry::bundled()
}

/// A Mastodon `Create`: a one-element `to`, `sensitive` defined in the
/// document's own context, and `content` beside `contentMap`.
#[test]
fn a_mastodon_create_reads_into_typed_fields() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {"sensitive": "as:sensitive", "toot": "http://joinmastodon.org/ns#"}
        ],
        "id": "https://mastodon.example/users/alice/statuses/1/activity",
        "type": "Create",
        "actor": "https://mastodon.example/users/alice",
        "to": [PUBLIC],
        "cc": ["https://mastodon.example/users/alice/followers"],
        "object": {
            "id": "https://mastodon.example/users/alice/statuses/1",
            "type": "Note",
            "attributedTo": "https://mastodon.example/users/alice",
            "content": "<p>hello</p>",
            "contentMap": {"en": "<p>hello</p>", "ko": "<p>안녕</p>"},
            "sensitive": true,
            "to": [PUBLIC],
            "cc": ["https://mastodon.example/users/alice/followers"],
            "inReplyTo": null
        }
    });

    let create = read::<Create<Note>>(&registry(), &document)
        .expect("read")
        .into_value();

    assert_eq!(create.to, vec![public()]);
    assert_eq!(create.cc.len(), 1);
    let Reference::Object(note) = create.object else {
        panic!("the note is embedded");
    };
    assert_eq!(note.content.as_deref(), Some("<p>hello</p>"));
    assert_eq!(note.content_map["ko"], "<p>안녕</p>");
    assert_eq!(note.content_map["en"], "<p>hello</p>");
    assert_eq!(note.sensitive, Some(true));
    assert_eq!(note.to, vec![public()]);
    assert_eq!(note.in_reply_to, None);
}

/// The same property under a spelling Feder never uses, which a reader that
/// matched on keys would drop.
#[test]
fn an_aliased_property_arrives_in_its_field() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {"nsfw": "as:sensitive", "body": "as:content"}
        ],
        "id": "https://other.example/notes/1",
        "type": "Note",
        "nsfw": true,
        "body": "text"
    });

    let note = read::<Note>(&registry(), &document)
        .expect("read")
        .into_value();

    assert_eq!(note.sensitive, Some(true));
    assert_eq!(note.content.as_deref(), Some("text"));
}

/// Text that only has language-tagged values has no untagged one to invent.
#[test]
fn text_with_only_languages_leaves_the_plain_value_empty() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://other.example/notes/2",
        "type": "Note",
        "contentMap": {"ja": "こんにちは"}
    });

    let note = read::<Note>(&registry(), &document)
        .expect("read")
        .into_value();

    assert_eq!(note.content, None);
    assert_eq!(note.content_map["ja"], "こんにちは");
}

/// A note Feder writes with languages reads back as the same note.
#[test]
fn a_note_with_languages_round_trips_through_read() {
    let mut note = Note::new("https://feder.example/notes/1".parse().unwrap());
    note.content = Some("hi".into());
    note.content_map.insert("en".into(), "hi".into());
    note.summary_map.insert("en".into(), "cw".into());
    note.to = vec![public()];

    let written = serde_json::to_value(&note).expect("serialize");
    assert_eq!(written["contentMap"], json!({"en": "hi"}));
    assert_eq!(written["summaryMap"], json!({"en": "cw"}));

    let mut read_back = read::<Note>(&registry(), &written)
        .expect("read")
        .into_value();
    read_back.context = note.context.clone();
    assert_eq!(read_back, note);
}

/// A consent request is recognised by the IRI its type names, however the
/// sender abbreviated it, and is written back with the context its type needs.
#[test]
fn a_quote_request_is_recognised_by_iri() {
    for (context, kind) in [
        (
            json!({"QuoteRequest": "https://w3id.org/fep/044f#QuoteRequest"}),
            "QuoteRequest",
        ),
        (
            json!({"fep": "https://w3id.org/fep/044f#"}),
            "fep:QuoteRequest",
        ),
        (
            json!({"QR": "https://w3id.org/fep/044f#QuoteRequest"}),
            "QR",
        ),
    ] {
        let document = json!({
            "@context": ["https://www.w3.org/ns/activitystreams", context],
            "id": "https://other.example/requests/1",
            "type": kind,
            "actor": "https://other.example/users/bob",
            "object": "https://feder.example/notes/1",
            "instrument": "https://other.example/notes/9"
        });

        let request = read::<ConsentRequest>(&registry(), &document)
            .unwrap_or_else(|error| panic!("read {kind}: {error}"))
            .into_value();

        assert_eq!(request.kind, RequestType::QuoteRequest, "{kind}");
        let written = serde_json::to_value(&request).expect("serialize");
        assert_eq!(
            written["@context"][1]["QuoteRequest"], "https://w3id.org/fep/044f#QuoteRequest",
            "{kind}"
        );
    }
}

/// A follow whose actor is embedded rather than referenced.
#[test]
fn an_embedded_actor_reads_as_an_object() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://other.example/follows/1",
        "type": "Follow",
        "actor": {
            "id": "https://other.example/users/bob",
            "type": "Person",
            "inbox": "https://other.example/users/bob/inbox",
            "outbox": "https://other.example/users/bob/outbox",
            "nameMap": {"en": "Bob"}
        },
        "object": "https://feder.example/users/alice"
    });

    let follow = read::<Follow>(&registry(), &document)
        .expect("read")
        .into_value();

    let Reference::Object(actor) = follow.actor else {
        panic!("the actor is embedded");
    };
    assert_eq!(actor.name_map["en"], "Bob");
}

/// A context Feder does not ship is reported. Its terms are not resolved:
/// ActivityStreams' `@vocab` keeps an undefined key under the sender's own
/// spelling, which no field of Feder's types matches.
#[test]
fn an_unknown_context_is_reported_and_its_terms_left_unresolved() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://unknown.example/ns"
        ],
        "id": "https://other.example/notes/3",
        "type": "Note",
        "content": "kept",
        "unknownTerm": "unresolved"
    });

    let read = read::<Value>(&registry(), &document).expect("read");

    assert_eq!(read.unresolved_contexts(), ["https://unknown.example/ns"]);
    assert_eq!(read.value()["content"], "kept");
    assert_eq!(read.value()["unknownTerm"], "unresolved");
}

/// `@graph` lets one graph be written as trees that say different things, so a
/// document using it is refused rather than read.
#[test]
fn a_document_using_graph_is_refused() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "@graph": [{"id": "https://other.example/notes/4", "type": "Note"}]
    });

    assert!(matches!(
        read::<Value>(&registry(), &document),
        Err(ReadError::JsonLd(_))
    ));
}

/// A document of another type is a shape error, not a silent default.
#[test]
fn the_wrong_type_is_a_shape_error() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://other.example/likes/1",
        "type": "Like",
        "actor": "https://other.example/users/bob",
        "object": "https://feder.example/notes/1"
    });

    assert!(matches!(
        read::<Follow>(&registry(), &document),
        Err(ReadError::Shape(_))
    ));
}
