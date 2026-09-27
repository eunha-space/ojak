//! Reading documents as other servers write them, through `feder_vocab::read`.

use feder_vocab::json::Text;
use feder_vocab::{
    AnyActor, AnyObject, Create, Follow, Iri, Note, QuoteRequest, ReadError, Registry, read, write,
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

    let create = read::<Create>(&registry(), &document)
        .expect("read")
        .into_value();

    assert_eq!(create.tos, vec![AnyObject::Iri(public())]);
    assert_eq!(create.ccs.len(), 1);
    let [AnyObject::Note(note)] = create.objects.as_slice() else {
        panic!("the note is embedded: {:?}", create.objects);
    };
    assert_eq!(note.content.value.as_deref(), Some("<p>hello</p>"));
    assert_eq!(note.content.languages["ko"], "<p>안녕</p>");
    assert_eq!(note.content.languages["en"], "<p>hello</p>");
    assert_eq!(note.sensitive, Some(true));
    assert_eq!(note.tos, vec![AnyObject::Iri(public())]);
    assert!(note.reply_targets.is_empty());
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
    assert_eq!(note.content.value.as_deref(), Some("text"));
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

    assert_eq!(note.content.value, None);
    assert_eq!(note.content.languages["ja"], "こんにちは");
}

/// A note Feder writes with languages reads back as the same note.
#[test]
fn a_note_with_languages_round_trips_through_read() {
    let mut content = Text::plain("hi");
    content.languages.insert("en".into(), "hi".into());
    let mut summary = Text::default();
    summary.languages.insert("en".into(), "cw".into());
    let note = Note {
        id: Some("https://feder.example/notes/1".parse().unwrap()),
        content,
        summary,
        tos: vec![AnyObject::Iri(public())],
        ..Note::default()
    };

    let written = write(&note);
    assert_eq!(written["contentMap"], json!({"en": "hi"}));
    assert_eq!(written["summaryMap"], json!({"en": "cw"}));

    let read_back = read::<Note>(&registry(), &written)
        .expect("read")
        .into_value();
    assert_eq!(read_back, note);
}

/// A consent request is recognised by the IRI its type names, however the
/// sender abbreviated it, and written back under a context that names it.
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

        let request = read::<QuoteRequest>(&registry(), &document)
            .unwrap_or_else(|error| panic!("read {kind}: {error}"))
            .into_value();

        assert_eq!(request.objects.len(), 1, "{kind}");
        // Written back under Feder's context, which names the type.
        let written = write(&request);
        assert_eq!(written["type"], "QuoteRequest", "{kind}");
        let read_again = read::<QuoteRequest>(&registry(), &written).expect("read again");
        assert_eq!(read_again.into_value(), request, "{kind}");
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

    let [AnyActor::Person(actor)] = follow.actors.as_slice() else {
        panic!("the actor is embedded: {:?}", follow.actors);
    };
    assert_eq!(actor.name.languages["en"], "Bob");
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

/// A portable actor (FEP-ef61): its `ap` URIs are not RFC 3986 URIs, since
/// the DID puts colons in the authority, and are read all the same, with its
/// gateways, and written back as they came.
#[test]
fn a_portable_actor_reads_its_ap_uris_and_gateways() {
    let did = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1",
            "https://w3id.org/fep/ef61"
        ],
        "type": "Person",
        "id": format!("ap://{did}/actor"),
        "inbox": format!("ap://{did}/actor/inbox"),
        "outbox": format!("ap://{did}/actor/outbox"),
        "gateways": ["https://server1.example", "https://server2.example"]
    });

    let read = feder_vocab::read_reporting::<AnyActor>(&registry(), &document).expect("read");
    assert!(read.lost().is_empty(), "{:?}", read.lost());
    assert!(read.unresolved_contexts().is_empty());
    let AnyActor::Person(person) = read.into_value() else {
        panic!("not a person");
    };
    let id = person.id.as_ref().expect("the id is kept");
    assert_eq!(decoded(id.as_str()), format!("ap://{did}/actor"));
    assert_eq!(
        person
            .gateways
            .iter()
            .map(|gateway| gateway.as_str())
            .collect::<Vec<_>>(),
        ["https://server1.example", "https://server2.example"]
    );
    let written = write(&*person);
    assert_eq!(written["id"], format!("ap://{did}/actor"));
    assert_eq!(written["inbox"], format!("ap://{did}/actor/inbox"));
}

fn decoded(encoded: &str) -> String {
    encoded.replace("%3A", ":")
}
