//! The generated vocabulary, reading documents as other servers write them.

use feder_vocab::{
    Iri, Reference, Registry,
    generated::{
        AnyActor, AnyObject, Create, Follow, Image, LinkOrIri, Note, Person, QuoteRequest,
    },
    json::{ProofPurpose, Text},
    read, write,
};
use serde_json::json;

const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

fn registry() -> Registry {
    Registry::bundled()
}

fn iri(value: &str) -> Iri {
    value.parse().expect("valid IRI")
}

#[test]
fn a_mastodon_create_reads_into_generated_types() {
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
            "inReplyTo": null
        }
    });

    let create = read::<Create>(&registry(), &document)
        .expect("read")
        .into_value();

    assert_eq!(create.tos, vec![AnyObject::Iri(iri(PUBLIC))]);
    assert_eq!(
        create.actors,
        vec![AnyActor::Iri(iri("https://mastodon.example/users/alice"))]
    );
    let [AnyObject::Note(note)] = create.objects.as_slice() else {
        panic!("the object is a Note: {:?}", create.objects);
    };
    assert_eq!(note.content.value.as_deref(), Some("<p>hello</p>"));
    assert_eq!(note.content.languages["ko"], "<p>안녕</p>");
    assert_eq!(note.sensitive, Some(true));
    assert!(note.reply_targets.is_empty());
}

#[test]
fn a_follow_with_an_embedded_actor() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://other.example/follows/1",
        "type": "Follow",
        "actor": {
            "id": "https://other.example/users/bob",
            "type": "Person",
            "inbox": "https://other.example/users/bob/inbox",
            "preferredUsername": "bob"
        },
        "object": "https://feder.example/users/alice"
    });

    let follow = read::<Follow>(&registry(), &document)
        .expect("read")
        .into_value();

    let [AnyActor::Person(person)] = follow.actors.as_slice() else {
        panic!("the actor is a Person: {:?}", follow.actors);
    };
    assert_eq!(person.preferred_username.value.as_deref(), Some("bob"));
    assert_eq!(
        follow.actors[0].id(),
        Some(&iri("https://other.example/users/bob"))
    );
}

#[test]
fn a_prefixed_quote_request_reads_as_its_type() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            {"fep": "https://w3id.org/fep/044f#"}
        ],
        "id": "https://other.example/requests/1",
        "type": "fep:QuoteRequest",
        "actor": "https://other.example/users/bob",
        "object": "https://feder.example/notes/1",
        "instrument": "https://other.example/notes/9"
    });

    let request = read::<QuoteRequest>(&registry(), &document)
        .expect("read")
        .into_value();

    assert_eq!(
        request.instruments,
        vec![AnyObject::Iri(iri("https://other.example/notes/9"))]
    );
}

#[test]
fn a_note_with_an_integrity_proof() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1"
        ],
        "id": "https://other.example/notes/1",
        "type": "Note",
        "content": "signed",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "https://other.example/users/bob#ed25519-key",
            "proofValue": "z3sMTQ"
        }
    });

    let note = read::<Note>(&registry(), &document)
        .expect("read")
        .into_value();

    let [Reference::Object(proof)] = note.proofs.as_slice() else {
        panic!("one embedded proof: {:?}", note.proofs);
    };
    assert_eq!(proof.cryptosuite.as_deref(), Some("eddsa-jcs-2022"));
    assert_eq!(proof.proof_purpose, Some(ProofPurpose::AssertionMethod));
    assert_eq!(proof.proof_value.as_deref(), Some("z3sMTQ"));
    assert_eq!(
        proof.verification_method,
        Some(Reference::Id(iri(
            "https://other.example/users/bob#ed25519-key"
        )))
    );
}

#[test]
fn an_actor_with_keys_and_a_link_for_an_icon() {
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": "https://other.example/users/bob",
        "type": "Person",
        "inbox": "https://other.example/users/bob/inbox",
        "publicKey": {
            "id": "https://other.example/users/bob#main-key",
            "owner": "https://other.example/users/bob",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
        },
        "assertionMethod": [{
            "id": "https://other.example/users/bob#ed25519-key",
            "type": "Multikey",
            "controller": "https://other.example/users/bob",
            "publicKeyMultibase": "z6MkabcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTU"
        }],
        "icon": {"type": "Link", "href": "https://other.example/avatar.png"}
    });

    let person = read::<Person>(&registry(), &document)
        .expect("read")
        .into_value();

    let [Reference::Object(key)] = person.public_keys.as_slice() else {
        panic!("one embedded key: {:?}", person.public_keys);
    };
    assert!(
        key.public_key
            .as_deref()
            .is_some_and(|pem| pem.starts_with("-----BEGIN"))
    );
    let [Reference::Object(multikey)] = person.assertion_methods.as_slice() else {
        panic!("one embedded Multikey: {:?}", person.assertion_methods);
    };
    assert!(
        multikey
            .public_key
            .as_deref()
            .is_some_and(|key| key.starts_with("z6Mk"))
    );
    // A Link where an Image is expected is read as an Image of its href.
    let [Reference::Object(icon)] = person.icons.as_slice() else {
        panic!("the icon is an Image: {:?}", person.icons);
    };
    assert_eq!(
        icon.urls,
        vec![LinkOrIri::Iri(iri("https://other.example/avatar.png"))]
    );
}

#[test]
fn a_type_no_schema_describes_is_kept() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://other.example/activities/1",
        "type": "Create",
        "actor": "https://other.example/users/bob",
        "object": {"id": "https://other.example/things/1", "type": "Thing", "name": "?"}
    });

    let create = read::<Create>(&registry(), &document)
        .expect("read")
        .into_value();

    let [AnyObject::Other(other)] = create.objects.as_slice() else {
        panic!("kept as it was: {:?}", create.objects);
    };
    assert_eq!(other["type"], "Thing");
}

#[test]
fn the_wrong_type_is_an_error() {
    let document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://other.example/likes/1",
        "type": "Like"
    });

    assert!(read::<Follow>(&registry(), &document).is_err());
}

#[test]
fn what_feder_writes_reads_back_the_same() {
    let note = Note {
        id: Some(iri("https://feder.example/notes/1")),
        content: Text {
            value: Some("hi".into()),
            languages: [("en".into(), "hi".into())].into(),
        },
        tos: vec![AnyObject::Iri(iri(PUBLIC))],
        icons: vec![Reference::object(Image {
            urls: vec![LinkOrIri::Iri(iri("https://feder.example/a.png"))],
            ..Image::default()
        })],
        ..Note::default()
    };

    let written = write(&note);
    assert_eq!(written["type"], "Note");
    assert_eq!(written["contentMap"], json!({"en": "hi"}));
    assert_eq!(written["to"], json!(PUBLIC));

    let read_back = read::<Note>(&registry(), &written)
        .expect("read")
        .into_value();
    assert_eq!(read_back, note);

    // Without the context, as `Serialize` writes an embedded object.
    let embedded = serde_json::to_value(&note).expect("serialize");
    assert!(embedded.get("@context").is_none());
    let deserialized: Note = serde_json::from_value(embedded).expect("deserialize");
    assert_eq!(deserialized, note);
}
