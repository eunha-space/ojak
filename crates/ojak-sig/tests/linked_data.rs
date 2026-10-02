//! `RsaSignature2017`, held to what Mastodon makes: the vectors in
//! *fixtures/rsa-signature-2017/mastodon.json* were signed and canonicalised
//! by Mastodon's own code path (see `make.rb` beside them).

use ojak_jsonld::Registry;
use ojak_sig::Error;
use ojak_sig::PrivateKey;
use ojak_sig::linked_data::{self, creator, sign, verify};
use serde_json::{Value, json};

const KEY: &str = include_str!("fixtures/rsa-signature-2017/key.pem");
const VECTORS: &str = include_str!("fixtures/rsa-signature-2017/mastodon.json");

/// 2026-10-02T00:00:00Z, between the vectors' `created` and `expires`.
const NOW: i64 = 1_790_899_200;
const CREATED: i64 = 1_790_856_000;
const EXPIRES: i64 = CREATED + linked_data::DEFAULT_LIFETIME_SECONDS;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn public_key() -> String {
    vectors()["public_key_pem"].as_str().unwrap().to_owned()
}

fn signed(name: &str) -> Value {
    vectors()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap()["signed"]
        .clone()
}

#[test]
fn canonical_forms_are_mastodons() {
    let registry = Registry::bundled();
    for vector in vectors()["vectors"].as_array().unwrap() {
        assert_eq!(
            ojak_jsonld::rdf::canonize(&registry, &vector["unsigned"]).unwrap(),
            vector["canonical"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn mastodons_signatures_verify() {
    let registry = Registry::bundled();
    for vector in vectors()["vectors"].as_array().unwrap() {
        assert_eq!(
            verify(&registry, &vector["signed"], &public_key(), NOW),
            Ok(()),
            "{}",
            vector["name"]
        );
        assert_eq!(
            creator(&vector["signed"]),
            Some("https://m.example/users/alice#main-key")
        );
    }
}

#[test]
fn signing_makes_what_mastodon_makes() {
    // RSASSA-PKCS1-v1_5 is deterministic: the same key over the same hashes
    // gives the same bytes, so a signature that differs at all hashed
    // something else.
    let registry = Registry::bundled();
    let key = PrivateKey::from_pem(KEY).unwrap();
    for vector in vectors()["vectors"].as_array().unwrap() {
        let ours = sign(
            &registry,
            &vector["unsigned"],
            "https://m.example/users/alice#main-key",
            &key,
            CREATED,
            EXPIRES,
        )
        .unwrap();
        assert_eq!(ours, vector["signed"], "{}", vector["name"]);
    }
}

#[test]
fn a_changed_document_does_not_verify() {
    let registry = Registry::bundled();
    let mut document = signed("create_note");
    document["object"]["content"] = json!("<p>Something else</p>");
    assert_eq!(
        verify(&registry, &document, &public_key(), NOW),
        Err(Error::Invalid)
    );

    let mut document = signed("announce");
    document["object"] = json!("https://r.example/users/bob/statuses/10");
    assert_eq!(
        verify(&registry, &document, &public_key(), NOW),
        Err(Error::Invalid)
    );
}

#[test]
fn changed_options_do_not_verify() {
    let registry = Registry::bundled();
    let mut document = signed("announce");
    document["signature"]["creator"] = json!("https://m.example/users/mallory#main-key");
    assert_eq!(
        verify(&registry, &document, &public_key(), NOW),
        Err(Error::Invalid)
    );

    let mut document = signed("announce");
    document["signature"]["expires"] = json!("2027-10-03T12:00:00Z");
    assert_eq!(
        verify(&registry, &document, &public_key(), NOW),
        Err(Error::Invalid)
    );
}

#[test]
fn an_expired_signature_does_not_verify() {
    let registry = Registry::bundled();
    assert_eq!(
        verify(&registry, &signed("announce"), &public_key(), EXPIRES + 1),
        Err(Error::Invalid)
    );
}

#[test]
fn rewording_without_changing_the_graph_still_verifies() {
    // The signature covers what the document means, not how it is spelled:
    // the same statements under different keys verify. This is why a reader
    // that takes a document on the strength of its signature has to read it
    // as JSON-LD, and not as written.
    let registry = Registry::bundled();
    let mut document = signed("announce");
    let object = document.as_object_mut().unwrap();
    // `as:actor` has no `@type: @id` of its own, so the actor is written
    // as a node to stay an IRI.
    let actor = object.remove("actor").unwrap();
    object.insert("as:actor".into(), json!({"id": actor}));
    object.insert("actor".into(), json!("https://evil.example/users/mallory"));
    object.insert(
        "@context".into(),
        json!([
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
            {"actor": null}
        ]),
    );
    assert_eq!(verify(&registry, &document, &public_key(), NOW), Ok(()));

    let read = ojak_jsonld::normalize(&registry, &document).unwrap();
    assert_eq!(
        read.document()["actor"],
        json!("https://m.example/users/alice")
    );
}

#[test]
fn a_context_ojak_does_not_ship_cannot_be_checked() {
    let registry = Registry::bundled();
    let mut document = signed("announce");
    document["@context"] = json!([
        "https://www.w3.org/ns/activitystreams",
        "https://unknown.example/context"
    ]);
    assert!(matches!(
        verify(&registry, &document, &public_key(), NOW),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn graph_restructuring_is_refused() {
    let registry = Registry::bundled();
    let mut document = signed("announce");
    document["@included"] = json!([{"id": "https://m.example/x", "type": "Note"}]);
    assert!(matches!(
        verify(&registry, &document, &public_key(), NOW),
        Err(Error::Unsupported(_))
    ));
}
