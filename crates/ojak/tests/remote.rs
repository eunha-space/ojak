//! `ojak::testing::Remote`, the other server an application's tests
//! federate with: its actors are fetched and established like any server's,
//! and it keeps what is delivered to it.

use ojak::client::Client;
use ojak::deliverer::{Deliverer, DelivererConfig};
use ojak::fetch::Fetcher;
use ojak::queue::MemoryQueue;
use ojak::sig::{PrivateKey, Scheme, SenderKey};
use ojak::testing::{PRIVATE_KEY_PEM, Remote, client_config, signed_post};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn its_actors_are_fetched_and_its_inboxes_keep_what_is_delivered() {
    let remote = Remote::start().await;
    let client = Client::new(client_config()).unwrap();

    let alice = remote.actor("alice");
    let actor = Fetcher::new(client.clone(), Scheme::DraftCavage)
        .lookup(&alice, None)
        .await
        .unwrap();
    assert_eq!(actor.id, alice.as_str());
    assert_eq!(actor.json["publicKey"]["id"], remote.key_id("alice"));
    let inbox = actor.json["endpoints"]["sharedInbox"].as_str().unwrap();

    // One key signs for any sender, and a map of keys only for its own.
    let key = SenderKey {
        key_id: "https://blog.test/users/blog#main-key".to_owned(),
        private_key: Arc::new(PrivateKey::from_pem(PRIVATE_KEY_PEM).unwrap()),
    };
    let deliverer = Deliverer::new(
        MemoryQueue::new(),
        key.clone(),
        client.clone(),
        DelivererConfig::default(),
    );
    let note = json!({"id": "https://blog.test/notes/1", "type": "Create"});
    deliverer
        .send("anyone", &note, [inbox.parse().unwrap()])
        .await
        .unwrap();
    deliverer.run_once().await.unwrap();
    assert_eq!(remote.received(), vec![note.clone()]);

    let keys = HashMap::from([("blog".to_owned(), key)]);
    let deliverer = Deliverer::new(MemoryQueue::new(), keys, client, DelivererConfig::default());
    deliverer
        .send("nobody", &note, [inbox.parse().unwrap()])
        .await
        .unwrap();
    deliverer.run_once().await.unwrap();
    assert_eq!(
        remote.received().len(),
        1,
        "a sender with no key sends nothing"
    );
}

#[test]
fn a_signed_post_targets_the_inbox_path_on_its_host() {
    let request = signed_post(
        "https://blog.test:8443/users/blog/inbox?x=1",
        &json!({"type": "Follow"}),
        "https://remote.test/users/alice#main-key",
        PRIVATE_KEY_PEM,
    );
    assert_eq!(request.method(), "POST");
    assert_eq!(request.uri(), "/users/blog/inbox?x=1");
    assert_eq!(request.headers()["host"], "blog.test:8443");
    assert!(
        request.headers()["digest"]
            .to_str()
            .unwrap()
            .starts_with("SHA-256=")
    );
    assert!(
        request.headers()["signature"]
            .to_str()
            .unwrap()
            .contains("keyId=\"https://remote.test/users/alice#main-key\"")
    );
}
