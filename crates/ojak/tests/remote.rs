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

#[cfg(feature = "metrics")]
mod observations {
    use super::*;
    use metrics::{
        Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    #[derive(Default)]
    struct Captured(Mutex<HashMap<Key, Arc<AtomicU64>>>);
    impl Recorder for Captured {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            Counter::from_arc(
                self.0
                    .lock()
                    .unwrap()
                    .entry(key.clone())
                    .or_default()
                    .clone(),
            )
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }

    #[tokio::test]
    async fn delivery_metrics_preserve_callbacks_and_exclude_protocol_identifiers() {
        let recorder = Captured::default();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let remote = Remote::start().await;
        let callbacks = Arc::new(AtomicU64::new(0));
        let attempts = callbacks.clone();
        let key = SenderKey {
            key_id: "https://private.test/users/secret#key".to_owned(),
            private_key: Arc::new(PrivateKey::from_pem(PRIVATE_KEY_PEM).unwrap()),
        };
        let deliverer = Deliverer::new(
            MemoryQueue::new(),
            HashMap::from([("sender".to_owned(), key)]),
            Client::new(client_config()).unwrap(),
            DelivererConfig::default(),
        )
        .metrics(vec![metrics::Label::new("tenant", "garden.test")])
        .on_attempt(move |_| {
            attempts.fetch_add(1, Ordering::Relaxed);
        });
        let inbox = remote.actor("alice").join("inbox").unwrap();
        let activity = json!({"id":"https://private.test/secret","type":"Create"});
        deliverer
            .send("sender", &activity, [inbox.clone()])
            .await
            .unwrap();
        deliverer.run_once().await.unwrap();
        deliverer
            .send("missing-key", &activity, [inbox])
            .await
            .unwrap();
        deliverer.run_once().await.unwrap();
        assert_eq!(callbacks.load(Ordering::Relaxed), 2);
        let captured = recorder.0.lock().unwrap();
        for (key, value) in captured.iter() {
            assert_eq!(key.name(), "ojak_delivery_attempts_total");
            let labels = key
                .labels()
                .map(|label| (label.key(), label.value()))
                .collect::<HashMap<_, _>>();
            assert_eq!(labels.len(), 2);
            assert_eq!(labels["tenant"], "garden.test");
            assert_eq!(
                value.load(Ordering::Relaxed),
                match labels["outcome"] {
                    "delivered" | "failed" => 1,
                    "held" => 0,
                    other => panic!("unexpected outcome {other}"),
                }
            );
        }
        assert_eq!(captured.len(), 3);
    }
}
