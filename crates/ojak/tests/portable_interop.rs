//! Portable objects (FEP-ef61) as other implementations sign and send them:
//! tootik's and Mitra's, captured by the Fedify project, verified and
//! received as they came. *fixtures/fep-ef61/README.md* says where each is
//! from.

use ojak::client::{Client, ClientConfig};
use ojak::federation::{Context, Federation, Handled, Received};
use ojak::fetch::Fetcher;
use ojak::kv::MemoryKvStore;
use ojak::portable::{self, ApUri, PortableError};
use ojak::sig::Scheme;
use ojak_vocab::generated::{Create, Follow};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/fep-ef61/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn tootiks_actor_is_vouched_for_by_its_key() {
    let actor = fixture("tootik-actor.json");
    let id = portable::verify(&actor, None).await.unwrap();
    assert_eq!(
        id.canonical(),
        "ap://did:key:z6MknxT9xX8cmnsEqBk2u74aYaGQNjVQL1eHxhn1qb27p5vE/actor"
    );
    // Its `id` is a compatible identifier, and its `gateways` unmapped by
    // any context it declares: read as written, which its proof covers.
    assert!(actor["id"].as_str().unwrap().starts_with("https://"));
    assert_eq!(portable::gateways(&actor), ["https://tootik.example"]);

    let mut changed = actor.clone();
    changed["preferredUsername"] = json!("mallory");
    assert!(matches!(
        portable::verify(&changed, None).await,
        Err(PortableError::Invalid(_))
    ));
}

#[tokio::test]
async fn mitras_actor_is_vouched_for_by_its_key() {
    let actor = fixture("mitra-actor.json");
    let id = portable::verify(&actor, None).await.unwrap();
    assert!(actor["id"].as_str().unwrap().starts_with("ap+ef61://"));
    assert_eq!(
        id.canonical(),
        "ap://did:key:z6MkuLKdSc7GHbgu9zDC8sZEjSbhAn7GzoHKXxsgsGNPakpB/actor"
    );
    assert_eq!(portable::gateways(&actor).len(), 2);
}

#[derive(Default)]
struct Store {
    received: Mutex<Vec<(String, Value)>>,
}

type App = Arc<Store>;

fn record<T>(ctx: &Context<App>, received: &Received<T>) -> Result<(), String> {
    ctx.data()
        .received
        .lock()
        .unwrap()
        .push((received.sender.to_string(), received.vouched.clone()));
    Ok(())
}

fn federation() -> Federation<App> {
    Federation::builder()
        .origin(Url::parse("https://fedify.example").unwrap())
        .shared_inbox("/inbox")
        // Nothing is fetched: a portable actor's proof is enough.
        .signed_fetch(
            Arc::new(Fetcher::new(
                Client::new(ClientConfig::default()).unwrap(),
                Scheme::DraftCavage,
            )),
            MemoryKvStore::new(),
            Duration::from_secs(3600),
            |_| async { Ok::<_, String>(None) },
        )
        .on::<Follow, _, _, _>(|ctx, received| async move { record(&ctx, &received) })
        .on::<Create, _, _, _>(|ctx, received| async move { record(&ctx, &received) })
        .build()
        .unwrap()
}

/// POST `body` to the shared inbox as it was sent, but with no HTTP
/// signature: the proof alone has to vouch for a portable actor.
async fn deliver(federation: &Federation<App>, store: &App, body: &Value) -> u16 {
    let request = http::Request::builder()
        .method("POST")
        .uri("/inbox")
        .header("host", "fedify.example")
        .header("content-type", "application/activity+json")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let body = serde_json::to_vec(body).unwrap();
    match federation
        .handle_with_body(&request, &body, store.clone())
        .await
    {
        Handled::Response(response) => response.status().as_u16(),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn tootiks_follow_is_received_on_its_proof() {
    let federation = federation();
    let store = App::default();
    let follow = fixture("tootik-follow.json");
    assert_eq!(deliver(&federation, &store, &follow).await, 202);
    let received = store.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    let actor = fixture("tootik-follow-actor.json");
    assert!(portable::same_object(
        &received[0].0,
        actor["id"].as_str().unwrap()
    ));

    let mut forged = follow.clone();
    forged["object"] = json!("https://fedify.example/users/bob");
    assert_eq!(deliver(&federation, &store, &forged).await, 401);
}

#[tokio::test]
async fn a_create_mitra_delivered_is_received_with_its_note() {
    let federation = federation();
    let store = App::default();
    let create = fixture("mitra-create.json");
    portable::verify(&create["object"], None).await.unwrap();
    assert_eq!(deliver(&federation, &store, &create).await, 202);
    let received = store.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    let (sender, vouched) = &received[0];
    assert_eq!(
        ApUri::parse(sender).unwrap().canonical(),
        "ap://did:key:z6MkuLKdSc7GHbgu9zDC8sZEjSbhAn7GzoHKXxsgsGNPakpB/actor"
    );
    // The note is under the activity's DID, so the activity's proof vouches
    // for it, and it is kept whole.
    assert_eq!(vouched["object"]["content"], create["object"]["content"]);
}
