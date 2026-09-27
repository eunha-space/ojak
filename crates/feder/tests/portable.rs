//! Portable objects (FEP-ef61): fetched from gateways on the loopback
//! interface, received from portable actors, served at
//! `/.well-known/apgateway/`, and delivered to the first gateway that takes
//! them.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use feder::client::{Client, ClientConfig};
use feder::deliverer::{Deliverer, DelivererConfig, PortableInbox, SenderKeys};
use feder::delivery::{Scheme, SenderKey};
use feder::federation::{ActorRef, Context, Federation, Found, Handled, PORTABLE_JSON, Received};
use feder::fetch::{FetchError, Fetcher};
use feder::kv::MemoryKvStore;
use feder::portable::{Ed25519Signer, ProofSigner};
use feder::queue::{MemoryQueue, QueueError, RetryPolicy};
use feder_core::portable::ApUri;
use feder_runtime::signature::PrivateKey;
use feder_vocab::generated::{Delete, Follow};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa.pem");
const HOST: &str = "oeee.test";

fn client() -> Client {
    Client::new(ClientConfig {
        allow_private: vec!["127.0.0.0/8".parse().unwrap()],
        ..ClientConfig::default()
    })
    .unwrap()
}

fn actor(signer: &Ed25519Signer, gateways: &[&str]) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1",
            "https://w3id.org/fep/ef61"
        ],
        "type": "Person",
        "id": format!("ap://{}/actor", signer.did()),
        "inbox": format!("ap://{}/actor/inbox", signer.did()),
        "gateways": gateways,
    })
}

/// A gateway: serves the documents it is given at their paths, and records
/// what is POSTed to it, answering with `status`.
#[derive(Clone, Default)]
struct Gateway {
    documents: Arc<Mutex<HashMap<String, Value>>>,
    posted: Arc<Mutex<Vec<Value>>>,
    status: Arc<Mutex<u16>>,
}

async fn gateway_get(
    State(gateway): State<Gateway>,
    Path(rest): Path<String>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    match gateway.documents.lock().unwrap().get(&rest) {
        Some(document) => (
            StatusCode::OK,
            [("content-type", PORTABLE_JSON)],
            document.to_string(),
        ),
        None => (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain")],
            String::new(),
        ),
    }
}

async fn gateway_post(State(gateway): State<Gateway>, body: Bytes) -> StatusCode {
    gateway
        .posted
        .lock()
        .unwrap()
        .push(serde_json::from_slice(&body).unwrap());
    StatusCode::from_u16(*gateway.status.lock().unwrap()).unwrap()
}

/// Serve `gateway`, returning its origin.
async fn serve(gateway: Gateway) -> String {
    *gateway.status.lock().unwrap() = 202;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/.well-known/apgateway/{*rest}",
            get(gateway_get).post(gateway_post),
        )
        .with_state(gateway);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

#[tokio::test]
async fn a_portable_object_is_taken_from_the_first_gateway_whose_copy_is_proven() {
    let alice = Ed25519Signer::generate();
    let (tampering, honest) = (Gateway::default(), Gateway::default());
    let first = serve(tampering.clone()).await;
    let second = serve(honest.clone()).await;
    let signed = alice
        .prove(&actor(&alice, &[&first, &second]))
        .await
        .unwrap();
    let path = format!("{}/actor", alice.did());
    let mut altered = signed.clone();
    altered["inbox"] = json!("https://attacker.example/inbox");
    tampering
        .documents
        .lock()
        .unwrap()
        .insert(path.clone(), altered);
    honest
        .documents
        .lock()
        .unwrap()
        .insert(path.clone(), signed.clone());

    let fetcher = Fetcher::new(client(), Scheme::DraftCavage);
    let uri = ApUri::parse(&format!("ap://{}/actor", alice.did())).unwrap();
    let document = fetcher
        .portable(&uri, &[&first, &second], None)
        .await
        .unwrap();
    assert_eq!(document.json, signed);
    assert!(document.url.as_str().starts_with(&second));

    // `lookup` takes a portable URL in either spelling, with the gateways
    // it hints at.
    let hinted = Url::parse(&format!(
        "{}?@gateway={}",
        uri.encoded(),
        second.replace(':', "%3A").replace('/', "%2F")
    ))
    .unwrap();
    assert_eq!(fetcher.lookup(&hinted, None).await.unwrap().json, signed);
    let compatible = Url::parse(&uri.at_gateway(&second)).unwrap();
    assert_eq!(
        fetcher.lookup(&compatible, None).await.unwrap().json,
        signed
    );

    // Only the tampered copy: nothing is established.
    let Err(FetchError::Portable(tried)) = fetcher.portable(&uri, &[&first], None).await else {
        panic!("the tampered copy is not taken");
    };
    assert_eq!(tried.len(), 1);

    // A gateway serving another object under the one asked for.
    let mallory = Ed25519Signer::generate();
    let other = mallory.prove(&actor(&mallory, &[&first])).await.unwrap();
    tampering.documents.lock().unwrap().insert(path, other);
    assert!(fetcher.portable(&uri, &[&first], None).await.is_err());
}

/// What the listeners saw.
#[derive(Default)]
struct Store {
    seen: Mutex<Vec<(String, Option<ActorRef>)>>,
    objects: Mutex<HashMap<String, Value>>,
}

type App = Arc<Store>;

fn record<T>(ctx: &Context<App>, received: &Received<T>) -> Result<(), String> {
    ctx.data()
        .seen
        .lock()
        .unwrap()
        .push((received.sender.to_string(), received.recipient.clone()));
    Ok(())
}

fn federation(alice: &Ed25519Signer) -> Federation<App> {
    let inbox = ApUri::parse(&format!("ap://{}/actor/inbox", alice.did())).unwrap();
    Federation::builder()
        .origin(Url::parse(&format!("https://{HOST}")).unwrap())
        .shared_inbox("/ap/inbox")
        .signed_fetch(
            Arc::new(Fetcher::new(client(), Scheme::DraftCavage)),
            MemoryKvStore::new(),
            Duration::from_secs(3600),
            |_| async { Ok::<_, String>(None) },
        )
        .on::<Follow, _, _, _>(|ctx, received| async move { record(&ctx, &received) })
        .on::<Delete, _, _, _>(|ctx, received| async move { record(&ctx, &received) })
        .gateway(|ctx: Context<App>, uri: ApUri| async move {
            Ok::<_, String>(
                match ctx.data().objects.lock().unwrap().get(&uri.canonical()) {
                    Some(document) => Found::Found(document.clone()),
                    None => Found::NotFound,
                },
            )
        })
        .gateway_inbox(move |_, uri: ApUri| {
            let hosted = uri == inbox;
            async move { Ok::<_, String>(hosted.then(|| ActorRef::new("person", "alice"))) }
        })
        .build()
        .unwrap()
}

fn request(method: &str, path: &str) -> http::request::Parts {
    http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .header("accept", PORTABLE_JSON)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

async fn post(federation: &Federation<App>, store: &App, path: &str, body: &Value) -> u16 {
    let body = serde_json::to_vec(body).unwrap();
    match federation
        .handle_with_body(&request("POST", path), &body, store.clone())
        .await
    {
        Handled::Response(response) => response.status().as_u16(),
        other => panic!("{other:?}"),
    }
}

fn follow(from: &Ed25519Signer, to: &Ed25519Signer, n: u32) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1"
        ],
        "id": format!("ap://{}/follows/{n}", from.did()),
        "type": "Follow",
        "actor": format!("ap://{}/actor", from.did()),
        "object": format!("ap://{}/actor", to.did()),
    })
}

#[tokio::test]
async fn a_portable_actor_is_vouched_for_by_its_key_alone() {
    let alice = Ed25519Signer::generate();
    let bob = Ed25519Signer::generate();
    let mallory = Ed25519Signer::generate();
    let federation = federation(&alice);
    let store = App::default();
    let alice_inbox = format!("/.well-known/apgateway/{}/actor/inbox", alice.did());

    // Signed by bob's key, with no HTTP signature at all: accepted, at
    // alice's portable inbox and at the shared one.
    let proven = bob.prove(&follow(&bob, &alice, 1)).await.unwrap();
    assert_eq!(post(&federation, &store, &alice_inbox, &proven).await, 202);
    let proven = bob.prove(&follow(&bob, &alice, 2)).await.unwrap();
    assert_eq!(post(&federation, &store, "/ap/inbox", &proven).await, 202);
    let seen = store.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    let sender = ApUri::parse(&seen[0].0).unwrap();
    assert_eq!(sender.canonical(), format!("ap://{}/actor", bob.did()));
    assert_eq!(seen[0].1, Some(ActorRef::new("person", "alice")));
    assert_eq!(seen[1].1, None);

    // Another key does not speak for bob, and no proof is no sender, a
    // Delete included.
    let forged = mallory.prove(&follow(&bob, &alice, 3)).await.unwrap();
    assert_eq!(post(&federation, &store, &alice_inbox, &forged).await, 401);
    assert_eq!(
        post(&federation, &store, &alice_inbox, &follow(&bob, &alice, 4)).await,
        401
    );
    let delete = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("ap://{}/deletes/1", bob.did()),
        "type": "Delete",
        "actor": format!("ap://{}/actor", bob.did()),
        "object": format!("ap://{}/notes/1", bob.did()),
    });
    assert_eq!(post(&federation, &store, &alice_inbox, &delete).await, 401);

    // Bob's key does not vouch for an activity under mallory's DID.
    let mut foreign = follow(&bob, &alice, 5);
    foreign["id"] = json!(format!("ap://{}/follows/5", mallory.did()));
    let foreign = bob.prove(&foreign).await.unwrap();
    assert_eq!(post(&federation, &store, &alice_inbox, &foreign).await, 401);
    assert_eq!(store.seen.lock().unwrap().len(), 2);

    // An inbox this server does not host.
    let elsewhere = format!("/.well-known/apgateway/{}/actor/inbox", bob.did());
    let proven = bob.prove(&follow(&bob, &alice, 6)).await.unwrap();
    assert_eq!(post(&federation, &store, &elsewhere, &proven).await, 404);
}

#[tokio::test]
async fn a_gateway_serves_what_the_application_stored() {
    let alice = Ed25519Signer::generate();
    let federation = federation(&alice);
    let store = App::default();
    let signed = alice
        .prove(&actor(&alice, &[&format!("https://{HOST}")]))
        .await
        .unwrap();
    store
        .objects
        .lock()
        .unwrap()
        .insert(format!("ap://{}/actor", alice.did()), signed.clone());

    // Found by its canonical identifier, however the path spells the DID.
    for path in [
        format!("/.well-known/apgateway/{}/actor", alice.did()),
        format!(
            "/.well-known/apgateway/{}/actor",
            alice.did().replace(':', "%3A")
        ),
    ] {
        assert!(federation.is_inbox(&path), "the adapter reads its body");
        let Handled::Response(response) = federation
            .handle(&request("GET", &path), store.clone())
            .await
        else {
            panic!("served");
        };
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], PORTABLE_JSON);
        let served: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(served, signed);
        feder::portable::verify(&served, None).await.unwrap();
    }

    let missing = format!("/.well-known/apgateway/{}/notes/1", alice.did());
    let Handled::Response(response) = federation
        .handle(&request("GET", &missing), store.clone())
        .await
    else {
        panic!("answered");
    };
    assert_eq!(response.status(), 404);
}

struct Keys;

impl SenderKeys for Keys {
    async fn key(&self, _: &str) -> Result<Option<SenderKey>, QueueError> {
        Ok(Some(SenderKey {
            key_id: format!("https://{HOST}/actor#main-key"),
            private_key: Arc::new(PrivateKey::from_pem(PRIVATE_KEY).unwrap()),
        }))
    }
}

#[tokio::test]
async fn a_delivery_goes_to_the_first_gateway_that_takes_it() {
    let (down, up) = (Gateway::default(), Gateway::default());
    let first = serve(down.clone()).await;
    let second = serve(up.clone()).await;
    *down.status.lock().unwrap() = 503;
    let bob = Ed25519Signer::generate();
    let inbox = ApUri::parse(&format!("ap://{}/actor/inbox", bob.did())).unwrap();

    let deliverer = Deliverer::new(
        MemoryQueue::new(),
        Keys,
        client(),
        DelivererConfig {
            retry: RetryPolicy {
                initial: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
                max_attempts: 3,
            },
            ..DelivererConfig::default()
        },
    );
    let activity = json!({"type": "Follow", "n": 1});
    let target = PortableInbox {
        inbox: inbox.clone(),
        gateways: vec![Url::parse(&first).unwrap(), Url::parse(&second).unwrap()],
    };
    deliverer
        .send_portable("alice", &activity, [target.clone(), target])
        .await
        .unwrap();
    assert_eq!(deliverer.run_once().await.unwrap(), 1, "queued once");

    assert_eq!(down.posted.lock().unwrap().len(), 1, "the first was tried");
    assert_eq!(*up.posted.lock().unwrap(), vec![activity]);
    let records = deliverer.queue().records();
    assert!(records[0].complete);
    assert_eq!(records[0].job.attempts, 0, "no retry was needed");
}
