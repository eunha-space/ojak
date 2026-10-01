//! Portable objects (FEP-ef61): fetched from gateways on the loopback
//! interface, received from portable actors, served at
//! `/.well-known/apgateway/`, and delivered to the first gateway that takes
//! them.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use ojak::client::{Client, ClientConfig};
use ojak::deliverer::{Deliverer, DelivererConfig, PortableInbox, SenderKeys};
use ojak::federation::{
    ActorRef, Context, Federation, Forward, ForwardTo, Found, GatewayInbox, Handled, PORTABLE_JSON,
    Received,
};
use ojak::fetch::{FetchError, Fetcher};
use ojak::kv::MemoryKvStore;
use ojak::portable::ApUri;
use ojak::portable::{Ed25519Signer, Hashlink, Media, ProofSigner};
use ojak::queue::{MemoryQueue, QueueError, RetryPolicy};
use ojak::sig::signature::{PrivateKey, sign_request_with_key};
use ojak::sig::{Scheme, SenderKey};
use ojak_vocab::generated::{Delete, Follow};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa_public.pem");
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
    media: Mutex<HashMap<Hashlink, Media>>,
    forwarded: Mutex<Vec<Forward>>,
    /// The activities as the listeners read them.
    activities: Mutex<Vec<Value>>,
}

type App = Arc<Store>;

fn record<T>(ctx: &Context<App>, received: &Received<T>) -> Result<(), String> {
    ctx.data()
        .seen
        .lock()
        .unwrap()
        .push((received.sender.to_string(), received.recipient.clone()));
    ctx.data()
        .activities
        .lock()
        .unwrap()
        .push(received.vouched.clone());
    Ok(())
}

/// The gateways alice lists: this server, and another.
const ALICE_GATEWAYS: [&str; 2] = ["https://oeee.test", "https://server2.example"];

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
        .gateway_media(|ctx: Context<App>, hashlink: Hashlink| async move {
            Ok::<_, String>(ctx.data().media.lock().unwrap().get(&hashlink).cloned())
        })
        .gateway_inbox(move |_, uri: ApUri| {
            let hosted = uri == inbox;
            async move {
                Ok::<_, String>(hosted.then(|| {
                    GatewayInbox {
                        recipient: ActorRef::new("person", "alice"),
                        gateways: ALICE_GATEWAYS
                            .iter()
                            .map(|g| Url::parse(g).unwrap())
                            .collect(),
                    }
                }))
            }
        })
        .forward(|ctx: Context<App>, forward| async move {
            ctx.data().forwarded.lock().unwrap().push(forward);
            Ok::<_, String>(())
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
        ojak::portable::verify(&served, None).await.unwrap();
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

async fn fetch_from(
    federation: &Federation<App>,
    store: &App,
    path: &str,
) -> http::Response<Vec<u8>> {
    match federation
        .handle(&request("GET", path), store.clone())
        .await
    {
        Handled::Response(response) => response,
        Handled::NotFound => {
            let mut response = http::Response::new(Vec::new());
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_gateway_serves_only_the_object_asked_for_with_its_proof() {
    let alice = Ed25519Signer::generate();
    let federation = federation(&alice);
    let store = App::default();
    let did = alice.did();
    let note = |n: u32| {
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("ap://{did}/notes/{n}"),
            "type": "Note",
            "attributedTo": format!("ap://{did}/actor"),
            "content": "Hello",
        })
    };
    let at = |path: &str| format!("/.well-known/apgateway/{did}{path}");
    let mut objects = HashMap::new();
    // Found under another object's identifier.
    objects.insert(
        format!("ap://{did}/notes/1"),
        alice.prove(&note(2)).await.unwrap(),
    );
    // Unsigned, and signed and changed since.
    objects.insert(format!("ap://{did}/notes/3"), note(3));
    let mut changed = alice.prove(&note(4)).await.unwrap();
    changed["content"] = json!("Goodbye");
    objects.insert(format!("ap://{did}/notes/4"), changed);
    // An actor listing what is not a gateway.
    let mut actor = actor(&alice, &["https://oeee.test/gateway"]);
    actor = alice.prove(&actor).await.unwrap();
    objects.insert(format!("ap://{did}/actor"), actor);
    // A collection, which may go unsigned.
    objects.insert(
        format!("ap://{did}/actor/outbox"),
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("ap://{did}/actor/outbox"),
            "type": "OrderedCollection",
            "totalItems": 0,
        }),
    );
    // A signed tombstone, which says it is gone in its owner's words.
    let tombstone = alice
        .prove(&json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("ap://{did}/notes/5"),
            "type": "Tombstone",
            "formerType": "Note",
        }))
        .await
        .unwrap();
    objects.insert(format!("ap://{did}/notes/5"), tombstone.clone());
    *store.objects.lock().unwrap() = objects;

    assert_eq!(
        fetch_from(&federation, &store, &at("/notes/1"))
            .await
            .status(),
        404
    );
    assert_eq!(
        fetch_from(&federation, &store, &at("/notes/3"))
            .await
            .status(),
        500
    );
    assert_eq!(
        fetch_from(&federation, &store, &at("/notes/4"))
            .await
            .status(),
        500
    );
    assert_eq!(
        fetch_from(&federation, &store, &at("/actor"))
            .await
            .status(),
        500
    );
    assert_eq!(
        fetch_from(&federation, &store, &at("/actor/outbox"))
            .await
            .status(),
        200
    );
    let gone = fetch_from(&federation, &store, &at("/notes/5")).await;
    assert_eq!(gone.status(), 410);
    assert_eq!(
        serde_json::from_slice::<Value>(gone.body()).unwrap(),
        tombstone
    );
    // Dot segments would make it another object at any URL parser.
    assert_eq!(
        fetch_from(&federation, &store, &at("/actor/../notes/5"))
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn a_gateway_serves_media_by_what_it_is() {
    let alice = Ed25519Signer::generate();
    let federation = federation(&alice);
    let store = App::default();
    let image = Media {
        content_type: "image/png".into(),
        bytes: b"\x89PNG...".to_vec(),
    };
    let hashlink = Hashlink::of(&image.bytes);
    let other = Hashlink::of(b"something else");
    store
        .media
        .lock()
        .unwrap()
        .insert(hashlink.clone(), image.clone());
    // What the application found under a digest that is not its own.
    store
        .media
        .lock()
        .unwrap()
        .insert(other.clone(), image.clone());

    let response = fetch_from(
        &federation,
        &store,
        &format!("/.well-known/apgateway/{hashlink}"),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "image/png");
    assert_eq!(response.body(), &image.bytes);
    let response = fetch_from(
        &federation,
        &store,
        &format!("/.well-known/apgateway/{other}"),
    )
    .await;
    assert_eq!(response.status(), 500);
    let missing = Hashlink::of(b"missing");
    let response = fetch_from(
        &federation,
        &store,
        &format!("/.well-known/apgateway/{missing}"),
    )
    .await;
    assert_eq!(response.status(), 404);
    let response = fetch_from(
        &federation,
        &store,
        "/.well-known/apgateway/hl:zNotAHashlink",
    )
    .await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn media_is_taken_from_the_first_gateway_that_serves_what_its_digest_names() {
    let (tampering, honest) = (Gateway::default(), Gateway::default());
    let first = serve(tampering.clone()).await;
    let second = serve(honest.clone()).await;
    let media = json!({"an": "image"});
    let hashlink = Hashlink::of(media.to_string().as_bytes());
    honest
        .documents
        .lock()
        .unwrap()
        .insert(hashlink.to_string(), media.clone());
    tampering
        .documents
        .lock()
        .unwrap()
        .insert(hashlink.to_string(), json!({"another": "image"}));

    let fetcher = Fetcher::new(client(), Scheme::DraftCavage);
    let digest = hashlink.multibase();
    let found = fetcher
        .portable_media(&hashlink.to_string(), &digest, &[&first, &second], None)
        .await
        .unwrap();
    assert_eq!(found.bytes, media.to_string().as_bytes());

    // By its URL, wherever that is, and checked all the same.
    let at = format!("{second}/.well-known/apgateway/{hashlink}");
    fetcher
        .portable_media(&at, &digest, &[], None)
        .await
        .unwrap();
    let tampered = format!("{first}/.well-known/apgateway/{hashlink}");
    assert!(matches!(
        fetcher.portable_media(&tampered, &digest, &[], None).await,
        Err(FetchError::Portable(_))
    ));
    // A hashlink of one digest does not stand for another.
    let other = Hashlink::of(b"other").multibase();
    assert!(matches!(
        fetcher
            .portable_media(&hashlink.to_string(), &other, &[&second], None)
            .await,
        Err(FetchError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_portable_collection_is_taken_unsigned_only_from_its_owners_gateways() {
    let alice = Ed25519Signer::generate();
    let (listed, unlisted) = (Gateway::default(), Gateway::default());
    let gateway = serve(listed.clone()).await;
    let elsewhere = serve(unlisted.clone()).await;
    let did = alice.did();
    let mut owner = actor(&alice, &[&gateway]);
    owner["outbox"] = json!(format!("ap://{did}/actor/outbox"));
    let owner = alice.prove(&owner).await.unwrap();
    let outbox = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("ap://{did}/actor/outbox"),
        "type": "OrderedCollection",
        "first": format!("ap://{did}/actor/outbox/page/1"),
    });
    let page = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("ap://{did}/actor/outbox/page/1"),
        "type": "OrderedCollectionPage",
        "partOf": format!("ap://{did}/actor/outbox"),
        "orderedItems": [],
    });
    let stray = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("ap://{did}/actor/drafts"),
        "type": "OrderedCollection",
    });
    for gateway in [&listed, &unlisted] {
        let mut documents = gateway.documents.lock().unwrap();
        documents.insert(format!("{did}/actor/outbox"), outbox.clone());
        documents.insert(format!("{did}/actor/outbox/page/1"), page.clone());
        documents.insert(format!("{did}/actor/drafts"), stray.clone());
        documents.insert(
            format!("{did}/notes/1"),
            json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": format!("ap://{did}/notes/1"),
                "type": "Note",
            }),
        );
    }

    let fetcher = Fetcher::new(client(), Scheme::DraftCavage);
    let collection = |iri: String| {
        let fetcher = &fetcher;
        let owner = &owner;
        async move { fetcher.portable_collection(owner, &iri, None).await }
    };
    assert_eq!(
        collection(format!("ap://{did}/actor/outbox"))
            .await
            .unwrap()
            .json,
        outbox
    );
    assert_eq!(
        collection(format!("ap://{did}/actor/outbox/page/1"))
            .await
            .unwrap()
            .json,
        page
    );
    // Not a collection its owner lists, and not a collection.
    assert!(
        collection(format!("ap://{did}/actor/drafts"))
            .await
            .is_err()
    );
    assert!(collection(format!("ap://{did}/notes/1")).await.is_err());
    // Its hints are no gateway of the owner's: not asked.
    let hinted = ApUri::parse(&format!("ap://{did}/actor/outbox"))
        .unwrap()
        .with_hints(&[&elsewhere]);
    let moved = alice.prove(&actor(&alice, &[&elsewhere])).await.unwrap();
    assert!(
        fetcher
            .portable_collection(&moved, &hinted, None)
            .await
            .is_err()
    );
    // A collection of someone else's.
    let bob = Ed25519Signer::generate();
    let bobs = format!("ap://{}/actor/outbox", bob.did());
    assert!(matches!(
        fetcher.portable_collection(&owner, &bobs, None).await,
        Err(FetchError::Invalid(_))
    ));
}

#[tokio::test]
async fn no_more_than_a_few_gateways_are_asked() {
    let alice = Ed25519Signer::generate();
    let uri = ApUri::parse(&format!("ap://{}/actor", alice.did())).unwrap();
    // Nothing listens on these.
    let gateways: Vec<String> = (1..=8)
        .map(|port| format!("http://127.0.0.1:{port}"))
        .collect();
    let gateways: Vec<&str> = gateways.iter().map(String::as_str).collect();
    let fetcher = Fetcher::new(client(), Scheme::DraftCavage);
    let Err(FetchError::Portable(tried)) = fetcher.portable(&uri, &gateways, None).await else {
        panic!("nothing is there");
    };
    assert_eq!(tried.len(), ojak::portable::MAX_GATEWAYS + 1);
    assert!(tried.last().unwrap().1.contains("too many"));
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

#[tokio::test]
async fn what_arrives_at_a_gateway_is_forwarded_to_the_others_once() {
    let alice = Ed25519Signer::generate();
    let bob = Ed25519Signer::generate();
    let federation = federation(&alice);
    let store = App::default();
    let alice_inbox = format!("/.well-known/apgateway/{}/actor/inbox", alice.did());

    let proven = bob.prove(&follow(&bob, &alice, 1)).await.unwrap();
    assert_eq!(post(&federation, &store, &alice_inbox, &proven).await, 202);
    // The same activity again, as another gateway forwarding it back would
    // send it: not forwarded a second time.
    assert_eq!(post(&federation, &store, &alice_inbox, &proven).await, 202);

    let forwarded = store.forwarded.lock().unwrap().clone();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].activity, proven);
    let ForwardTo::Gateways(to) = &forwarded[0].to else {
        panic!("forwarded to the gateways: {:?}", forwarded[0].to);
    };
    assert_eq!(
        to.inbox,
        ApUri::parse(&format!("ap://{}/actor/inbox", alice.did())).unwrap()
    );
    assert_eq!(
        to.gateways,
        [Url::parse("https://server2.example").unwrap()],
        "this gateway is left out"
    );

    // What is refused is not forwarded, and nor is what arrives at an
    // ordinary inbox.
    let mallory = Ed25519Signer::generate();
    let forged = mallory.prove(&follow(&bob, &alice, 2)).await.unwrap();
    assert_eq!(post(&federation, &store, &alice_inbox, &forged).await, 401);
    let proven = bob.prove(&follow(&bob, &alice, 3)).await.unwrap();
    assert_eq!(post(&federation, &store, "/ap/inbox", &proven).await, 202);
    assert_eq!(store.forwarded.lock().unwrap().len(), 1);
}

/// An ordinary server on the loopback interface: actors with a key, and the
/// activities it serves at their ids.
#[derive(Clone, Default)]
struct Origin {
    activities: Arc<Mutex<HashMap<String, Value>>>,
    fetches: Arc<Mutex<Vec<String>>>,
}

async fn origin_actor(
    State(origin): State<Origin>,
    Path(name): Path<String>,
    headers: http::HeaderMap,
) -> ([(&'static str, &'static str); 1], String) {
    let host = headers["host"].to_str().unwrap();
    let id = format!("http://{host}/users/{name}");
    origin
        .fetches
        .lock()
        .unwrap()
        .push(format!("/users/{name}"));
    (
        [("content-type", "application/activity+json")],
        json!({
            "@context": ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
            "id": id,
            "type": "Person",
            "inbox": format!("{id}/inbox"),
            "publicKey": {"id": format!("{id}#main-key"), "owner": id, "publicKeyPem": PUBLIC_KEY},
        })
        .to_string(),
    )
}

async fn origin_activity(
    State(origin): State<Origin>,
    Path(n): Path<String>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    let path = format!("/activities/{n}");
    origin.fetches.lock().unwrap().push(path.clone());
    match origin.activities.lock().unwrap().get(&path) {
        Some(activity) => (
            StatusCode::OK,
            [("content-type", "application/activity+json")],
            activity.to_string(),
        ),
        None => (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain")],
            String::new(),
        ),
    }
}

async fn serve_origin(origin: Origin) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/users/{name}", get(origin_actor))
        .route("/activities/{n}", get(origin_activity))
        .with_state(origin);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

/// A POST of `body` to `path`, signed with the key of `key_id`.
fn signed(path: &str, key_id: &str, body: &Value) -> (http::request::Parts, Vec<u8>) {
    let bytes = serde_json::to_vec(body).unwrap();
    let key = PrivateKey::from_pem(PRIVATE_KEY).unwrap();
    let signed = sign_request_with_key(
        "post",
        &format!("https://{HOST}{path}"),
        &bytes,
        key_id,
        &key,
        &[],
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let parts = http::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", HOST)
        .header("content-type", "application/activity+json")
        .header("date", signed.date)
        .header("digest", signed.digest)
        .header("signature", signed.signature)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    (parts, bytes)
}

async fn status_of(
    federation: &Federation<App>,
    store: &App,
    (parts, body): (http::request::Parts, Vec<u8>),
) -> u16 {
    match federation
        .handle_with_body(&parts, &body, store.clone())
        .await
    {
        Handled::Response(response) => response.status().as_u16(),
        other => panic!("{other:?}"),
    }
}

/// An activity forwarded by a server other than its actor's, with no proof,
/// is taken from its origin; the forwarder's copy is only a claim, and
/// without a signature nothing is fetched at all.
#[tokio::test]
async fn a_forwarded_activity_is_taken_from_its_origin() {
    let alice = Ed25519Signer::generate();
    let federation = federation(&alice);
    let store = App::default();
    let (bobs, forwarders) = (Origin::default(), Origin::default());
    let bob_server = serve_origin(bobs.clone()).await;
    let forwarder = serve_origin(forwarders).await;
    let bob = format!("{bob_server}/users/bob");
    let alice_inbox = format!("/.well-known/apgateway/{}/actor/inbox", alice.did());
    let follow = |n: u32, object: &str| {
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{bob_server}/activities/{n}"),
            "type": "Follow",
            "actor": bob,
            "object": object,
        })
    };
    let alice_actor = format!("ap://{}/actor", alice.did());
    bobs.activities
        .lock()
        .unwrap()
        .insert("/activities/1".into(), follow(1, &alice_actor));

    // Forwarded, and altered on the way: what is processed is what bob's
    // server serves.
    let claim = follow(1, "https://elsewhere.example/users/carol");
    let forwarder_key = format!("{forwarder}/users/gateway#main-key");
    assert_eq!(
        status_of(
            &federation,
            &store,
            signed(&alice_inbox, &forwarder_key, &claim)
        )
        .await,
        202
    );
    let seen = store.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, bob);
    let activities = store.activities.lock().unwrap().clone();
    assert_eq!(activities[0]["object"], alice_actor.as_str());

    // What bob's server does not serve is not established: dropped, and
    // answered 202 as Mastodon answers a relayed activity it cannot verify,
    // since the forwarder's own signature holds.
    let unserved = follow(2, &alice_actor);
    assert_eq!(
        status_of(
            &federation,
            &store,
            signed(&alice_inbox, &forwarder_key, &unserved)
        )
        .await,
        202
    );

    // Unsigned, it makes this server fetch nothing.
    let before = bobs.fetches.lock().unwrap().len();
    assert_eq!(
        post(&federation, &store, &alice_inbox, &follow(3, &alice_actor)).await,
        401
    );
    assert_eq!(bobs.fetches.lock().unwrap().len(), before);
    assert_eq!(store.seen.lock().unwrap().len(), 1);
}
