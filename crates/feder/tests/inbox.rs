//! Receiving activities: a remote server on the loopback interface publishes
//! the sender's key, and activities are POSTed to `oeee.test`'s inboxes as
//! that server would sign them.

use axum::Router;
use axum::extract::State;
use axum::routing;
use feder::client::{Client, ClientConfig};
use feder::delivery::Scheme;
use feder::federation::{
    ActorRef, Context, Federation, Found, Handled, InboxWorker, InboxWorkerConfig, Received,
};
use feder::fetch::Fetcher;
use feder::kv::MemoryKvStore;
use feder::queue::{MemoryQueue, RetryPolicy, SharedQueue, shared};
use feder_runtime::signature::{PrivateKey, sign_request_with_key};
use feder_vocab::generated::{Create, Delete, Follow};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa_public.pem");
const HOST: &str = "oeee.test";

/// What the listeners saw.
#[derive(Clone, Debug)]
struct Seen {
    kind: &'static str,
    sender: String,
    recipient: Option<ActorRef>,
    activity: Value,
}

#[derive(Default)]
struct Store {
    seen: Mutex<Vec<Seen>>,
    unverified: Mutex<Vec<Value>>,
    queue: Option<SharedQueue>,
    /// Listener calls to fail before succeeding.
    failures: AtomicUsize,
}

type App = Arc<Store>;

impl Store {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn record<T: feder_vocab::json::ToJson>(
    ctx: &Context<App>,
    kind: &'static str,
    received: &Received<T>,
) -> Result<(), String> {
    let store = ctx.data();
    if store
        .failures
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
    {
        return Err("the database is away".into());
    }
    store.seen.lock().unwrap().push(Seen {
        kind,
        sender: received.sender.to_string(),
        recipient: received.recipient.clone(),
        activity: received.activity.to_json(),
    });
    Ok(())
}

/// The remote server: bob, with his key, counting fetches.
#[derive(Clone, Default)]
struct Remote {
    fetches: Arc<AtomicUsize>,
    /// The Ed25519 key bob lists as an assertionMethod, if he lists one.
    multikey: Arc<Mutex<Option<String>>>,
}

async fn bob(
    State(remote): State<Remote>,
    headers: http::HeaderMap,
) -> ([(&'static str, &'static str); 1], String) {
    remote.fetches.fetch_add(1, Ordering::SeqCst);
    let host = headers["host"].to_str().unwrap();
    let id = format!("http://{host}/users/bob");
    let mut actor = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": id,
        "type": "Person",
        "inbox": format!("{id}/inbox"),
        "publicKey": {"id": format!("{id}#main-key"), "owner": id, "publicKeyPem": PUBLIC_KEY},
    });
    if let Some(multikey) = remote.multikey.lock().unwrap().clone() {
        actor["assertionMethod"] = json!([{
            "id": format!("{id}#ed25519-key"),
            "type": "Multikey",
            "controller": id,
            "publicKeyMultibase": multikey,
        }]);
    }
    (
        [("content-type", "application/activity+json")],
        actor.to_string(),
    )
}

async fn serve_remote(remote: Remote) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/users/bob", routing::get(bob))
        .with_state(remote);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}/users/bob")
}

fn federation(
    configure: impl FnOnce(feder::federation::Builder<App>) -> feder::federation::Builder<App>,
) -> Federation<App> {
    let client = Client::new(ClientConfig {
        allow_private: vec!["127.0.0.0/8".parse().unwrap()],
        ..ClientConfig::default()
    })
    .unwrap();
    let builder = Federation::builder()
        .origin(Url::parse(&format!("https://{HOST}")).unwrap())
        .actor(
            "person",
            "/ap/users/{user_id}",
            |_, id: String| async move {
                Ok::<_, String>(Found::Found(
                    json!({"id": format!("https://{HOST}/ap/users/{id}")}),
                ))
            },
        )
        .inbox("person", "/ap/users/{user_id}/inbox")
        .shared_inbox("/ap/inbox")
        .signed_fetch(
            Arc::new(Fetcher::new(client, Scheme::DraftCavage)),
            MemoryKvStore::new(),
            Duration::from_secs(3600),
            |_| async { Ok::<_, String>(None) },
        )
        .on::<Follow, _, _, _>(|ctx, received| async move { record(&ctx, "Follow", &received) })
        .on::<Create, _, _, _>(|ctx, received| async move { record(&ctx, "Create", &received) })
        .on::<Delete, _, _, _>(|ctx, received| async move { record(&ctx, "Delete", &received) })
        .on_unverified(|ctx: Context<App>, document| async move {
            ctx.data().unverified.lock().unwrap().push(document);
        })
        .inbox_queue(|store: &App| store.queue.clone());
    configure(builder).build().unwrap()
}

/// A POST of `body`, signed by bob over `signed_body`.
fn post(
    path: &str,
    key_id: &str,
    signed_body: &Value,
    body: &Value,
) -> (http::request::Parts, Vec<u8>) {
    let signed_bytes = serde_json::to_vec(signed_body).unwrap();
    let key = PrivateKey::from_pem(PRIVATE_KEY).unwrap();
    let signed = sign_request_with_key(
        "post",
        &format!("https://{HOST}{path}"),
        &signed_bytes,
        key_id,
        &key,
        &[],
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
    (parts, serde_json::to_vec(body).unwrap())
}

async fn deliver(
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

fn follow(bob: &str, n: u32) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{bob}/follows/{n}"),
        "type": "Follow",
        "actor": bob,
        "object": format!("https://{HOST}/ap/users/1"),
    })
}

#[tokio::test]
async fn an_authenticated_activity_reaches_its_listener_typed() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| b);
    let store = App::default();

    let activity = follow(&bob, 1);
    let status = deliver(
        &federation,
        &store,
        post("/ap/users/1/inbox", &key_id, &activity, &activity),
    )
    .await;
    assert_eq!(status, 202);
    let activity = follow(&bob, 2);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &activity, &activity)
        )
        .await,
        202
    );

    let seen = store.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].kind, "Follow");
    assert_eq!(seen[0].sender, bob);
    assert_eq!(seen[0].recipient, Some(ActorRef::new("person", "1")));
    assert_eq!(
        seen[1].recipient, None,
        "the shared inbox names no recipient"
    );
    assert_eq!(
        seen[0].activity["object"],
        format!("https://{HOST}/ap/users/1")
    );
}

#[tokio::test]
async fn what_is_not_authenticated_reaches_no_listener() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| b);
    let store = App::default();

    // Unsigned.
    let activity = follow(&bob, 1);
    let parts = http::Request::post("/ap/inbox")
        .header("host", HOST)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let body = serde_json::to_vec(&activity).unwrap();
    assert_eq!(deliver(&federation, &store, (parts, body)).await, 401);

    // Signed over one body, carrying another.
    let other = follow(&bob, 2);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &activity, &other)
        )
        .await,
        401
    );

    // Signed by bob, claiming an actor on another server.
    let forged = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://elsewhere.test/follows/1",
        "type": "Follow",
        "actor": "https://elsewhere.test/users/eve",
        "object": format!("https://{HOST}/ap/users/1"),
    });
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &forged, &forged)
        )
        .await,
        401
    );

    // An unverified Delete is accepted and dropped, and the hook sees it.
    let delete = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://gone.test/users/carol#delete",
        "type": "Delete",
        "actor": "https://gone.test/users/carol",
        "object": "https://gone.test/users/carol",
    });
    let parts = http::Request::post("/ap/inbox")
        .header("host", HOST)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    assert_eq!(
        deliver(
            &federation,
            &store,
            (parts, serde_json::to_vec(&delete).unwrap())
        )
        .await,
        202
    );

    assert!(store.seen().is_empty(), "{:?}", store.seen());
    // The forged actor was sent by bob, authenticated, and refused for
    // claiming someone else: not unverified.
    assert_eq!(store.unverified.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn an_embedded_object_from_elsewhere_arrives_as_a_reference() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| b);
    let store = App::default();
    let origin = bob.trim_end_matches("/users/bob");

    let create = |n: u32, object: Value| {
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{bob}/creates/{n}"),
            "type": "Create",
            "actor": bob,
            "object": object,
        })
    };
    let foreign = create(
        1,
        json!({
            "id": "https://elsewhere.test/notes/1",
            "type": "Note",
            "attributedTo": "https://elsewhere.test/users/eve",
            "content": "words put in eve's mouth",
        }),
    );
    let own = create(
        2,
        json!({
            "id": format!("{origin}/notes/2"),
            "type": "Note",
            "attributedTo": bob,
            "content": "bob's own",
        }),
    );
    for activity in [&foreign, &own] {
        assert_eq!(
            deliver(
                &federation,
                &store,
                post("/ap/inbox", &key_id, activity, activity)
            )
            .await,
            202
        );
    }
    let seen = store.seen();
    assert_eq!(seen[0].activity["object"], "https://elsewhere.test/notes/1");
    assert_eq!(seen[1].activity["object"]["content"], "bob's own");
}

#[tokio::test]
async fn an_activity_is_processed_once_and_unknown_ones_are_dropped() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| b);
    let store = App::default();

    let activity = follow(&bob, 1);
    for _ in 0..2 {
        assert_eq!(
            deliver(
                &federation,
                &store,
                post("/ap/inbox", &key_id, &activity, &activity)
            )
            .await,
            202
        );
    }
    assert_eq!(store.seen().len(), 1, "the second delivery is a duplicate");

    let unknown = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{bob}/views/1"),
        "type": "View",
        "actor": bob,
        "object": format!("https://{HOST}/ap/users/1"),
    });
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &unknown, &unknown)
        )
        .await,
        202
    );
    assert_eq!(store.seen().len(), 1);
}

#[tokio::test]
async fn a_blocked_server_costs_no_key_fetch() {
    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| {
        b.blocked(|_, host: String| async move { Ok::<_, String>(host == "127.0.0.1") })
    });
    let store = App::default();

    let activity = follow(&bob, 1);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &activity, &activity)
        )
        .await,
        202
    );
    assert!(store.seen().is_empty());
    assert_eq!(remote.fetches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_failing_listener_is_retried() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| b);

    // Inline: a failure is a 500, and the sender's retry is processed.
    let store = App::default();
    store.failures.store(1, Ordering::SeqCst);
    let activity = follow(&bob, 1);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &activity, &activity)
        )
        .await,
        500
    );
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &activity, &activity)
        )
        .await,
        202
    );
    assert_eq!(store.seen().len(), 1);

    // Queued: accepted at once, run by the worker, retried there.
    let queue = shared(MemoryQueue::new());
    let store = Arc::new(Store {
        queue: Some(queue.clone()),
        failures: AtomicUsize::new(1),
        ..Store::default()
    });
    let activity = follow(&bob, 2);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &activity, &activity)
        )
        .await,
        202
    );
    assert!(store.seen().is_empty(), "nothing runs before the worker");
    let worker =
        InboxWorker::new(federation.clone(), store.clone(), queue).with_config(InboxWorkerConfig {
            retry: RetryPolicy {
                initial: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
                max_attempts: 3,
            },
            ..InboxWorkerConfig::default()
        });
    assert_eq!(worker.run_once().await.unwrap(), 1);
    assert!(store.seen().is_empty(), "the first run failed");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(worker.run_once().await.unwrap(), 1);
    let seen = store.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].sender, bob);
}

#[tokio::test]
async fn an_inbox_that_could_not_authenticate_is_not_built() {
    let error =
        |builder: feder::federation::Builder<App>| builder.build().err().unwrap().to_string();
    let base = || {
        Federation::<App>::builder()
            .origin(Url::parse("https://oeee.test").unwrap())
            .actor("person", "/ap/users/{id}", |_, _: String| async {
                Ok::<_, String>(Found::NotFound)
            })
    };
    assert!(error(base().shared_inbox("/ap/inbox")).contains("needs signed_fetch"));
    assert!(error(base().inbox("robot", "/robots/{id}/inbox")).contains("no actor kind"));
    assert!(
        error(
            base()
                .on::<Follow, _, _, _>(|_, _| async { Ok::<_, String>(()) })
                .on::<Follow, _, _, _>(|_, _| async { Ok::<_, String>(()) })
        )
        .contains("two listeners")
    );
}

/// Without a signature, an FEP-8b32 proof made with a key the actor lists as
/// an assertionMethod authenticates the activity.
#[tokio::test]
async fn an_integrity_proof_authenticates_an_unsigned_activity() {
    use feder_runtime::integrity;

    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let pem = integrity::generate_ed25519_key().unwrap();
    let (seed, public) = integrity::parse_ed25519_key(&pem).unwrap();
    *remote.multikey.lock().unwrap() = Some(integrity::encode_ed25519_multikey(&public));
    let federation = federation(|b| b);
    let store = App::default();

    let activity = integrity::sign_object_integrity_proof(
        &follow(&bob, 1),
        &format!("{bob}#ed25519-key"),
        &seed,
    )
    .unwrap();
    let unsigned = |body: &Value| {
        let parts = http::Request::post("/ap/inbox")
            .header("host", HOST)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        (parts, serde_json::to_vec(body).unwrap())
    };
    assert_eq!(deliver(&federation, &store, unsigned(&activity)).await, 202);
    let seen = store.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].sender, bob);

    // The proof covers what it signed: altered, it proves nothing.
    let mut altered = activity.clone();
    altered["object"] = json!(format!("https://{HOST}/ap/users/2"));
    altered["id"] = json!(format!("{bob}/follows/2"));
    assert_eq!(deliver(&federation, &store, unsigned(&altered)).await, 401);
}
