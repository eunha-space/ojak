//! Receiving activities: a remote server on the loopback interface publishes
//! the sender's key, and activities are POSTed to `oeee.test`'s inboxes as
//! that server would sign them.

use axum::Router;
use axum::extract::State;
use axum::routing;
use ojak::client::{Client, ClientConfig};
use ojak::federation::{
    ActorRef, CollectionRef, Context, Federation, Forward, ForwardTo, Found, Handled, InboxWorker,
    InboxWorkerConfig, Received,
};
use ojak::fetch::Fetcher;
use ojak::kv::MemoryKvStore;
use ojak::queue::{MemoryQueue, RetryPolicy, SharedQueue, shared};
use ojak::sig::Scheme;
use ojak::sig::signature::{PrivateKey, sign_request_with_key};
use ojak_vocab::generated::{Create, Delete, Follow};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa_public.pem");
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
    forwarded: Mutex<Vec<Forward>>,
}

type App = Arc<Store>;

impl Store {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn record<T: ojak_vocab::json::ToJson>(
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
    configure: impl FnOnce(ojak::federation::Builder<App>) -> ojak::federation::Builder<App>,
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

/// The actor document fetched for a key is handed over once it verifies.
#[tokio::test]
async fn the_actor_fetched_for_a_key_is_handed_over() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let documents: Arc<Mutex<Vec<Value>>> = Arc::default();
    let seen = documents.clone();
    let federation = federation(move |b| {
        let seen = seen.clone();
        b.key_fetched(move |_, document| {
            let seen = seen.clone();
            async move { seen.lock().unwrap().push(document) }
        })
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
    let documents = documents.lock().unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["id"], bob);
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

    // Signed by bob, claiming an actor on another server: taken as
    // forwarded, and dropped when that server does not serve it — answered
    // 202, as Mastodon answers a relayed activity it cannot verify, since
    // bob's own signature holds and a retry would change nothing.
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
        202
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
            retry: RetryPolicy::exponential(Duration::from_millis(1), Duration::from_millis(1), 3),
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
        |builder: ojak::federation::Builder<App>| builder.build().err().unwrap().to_string();
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
    use ojak::sig::integrity;

    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let pem = integrity::generate_ed25519_key(&mut rand_core::OsRng).unwrap();
    let (seed, public) = integrity::parse_ed25519_key(&pem).unwrap();
    *remote.multikey.lock().unwrap() = Some(integrity::encode_ed25519_multikey(&public));
    let federation = federation(|b| b);
    let store = App::default();

    let activity = integrity::sign_object_integrity_proof(
        &follow(&bob, 1),
        &format!("{bob}#ed25519-key"),
        &seed,
        chrono::Utc::now().timestamp(),
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

/// A key the application already holds is used without a fetch, and an
/// activity with no typed listener reaches the catch-all, whose `vouched`
/// document is reduced as the typed one is.
#[tokio::test]
async fn a_known_key_and_the_catch_all() {
    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let key_id = format!("{bob}#main-key");
    let caught: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    let catch = caught.clone();
    let bob_url = Url::parse(&bob).unwrap();
    let federation = federation(move |b| {
        let catch = catch.clone();
        let bob_url = bob_url.clone();
        b.known_key(move |_, key: String| {
            let bob_url = bob_url.clone();
            async move {
                Ok::<_, String>((key == format!("{bob_url}#main-key")).then(|| {
                    ojak::federation::KnownKey {
                        pem: PUBLIC_KEY.to_owned(),
                        actor: bob_url,
                    }
                }))
            }
        })
        .on_any(
            move |_, received: Received<ojak_vocab::generated::AnyObject>| {
                let catch = catch.clone();
                async move {
                    catch
                        .lock()
                        .unwrap()
                        .push((received.sender.to_string(), received.vouched));
                    Ok::<_, String>(())
                }
            },
        )
    });
    let store = App::default();

    let announce = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{bob}/announces/1"),
        "type": "Announce",
        "actor": bob,
        "object": {
            "id": "https://elsewhere.test/notes/1",
            "type": "Note",
            "attributedTo": "https://elsewhere.test/users/eve",
            "content": "eve's words, as bob tells them"
        },
    });
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &key_id, &announce, &announce)
        )
        .await,
        202
    );
    assert_eq!(
        remote.fetches.load(Ordering::SeqCst),
        0,
        "the known key was used"
    );
    let caught = caught.lock().unwrap();
    assert_eq!(caught.len(), 1);
    assert_eq!(caught[0].0, bob);
    assert_eq!(caught[0].1["object"], "https://elsewhere.test/notes/1");
    assert_eq!(
        caught[0].1["type"], "Announce",
        "in the sender's own spelling"
    );
}

/// A reply to a post of ours, addressed to its author's followers, is
/// forwarded to them, once; what concerns nothing of ours, or is not
/// addressed to a collection of ours, is not.
#[tokio::test]
async fn a_reply_to_our_post_is_forwarded_to_its_authors_followers() {
    use ojak::federation::{Collection, Page};

    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let federation = federation(|b| {
        b.object("post", "/ap/posts/{post_id}", |_, _| async {
            Ok::<_, String>(Found::NotFound)
        })
        .collection(
            "followers",
            "/ap/users/{user_id}/followers",
            Collection::new(|_, _, _| async { Ok::<_, String>(None::<Page>) }),
        )
        .forward(|ctx: Context<App>, forward| async move {
            ctx.data().forwarded.lock().unwrap().push(forward);
            Ok::<_, String>(())
        })
    });
    let store = App::default();
    let followers = format!("https://{HOST}/ap/users/1/followers");
    let reply = |n: u32, in_reply_to: &str, cc: &str| {
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{bob}/notes/{n}/activity"),
            "type": "Create",
            "actor": bob,
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "cc": [cc],
            "object": {
                "id": format!("{bob}/notes/{n}"),
                "type": "Note",
                "attributedTo": bob,
                "inReplyTo": in_reply_to,
                "content": "a reply",
            },
        })
    };
    let ours = format!("https://{HOST}/ap/posts/1");
    let send = |activity: Value| post("/ap/inbox", &key_id, &activity, &activity);

    let activity = reply(1, &ours, &followers);
    assert_eq!(
        deliver(&federation, &store, send(activity.clone())).await,
        202
    );
    assert_eq!(
        deliver(&federation, &store, send(activity.clone())).await,
        202
    );
    assert_eq!(
        deliver(
            &federation,
            &store,
            send(reply(2, "https://elsewhere.test/notes/1", &followers))
        )
        .await,
        202
    );
    assert_eq!(
        deliver(
            &federation,
            &store,
            send(reply(3, &ours, &format!("{bob}/followers")))
        )
        .await,
        202
    );

    let forwarded = store.forwarded.lock().unwrap().clone();
    assert_eq!(forwarded.len(), 1, "{forwarded:?}");
    assert_eq!(forwarded[0].activity, activity);
    let ForwardTo::Collections(collections) = &forwarded[0].to else {
        panic!("forwarded to a collection: {:?}", forwarded[0].to);
    };
    assert_eq!(
        collections,
        &[CollectionRef {
            kind: "followers".into(),
            identifier: "1".into()
        }]
    );
}

/// Read as written, an activity reaches its listener without JSON-LD
/// processing: in its sender's spelling, and even with a context ojak could
/// not have processed, which is otherwise refused.
#[tokio::test]
async fn an_activity_can_be_read_as_written() {
    let bob = serve_remote(Remote::default()).await;
    let key_id = format!("{bob}#main-key");
    let mut unprocessable = follow(&bob, 1);
    unprocessable["@context"] = json!(5);

    let processing = federation(|b| b);
    let store = App::default();
    assert_eq!(
        deliver(
            &processing,
            &store,
            post("/ap/inbox", &key_id, &unprocessable, &unprocessable)
        )
        .await,
        400,
        "processed, a context that cannot be is refused"
    );

    let as_written = federation(ojak::federation::Builder::read_inbox_as_written);
    let store = App::default();
    assert_eq!(
        deliver(
            &as_written,
            &store,
            post("/ap/inbox", &key_id, &unprocessable, &unprocessable)
        )
        .await,
        202
    );
    let seen = store.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].kind, "Follow");
    assert_eq!(
        seen[0].activity["object"],
        format!("https://{HOST}/ap/users/1")
    );
}

/// A key the application keeps — handed its actor's document and giving the
/// key back through `known_key`, as eunha does — is not cached by Ojak too;
/// without the application keeping it, Ojak caches it as before.
#[tokio::test]
async fn a_key_the_application_keeps_is_not_cached_twice() {
    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let key_id = format!("{bob}#main-key");
    // The application's own store of actors' keys.
    let kept: Arc<Mutex<Option<String>>> = Arc::default();
    let (keep, give) = (kept.clone(), kept.clone());
    let keeping = federation(move |b| {
        let (keep, give) = (keep.clone(), give.clone());
        b.key_fetched(move |_, document: Value| {
            let keep = keep.clone();
            async move {
                *keep.lock().unwrap() = document["publicKey"]["publicKeyPem"]
                    .as_str()
                    .map(str::to_owned);
            }
        })
        .known_key(move |_, key: String| {
            let give = give.clone();
            async move {
                let actor = Url::parse(key.split('#').next().unwrap()).unwrap();
                Ok::<_, String>(
                    give.lock()
                        .unwrap()
                        .clone()
                        .map(|pem| ojak::federation::KnownKey { pem, actor }),
                )
            }
        })
    });
    let store = App::default();
    for n in 1..=2 {
        let activity = follow(&bob, n);
        let request = post("/ap/inbox", &key_id, &activity, &activity);
        assert_eq!(deliver(&keeping, &store, request).await, 202);
    }
    assert_eq!(
        remote.fetches.load(Ordering::SeqCst),
        1,
        "the second came from the application's store"
    );

    // Had Ojak cached the key too, it would survive the application
    // forgetting it; it is fetched again instead.
    *kept.lock().unwrap() = None;
    let activity = follow(&bob, 3);
    let request = post("/ap/inbox", &key_id, &activity, &activity);
    assert_eq!(deliver(&keeping, &store, request).await, 202);
    assert_eq!(remote.fetches.load(Ordering::SeqCst), 2);

    // An application that keeps no keys has Ojak cache them, as before.
    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let key_id = format!("{bob}#main-key");
    let caching = federation(|b| b);
    let store = App::default();
    for n in 1..=2 {
        let activity = follow(&bob, n);
        let request = post("/ap/inbox", &key_id, &activity, &activity);
        assert_eq!(deliver(&caching, &store, request).await, 202);
    }
    assert_eq!(remote.fetches.load(Ordering::SeqCst), 1);
}

/// A POST of `body` signed with RFC 9421 by bob's Ed25519 key.
fn post_ed25519(
    path: &str,
    key_id: &str,
    seed: &[u8; 32],
    body: &Value,
) -> (http::request::Parts, Vec<u8>) {
    use ojak::sig::rfc9421;

    let bytes = serde_json::to_vec(body).unwrap();
    let signed = rfc9421::sign_request(
        "post",
        &format!("https://{HOST}{path}"),
        Some(&bytes),
        key_id,
        &rfc9421::SigningKey::Ed25519(seed),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let parts = http::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", HOST)
        .header("content-type", "application/activity+json")
        .header("content-digest", signed.content_digest.unwrap())
        .header("signature-input", signed.signature_input)
        .header("signature", signed.signature)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    (parts, bytes)
}

/// An RFC 9421 signature by an Ed25519 key the actor lists as an
/// `assertionMethod` authenticates, as an RSA `publicKey` does.
#[tokio::test]
async fn an_ed25519_signature_by_a_listed_multikey_authenticates() {
    use ojak::sig::integrity;

    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let pem = integrity::generate_ed25519_key(&mut rand_core::OsRng).unwrap();
    let (seed, public) = integrity::parse_ed25519_key(&pem).unwrap();
    *remote.multikey.lock().unwrap() = Some(integrity::encode_ed25519_multikey(&public));
    let federation = federation(|b| b);
    let store = App::default();

    let activity = follow(&bob, 1);
    let key_id = format!("{bob}#ed25519-key");
    assert_eq!(
        deliver(
            &federation,
            &store,
            post_ed25519("/ap/inbox", &key_id, &seed, &activity)
        )
        .await,
        202
    );
    // Again, with the key from the cache rather than bob's document.
    let activity = follow(&bob, 2);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post_ed25519("/ap/inbox", &key_id, &seed, &activity)
        )
        .await,
        202
    );
    assert_eq!(remote.fetches.load(Ordering::SeqCst), 1);
    let seen = store.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].sender, bob);

    // A key bob does not list proves nothing.
    let other = integrity::parse_ed25519_key(
        &integrity::generate_ed25519_key(&mut rand_core::OsRng).unwrap(),
    )
    .unwrap()
    .0;
    let activity = follow(&bob, 3);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post_ed25519("/ap/inbox", &key_id, &other, &activity)
        )
        .await,
        401
    );
}

/// PeerTube signs with its actor's id for the key ID, for the key it
/// publishes as `#main-key`.
#[tokio::test]
async fn a_key_id_that_is_the_actor_names_its_main_key() {
    let bob = serve_remote(Remote::default()).await;
    let federation = federation(|b| b);
    let store = App::default();

    let activity = follow(&bob, 1);
    assert_eq!(
        deliver(
            &federation,
            &store,
            post("/ap/inbox", &bob, &activity, &activity)
        )
        .await,
        202
    );
    assert_eq!(store.seen()[0].sender, bob);
}
