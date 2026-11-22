//! Payload limits: activities and documents inflated past what any real
//! server sends are refused, and ojak does no work for each of their
//! recipients or mentions, whether it refuses them or not.
//!
//! The activities are modelled on a real one: a `Create` of a 7.1 MB `Note`
//! whose `content` was 5.85 MB, a whole book and 7,811 links, and whose
//! `tag` held 7,806 `Mention`s of distinct actors on hundreds of servers,
//! every one of them also in `to`. About 2,500 such mentions fit under the
//! 1 MiB an inbox reads.
//!
//! Half the mentioned actors are on the remote server below, which counts
//! every request made to it, so that resolving, fetching or WebFingering any
//! of them would show; the rest are on servers that do not exist.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Uri};
use axum::routing::get;
use ojak::client::{Client, ClientConfig, RequestError};
use ojak::federation::{
    ActorKind, Collection, CollectionKind, Context, Federation, Forward, Found, Handled,
    InboxWorker, MAX_INBOX_BODY, ObjectKind, Page, Received,
};
use ojak::fetch::{FetchError, Fetcher};
use ojak::kv::MemoryKvStore;
use ojak::limits::{Limit, PayloadLimits};
use ojak::queue::{MemoryQueue, SharedQueue, shared};
use ojak::sig::Scheme;
use ojak::sig::signature::{PrivateKey, sign_request_with_key};
use ojak_vocab::generated::Create;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa_public.pem");
const HOST: &str = "oeee.test";

/// The remote server: bob, the actors he mentions, and the documents it
/// serves, with every request it gets.
#[derive(Clone, Default)]
struct Remote {
    requests: Arc<Mutex<Vec<String>>>,
    documents: Arc<Mutex<std::collections::HashMap<String, String>>>,
}

impl Remote {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn serve_document(&self, name: &str, document: &Value) {
        self.documents
            .lock()
            .unwrap()
            .insert(name.to_owned(), document.to_string());
    }
}

async fn actor(
    State(remote): State<Remote>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> ([(&'static str, &'static str); 1], String) {
    remote
        .requests
        .lock()
        .unwrap()
        .push(format!("/users/{name}"));
    let host = headers["host"].to_str().unwrap();
    let id = format!("http://{host}/users/{name}");
    let actor = json!({
        "@context": ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
        "id": id,
        "type": "Person",
        "inbox": format!("{id}/inbox"),
        "publicKey": {"id": format!("{id}#main-key"), "owner": id, "publicKeyPem": PUBLIC_KEY},
    });
    (
        [("content-type", "application/activity+json")],
        actor.to_string(),
    )
}

async fn document(
    State(remote): State<Remote>,
    Path(name): Path<String>,
) -> ([(&'static str, &'static str); 1], String) {
    remote
        .requests
        .lock()
        .unwrap()
        .push(format!("/notes/{name}"));
    let body = remote
        .documents
        .lock()
        .unwrap()
        .get(&name)
        .cloned()
        .unwrap_or_default();
    ([("content-type", "application/activity+json")], body)
}

async fn anything_else(State(remote): State<Remote>, uri: Uri) -> axum::http::StatusCode {
    remote.requests.lock().unwrap().push(uri.to_string());
    axum::http::StatusCode::NOT_FOUND
}

/// Start the remote server; its origin, such as `http://127.0.0.1:49152`.
async fn serve(remote: Remote) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/users/{name}", get(actor))
        .route("/notes/{name}", get(document))
        .fallback(anything_else)
        .with_state(remote);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

/// What the application saw.
#[derive(Default)]
struct Store {
    seen: Mutex<Vec<Value>>,
    forwarded: Mutex<Vec<Forward>>,
    queue: Option<SharedQueue>,
}

type App = Arc<Store>;

fn client() -> Client {
    Client::new(ClientConfig {
        allow_private: vec!["127.0.0.0/8".parse().unwrap()],
        ..ClientConfig::default()
    })
    .unwrap()
}

fn federation(
    errors: Arc<Mutex<Vec<String>>>,
    configure: impl FnOnce(ojak::federation::Builder<App>) -> ojak::federation::Builder<App>,
) -> Federation<App> {
    let builder = Federation::builder()
        .origin(Url::parse(&format!("https://{HOST}")).unwrap())
        .actor(
            ActorKind::new("person"),
            "/ap/users/{user_id}",
            |_, id: String| async move {
                Ok::<_, String>(Found::Found(
                    json!({"id": format!("https://{HOST}/ap/users/{id}")}),
                ))
            },
        )
        .object(
            ObjectKind::new("post"),
            "/ap/posts/{post_id}",
            |_, _| async { Ok::<_, String>(Found::NotFound) },
        )
        .collection(
            CollectionKind::new("followers"),
            "/ap/users/{user_id}/followers",
            Collection::new(|_, _, _| async { Ok::<_, String>(None::<Page>) }),
        )
        .inbox(ActorKind::new("person"), "/ap/users/{user_id}/inbox")
        .shared_inbox("/ap/inbox")
        .signed_fetch(
            Arc::new(Fetcher::new(client(), Scheme::DraftCavage)),
            MemoryKvStore::new(),
            Duration::from_secs(3600),
            |_| async { Ok::<_, String>(None) },
        )
        .on::<Create, _, _, _>(|ctx: Context<App>, received: Received<Create>| async move {
            ctx.data().seen.lock().unwrap().push(received.document);
            Ok::<_, String>(())
        })
        .forward(|ctx: Context<App>, forward| async move {
            ctx.data().forwarded.lock().unwrap().push(forward);
            Ok::<_, String>(())
        })
        .on_error(move |error| errors.lock().unwrap().push(error.to_string()))
        .inbox_queue(|store: &App| store.queue.clone());
    configure(builder).build().unwrap()
}

/// `activity`, POSTed to the shared inbox and signed by bob.
fn post(bob: &str, activity: &Value) -> (http::request::Parts, Vec<u8>) {
    let body = serde_json::to_vec(activity).unwrap();
    let key = PrivateKey::from_pem(PRIVATE_KEY).unwrap();
    let signed = sign_request_with_key(
        "post",
        &format!("https://{HOST}/ap/inbox"),
        &body,
        &format!("{bob}#main-key"),
        &key,
        &[],
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let parts = http::Request::builder()
        .method("POST")
        .uri("/ap/inbox")
        .header("host", HOST)
        .header("content-type", "application/activity+json")
        .header("date", signed.date)
        .header("digest", signed.digest)
        .header("signature", signed.signature)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    (parts, body)
}

async fn deliver(
    federation: &Federation<App>,
    store: &App,
    (parts, body): (http::request::Parts, Vec<u8>),
) -> (u16, String) {
    match federation
        .handle_with_body(&parts, &body, store.clone())
        .await
    {
        Handled::Response(response) => (
            response.status().as_u16(),
            String::from_utf8_lossy(response.body()).into_owned(),
        ),
        other => panic!("{other:?}"),
    }
}

/// The actors the flood mentions: every other one on `origin`, the rest on
/// 300 servers that do not exist.
fn mentioned(origin: &str, i: usize) -> (String, String) {
    if i.is_multiple_of(2) {
        (format!("{origin}/users/m{i}"), format!("@m{i}@{origin}"))
    } else {
        let host = format!("s{}.invalid", i % 300);
        (
            format!("https://{host}/users/u{i}"),
            format!("@u{i}@{host}"),
        )
    }
}

/// A `Create` of a `Note` by bob at `origin`, numbered `n`, mentioning
/// `mentions` distinct actors, every one also in `to`, with `content` of
/// at least `content_bytes`: a paragraph linking each of them, as the real
/// one's did, and then a book's worth of verses. It replies to a post of
/// ours, and is addressed to its author's followers, so that it would be
/// forwarded.
fn flood(origin: &str, n: u32, mentions: usize, content_bytes: usize) -> Value {
    let bob = format!("{origin}/users/bob");
    let mentioned: Vec<(String, String)> = (0..mentions).map(|i| mentioned(origin, i)).collect();
    let mut content: String = mentioned
        .iter()
        .map(|(href, name)| {
            format!(
                r#"<span class="h-card"><a href="{href}" class="u-url mention">{name}</a></span> "#
            )
        })
        .collect();
    let mut verse = 0;
    while content.len() < content_bytes {
        verse += 1;
        content.push_str(&format!(
            "<p>{verse}:1 In the beginning the inbox was without form, and void.</p>"
        ));
    }
    let mut to: Vec<Value> = vec![json!("https://www.w3.org/ns/activitystreams#Public")];
    to.extend(mentioned.iter().map(|(href, _)| json!(href)));
    let tag: Vec<Value> = mentioned
        .iter()
        .map(|(href, name)| json!({"type": "Mention", "href": href, "name": name}))
        .collect();
    let cc = json!([format!("https://{HOST}/ap/users/1/followers")]);
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{bob}/notes/{n}/activity"),
        "type": "Create",
        "actor": bob,
        "to": to,
        "cc": cc,
        "object": {
            "id": format!("{bob}/notes/{n}"),
            "type": "Note",
            "attributedTo": bob,
            "inReplyTo": format!("https://{HOST}/ap/posts/1"),
            "content": content,
            "tag": tag,
            "to": to,
            "cc": cc,
        },
    })
}

/// The flood, as large as it fits in what an inbox reads, less `slack`
/// bytes.
fn flood_under(origin: &str, n: u32, mentions: usize, slack: usize) -> Value {
    let bare = serde_json::to_vec(&flood(origin, n, mentions, 0))
        .unwrap()
        .len();
    let content = flood(origin, n, mentions, 0)["object"]["content"]
        .as_str()
        .unwrap()
        .len();
    // The content pads in whole verses of under 100 bytes.
    let activity = flood(
        origin,
        n,
        mentions,
        MAX_INBOX_BODY - slack - 100 - bare + content,
    );
    let size = serde_json::to_vec(&activity).unwrap().len();
    assert!(size < MAX_INBOX_BODY - slack + 100, "{size}");
    assert!(size > MAX_INBOX_BODY - slack - 200, "{size}");
    activity
}

/// Nothing came of an activity: no request to the remote server, nothing
/// queued, nothing seen, nothing forwarded.
async fn nothing_came_of_it(
    federation: &Federation<App>,
    store: &App,
    queue: SharedQueue,
    remote: &Remote,
) {
    assert_eq!(remote.requests(), Vec::<String>::new(), "no request made");
    let worker = InboxWorker::new(federation.clone(), store.clone(), queue);
    assert_eq!(worker.run_once().await.unwrap(), 0, "nothing queued");
    assert!(store.seen.lock().unwrap().is_empty(), "no listener ran");
    assert!(
        store.forwarded.lock().unwrap().is_empty(),
        "nothing forwarded"
    );
}

#[tokio::test]
async fn the_real_floods_size_is_refused_unread() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let errors = Arc::default();
    let federation = federation(Arc::clone(&errors), |b| b);
    let queue = shared(MemoryQueue::new());
    let store = Arc::new(Store {
        queue: Some(queue.clone()),
        ..Store::default()
    });

    let activity = flood(&origin, 1, 7_806, 5_850_000);
    let bob = format!("{origin}/users/bob");
    let request = post(&bob, &activity);
    assert!(request.1.len() > 7_000_000, "{}", request.1.len());
    let (status, _) = deliver(&federation, &store, request).await;
    assert_eq!(status, 413);
    nothing_came_of_it(&federation, &store, queue, &remote).await;
}

#[tokio::test]
async fn a_flood_under_a_megabyte_is_refused_before_anything_is_fetched() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let errors: Arc<Mutex<Vec<String>>> = Arc::default();
    let federation = federation(Arc::clone(&errors), |b| b);
    let queue = shared(MemoryQueue::new());
    let store = Arc::new(Store {
        queue: Some(queue.clone()),
        ..Store::default()
    });
    let bob = format!("{origin}/users/bob");

    let activity = flood_under(&origin, 1, 2_500, 1_024);
    let request = post(&bob, &activity);
    assert!(request.1.len() < MAX_INBOX_BODY, "{}", request.1.len());
    let (status, body) = deliver(&federation, &store, request).await;
    assert_eq!(status, 422, "{body}");
    // The public collection, 2,500 actors, and our followers collection.
    assert_eq!(body, "refused: 2502 recipients, more than 1000");
    nothing_came_of_it(&federation, &store, queue.clone(), &remote).await;
    let errors = errors.lock().unwrap().clone();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with(&format!("inbox refused {bob}/notes/1/activity by {bob}: ")),
        "{errors:?}"
    );

    // Mentions alone, not one of them addressed, are refused as well.
    let mut activity = flood_under(&origin, 2, 2_500, 1_024);
    activity["to"] = json!("https://www.w3.org/ns/activitystreams#Public");
    activity["object"]["to"] = activity["to"].clone();
    let (status, body) = deliver(&federation, &store, post(&bob, &activity)).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body, "refused: 2500 tags, more than 1000");

    // And so is content alone.
    let mut activity = flood_under(&origin, 3, 0, 1_024);
    activity["to"] = json!("https://www.w3.org/ns/activitystreams#Public");
    activity["object"]["to"] = activity["to"].clone();
    let (status, body) = deliver(&federation, &store, post(&bob, &activity)).await;
    assert_eq!(status, 422, "{body}");
    assert!(body.starts_with("refused: content of "), "{body}");
    nothing_came_of_it(&federation, &store, queue, &remote).await;
}

/// A context can name `tag` anything: what the activity reads as is held to
/// the limits too, before any listener or forward.
#[tokio::test]
async fn mentions_under_another_name_are_refused_once_read() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let errors = Arc::default();
    let federation = federation(errors, |b| b);
    let queue = shared(MemoryQueue::new());
    let store = Arc::new(Store {
        queue: Some(queue.clone()),
        ..Store::default()
    });
    let bob = format!("{origin}/users/bob");

    let mut activity = flood(&origin, 1, 600, 0);
    activity["@context"] = json!([
        "https://www.w3.org/ns/activitystreams",
        {"tagged": "as:tag"}
    ]);
    let object = activity["object"].as_object_mut().unwrap();
    let tags = object.remove("tag").unwrap();
    object.insert("tagged".into(), tags);
    activity["to"] = json!("https://www.w3.org/ns/activitystreams#Public");
    activity["object"]["to"] = activity["to"].clone();

    let (status, body) = deliver(&federation, &store, post(&bob, &activity)).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body, "refused: 600 mentions, more than 500");
    // Bob's key is all that was fetched, to authenticate it.
    assert_eq!(remote.requests(), vec!["/users/bob".to_owned()]);
    remote.requests.lock().unwrap().clear();
    nothing_came_of_it(&federation, &store, queue, &remote).await;
}

/// With the limits off, the flood under a megabyte reaches the listener —
/// and still ojak fetches nothing but its sender's key, and forwards it
/// once, to the one collection of ours it is addressed to.
#[tokio::test]
async fn an_accepted_flood_costs_one_key_fetch() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let errors = Arc::default();
    let federation = federation(errors, |b| b.payload_limits(PayloadLimits::UNLIMITED));
    let queue = shared(MemoryQueue::new());
    let store = Arc::new(Store {
        queue: Some(queue.clone()),
        ..Store::default()
    });
    let bob = format!("{origin}/users/bob");

    let activity = flood_under(&origin, 1, 2_500, 1_024);
    let (status, body) = deliver(&federation, &store, post(&bob, &activity)).await;
    assert_eq!(status, 202, "{body}");
    let worker = InboxWorker::new(federation.clone(), store.clone(), queue.clone());
    assert_eq!(worker.run_once().await.unwrap(), 1, "queued once");
    assert_eq!(worker.run_once().await.unwrap(), 0);
    assert_eq!(store.seen.lock().unwrap().len(), 1);
    assert_eq!(store.forwarded.lock().unwrap().len(), 1);
    assert_eq!(remote.requests(), vec!["/users/bob".to_owned()]);
}

/// Limits the application sets apply, to the inbox and to its worker.
#[tokio::test]
async fn an_applications_own_limits_apply() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let bob = format!("{origin}/users/bob");
    let errors = Arc::default();
    let strict = PayloadLimits {
        max_mentions: 3,
        ..PayloadLimits::default()
    };
    let loose = federation(Arc::default(), |b| b);
    let federation = federation(errors, |b| b.payload_limits(strict));
    let queue = shared(MemoryQueue::new());
    let store = Arc::new(Store {
        queue: Some(queue.clone()),
        ..Store::default()
    });
    let (status, _) = deliver(&federation, &store, post(&bob, &flood(&origin, 1, 3, 0))).await;
    assert_eq!(status, 202);
    let (status, body) = deliver(&federation, &store, post(&bob, &flood(&origin, 2, 4, 0))).await;
    assert_eq!(
        (status, body.as_str()),
        (422, "refused: 4 mentions, more than 3")
    );

    // Queued under looser limits, it is refused by a worker under these.
    let (status, _) = deliver(&loose, &store, post(&bob, &flood(&origin, 3, 4, 0))).await;
    assert_eq!(status, 202);
    let worker = InboxWorker::new(federation.clone(), store.clone(), queue);
    assert_eq!(worker.run_once().await.unwrap(), 2);
    let seen = store.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "only the first");
    assert_eq!(seen[0]["id"], format!("{bob}/notes/1/activity"));
}

/// An activity addressed to more of our collections than the bound is
/// forwarded to none of them.
#[tokio::test]
async fn forwarding_to_many_of_our_collections_is_refused() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let bob = format!("{origin}/users/bob");
    let errors: Arc<Mutex<Vec<String>>> = Arc::default();
    let federation = federation(Arc::clone(&errors), |b| b);
    let store = App::default();
    let followers = |n: u32| format!("https://{HOST}/ap/users/{n}/followers");

    let mut two = flood(&origin, 1, 1, 0);
    two["cc"] = json!([followers(1), followers(2)]);
    let mut three = flood(&origin, 2, 1, 0);
    three["cc"] = json!([followers(1), followers(2), followers(3)]);
    for activity in [&two, &three] {
        let (status, body) = deliver(&federation, &store, post(&bob, activity)).await;
        assert_eq!(status, 202, "{body}");
    }
    let forwarded = store.forwarded.lock().unwrap().clone();
    assert_eq!(forwarded.len(), 1, "{forwarded:?}");
    assert_eq!(forwarded[0].activity["id"], two["id"]);
    assert_eq!(store.seen.lock().unwrap().len(), 2, "both processed");
    let errors = errors.lock().unwrap().clone();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("addressed to 3 collections of ours, more than 2")),
        "{errors:?}"
    );
}

/// A document fetched is held to the fetcher's limits, and one over a
/// megabyte to the client's.
#[tokio::test]
async fn a_fetched_flood_is_refused() {
    let remote = Remote::default();
    let origin = serve(remote.clone()).await;
    let fetcher = Fetcher::new(client(), Scheme::DraftCavage);

    let note = |activity: Value| {
        let mut note = activity["object"].clone();
        note["@context"] = json!("https://www.w3.org/ns/activitystreams");
        note
    };
    let mut under = note(flood_under(&origin, 1, 2_500, 1_024));
    under["id"] = json!(format!("{origin}/notes/under"));
    remote.serve_document("under", &under);
    let mut over = note(flood(&origin, 2, 7_806, 5_850_000));
    over["id"] = json!(format!("{origin}/notes/over"));
    remote.serve_document("over", &over);

    let url = Url::parse(&format!("{origin}/notes/under")).unwrap();
    for result in [
        fetcher.document(&url, None).await.map(|d| d.json),
        fetcher.document_at(&url, None).await.map(|d| d.json),
        fetcher.lookup(&url, None).await.map(|d| d.json),
        fetcher
            .unverified_json(&url, None)
            .await
            .map(Option::unwrap_or_default),
    ] {
        match result {
            Err(FetchError::Oversized(exceeded)) => {
                assert_eq!(exceeded.limit, Limit::Tags);
                assert_eq!(exceeded.found, 2_500);
            }
            other => panic!("{other:?}"),
        }
    }
    let lenient =
        Fetcher::new(client(), Scheme::DraftCavage).with_payload_limits(PayloadLimits::UNLIMITED);
    assert!(lenient.document(&url, None).await.is_ok());

    let url = Url::parse(&format!("{origin}/notes/over")).unwrap();
    assert!(matches!(
        fetcher.document(&url, None).await,
        Err(FetchError::Request(RequestError::TooLarge))
    ));
    assert_eq!(
        remote.requests().len(),
        6,
        "one request a fetch, and none for any mention: {:?}",
        remote.requests()
    );
}
