//! The blog federating with a reader on another server: the reader follows,
//! is sent each new post, replies, likes, deletes the reply and unfollows.
//!
//! The reader's server runs on the loopback interface, which the blog's
//! client is allowed to reach here, and signs what it sends the way a real
//! server would. The blog is `blog.test`, reached without a network.

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::routing::{get, post};
use http::{Request, StatusCode};
use ojak::client::ClientConfig;
use ojak::sig::signature::{PrivateKey, sign_request_with_key};
use ojak_example_blog::{App, Blog, Config, activitypub, router};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;

const PRIVATE_KEY: &str =
    include_str!("../../../crates/ojak/tests/fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str =
    include_str!("../../../crates/ojak/tests/fixtures/rfc9421_test_key_rsa_public.pem");
const BLOG: &str = "https://blog.test";
const INBOX: &str = "/users/blog/inbox";

/// What the reader's server was sent.
type Received = Arc<Mutex<Vec<Value>>>;

// #region reader
/// The reader's server: their actor, and an inbox that keeps what arrives.
async fn serve_reader(received: Received) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let actor = json!({
        "@context": ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
        "id": format!("{origin}/users/reader"),
        "type": "Person",
        "preferredUsername": "reader",
        "inbox": format!("{origin}/users/reader/inbox"),
        "endpoints": {"sharedInbox": format!("{origin}/inbox")},
        "publicKey": {
            "id": format!("{origin}/users/reader#main-key"),
            "owner": format!("{origin}/users/reader"),
            "publicKeyPem": PUBLIC_KEY,
        },
    });
    let app = Router::new()
        .route(
            "/users/reader",
            get(move || async move {
                (
                    [("content-type", "application/activity+json")],
                    actor.to_string(),
                )
            }),
        )
        .route(
            "/inbox",
            post(|State(received): State<Received>, body: Bytes| async move {
                received
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                StatusCode::ACCEPTED
            }),
        )
        .with_state(received);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("{origin}/users/reader")
}
// #endregion reader

fn blog() -> App {
    Blog::new(Config {
        origin: BLOG.parse().unwrap(),
        username: "blog".to_owned(),
        title: "A test blog".to_owned(),
        token: "secret".to_owned(),
        private_key_pem: PRIVATE_KEY.to_owned(),
        public_key_pem: PUBLIC_KEY.to_owned(),
        client: ClientConfig {
            allow_private: vec!["127.0.0.0/8".parse().unwrap()],
            ..ClientConfig::default()
        },
    })
    .unwrap()
}

// #region send
/// `activity`, POSTed to the blog's inbox and signed by the reader.
async fn send(blog: &App, reader: &str, activity: &Value) -> StatusCode {
    let body = serde_json::to_vec(activity).unwrap();
    let signed = sign_request_with_key(
        "post",
        &format!("{BLOG}{INBOX}"),
        &body,
        &format!("{reader}#main-key"),
        &PrivateKey::from_pem(PRIVATE_KEY).unwrap(),
        &[],
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let request = Request::post(INBOX)
        .header("host", "blog.test")
        .header("content-type", "application/activity+json")
        .header("date", signed.date)
        .header("digest", signed.digest)
        .header("signature", signed.signature)
        .body(Body::from(body))
        .unwrap();
    router(blog.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status()
}
// #endregion send

async fn get_page(blog: &App, path: &str, accept: &str) -> (StatusCode, String) {
    let request = Request::get(path)
        .header("host", "blog.test")
        .header("accept", accept)
        .body(Body::empty())
        .unwrap();
    let response = router(blog.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn a_reader_follows_reads_replies_likes_and_leaves() {
    let received = Received::default();
    let reader = serve_reader(received.clone()).await;
    let blog = blog();
    let author = format!("{BLOG}/users/blog");

    // The reader finds the blog by its handle, and follows it.
    let (status, jrd) = get_page(
        &blog,
        "/.well-known/webfinger?resource=acct:blog@blog.test",
        "*/*",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&jrd).unwrap()["links"][0]["href"],
        author
    );
    let follow = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{reader}/follows/1"),
        "type": "Follow",
        "actor": reader,
        "object": author,
    });
    assert_eq!(send(&blog, &reader, &follow).await, StatusCode::ACCEPTED);
    assert_eq!(blog.store().follower_count(), 1);

    // The blog accepts, delivering to the reader's shared inbox.
    blog.deliverer.run_once().await.unwrap();
    let accept = received.lock().unwrap().pop().expect("an Accept");
    assert_eq!(accept["type"], "Accept");
    assert_eq!(accept["actor"], author);
    assert_eq!(accept["object"]["id"], follow["id"]);

    // The author publishes, and the reader is sent the post.
    let request = Request::post("/api/posts")
        .header("host", "blog.test")
        .header("authorization", "Bearer secret")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"title": "Hello", "body": "First post.\n\nWith two paragraphs."}).to_string(),
        ))
        .unwrap();
    let response = router(blog.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    blog.deliverer.run_once().await.unwrap();
    let create = received.lock().unwrap().pop().expect("a Create");
    assert_eq!(create["type"], "Create");
    assert_eq!(create["object"]["type"], "Article");
    assert_eq!(create["object"]["name"], "Hello");
    let post = create["object"]["id"].as_str().unwrap().to_owned();
    assert_eq!(post, format!("{BLOG}/posts/1"));

    // The post's URL serves the Article to a server and a page to a browser.
    let (_, document) = get_page(&blog, "/posts/1", "application/activity+json").await;
    assert_eq!(
        serde_json::from_str::<Value>(&document).unwrap()["id"],
        post
    );
    let (_, html) = get_page(&blog, "/posts/1", "text/html").await;
    assert!(html.contains("<p>With two paragraphs.</p>"), "{html}");

    // The reader replies, and likes the post.
    let note = format!("{reader}/notes/1");
    let reply = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{note}/activity"),
        "type": "Create",
        "actor": reader,
        "object": {
            "id": note,
            "type": "Note",
            "attributedTo": reader,
            "inReplyTo": post,
            "content": "<p>Nice <b>post</b>!</p><script>alert(1)</script>",
        },
    });
    assert_eq!(send(&blog, &reader, &reply).await, StatusCode::ACCEPTED);
    let like = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{reader}/likes/1"),
        "type": "Like",
        "actor": reader,
        "object": post,
    });
    assert_eq!(send(&blog, &reader, &like).await, StatusCode::ACCEPTED);
    let (_, html) = get_page(&blog, "/posts/1", "text/html").await;
    assert!(html.contains("Nice post!"), "{html}");
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("♥ 1"), "{html}");

    // The reader deletes the reply, and unfollows.
    let delete = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{note}#delete"),
        "type": "Delete",
        "actor": reader,
        "object": {"id": note, "type": "Tombstone"},
    });
    assert_eq!(send(&blog, &reader, &delete).await, StatusCode::ACCEPTED);
    assert!(blog.store().comments(1).is_empty());
    let undo = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{reader}/follows/1/undo"),
        "type": "Undo",
        "actor": reader,
        "object": follow,
    });
    assert_eq!(send(&blog, &reader, &undo).await, StatusCode::ACCEPTED);
    assert_eq!(blog.store().follower_count(), 0);
}

#[tokio::test]
async fn an_unsigned_activity_is_refused() {
    let blog = blog();
    let request = Request::post(INBOX)
        .header("host", "blog.test")
        .body(Body::from(
            json!({"type": "Follow", "actor": "https://elsewhere.test/users/x"}).to_string(),
        ))
        .unwrap();
    let status = router(blog.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(blog.store().follower_count(), 0);
}

#[tokio::test]
async fn publishing_takes_the_token() {
    let blog = blog();
    let request = Request::post("/api/posts")
        .header("host", "blog.test")
        .header("content-type", "application/json")
        .body(Body::from(json!({"title": "x", "body": "y"}).to_string()))
        .unwrap();
    let status = router(blog.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(blog.store().posts().count(), 0);
}

#[test]
fn the_key_is_named_after_the_author_the_federation_serves() {
    let blog = blog();
    let served = blog
        .context()
        .actor_uri(activitypub::AUTHOR, &blog.config.username)
        .unwrap();
    assert_eq!(
        activitypub::author_id(&blog.config).unwrap(),
        served,
        "the key ID and the actor's IRI agree"
    );
}

#[tokio::test]
async fn the_compose_page_publishes_with_the_token() {
    let blog = blog();
    let form = |token: &str| {
        Request::post("/new")
            .header("host", "blog.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "title=Hi&body=From+the+form&token={token}"
            )))
            .unwrap()
    };
    let refused = router(blog.clone()).oneshot(form("wrong")).await.unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let published = router(blog.clone()).oneshot(form("secret")).await.unwrap();
    assert_eq!(published.status(), StatusCode::SEE_OTHER);
    assert_eq!(published.headers()["location"], "/posts/1");
    assert_eq!(blog.store().post(1).unwrap().body, "From the form");
}
