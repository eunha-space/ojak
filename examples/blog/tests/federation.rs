//! The blog federating with a reader on another server: the reader follows,
//! is sent each new post, replies, likes, deletes the reply and unfollows.
//!
//! The reader's server is Ojak's [`Remote`], on the loopback interface,
//! which the blog's client is allowed to reach here; it signs what it sends
//! the way a real server would. The blog is `blog.test`, reached without a
//! network.

use axum::body::{Body, to_bytes};
use http::{Request, StatusCode};
use ojak::testing::{PRIVATE_KEY_PEM, PUBLIC_KEY_PEM, Remote, client_config};
use ojak_example_blog::{App, Blog, Config, router};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const BLOG: &str = "https://blog.test";

fn blog() -> App {
    Blog::new(Config {
        origin: BLOG.parse().unwrap(),
        username: "blog".to_owned(),
        title: "A test blog".to_owned(),
        token: "secret".to_owned(),
        private_key_pem: PRIVATE_KEY_PEM.to_owned(),
        public_key_pem: PUBLIC_KEY_PEM.to_owned(),
        // The reader's server is on the loopback interface, which a real
        // client refuses to reach.
        client: client_config(),
    })
    .unwrap()
}

// #region send
/// `activity`, delivered to the blog's inbox by the reader's server, signed
/// by the reader.
async fn send(blog: &App, remote: &Remote, activity: &Value) -> StatusCode {
    let request = remote.sign("reader", &format!("{BLOG}/users/blog/inbox"), activity);
    router(blog.clone())
        .oneshot(request.map(Body::from))
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
    let remote = Remote::start().await;
    let reader = remote.actor("reader");
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
        "actor": reader.as_str(),
        "object": author,
    });
    assert_eq!(send(&blog, &remote, &follow).await, StatusCode::ACCEPTED);
    assert_eq!(blog.store().follower_count(), 1);

    // The blog accepts, delivering to the reader's shared inbox.
    blog.deliverer.run_once().await.unwrap();
    let accept = remote.received().pop().expect("an Accept");
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
    let create = remote.received().pop().expect("a Create");
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
        "actor": reader.as_str(),
        "object": {
            "id": note,
            "type": "Note",
            "attributedTo": reader.as_str(),
            "inReplyTo": post,
            "content": "<p>Nice <b>post</b>!</p><script>alert(1)</script>",
        },
    });
    assert_eq!(send(&blog, &remote, &reply).await, StatusCode::ACCEPTED);
    let like = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{reader}/likes/1"),
        "type": "Like",
        "actor": reader.as_str(),
        "object": post,
    });
    assert_eq!(send(&blog, &remote, &like).await, StatusCode::ACCEPTED);
    let (_, html) = get_page(&blog, "/posts/1", "text/html").await;
    assert!(html.contains("Nice post!"), "{html}");
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("♥ 1"), "{html}");

    // The reader deletes the reply, and unfollows.
    let delete = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{note}#delete"),
        "type": "Delete",
        "actor": reader.as_str(),
        "object": {"id": note, "type": "Tombstone"},
    });
    assert_eq!(send(&blog, &remote, &delete).await, StatusCode::ACCEPTED);
    assert!(blog.store().comments(1).is_empty());
    let undo = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{reader}/follows/1/undo"),
        "type": "Undo",
        "actor": reader.as_str(),
        "object": follow,
    });
    assert_eq!(send(&blog, &remote, &undo).await, StatusCode::ACCEPTED);
    assert_eq!(blog.store().follower_count(), 0);
}

#[tokio::test]
async fn an_unsigned_activity_is_refused() {
    let blog = blog();
    let request = Request::post("/users/blog/inbox")
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
