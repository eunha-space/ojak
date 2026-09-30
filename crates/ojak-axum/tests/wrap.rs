//! The adapter in front of an application's router.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use ojak::federation::{Federation, Found};
use serde_json::{Value, json};
use tower::ServiceExt as _;

fn app() -> Router {
    let federation = Federation::builder()
        .origin("https://oeee.test".parse().unwrap())
        .actor("person", "/ap/users/{id}", |_, id: String| async move {
            Ok::<_, String>(Found::Found(
                json!({"id": format!("https://oeee.test/ap/users/{id}")}),
            ))
        })
        .build()
        .unwrap();
    let pages = Router::new()
        .route("/ap/users/{id}", get(|| async { "a page" }))
        .route("/about", get(|| async { "about" }));
    ojak_axum::wrap(pages, federation, |_| Some(()))
}

async fn call(path: &str, accept: &str) -> (StatusCode, Vec<u8>) {
    let response = app()
        .oneshot(
            Request::get(path)
                .header("host", "oeee.test")
                .header("accept", accept)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
}

#[tokio::test]
async fn ojak_answers_activitypub_and_the_application_the_rest() {
    let (status, body) = call("/ap/users/1", "application/activity+json").await;
    assert_eq!(status, StatusCode::OK);
    let actor: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(actor["id"], "https://oeee.test/ap/users/1");

    let (status, body) = call("/ap/users/1", "text/html").await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"a page"[..]));
    let (_, body) = call("/about", "application/activity+json").await;
    assert_eq!(body, b"about");
    let (status, _) = call("/nowhere", "text/html").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(
        "/.well-known/webfinger?resource=https://oeee.test/ap/users/1",
        "*/*",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
}

#[tokio::test]
async fn an_inbox_post_is_read_and_received() {
    use ojak::client::{Client, ClientConfig};
    use ojak::fetch::Fetcher;
    use ojak::kv::MemoryKvStore;
    use ojak::sig::Scheme;
    use std::sync::Arc;
    use std::time::Duration;

    let federation = Federation::builder()
        .origin("https://oeee.test".parse().unwrap())
        .actor("person", "/ap/users/{id}", |_, _: String| async move {
            Ok::<_, String>(Found::NotFound)
        })
        .shared_inbox("/ap/inbox")
        .signed_fetch(
            Arc::new(Fetcher::new(
                Client::new(ClientConfig::default()).unwrap(),
                Scheme::DraftCavage,
            )),
            MemoryKvStore::new(),
            Duration::from_secs(60),
            |_| async { Ok::<_, String>(None) },
        )
        .build()
        .unwrap();
    let app = ojak_axum::wrap(Router::new(), federation, |_| Some(()));
    let post = |body: Vec<u8>| {
        app.clone().oneshot(
            Request::post("/ap/inbox")
                .header("host", "oeee.test")
                .body(Body::from(body))
                .unwrap(),
        )
    };

    let unsigned = post(br#"{"type":"Follow","actor":"https://a.test/users/a"}"#.to_vec())
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    let huge = post(vec![b' '; ojak::federation::MAX_INBOX_BODY + 1])
        .await
        .unwrap();
    assert_eq!(huge.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_page_at_an_activitypub_url_varies_on_accept() {
    let vary = |path: &'static str| async move {
        let response = app()
            .oneshot(
                Request::get(path)
                    .header("host", "oeee.test")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        response
            .headers()
            .get_all("vary")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        vary("/ap/users/1").await,
        vec!["Accept"],
        "a cache must not hand the page to a server asking for the actor"
    );
    assert!(
        vary("/about").await.is_empty(),
        "a page Ojak has no route at is left as it is"
    );
}
