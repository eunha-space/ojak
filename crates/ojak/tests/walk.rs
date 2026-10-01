//! Walking a collection served on the loopback interface, a page at a time.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use ojak::client::{Client, ClientConfig};
use ojak::fetch::{FetchError, Fetcher, WalkLimits};
use ojak::sig::Scheme;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use url::Url;

/// Documents by path, with `{base}` in them standing for the server's
/// origin; and the paths asked for.
#[derive(Clone, Default)]
struct Server {
    documents: Arc<Mutex<HashMap<String, String>>>,
    asked: Arc<Mutex<Vec<String>>>,
    base: Arc<Mutex<String>>,
}

async fn document(
    State(server): State<Server>,
    Path(path): Path<String>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    server.asked.lock().unwrap().push(path.clone());
    let base = server.base.lock().unwrap().clone();
    match server.documents.lock().unwrap().get(&path) {
        Some(document) => (
            StatusCode::OK,
            [("content-type", "application/activity+json")],
            document.replace("{base}", &base),
        ),
        None => (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain")],
            String::new(),
        ),
    }
}

async fn serve(documents: &[(&str, Value)]) -> (Server, String) {
    let server = Server::default();
    for (path, document) in documents {
        server
            .documents
            .lock()
            .unwrap()
            .insert((*path).to_owned(), document.to_string());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    *server.base.lock().unwrap() = base.clone();
    let app = Router::new()
        .route("/{*path}", get(document))
        .with_state(server.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (server, base)
}

fn fetcher() -> Fetcher {
    Fetcher::new(
        Client::new(ClientConfig {
            allow_private: vec!["127.0.0.0/8".parse().unwrap()],
            ..ClientConfig::default()
        })
        .unwrap(),
        Scheme::DraftCavage,
    )
}

fn page(n: u32, items: &[&str], next: Option<u32>) -> Value {
    let mut page = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{{base}}/outbox/page/{n}"),
        "type": "OrderedCollectionPage",
        "partOf": "{base}/outbox",
        "orderedItems": items,
    });
    if let Some(next) = next {
        page["next"] = json!(format!("{{base}}/outbox/page/{next}"));
    }
    page
}

#[tokio::test]
async fn a_collection_is_walked_page_by_page_as_its_items_are_wanted() {
    let (server, base) = serve(&[
        (
            "outbox",
            json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": "{base}/outbox",
                "type": "OrderedCollection",
                "totalItems": 5,
                // Mastodon embeds no page; Misskey and others embed the first.
                "first": page(1, &["a", "b"], Some(2)),
            }),
        ),
        ("outbox/page/2", page(2, &["c", "d"], Some(3))),
        ("outbox/page/3", page(3, &["e"], None)),
    ])
    .await;
    let fetcher = fetcher();
    let url = Url::parse(&format!("{base}/outbox")).unwrap();

    let mut walk = fetcher.walk(&url, None, WalkLimits::default());
    assert_eq!(walk.next().await.unwrap(), Some(json!("a")));
    assert_eq!(walk.total(), Some(5));
    assert_eq!(
        server.asked.lock().unwrap().len(),
        1,
        "the first page came embedded"
    );
    let rest = walk.collect().await.unwrap();
    assert_eq!(rest, [json!("b"), json!("c"), json!("d"), json!("e")]);

    let first_three = fetcher
        .walk(
            &url,
            None,
            WalkLimits {
                pages: 100,
                items: 3,
            },
        )
        .collect()
        .await
        .unwrap();
    assert_eq!(first_three.len(), 3);
}

#[tokio::test]
async fn a_page_on_another_origin_is_not_followed() {
    let (_, base) = serve(&[(
        "outbox",
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "{base}/outbox",
            "type": "OrderedCollection",
            "first": "https://elsewhere.example/outbox/page/1",
        }),
    )])
    .await;
    let url = Url::parse(&format!("{base}/outbox")).unwrap();
    let walked = fetcher()
        .walk(&url, None, WalkLimits::default())
        .collect()
        .await;
    assert!(matches!(walked, Err(FetchError::Invalid(_))), "{walked:?}");
}

#[tokio::test]
async fn a_loop_of_pages_is_walked_once() {
    let (server, base) = serve(&[
        (
            "outbox",
            json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": "{base}/outbox",
                "type": "OrderedCollection",
                "first": "{base}/outbox/page/1",
            }),
        ),
        ("outbox/page/1", page(1, &["a"], Some(2))),
        ("outbox/page/2", page(2, &["b"], Some(1))),
    ])
    .await;
    let url = Url::parse(&format!("{base}/outbox")).unwrap();
    let items = fetcher()
        .walk(&url, None, WalkLimits::default())
        .collect()
        .await
        .unwrap();
    assert_eq!(items, [json!("a"), json!("b")]);
    assert_eq!(server.asked.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn what_is_not_a_collection_is_not_walked() {
    let (_, base) = serve(&[(
        "note",
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "{base}/note",
            "type": "Note",
        }),
    )])
    .await;
    let url = Url::parse(&format!("{base}/note")).unwrap();
    assert!(matches!(
        fetcher()
            .walk(&url, None, WalkLimits::default())
            .next()
            .await,
        Err(FetchError::Invalid(_))
    ));
}
