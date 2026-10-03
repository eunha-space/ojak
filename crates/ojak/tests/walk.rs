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
    if path.starts_with("unavailable") {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("content-type", "text/plain")],
            String::new(),
        );
    }
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

#[tokio::test]
async fn a_collection_is_walked_a_page_at_a_time() {
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
        ("outbox/page/1", page(1, &["a", "b", "c"], Some(2))),
        ("outbox/page/2", page(2, &["d"], Some(3))),
        ("outbox/page/3", page(3, &["e"], None)),
    ])
    .await;
    let url = Url::parse(&format!("{base}/outbox")).unwrap();

    // The item limit ends the walk at the end of the page that reaches it.
    let fetcher = fetcher();
    let mut walk = fetcher.walk(
        &url,
        None,
        WalkLimits {
            pages: 100,
            items: 2,
        },
    );
    assert_eq!(
        walk.next_page().await.unwrap(),
        Some(vec![json!("a"), json!("b"), json!("c")])
    );
    assert_eq!(walk.pages_fetched(), 2);
    assert_eq!(walk.next_page().await.unwrap(), None);
    assert_eq!(server.asked.lock().unwrap().len(), 2);

    // A page's items are handed out whole, after any `next` left unread.
    let mut walk = fetcher.walk(&url, None, WalkLimits::default());
    assert_eq!(walk.next().await.unwrap(), Some(json!("a")));
    assert_eq!(
        walk.next_page().await.unwrap(),
        Some(vec![json!("b"), json!("c")])
    );
    assert_eq!(walk.next_page().await.unwrap(), Some(vec![json!("d")]));
    assert_eq!(walk.next_page().await.unwrap(), Some(vec![json!("e")]));
    assert_eq!(walk.next_page().await.unwrap(), None);
}

#[tokio::test]
async fn a_collection_without_pages_is_one_page_even_when_empty() {
    let (_, base) = serve(&[(
        "empty",
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "{base}/empty",
            "type": "Collection",
            "totalItems": 0,
        }),
    )])
    .await;
    let url = Url::parse(&format!("{base}/empty")).unwrap();
    let fetcher = fetcher();
    let mut walk = fetcher.walk(&url, None, WalkLimits::default());
    assert_eq!(walk.next_page().await.unwrap(), Some(vec![]));
    assert_eq!(walk.next_page().await.unwrap(), None);
}

#[tokio::test]
async fn an_embedded_collection_is_read_in_hand_and_kept_to_its_embedder() {
    let (server, base) = serve(&[(
        "notes/1/replies/2",
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "{base}/notes/1/replies/2",
            "type": "CollectionPage",
            "items": ["{base}/notes/3"],
        }),
    )])
    .await;
    let note = format!("{base}/notes/1");
    let replies = json!({
        "id": format!("{base}/notes/1/replies"),
        "type": "Collection",
        "first": {
            "type": "CollectionPage",
            "items": [format!("{base}/notes/2")],
            "next": format!("{base}/notes/1/replies/2"),
        },
    });
    let fetcher = fetcher();
    let mut walk = fetcher.walk_embedded(&replies, &note, None, WalkLimits::default());
    assert_eq!(
        walk.next_page().await.unwrap(),
        Some(vec![json!(format!("{base}/notes/2"))])
    );
    assert!(
        server.asked.lock().unwrap().is_empty(),
        "the first page came embedded"
    );
    assert_eq!(
        walk.next_page().await.unwrap(),
        Some(vec![json!(format!("{base}/notes/3"))])
    );
    assert_eq!(walk.next_page().await.unwrap(), None);

    // Neither the collection nor its pages are fetched from elsewhere.
    let elsewhere = json!("https://elsewhere.example/notes/1/replies");
    let walked = fetcher
        .walk_embedded(&elsewhere, &note, None, WalkLimits::default())
        .collect()
        .await;
    assert!(matches!(walked, Err(FetchError::Invalid(_))), "{walked:?}");
    let pointing_elsewhere = json!({
        "type": "Collection",
        "first": "https://elsewhere.example/notes/1/replies/1",
    });
    let walked = fetcher
        .walk_embedded(&pointing_elsewhere, &note, None, WalkLimits::default())
        .collect()
        .await;
    assert!(matches!(walked, Err(FetchError::Invalid(_))), "{walked:?}");
    assert_eq!(server.asked.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn by_host_a_page_on_another_port_of_the_host_is_followed() {
    let (_, base) = serve(&[("outbox/page/1", page(1, &["a"], None))]).await;
    let port = Url::parse(&base).unwrap().port().unwrap();
    // The embedder names the same host on another port.
    let embedder = format!("http://127.0.0.1:{}/notes/1", port.wrapping_add(1));
    let collection = json!({
        "type": "OrderedCollection",
        "first": format!("{base}/outbox/page/1"),
    });
    let fetcher = fetcher();
    let by_origin = fetcher
        .walk_embedded(&collection, &embedder, None, WalkLimits::default())
        .collect()
        .await;
    assert!(matches!(by_origin, Err(FetchError::Invalid(_))));
    let by_host = fetcher
        .walk_embedded(&collection, &embedder, None, WalkLimits::default())
        .by_host()
        .collect()
        .await
        .unwrap();
    assert_eq!(by_host, [json!("a")]);
}

#[tokio::test]
async fn a_mastodon_compatible_walk_reads_as_mastodon_does() {
    let (server, base) = serve(&[
        (
            "replies",
            json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": "{base}/replies",
                "type": "Collection",
                // Ignored, since `first` is present.
                "items": ["ignored"],
                "first": "{base}/replies/1",
            }),
        ),
        // Whatever its id and type say, a page is what was served.
        (
            "replies/1",
            json!({
                "id": "https://elsewhere.example/page",
                "type": "CollectionPage",
                "items": ["a"],
                "orderedItems": ["not read"],
                "next": {
                    "id": "https://elsewhere.example/embedded",
                    "type": "OrderedCollectionPage",
                    "orderedItems": ["b"],
                    "next": "{base}/replies/3",
                },
            }),
        ),
        (
            "replies/3",
            json!({"type": "Page", "items": ["c"], "next": "https://elsewhere.example/4"}),
        ),
    ])
    .await;
    let fetcher = fetcher();
    let note = format!("{base}/notes/1");
    let collection = json!(format!("{base}/replies"));
    let mut walk = fetcher
        .walk_embedded(&collection, &note, None, WalkLimits::default())
        .mastodon_compatible();
    assert_eq!(walk.next_page().await.unwrap(), Some(vec![json!("a")]));
    assert_eq!(walk.next_page().await.unwrap(), Some(vec![json!("b")]));
    // A page of no type Mastodon reads holds nothing.
    assert_eq!(walk.next_page().await.unwrap(), Some(vec![]));
    // A page on another host ends the walk.
    assert_eq!(walk.next_page().await.unwrap(), None);
    assert_eq!(server.asked.lock().unwrap().len(), 3);

    // A failure the server answers with is the caller's to judge.
    let unavailable = json!(format!("{base}/unavailable"));
    let walked = fetcher
        .walk_embedded(&unavailable, &note, None, WalkLimits::default())
        .mastodon_compatible()
        .next_page()
        .await;
    assert!(matches!(walked, Err(FetchError::Status(503))), "{walked:?}");
}

#[test]
fn hosts_are_compared_as_mastodon_compares_them() {
    use ojak::origin::same_host;
    assert!(same_host(
        "https://a.example/users/x",
        "http://A.example:8443/notes/1"
    ));
    assert!(!same_host(
        "https://a.example/users/x",
        "https://b.example/notes/1"
    ));
    assert!(!same_host(
        "https://a.example/users/x",
        "ftp://a.example/notes/1"
    ));
}
