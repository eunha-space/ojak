//! Finding what software another server runs, from its NodeInfo.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use ojak::client::{Client, ClientConfig};
use ojak::fetch::{FetchError, Fetcher};
use ojak::sig::Scheme;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

type Documents = Arc<HashMap<String, String>>;

async fn document(
    State(documents): State<(Documents, String)>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    let (documents, base) = documents;
    match documents.get(&path) {
        Some(document) => (StatusCode::OK, document.replace("{base}", &base)),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

async fn serve(documents: &[(&str, Value)]) -> Url {
    let documents: Documents = Arc::new(
        documents
            .iter()
            .map(|(path, document)| ((*path).to_owned(), document.to_string()))
            .collect(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/{*path}", get(document))
        .with_state((documents, base.clone()));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&base).unwrap()
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

#[tokio::test]
async fn the_newest_schema_linked_is_read() {
    let origin = serve(&[
        (
            ".well-known/nodeinfo",
            json!({"links": [
                {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.0", "href": "{base}/nodeinfo/2.0"},
                {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": "/nodeinfo/2.1"},
                {"rel": "https://www.w3.org/ns/activitystreams#Application", "href": "{base}/actor"},
            ]}),
        ),
        (
            "nodeinfo/2.1",
            json!({
                "version": "2.1",
                "software": {"name": "Mastodon", "version": "4.7.2", "repository": "https://github.com/mastodon/mastodon"},
                "protocols": ["activitypub"],
                "services": {"inbound": [], "outbound": []},
                "openRegistrations": true,
                "usage": {"users": {"total": 12, "activeMonth": 3}, "localPosts": 400},
                "metadata": {"nodeName": "A server"},
            }),
        ),
    ])
    .await;

    let nodeinfo = fetcher().nodeinfo(&origin).await.unwrap();
    assert_eq!(nodeinfo.software.name, "mastodon");
    assert_eq!(nodeinfo.software.version, "4.7.2");
    assert_eq!(nodeinfo.protocols, ["activitypub"]);
    assert!(nodeinfo.open_registrations);
    assert_eq!(nodeinfo.usage.users_total, Some(12));
    assert_eq!(nodeinfo.usage.users_active_halfyear, None);
    assert_eq!(nodeinfo.usage.local_posts, Some(400));
    assert_eq!(nodeinfo.metadata["nodeName"], "A server");
}

#[tokio::test]
async fn a_link_to_another_host_is_not_followed() {
    let origin = serve(&[(
        ".well-known/nodeinfo",
        json!({"links": [
            {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": "https://elsewhere.example/nodeinfo/2.1"},
        ]}),
    )])
    .await;
    assert!(matches!(
        fetcher().nodeinfo(&origin).await,
        Err(FetchError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_server_without_nodeinfo_says_so() {
    let origin = serve(&[]).await;
    assert!(matches!(
        fetcher().nodeinfo(&origin).await,
        Err(FetchError::Status(404))
    ));
}
