//! Fetching JSON-LD contexts from a real server on the loopback interface,
//! as Mastodon's document loader fetches them.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ojak::client::{Client, ClientConfig, RequestError};
use ojak::contexts::{self, Error};
use ojak::kv::{KvError, KvStore, MemoryKvStore};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How many requests the server answered, and what each asked for.
#[derive(Clone, Default)]
struct Server {
    requests: Arc<AtomicUsize>,
}

async fn handle(
    State(server): State<Server>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    server.requests.fetch_add(1, Ordering::SeqCst);
    let context = json!({"@context": {"mood": "https://contexts.example/ns#mood"}}).to_string();
    match path.as_str() {
        // Only what asks for JSON-LD is answered as JSON-LD.
        "ns" if headers["accept"] == contexts::MEDIA_TYPE => (
            [("content-type", "application/ld+json; charset=utf-8")],
            context,
        )
            .into_response(),
        "ns" => axum::http::StatusCode::NOT_ACCEPTABLE.into_response(),
        "json" => ([("content-type", "application/json")], context).into_response(),
        "moved" => (
            axum::http::StatusCode::FOUND,
            [("location", "/ns")],
            String::new(),
        )
            .into_response(),
        "huge" => (
            [("content-type", "application/ld+json")],
            "x".repeat(contexts::MAX_CONTEXT_BYTES + 1),
        )
            .into_response(),
        _ => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(server: Server) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/{*path}", get(handle))
        .with_state(server);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn client(allow_loopback: bool) -> Client {
    Client::new(ClientConfig {
        allow_private: if allow_loopback {
            vec!["127.0.0.0/8".parse().unwrap()]
        } else {
            Vec::new()
        },
        ..ClientConfig::default()
    })
    .unwrap()
}

#[tokio::test]
async fn a_context_is_fetched_as_json_ld_and_nothing_else() {
    let base = serve(Server::default()).await;
    let client = client(true);

    let body = contexts::fetch(&client, &format!("{base}/ns"))
        .await
        .unwrap();
    assert!(body.contains("contexts.example/ns#mood"), "{body}");
    // Followed through a redirect, as `Request` follows them.
    contexts::fetch(&client, &format!("{base}/moved"))
        .await
        .unwrap();

    let result = contexts::fetch(&client, &format!("{base}/json")).await;
    assert!(
        matches!(&result, Err(Error::MediaType(_, Some(kind))) if kind == "application/json"),
        "{result:?}"
    );
    let result = contexts::fetch(&client, &format!("{base}/missing")).await;
    assert!(matches!(result, Err(Error::Status(_, 404))), "{result:?}");
    let result = contexts::fetch(&client, &format!("{base}/huge")).await;
    assert!(
        matches!(result, Err(Error::Request(_, RequestError::TooLarge))),
        "{result:?}"
    );
    let result = contexts::fetch(&client, "ftp://contexts.example/ns").await;
    assert!(matches!(result, Err(Error::InvalidIri(_))), "{result:?}");
}

#[tokio::test]
async fn a_private_address_is_refused_unless_allowed() {
    let server = Server::default();
    let base = serve(server.clone()).await;
    let result = contexts::fetch(&client(false), &format!("{base}/ns")).await;
    assert!(
        matches!(result, Err(Error::Request(_, RequestError::Refused(_)))),
        "{result:?}"
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_fetched_context_is_kept_and_a_refused_one_is_not() {
    let server = Server::default();
    let base = serve(server.clone()).await;
    let client = client(true);
    let kv = MemoryKvStore::new();
    let ttl = Duration::from_secs(60);

    for _ in 0..2 {
        contexts::fetch_cached(&kv, &client, &format!("{base}/ns"), ttl, |_| {})
            .await
            .unwrap();
    }
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);

    for _ in 0..2 {
        contexts::fetch_cached(&kv, &client, &format!("{base}/json"), ttl, |_| {})
            .await
            .unwrap_err();
    }
    assert_eq!(server.requests.load(Ordering::SeqCst), 3);
}

/// A store that fails every read and write.
struct Broken;

impl KvStore for Broken {
    async fn get(&self, _: &[&str]) -> Result<Option<serde_json::Value>, KvError> {
        Err(KvError("down".into()))
    }
    async fn set(
        &self,
        _: &[&str],
        _: serde_json::Value,
        _: Option<Duration>,
    ) -> Result<(), KvError> {
        Err(KvError("down".into()))
    }
    async fn insert(
        &self,
        _: &[&str],
        _: serde_json::Value,
        _: Option<Duration>,
    ) -> Result<bool, KvError> {
        Err(KvError("down".into()))
    }
    async fn delete(&self, _: &[&str]) -> Result<(), KvError> {
        Err(KvError("down".into()))
    }
}

/// A store that cannot be reached is a miss, as `Rails.cache` takes a Redis
/// it cannot reach: the context is fetched, and the failures are reported.
#[tokio::test]
async fn a_failing_store_is_a_miss() {
    let server = Server::default();
    let base = serve(server.clone()).await;
    let mut failures = Vec::new();
    let body = contexts::fetch_cached(
        &Broken,
        &client(true),
        &format!("{base}/ns"),
        Duration::from_secs(60),
        |error| failures.push(error),
    )
    .await
    .unwrap();
    assert!(body.contains("@context"));
    assert_eq!(failures.len(), 2, "the read and the write");
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}
