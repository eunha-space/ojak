//! Fetching from a real server on the loopback interface.
//!
//! `127.0.0.1` and `localhost` are two origins on one server, which is how
//! these tests serve a document from one origin that claims to be from
//! another.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ojak::client::{Client, ClientConfig, RequestError};
use ojak::fetch::{FetchError, Fetcher};
use ojak::sig::signature::PrivateKey;
use ojak::sig::verification::{self, Key, Request};
use ojak::sig::{Scheme, SenderKey};
use serde_json::json;
use std::sync::{Arc, Mutex};
use url::Url;

const PRIVATE_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa_public.pem");
const KEY_ID: &str = "https://ojak.example/actor#main-key";

/// A request the server saw.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    /// The scheme it was signed in, if it was signed.
    scheme: Option<Scheme>,
    /// Whether the signature verified for the path it arrived at. The
    /// verifier rebuilds an RFC 9421 `@target-uri` as `https`, as a server
    /// behind TLS termination must, so over this plain-http server an RFC
    /// 9421 signature counts as verified when it is present; the verifier's
    /// own tests cover the rest.
    verified: bool,
}

#[derive(Clone, Default)]
struct Server {
    seen: Arc<Mutex<Vec<Seen>>>,
    /// Refuse draft-cavage with 401, as a server that verifies only RFC 9421
    /// does.
    only_rfc9421: bool,
    /// Refuse a request that is not signed.
    authorized_fetch: bool,
}

impl Server {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn check(uri: &Uri, headers: &HeaderMap) -> Seen {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
        .collect();
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let path_and_query = uri.path_and_query().unwrap().as_str();
    let request = Request {
        method: "GET",
        path_and_query,
        headers: &pairs,
        body: b"",
    };
    let (scheme, verified) = match verification::parse(&request) {
        Ok(parsed) => match parsed.scheme {
            verification::Scheme::DraftCavage => (
                Some(Scheme::DraftCavage),
                verification::verify(&parsed, &request, Key::RsaPem(PUBLIC_KEY)).is_ok(),
            ),
            verification::Scheme::Rfc9421 => (Some(Scheme::Rfc9421), parsed.key_id == KEY_ID),
        },
        Err(_) => (None, false),
    };
    Seen {
        path: path_and_query.to_owned(),
        scheme,
        verified,
    }
}

fn activity(mut body: serde_json::Value) -> Response {
    body["@context"] = json!("https://www.w3.org/ns/activitystreams");
    (
        [("content-type", "application/activity+json")],
        body.to_string(),
    )
        .into_response()
}

fn redirect(to: &str) -> Response {
    (StatusCode::FOUND, [("location", to.to_owned())]).into_response()
}

async fn handle(
    State(server): State<Server>,
    Path(path): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let seen = check(&uri, &headers);
    server.seen.lock().unwrap().push(seen.clone());
    if server.authorized_fetch && !seen.verified {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if server.only_rfc9421 && seen.scheme == Some(Scheme::DraftCavage) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let host = headers["host"].to_str().unwrap();
    let port = host.rsplit_once(':').unwrap().1;
    match path.as_str() {
        "users/bob" => activity(json!({
            "id": format!("http://{host}/users/bob"),
            "type": "Person",
            "preferredUsername": "bob",
            "inbox": format!("http://{host}/users/bob/inbox"),
            "somethingNobodyDefines": true,
        })),
        // A profile page's address, redirected to the actor.
        "@bob" => redirect("/users/bob"),
        "loop" => redirect("/loop"),
        "private" => redirect("http://10.0.0.1/users/bob"),
        // Served from 127.0.0.1, claiming to be from localhost.
        "impostor" => activity(json!({
            "id": format!("http://localhost:{port}/users/bob"),
            "type": "Person",
            "name": "not bob",
        })),
        // Served from 127.0.0.1, with an id whose userinfo reads as
        // 127.0.0.1 to a hand-split authority, and as localhost to a URL
        // parser, which takes the backslash for a `/`.
        "backslash" => activity(json!({
            "id": format!("http://localhost:{port}\\@{host}/users/bob"),
            "type": "Person",
        })),
        // Claiming to be on whichever of the two origins it was not
        // fetched from, from both.
        "bounce" => {
            let other = if host.starts_with("localhost") {
                "127.0.0.1"
            } else {
                "localhost"
            };
            activity(json!({
                "id": format!("http://{other}:{port}/bounce"),
                "type": "Person",
            }))
        }
        // A note on 127.0.0.1 attributed to an actor on localhost.
        "forged-note" => activity(json!({
            "id": format!("http://{host}/forged-note"),
            "type": "Note",
            "attributedTo": format!("http://localhost:{port}/users/bob"),
            "content": "not by bob",
        })),
        "note" => activity(json!({
            "id": format!("http://{host}/note"),
            "type": "Note",
            "attributedTo": [format!("http://{host}/users/bob"), {"id": format!("http://{host}/users/carol")}],
        })),
        "portable" => activity(json!({
            "id": "ap://did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2/actor",
            "type": "Person",
        })),
        "plain-json" => (
            [("content-type", "application/json")],
            json!({"id": format!("http://{host}/plain-json")}).to_string(),
        )
            .into_response(),
        "anonymous" => activity(json!({"type": "Note"})),
        "gone" => StatusCode::GONE.into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serve `server` on a free loopback port, returning its base URL.
async fn serve(server: Server) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/{*path}", get(handle))
        .with_state(server);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&format!("http://{address}/")).unwrap()
}

fn fetcher() -> Fetcher {
    let client = Client::new(ClientConfig {
        allow_private: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
        ..ClientConfig::default()
    })
    .unwrap();
    Fetcher::new(client, Scheme::DraftCavage)
}

fn key() -> SenderKey {
    SenderKey {
        key_id: KEY_ID.to_owned(),
        private_key: Arc::new(PrivateKey::from_pem(PRIVATE_KEY).unwrap()),
    }
}

/// The same address with `localhost` for its host.
fn on_localhost(url: &Url) -> Url {
    let mut url = url.clone();
    url.set_host(Some("localhost")).unwrap();
    url
}

#[tokio::test]
async fn a_document_is_fetched_from_its_own_origin() {
    let base = serve(Server::default()).await;
    let url = base.join("users/bob").unwrap();

    let document = fetcher().document(&url, None).await.unwrap();

    assert_eq!(document.id, url.as_str());
    assert_eq!(document.url, url);
    assert_eq!(document.json["type"], "Person");
}

#[tokio::test]
async fn each_redirect_is_signed_for_where_it_goes() {
    let server = Server {
        authorized_fetch: true,
        ..Server::default()
    };
    let base = serve(server.clone()).await;

    let document = fetcher()
        .document(&base.join("@bob").unwrap(), Some(&key()))
        .await
        .unwrap();

    assert_eq!(document.url, base.join("users/bob").unwrap());
    let seen = server.seen();
    let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(paths, ["/@bob", "/users/bob"]);
    assert!(
        seen.iter().all(|s| s.verified),
        "every hop verified: {seen:?}"
    );
}

#[tokio::test]
async fn redirects_are_bounded() {
    let base = serve(Server::default()).await;
    let error = fetcher()
        .document(&base.join("loop").unwrap(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Redirect(_)), "{error}");
}

#[tokio::test]
async fn a_redirect_to_a_private_address_is_refused() {
    let base = serve(Server::default()).await;
    let error = fetcher()
        .document(&base.join("private").unwrap(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::Request(RequestError::Refused(_))),
        "{error}"
    );
}

#[tokio::test]
async fn a_refused_scheme_is_retried_in_the_other_and_remembered() {
    let server = Server {
        only_rfc9421: true,
        ..Server::default()
    };
    let base = serve(server.clone()).await;
    let url = base.join("users/bob").unwrap();
    let fetcher = fetcher();

    fetcher.document(&url, Some(&key())).await.unwrap();
    fetcher.document(&url, Some(&key())).await.unwrap();

    let schemes: Vec<Option<Scheme>> = server.seen().iter().map(|s| s.scheme).collect();
    assert_eq!(
        schemes,
        [
            Some(Scheme::DraftCavage),
            Some(Scheme::Rfc9421),
            Some(Scheme::Rfc9421)
        ]
    );
    assert!(server.seen().iter().all(|s| s.verified));
}

#[tokio::test]
async fn a_document_claiming_another_origin_is_not_trusted() {
    let base = serve(Server::default()).await;
    let url = base.join("impostor").unwrap();

    let error = fetcher().document(&url, None).await.unwrap_err();

    let FetchError::CrossOrigin { id, url: served } = error else {
        panic!("{error}");
    };
    assert_eq!(id, on_localhost(&base).join("users/bob").unwrap().as_str());
    assert_eq!(served, url);
}

#[tokio::test]
async fn an_id_that_parses_as_two_origins_is_not_trusted() {
    let base = serve(Server::default()).await;
    let url = base.join("backslash").unwrap();

    let error = fetcher().document(&url, None).await.unwrap_err();

    assert!(matches!(error, FetchError::CrossOrigin { .. }), "{error}");
    let error = fetcher().lookup(&url, None).await.unwrap_err();
    assert!(matches!(error, FetchError::CrossOrigin { .. }), "{error}");
}

#[tokio::test]
async fn a_document_by_an_author_on_another_origin_is_not_trusted() {
    let base = serve(Server::default()).await;

    let error = fetcher()
        .lookup(&base.join("forged-note").unwrap(), None)
        .await
        .unwrap_err();

    let FetchError::ForeignAuthor { author, .. } = error else {
        panic!("{error}");
    };
    assert_eq!(
        author,
        on_localhost(&base).join("users/bob").unwrap().as_str()
    );
    fetcher()
        .document(&base.join("note").unwrap(), None)
        .await
        .expect("a note by authors on its own origin");
}

#[tokio::test]
async fn a_lookup_asks_the_owner_of_the_id() {
    let base = serve(Server::default()).await;

    let document = fetcher()
        .lookup(&base.join("impostor").unwrap(), None)
        .await
        .unwrap();

    let own = on_localhost(&base).join("users/bob").unwrap();
    assert_eq!(document.id, own.as_str());
    assert_eq!(document.url, own);
    assert_eq!(
        document.json.get("name"),
        None,
        "what the owner serves, not what the impostor said"
    );
}

#[tokio::test]
async fn a_lookup_asks_only_once() {
    let base = serve(Server::default()).await;
    let error = fetcher()
        .lookup(&base.join("bounce").unwrap(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::CrossOrigin { .. }), "{error}");
}

#[tokio::test]
async fn a_portable_object_is_not_trusted_from_a_fetch() {
    let base = serve(Server::default()).await;
    let error = fetcher()
        .lookup(&base.join("portable").unwrap(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::CrossOrigin { .. }), "{error}");
}

#[tokio::test]
async fn what_is_not_an_established_document_is_refused() {
    let base = serve(Server::default()).await;
    let fetcher = fetcher();

    let error = fetcher
        .document(&base.join("plain-json").unwrap(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::NotActivityPub(_)), "{error}");

    let error = fetcher
        .document(&base.join("anonymous").unwrap(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::NoId), "{error}");

    let error = fetcher
        .document(&base.join("gone").unwrap(), None)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(410));
}

#[tokio::test]
async fn a_lookup_reads_into_the_type_asked_for_and_says_what_it_lost() {
    use ojak_vocab::generated::{AnyObject, Note, Person};

    let base = serve(Server::default()).await;
    let url = base.join("users/bob").unwrap();
    let fetcher = fetcher();

    let person = fetcher.lookup_as::<Person>(&url, None).await.unwrap();
    assert_eq!(
        person.read.value().preferred_username.value.as_deref(),
        Some("bob")
    );
    assert_eq!(person.document.url, url);
    let lost: Vec<&str> = person.read.lost().iter().map(|l| l.path.as_str()).collect();
    assert_eq!(lost, ["somethingNobodyDefines"]);

    let any = fetcher.lookup_as::<AnyObject>(&url, None).await.unwrap();
    assert!(matches!(any.read.value(), AnyObject::Person(_)));

    let error = fetcher.lookup_as::<Note>(&url, None).await.unwrap_err();
    assert!(matches!(error, FetchError::Read(_)), "{error}");
}
