//! Serving, through a small application: people, communities, notes and
//! their collections, on `oeee.test` with `www.oeee.test` as an alias.

use axum::Router;
use axum::extract::State;
use axum::routing;
use chrono::{TimeZone, Utc};
use feder::client::{Client, ClientConfig};
use feder::delivery::Scheme;
use feder::federation::{
    ActorRef, Collection, Context, Federation, First, Found, Handled, NodeInfo, Page, PublicKey,
    Route, Software, with_keys,
};
use feder::fetch::Fetcher;
use feder::kv::MemoryKvStore;
use feder::template::Values;
use feder_runtime::signature::{self, PrivateKey};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa_public.pem");
const ACCEPT_AP: &str = "application/activity+json";
const BROWSER: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

/// The application's data: what its dispatchers read.
#[derive(Default)]
struct Store {
    /// Remote actors that follow alice, for the followers-only note.
    followers: Mutex<Vec<String>>,
}

type App = Arc<Store>;

fn canonical() -> Url {
    Url::parse("https://oeee.test").unwrap()
}

async fn person(ctx: Context<App>, id: String) -> Result<Found<Value>, String> {
    let (username, name) = match id.as_str() {
        "1" => ("alice", "Alice"),
        "2" => return Ok(Found::Gone(None)),
        _ => return Ok(Found::NotFound),
    };
    let uri = ctx.actor_uri("person", &id).map_err(|e| e.to_string())?;
    let mut actor = json!({
        "id": uri.as_str(),
        "type": "Person",
        "preferredUsername": username,
        "name": name,
        "url": format!("{}@{username}", ctx.origin()),
        "followers": ctx.collection_uri("followers", &id).unwrap().as_str(),
        "featured": ctx.collection_uri("featured", &id).unwrap().as_str(),
    });
    let keys = ctx
        .actor_keys(&ActorRef::new("person", &id))
        .await
        .map_err(|e| e.to_string())?;
    with_keys(&mut actor, &keys);
    Ok(Found::Found(actor))
}

async fn group(ctx: Context<App>, id: String) -> Result<Found<Value>, String> {
    if id != "cafe" {
        return Ok(Found::NotFound);
    }
    Ok(Found::Found(json!({
        "id": ctx.actor_uri("group", &id).unwrap().as_str(),
        "type": "Group",
        "preferredUsername": "cafe",
    })))
}

async fn instance(ctx: Context<App>, _id: String) -> Result<Found<Value>, String> {
    Ok(Found::Found(json!({
        "id": ctx.actor_uri("instance", "").unwrap().as_str(),
        "type": "Application",
        "preferredUsername": ctx.origin().host_str().unwrap(),
    })))
}

async fn note(ctx: Context<App>, values: Values) -> Result<Found<Value>, String> {
    let id = values["post_id"].to_owned();
    match id.as_str() {
        "10" => {}
        "11" => {
            // Followers only: served to a follower's server, and nobody else.
            let followed = match ctx.signer().await {
                Some(signer) => ctx
                    .data()
                    .followers
                    .lock()
                    .unwrap()
                    .contains(&signer.to_string()),
                None => false,
            };
            if !followed {
                return Ok(Found::NotFound);
            }
        }
        "12" => {
            return Ok(Found::Gone(Some(
                Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).unwrap(),
            )));
        }
        _ => return Ok(Found::NotFound),
    }
    Ok(Found::Found(json!({
        "id": ctx.object_uri("note", &[("post_id", &id)]).unwrap().as_str(),
        "type": "Note",
        "attributedTo": ctx.actor_uri("person", "1").unwrap().as_str(),
        "content": "hello",
    })))
}

/// Five followers, two to a page; the cursor is an offset.
fn followers() -> Collection<App> {
    Collection::new(
        |ctx: Context<App>, id: String, cursor: Option<String>| async move {
            if id != "1" {
                return Ok::<_, String>(None);
            }
            let all: Vec<Value> = (1..=5)
                .map(|n| json!(format!("https://remote.test/users/{n}")))
                .collect();
            let start: usize = cursor.unwrap_or_default().parse().unwrap_or(0);
            let _ = ctx.origin();
            Ok(Some(Page {
                items: all.iter().skip(start).take(2).cloned().collect(),
                next: (start + 2 < all.len()).then(|| (start + 2).to_string()),
                prev: (start > 0).then(|| start.saturating_sub(2).to_string()),
            }))
        },
    )
    .count(|_, id: String| async move { Ok::<_, String>((id == "1").then_some(5)) })
    .first_cursor(|_, id: String| async move {
        Ok::<_, String>(match id.as_str() {
            "1" => Some(First::At("0".into())),
            "3" => Some(First::Hidden),
            _ => None,
        })
    })
    .last_cursor(|_, _| async move { Ok::<_, String>(Some("4".into())) })
}

/// Featured, named by the canonical `/ap/users/{id}` form even when it is
/// asked for under the handle form.
fn featured_by_handle() -> Collection<App> {
    featured().uri(|ctx: Context<App>, handle: String| async move {
        Ok::<_, String>((handle == "alice").then(|| ctx.collection_uri("featured", "1").unwrap()))
    })
}

fn featured() -> Collection<App> {
    Collection::new(
        |ctx: Context<App>, _id: String, _cursor: Option<String>| async move {
            Ok::<_, String>(Some(Page {
                items: vec![json!(
                    ctx.object_uri("note", &[("post_id", "10")])
                        .unwrap()
                        .as_str()
                )],
                ..Page::default()
            }))
        },
    )
}

fn builder() -> feder::federation::Builder<App> {
    Federation::builder()
        .origin_with(|host, _| match host {
            "oeee.test" | "www.oeee.test" => Some(canonical()),
            _ => None,
        })
        .actor("person", "/ap/users/{user_id}", person)
        .actor("group", "/ap/communities/{community_id}", group)
        .actor("instance", "/actor", instance)
        .object("note", "/ap/posts/{post_id}", note)
        .collection("followers", "/ap/users/{user_id}/followers", followers())
        .collection("featured", "/ap/users/{user_id}/featured", featured())
        .collection(
            "featured_by_handle",
            "/users/{handle}/featured",
            featured_by_handle(),
        )
        .key_pairs(|ctx: Context<App>, actor: ActorRef| async move {
            let id = ctx.actor_uri(&actor.kind, &actor.identifier).unwrap();
            Ok::<_, String>(vec![PublicKey::Rsa {
                id: format!("{id}#main-key"),
                pem: "PEM".into(),
            }])
        })
        .handle(|_, username: String| async move {
            Ok::<_, String>(match username.as_str() {
                "alice" => Some(ActorRef::new("person", "1")),
                "cafe" => Some(ActorRef::new("group", "cafe")),
                _ => None,
            })
        })
        .map_alias(|_, url: Url| async move {
            Ok::<_, String>((url.path() == "/@alice").then(|| ActorRef::new("person", "1")))
        })
        .webfinger_links(|ctx, _, _| {
            vec![json!({
                "rel": "http://ostatus.org/schema/1.0/subscribe",
                "template": format!("{}authorize_interaction?uri={{uri}}", ctx.origin()),
            })]
        })
        .nodeinfo(|_| async move {
            let mut nodeinfo = NodeInfo::new(Software {
                name: "oeee-cafe".into(),
                version: "1.0".into(),
                repository: Some("https://github.com/oeee-cafe/web".into()),
                homepage: None,
            });
            nodeinfo.open_registrations = true;
            nodeinfo.usage.users_total = Some(2);
            Ok::<_, String>(nodeinfo)
        })
}

fn federation() -> Federation<App> {
    builder().build().unwrap()
}

fn request(method: &str, host: &str, path: &str, accept: Option<&str>) -> http::request::Parts {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(accept) = accept {
        builder = builder.header("accept", accept);
    }
    builder.body(()).unwrap().into_parts().0
}

struct Answer {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map_or("", |value| value.to_str().unwrap())
    }
}

async fn get(federation: &Federation<App>, path: &str) -> Answer {
    send(
        federation,
        request("GET", "oeee.test", path, Some(ACCEPT_AP)),
    )
    .await
}

async fn send(federation: &Federation<App>, parts: http::request::Parts) -> Answer {
    match federation.handle(&parts, App::default()).await {
        Handled::Response(response) => {
            let (parts, body) = response.into_parts();
            Answer {
                status: parts.status.as_u16(),
                headers: parts.headers,
                body,
            }
        }
        other => panic!("not answered: {other:?}"),
    }
}

#[tokio::test]
async fn an_actor_is_served_with_its_context_and_keys() {
    let answer = get(&federation(), "/ap/users/1").await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("content-type"), ACCEPT_AP);
    assert_eq!(answer.header("vary"), "Accept");
    let actor = answer.json();
    assert_eq!(actor["@context"], feder::federation::default_context());
    assert_eq!(actor["id"], "https://oeee.test/ap/users/1");
    assert_eq!(actor["followers"], "https://oeee.test/ap/users/1/followers");
    assert_eq!(
        actor["publicKey"]["id"],
        "https://oeee.test/ap/users/1#main-key"
    );
    assert_eq!(actor["publicKey"]["owner"], "https://oeee.test/ap/users/1");
    let first = actor.as_object().unwrap().keys().next().unwrap();
    assert_eq!(first, "@context", "the context comes first");

    let instance = get(&federation(), "/actor").await.json();
    assert_eq!(instance["id"], "https://oeee.test/actor");
}

#[tokio::test]
async fn a_request_that_does_not_ask_for_activitypub_is_the_applications() {
    let federation = federation();
    for accept in [Some(BROWSER), None, Some("*/*")] {
        let parts = request("GET", "oeee.test", "/ap/users/1", accept);
        assert!(matches!(
            federation.handle(&parts, App::default()).await,
            Handled::NotAcceptable
        ));
    }
    let parts = request("GET", "oeee.test", "/@alice", Some(ACCEPT_AP));
    assert!(matches!(
        federation.handle(&parts, App::default()).await,
        Handled::NotFound
    ));
    let parts = request("GET", "unknown.test", "/ap/users/1", Some(ACCEPT_AP));
    assert!(
        matches!(
            federation.handle(&parts, App::default()).await,
            Handled::NotFound
        ),
        "a host that is not ours is not answered"
    );
}

#[tokio::test]
async fn head_is_get_without_a_body_and_other_methods_are_refused() {
    let federation = federation();
    let head = send(
        &federation,
        request("HEAD", "oeee.test", "/ap/users/1", Some(ACCEPT_AP)),
    )
    .await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_ne!(head.header("content-length"), "0");
    let post = send(
        &federation,
        request("POST", "oeee.test", "/ap/users/1", Some(ACCEPT_AP)),
    )
    .await;
    assert_eq!(post.status, 405);
    assert_eq!(post.header("allow"), "GET, HEAD");
}

#[tokio::test]
async fn what_is_gone_is_a_tombstone_and_what_is_not_there_is_404() {
    let federation = federation();
    let gone = get(&federation, "/ap/posts/12").await;
    assert_eq!(gone.status, 410);
    assert_eq!(
        gone.json(),
        json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://oeee.test/ap/posts/12",
            "type": "Tombstone",
            "deleted": "2026-09-01T12:00:00Z",
        })
    );
    assert_eq!(get(&federation, "/ap/users/2").await.status, 410);
    assert_eq!(get(&federation, "/ap/users/9").await.status, 404);
    assert_eq!(get(&federation, "/ap/posts/99").await.status, 404);
}

#[tokio::test]
async fn a_paged_collection_links_its_pages() {
    let federation = federation();
    let collection = get(&federation, "/ap/users/1/followers").await.json();
    assert_eq!(
        collection,
        json!({
            "@context": feder::federation::default_context(),
            "id": "https://oeee.test/ap/users/1/followers",
            "type": "OrderedCollection",
            "totalItems": 5,
            "first": "https://oeee.test/ap/users/1/followers?cursor=0",
            "last": "https://oeee.test/ap/users/1/followers?cursor=4",
        })
    );
    let page = get(&federation, "/ap/users/1/followers?cursor=2")
        .await
        .json();
    assert_eq!(page["type"], "OrderedCollectionPage");
    assert_eq!(
        page["id"],
        "https://oeee.test/ap/users/1/followers?cursor=2"
    );
    assert_eq!(page["partOf"], "https://oeee.test/ap/users/1/followers");
    assert_eq!(
        page["orderedItems"],
        json!(["https://remote.test/users/3", "https://remote.test/users/4"])
    );
    assert_eq!(
        page["next"],
        "https://oeee.test/ap/users/1/followers?cursor=4"
    );
    assert_eq!(
        page["prev"],
        "https://oeee.test/ap/users/1/followers?cursor=0"
    );

    let hidden = get(&federation, "/ap/users/3/followers").await.json();
    assert_eq!(
        hidden.get("first"),
        None,
        "a hidden collection has no pages"
    );
    assert_eq!(get(&federation, "/ap/users/9/followers").await.status, 404);
}

#[tokio::test]
async fn an_unpaged_collection_is_one_document() {
    let featured = get(&federation(), "/ap/users/1/featured").await.json();
    assert_eq!(featured["type"], "OrderedCollection");
    assert_eq!(featured["totalItems"], 1);
    assert_eq!(
        featured["orderedItems"],
        json!(["https://oeee.test/ap/posts/10"])
    );
}

#[tokio::test]
async fn a_collection_asked_for_under_another_template_is_named_by_its_own_uri() {
    let featured = get(&federation(), "/users/alice/featured").await.json();
    assert_eq!(featured["id"], "https://oeee.test/ap/users/1/featured");
}

#[tokio::test]
async fn webfinger_finds_an_actor_by_handle_uri_or_page() {
    let federation = federation();
    for resource in [
        "acct:alice@oeee.test",
        "acct:alice@www.oeee.test",
        "alice@oeee.test",
        "acct:@alice@oeee.test",
        "https://oeee.test/ap/users/1",
        "https://oeee.test/@alice",
    ] {
        let path = format!(
            "/.well-known/webfinger?resource={}",
            url::form_urlencoded::byte_serialize(resource.as_bytes()).collect::<String>()
        );
        let answer = send(&federation, request("GET", "oeee.test", &path, None)).await;
        assert_eq!(answer.status, 200, "{resource}");
        assert_eq!(answer.header("content-type"), "application/jrd+json");
        assert_eq!(answer.header("access-control-allow-origin"), "*");
        let jrd = answer.json();
        assert_eq!(jrd["subject"], "acct:alice@oeee.test", "{resource}");
        assert_eq!(
            jrd["aliases"],
            json!(["https://oeee.test/ap/users/1", "https://oeee.test/@alice"])
        );
        assert_eq!(
            jrd["links"][0],
            json!({"rel": "self", "type": ACCEPT_AP, "href": "https://oeee.test/ap/users/1"})
        );
        assert_eq!(
            jrd["links"][1],
            json!({"rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": "https://oeee.test/@alice"})
        );
        assert_eq!(
            jrd["links"][2]["rel"],
            "http://ostatus.org/schema/1.0/subscribe"
        );
    }

    let group = send(
        &federation,
        request(
            "GET",
            "oeee.test",
            "/.well-known/webfinger?resource=acct:cafe@oeee.test",
            None,
        ),
    )
    .await
    .json();
    assert_eq!(group["subject"], "acct:cafe@oeee.test");

    for (resource, status) in [
        ("acct:alice@elsewhere.test", 404),
        ("acct:nobody@oeee.test", 404),
        ("https://elsewhere.test/ap/users/1", 404),
        ("", 400),
    ] {
        let path = format!("/.well-known/webfinger?resource={resource}");
        let answer = send(&federation, request("GET", "oeee.test", &path, None)).await;
        assert_eq!(answer.status, status, "{resource:?}");
    }
}

#[tokio::test]
async fn host_meta_says_where_webfinger_is() {
    let answer = send(
        &federation(),
        request("GET", "www.oeee.test", "/.well-known/host-meta", None),
    )
    .await;
    assert_eq!(answer.status, 200);
    let body = String::from_utf8(answer.body).unwrap();
    assert!(
        body.contains(r#"template="https://oeee.test/.well-known/webfinger?resource={uri}""#),
        "{body}"
    );
}

#[tokio::test]
async fn nodeinfo_is_served_in_both_versions() {
    let federation = federation();
    let links = send(
        &federation,
        request("GET", "oeee.test", "/.well-known/nodeinfo", None),
    )
    .await
    .json();
    assert_eq!(
        links["links"],
        json!([
            {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.0", "href": "https://oeee.test/nodeinfo/2.0"},
            {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": "https://oeee.test/nodeinfo/2.1"},
        ])
    );
    let v20 = send(
        &federation,
        request("GET", "oeee.test", "/nodeinfo/2.0", None),
    )
    .await;
    assert_eq!(
        v20.header("content-type"),
        "application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.0#\""
    );
    let v20 = v20.json();
    assert_eq!(v20["version"], "2.0");
    assert_eq!(v20["software"].get("repository"), None);
    assert_eq!(v20["openRegistrations"], true);
    assert_eq!(v20["usage"]["users"]["total"], 2);
    let v21 = send(
        &federation,
        request("GET", "oeee.test", "/nodeinfo/2.1", None),
    )
    .await
    .json();
    assert_eq!(
        v21["software"]["repository"],
        "https://github.com/oeee-cafe/web"
    );
}

#[tokio::test]
async fn uris_are_built_in_the_canonical_origin_and_parsed_back() {
    let federation = federation();
    let answer = send(
        &federation,
        request("GET", "www.oeee.test", "/ap/users/1", Some(ACCEPT_AP)),
    )
    .await;
    assert_eq!(
        answer.json()["id"],
        "https://oeee.test/ap/users/1",
        "an alias is answered in the canonical origin's URIs"
    );

    let ctx = federation.context(canonical(), App::default());
    let did = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let uri = ctx.actor_uri("person", did).unwrap();
    assert_eq!(
        ctx.parse_uri(uri.as_str()),
        Some(Route::Actor(ActorRef::new("person", did)))
    );
    assert_eq!(
        ctx.parse_uri("https://www.oeee.test/ap/posts/10"),
        Some(Route::Object {
            kind: "note".into(),
            values: [("post_id", "10")].into_iter().collect()
        })
    );
    assert_eq!(
        ctx.parse_uri("https://oeee.test/ap/users/1/followers"),
        Some(Route::Collection {
            kind: "followers".into(),
            identifier: "1".into()
        })
    );
    assert_eq!(ctx.parse_uri("https://elsewhere.test/ap/users/1"), None);
    assert_eq!(ctx.parse_uri("http://oeee.test/ap/users/1"), None);
    assert_eq!(ctx.parse_uri("https://oeee.test/about"), None);
    assert!(ctx.actor_uri("robot", "1").is_err());
    assert!(
        ctx.collection_uri("outbox", "1").is_err(),
        "an unregistered collection has no URI"
    );
}

#[tokio::test]
async fn a_federation_that_could_not_route_is_not_built() {
    let error =
        |builder: feder::federation::Builder<App>| builder.build().err().unwrap().to_string();
    assert!(error(Federation::builder()).contains("no origin"));
    assert!(
        error(builder().actor("robot", "/ap/users/{id}", person)).contains("could match one path")
    );
    assert!(error(builder().actor("person", "/people/{id}", person)).contains("two dispatchers"));
    assert!(error(builder().actor("robot", "/.well-known/{x}", person)).contains("Feder serves"));
    assert!(
        error(builder().actor("robot", "/robots/{a}/{b}", person))
            .contains("more than one expression")
    );
    assert!(
        error(builder().authorize("outbox", |_, _, _| async { Ok::<_, String>(true) }))
            .contains("no dispatcher")
    );
}

/// A remote server publishing bob's key, counting how often it is fetched.
#[derive(Clone, Default)]
struct Remote {
    fetches: Arc<AtomicUsize>,
}

async fn bob(
    State(remote): State<Remote>,
    headers: http::HeaderMap,
) -> ([(&'static str, &'static str); 1], String) {
    remote.fetches.fetch_add(1, Ordering::SeqCst);
    let host = headers["host"].to_str().unwrap();
    let id = format!("http://{host}/users/bob");
    (
        [("content-type", ACCEPT_AP)],
        json!({
            "id": id,
            "type": "Person",
            "publicKey": {"id": format!("{id}#main-key"), "owner": id, "publicKeyPem": PUBLIC_KEY},
        })
        .to_string(),
    )
}

async fn serve_remote(remote: Remote) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/users/bob", routing::get(bob))
        .with_state(remote);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&format!("http://{address}/users/bob")).unwrap()
}

fn signed_request(path: &str, key_id: &str) -> http::request::Parts {
    let key = PrivateKey::from_pem(PRIVATE_KEY).unwrap();
    let signed =
        signature::sign_get_with_key(&format!("https://oeee.test{path}"), key_id, &key).unwrap();
    let mut parts = request("GET", "oeee.test", path, Some(ACCEPT_AP));
    parts.headers.insert("date", signed.date.parse().unwrap());
    parts
        .headers
        .insert("signature", signed.signature.parse().unwrap());
    parts
}

fn with_signed_fetch(builder: feder::federation::Builder<App>) -> Federation<App> {
    let client = Client::new(ClientConfig {
        allow_private: vec!["127.0.0.0/8".parse().unwrap()],
        ..ClientConfig::default()
    })
    .unwrap();
    builder
        .signed_fetch(
            Arc::new(Fetcher::new(client, Scheme::DraftCavage)),
            MemoryKvStore::new(),
            Duration::from_secs(3600),
            |_| async { Ok::<_, String>(None) },
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn a_signed_fetch_is_verified_when_a_dispatcher_asks() {
    let remote = Remote::default();
    let bob = serve_remote(remote.clone()).await;
    let key_id = format!("{bob}#main-key");
    let federation = with_signed_fetch(builder());
    let store = App::default();
    store.followers.lock().unwrap().push(bob.to_string());

    let answer = |parts: http::request::Parts| {
        let federation = federation.clone();
        let store = store.clone();
        async move {
            match federation.handle(&parts, store).await {
                Handled::Response(response) => response.status().as_u16(),
                other => panic!("{other:?}"),
            }
        }
    };

    assert_eq!(
        answer(request("GET", "oeee.test", "/ap/posts/11", Some(ACCEPT_AP))).await,
        404,
        "unsigned, a followers-only note is not there"
    );
    assert_eq!(answer(signed_request("/ap/posts/11", &key_id)).await, 200);
    assert_eq!(answer(signed_request("/ap/posts/11", &key_id)).await, 200);
    assert_eq!(
        remote.fetches.load(Ordering::SeqCst),
        1,
        "the key is fetched once and then read from the cache"
    );

    // Signed for another path, the signature does not verify.
    let mut replayed = signed_request("/ap/posts/10", &key_id);
    replayed.uri = "/ap/posts/11".parse().unwrap();
    assert_eq!(answer(replayed).await, 404);

    // A signer that does not follow sees nothing either.
    store.followers.lock().unwrap().clear();
    assert_eq!(answer(signed_request("/ap/posts/11", &key_id)).await, 404);
}

#[tokio::test]
async fn authorize_refuses_what_it_does_not_allow() {
    let remote = Remote::default();
    let bob = serve_remote(remote).await;
    let key_id = format!("{bob}#main-key");
    // Secure mode for people: only signed requests see an actor.
    let federation = with_signed_fetch(
        builder().authorize("person", |_, _, signer: Option<Url>| async move {
            Ok::<_, String>(signer.is_some())
        }),
    );

    let unsigned = send(
        &federation,
        request("GET", "oeee.test", "/ap/users/1", Some(ACCEPT_AP)),
    )
    .await;
    assert_eq!(unsigned.status, 401);
    assert!(unsigned.header("www-authenticate").starts_with("Signature"));
    let signed = send(&federation, signed_request("/ap/users/1", &key_id)).await;
    assert_eq!(signed.status, 200);
    let instance = send(
        &federation,
        request("GET", "oeee.test", "/actor", Some(ACCEPT_AP)),
    )
    .await;
    assert_eq!(instance.status, 200, "the instance actor stays public");
}
