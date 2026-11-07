//! Serve one temporary actor and report Ojak's inbox decisions.

use anyhow::{Context as _, Result};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::{self, Next};
use axum::response::Response;
use ojak::client::{Client, ClientConfig};
use ojak::federation::{ActorRef, Collection, Context, Error, Federation, Found, Page, PublicKey};
use ojak::fetch::Fetcher;
use ojak::kv::MemoryKvStore;
use ojak::sig::{PrivateKey, Scheme, SenderKey, signature::generate_rsa_keypair};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

const KIND: &str = "actor";
const USERNAME: &str = "inbox";
const ACTOR: &str = "/actor";
const INBOX: &str = "/inbox";
const OUTBOX: &str = "/outbox";
const HISTORY_LIMIT: usize = 100;

type Capture = Arc<Mutex<Option<Value>>>;
type History = Arc<Mutex<VecDeque<Value>>>;

struct Identity {
    key: SenderKey,
    public_key: String,
}

#[derive(Clone)]
struct Data {
    identity: Arc<Identity>,
    capture: Option<Capture>,
}

pub async fn run(
    origin: Option<Url>,
    port: u16,
    provider: Option<crate::tunnel::Provider>,
) -> Result<()> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .context("could not bind the loopback listener")?;
    let (origin, tunnel) = if let Some(origin) = origin {
        (origin, None)
    } else {
        let Some(tunnel) = crate::tunnel::open(listener.local_addr()?.port(), provider).await?
        else {
            return Ok(());
        };
        (tunnel.origin.clone(), Some(tunnel))
    };
    let mut key_id = origin.join(ACTOR)?;
    key_id.set_fragment(Some("main-key"));
    let (private_key, public_key) =
        generate_rsa_keypair(&mut rand_core::UnwrapErr(getrandom::SysRng))?;
    let identity = Arc::new(Identity {
        key: SenderKey {
            key_id: key_id.to_string(),
            private_key: Arc::new(PrivateKey::from_pem(&private_key)?),
        },
        public_key,
    });
    let history = History::default();
    let client = Client::new(ClientConfig::default())?;
    let app = router(origin.clone(), identity, history.clone(), client)?;
    let shutdown = tokio::signal::ctrl_c();
    println!("Listening on http://{}", listener.local_addr()?);
    println!(
        "Actor @{USERNAME}@{}",
        origin.host_str().unwrap_or_default()
    );
    println!("Actor URL {}", origin.join(ACTOR)?);
    println!("Inbox URL {}", origin.join(INBOX)?);
    println!("Waiting for ActivityPub deliveries. Press Ctrl-C to stop.");
    let serve = async {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                if let Err(error) = shutdown.await {
                    eprintln!("Could not listen for Ctrl-C ({error})");
                }
            })
            .await
    };
    if let Some(mut tunnel) = tunnel {
        tokio::select! {
            biased;
            result = serve => result?,
            result = tunnel.wait() => result?,
        }
        tunnel.close().await?;
    } else {
        serve.await?;
    }
    println!(
        "Stopped with {} recent delivery summaries in memory.",
        history.lock().expect("delivery history lock").len()
    );
    Ok(())
}

fn router(
    origin: Url,
    identity: Arc<Identity>,
    history: History,
    client: Client,
) -> Result<Router> {
    let fetcher = Arc::new(Fetcher::new(client, Scheme::DraftCavage));
    let federation =
        Federation::builder()
            .origin(origin)
            .actor(KIND, ACTOR, actor)
            .handle(|_: Context<Data>, username: String| async move {
                Ok::<_, Error>((username == USERNAME).then(|| ActorRef::new(KIND, "")))
            })
            .key_pairs(|ctx: Context<Data>, _: ActorRef| async move {
                Ok::<_, Error>(vec![PublicKey::Rsa {
                    id: ctx.data().identity.key.key_id.clone(),
                    pem: ctx.data().identity.public_key.clone(),
                }])
            })
            .collection(
                "outbox",
                OUTBOX,
                Collection::new(|_: Context<Data>, _, _| async {
                    Ok::<_, Error>(Some(Page::default()))
                })
                .count(|_, _| async { Ok::<_, Error>(Some(0)) }),
            )
            .inbox(KIND, INBOX)
            .signed_fetch(
                fetcher,
                MemoryKvStore::new(),
                Duration::from_secs(15 * 60),
                |ctx: Context<Data>| async move {
                    Ok::<_, Error>(Some(ctx.data().identity.key.clone()))
                },
            )
            .on_any(|ctx: Context<Data>, received| async move {
                record(
                    &ctx,
                    json!({
                        "type": activity_type(&received.document),
                        "sender": display_url(received.sender),
                        "authentication": format!("{:?}", received.vouched_by),
                        "outcome": "received",
                    }),
                );
                Ok::<_, Error>(())
            })
            .on_unverified(|ctx: Context<Data>, document| async move {
                record(
                    &ctx,
                    json!({
                        "type": activity_type(&document),
                        "authentication": "unverified",
                        "outcome": "not dispatched",
                    }),
                );
            })
            .build()?;

    let app = ojak_axum::wrap(Router::new(), federation, move |parts| {
        Some(Data {
            identity: identity.clone(),
            capture: parts.extensions.get::<Capture>().cloned(),
        })
    });
    Ok(app.layer(middleware::from_fn_with_state(history, observe)))
}

async fn actor(ctx: Context<Data>, _: String) -> Result<Found<Value>, Error> {
    let id = ctx.actor_uri(KIND, "")?;
    let mut document = json!({
        "id": id.as_str(),
        "type": "Person",
        "preferredUsername": USERNAME,
        "name": "Ojak test inbox",
        "inbox": ctx.inbox_uri(KIND, "")?.as_str(),
        "outbox": ctx.collection_uri("outbox", "")?.as_str(),
        "manuallyApprovesFollowers": true,
    });
    let keys = ctx.actor_keys(&ActorRef::new(KIND, "")).await?;
    ojak::federation::with_keys(&mut document, &keys);
    Ok(Found::Found(document))
}

fn activity_type(document: &Value) -> Option<String> {
    let kind = &document["type"];
    let kind = kind
        .as_str()
        .or_else(|| kind.as_array()?.first()?.as_str())?;
    Some(kind.chars().take(128).collect())
}

fn display_url(mut url: Url) -> String {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn record(ctx: &Context<Data>, entry: Value) {
    if let Some(capture) = &ctx.data().capture {
        *capture.lock().expect("delivery capture lock") = Some(entry);
    }
}

async fn observe(State(history): State<History>, mut request: Request, next: Next) -> Response {
    if request.method() != Method::POST || request.uri().path() != INBOX {
        return next.run(request).await;
    }
    let capture = Capture::default();
    request.extensions_mut().insert(capture.clone());
    let response = next.run(request).await;
    let mut entry = capture
        .lock()
        .expect("delivery capture lock")
        .take()
        .unwrap_or_else(|| json!({"outcome": "not dispatched"}));
    entry["status"] = json!(response.status().as_u16());
    println!("{entry}");
    let mut history = history.lock().expect("delivery history lock");
    if history.len() == HISTORY_LIMIT {
        history.pop_front();
    }
    history.push_back(entry);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::StatusCode;
    use ojak::testing::{PRIVATE_KEY_PEM, PUBLIC_KEY_PEM, Remote, client_config};
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn discovers_the_actor_and_reports_signed_and_unsigned_deliveries() {
        let origin = Url::parse("https://trial.example").unwrap();
        let identity = Arc::new(Identity {
            key: SenderKey {
                key_id: "https://trial.example/actor#main-key".into(),
                private_key: Arc::new(PrivateKey::from_pem(PRIVATE_KEY_PEM).unwrap()),
            },
            public_key: PUBLIC_KEY_PEM.into(),
        });
        let history = History::default();
        let app = router(
            origin,
            identity,
            history.clone(),
            Client::new(client_config()).unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::get("/.well-known/webfinger?resource=acct:inbox@trial.example")
                    .header("host", "trial.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let finger: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert!(finger["links"].as_array().unwrap().iter().any(|link| {
            link["rel"] == "self" && link["href"] == "https://trial.example/actor"
        }));

        let remote = Remote::start().await;
        let sender = remote.actor("alice");
        let follow = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{sender}/follows/1"),
            "type": "Follow",
            "actor": sender.as_str(),
            "object": "https://trial.example/actor",
        });
        let mut unsigned = remote.sign("alice", "https://trial.example/inbox", &follow);
        unsigned.headers_mut().remove("signature");
        let response = app.clone().oneshot(unsigned.map(Body::from)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(
                remote
                    .sign("alice", "https://trial.example/inbox", &follow)
                    .map(Body::from),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let history = history.lock().unwrap();
        assert_eq!(history[0]["authentication"], "unverified");
        assert_eq!(history[0]["status"], 401);
        assert_eq!(history[1]["type"], "Follow");
        assert_eq!(history[1]["sender"], sender.as_str());
        assert_eq!(history[1]["authentication"], "Signature");
        assert_eq!(history[1]["status"], 202);
    }
}
