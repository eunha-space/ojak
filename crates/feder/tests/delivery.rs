//! Delivering to a real inbox on the loopback interface.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use feder::client::{Client, ClientConfig, RequestError};
use feder::deliverer::{Deliverer, DelivererConfig, DeliveryFailure, SenderKeys};
use feder::delivery::{self, DeliveryError, Scheme, SenderKey};
use feder::queue::{MemoryQueue, QueueError, RetryPolicy};
use feder_runtime::signature::{self, PrivateKey};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const PRIVATE_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str =
    include_str!("../../feder-runtime/tests/fixtures/rfc9421_test_key_rsa_public.pem");
const KEY_ID: &str = "https://feder.example/users/alice#main-key";

/// What the test inbox does with each request.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// Accept a request it can verify, whatever the scheme.
    Accept,
    /// Refuse draft-cavage with 401, as a server that verifies only RFC 9421
    /// does; accept RFC 9421.
    OnlyRfc9421,
    /// Answer with this status.
    Status(u16),
}

#[derive(Clone, Debug)]
struct Received {
    scheme: Scheme,
    verified: bool,
    body: Vec<u8>,
}

#[derive(Clone, Default)]
struct Inbox {
    /// Answers to give, in order; `Accept` once they run out.
    answers: Arc<Mutex<VecDeque<Answer>>>,
    received: Arc<Mutex<Vec<Received>>>,
}

impl Inbox {
    fn answering(answers: impl IntoIterator<Item = Answer>) -> Self {
        let inbox = Self::default();
        inbox.answers.lock().unwrap().extend(answers);
        inbox
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

async fn receive(State(inbox): State<Inbox>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let scheme = if headers.contains_key("signature-input") {
        Scheme::Rfc9421
    } else {
        Scheme::DraftCavage
    };
    let verified = match scheme {
        Scheme::DraftCavage => {
            let pairs: Vec<(String, String)> = headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
                .collect();
            let pairs: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            signature::verify_request("post", "/inbox", &pairs, &body, PUBLIC_KEY).is_ok()
        }
        // The RFC 9421 verifier's own tests cover the signature; here it is
        // enough that the headers it needs are present.
        Scheme::Rfc9421 => {
            headers.contains_key("signature") && headers.contains_key("content-digest")
        }
    };
    inbox.received.lock().unwrap().push(Received {
        scheme,
        verified,
        body: body.to_vec(),
    });
    let answer = inbox
        .answers
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(Answer::Accept);
    match (answer, scheme) {
        (Answer::Accept | Answer::OnlyRfc9421, _) if !verified => StatusCode::UNAUTHORIZED,
        (Answer::OnlyRfc9421, Scheme::DraftCavage) => {
            // Stays refusing cavage for the rest of the test.
            inbox
                .answers
                .lock()
                .unwrap()
                .push_front(Answer::OnlyRfc9421);
            StatusCode::UNAUTHORIZED
        }
        (Answer::Accept | Answer::OnlyRfc9421, _) => StatusCode::ACCEPTED,
        (Answer::Status(status), _) => StatusCode::from_u16(status).unwrap(),
    }
}

/// Serve `inbox` on a free loopback port, returning its URL.
async fn serve(inbox: Inbox) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/inbox", post(receive))
        .with_state(inbox);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&format!("http://{address}/inbox")).unwrap()
}

fn client() -> Client {
    Client::new(ClientConfig {
        allow_private: vec!["127.0.0.0/8".parse().unwrap()],
        ..ClientConfig::default()
    })
    .unwrap()
}

fn key() -> SenderKey {
    SenderKey {
        key_id: KEY_ID.to_owned(),
        private_key: Arc::new(PrivateKey::from_pem(PRIVATE_KEY).unwrap()),
    }
}

struct Keys;

impl SenderKeys for Keys {
    async fn key(&self, sender: &str) -> Result<Option<SenderKey>, QueueError> {
        Ok((sender == "alice").then(key))
    }
}

fn fast() -> DelivererConfig {
    DelivererConfig {
        retry: RetryPolicy {
            initial: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            max_attempts: 3,
        },
        ..DelivererConfig::default()
    }
}

/// Run the delivery loop until nothing is due or `rounds` batches have run.
async fn drain(deliverer: &Deliverer<MemoryQueue, Keys>, rounds: usize) {
    for _ in 0..rounds {
        tokio::time::sleep(Duration::from_millis(5)).await;
        deliverer.run_once().await.unwrap();
    }
}

#[tokio::test]
async fn a_delivery_verifies_at_the_inbox() {
    let inbox = Inbox::default();
    let url = serve(inbox.clone()).await;
    let body = br#"{"type":"Create"}"#;

    let accepted = delivery::deliver(&client(), &url, body, &key(), Scheme::DraftCavage)
        .await
        .unwrap();

    assert_eq!(accepted, Scheme::DraftCavage);
    let received = inbox.received();
    assert_eq!(received.len(), 1);
    assert!(received[0].verified, "the inbox verified the signature");
    assert_eq!(received[0].body, body);
}

#[tokio::test]
async fn a_refused_scheme_is_retried_in_the_other() {
    let inbox = Inbox::answering([Answer::OnlyRfc9421]);
    let url = serve(inbox.clone()).await;

    let accepted = delivery::deliver(&client(), &url, b"{}", &key(), Scheme::DraftCavage)
        .await
        .unwrap();

    assert_eq!(accepted, Scheme::Rfc9421);
    let schemes: Vec<Scheme> = inbox.received().iter().map(|r| r.scheme).collect();
    assert_eq!(schemes, [Scheme::DraftCavage, Scheme::Rfc9421]);
}

#[tokio::test]
async fn a_host_that_took_the_other_scheme_is_sent_it_first_next_time() {
    let inbox = Inbox::answering([Answer::OnlyRfc9421]);
    let url = serve(inbox.clone()).await;
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast());

    deliverer
        .send("alice", &json!({"n": 1}), [url.clone()])
        .await
        .unwrap();
    drain(&deliverer, 1).await;
    deliverer
        .send("alice", &json!({"n": 2}), [url])
        .await
        .unwrap();
    drain(&deliverer, 1).await;

    let schemes: Vec<Scheme> = inbox.received().iter().map(|r| r.scheme).collect();
    assert_eq!(
        schemes,
        [Scheme::DraftCavage, Scheme::Rfc9421, Scheme::Rfc9421]
    );
}

#[tokio::test]
async fn a_server_error_is_retried_until_it_passes() {
    let inbox = Inbox::answering([Answer::Status(503), Answer::Status(502)]);
    let url = serve(inbox.clone()).await;
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast());

    deliverer.send("alice", &json!({}), [url]).await.unwrap();
    drain(&deliverer, 5).await;

    let records = deliverer.queue().records();
    assert!(records[0].complete);
    assert_eq!(records[0].job.attempts, 2);
    assert_eq!(inbox.received().len(), 3);
}

#[tokio::test]
async fn gone_is_given_up_on_at_once_and_reported() {
    let inbox = Inbox::answering([Answer::Status(410)]);
    let url = serve(inbox.clone()).await;
    let failures: Arc<Mutex<Vec<DeliveryFailure>>> = Arc::default();
    let seen = failures.clone();
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast())
        .on_failure(move |failure| seen.lock().unwrap().push(failure.clone()));

    deliverer
        .send("alice", &json!({}), [url.clone()])
        .await
        .unwrap();
    drain(&deliverer, 3).await;

    assert_eq!(inbox.received().len(), 1, "a 410 is not retried");
    let records = deliverer.queue().records();
    assert!(records[0].failed);
    let failures = failures.lock().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].status, Some(410));
    assert_eq!(failures[0].inbox, url);
}

#[tokio::test]
async fn retries_stop_at_the_policy_limit() {
    let inbox = Inbox::answering([Answer::Status(500); 10]);
    let url = serve(inbox.clone()).await;
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast());

    deliverer.send("alice", &json!({}), [url]).await.unwrap();
    drain(&deliverer, 6).await;

    let records = deliverer.queue().records();
    assert!(records[0].failed);
    assert_eq!(inbox.received().len(), 3, "max_attempts is 3");
}

#[tokio::test]
async fn one_inbox_named_twice_is_sent_once() {
    let inbox = Inbox::default();
    let url = serve(inbox.clone()).await;
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast());

    deliverer
        .send("alice", &json!({}), [url.clone(), url])
        .await
        .unwrap();
    drain(&deliverer, 1).await;

    assert_eq!(inbox.received().len(), 1);
}

#[tokio::test]
async fn an_unknown_sender_is_given_up_on() {
    let inbox = Inbox::default();
    let url = serve(inbox.clone()).await;
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast());

    deliverer.send("mallory", &json!({}), [url]).await.unwrap();
    drain(&deliverer, 2).await;

    assert!(inbox.received().is_empty());
    assert!(deliverer.queue().records()[0].failed);
}

#[tokio::test]
async fn loopback_is_refused_unless_allowed() {
    let inbox = Inbox::default();
    let url = serve(inbox.clone()).await;
    let guarded = Client::new(ClientConfig::default()).unwrap();

    let error = delivery::deliver(&guarded, &url, b"{}", &key(), Scheme::DraftCavage)
        .await
        .unwrap_err();

    assert!(
        matches!(error, DeliveryError::Request(RequestError::Refused(_))),
        "{error}"
    );
    assert!(error.is_permanent());
    assert!(inbox.received().is_empty());
}

#[tokio::test]
async fn a_name_that_resolves_to_loopback_is_refused() {
    let guarded = Client::new(ClientConfig::default()).unwrap();
    let url = Url::parse("http://localhost:9/inbox").unwrap();

    let error = guarded
        .post(&url, reqwest::header::HeaderMap::new(), Vec::new())
        .await
        .unwrap_err();

    assert!(matches!(error, RequestError::Refused(_)), "{error}");
}

#[tokio::test]
async fn a_shared_limit_lets_every_delivery_through_in_turn() {
    let inbox = Inbox::default();
    let url = serve(inbox.clone()).await;
    let limit = Arc::new(tokio::sync::Semaphore::new(1));
    let config = DelivererConfig {
        shared_limit: Some(limit.clone()),
        ..fast()
    };
    let first = Deliverer::new(MemoryQueue::new(), Keys, client(), config.clone());
    let second = Deliverer::new(MemoryQueue::new(), Keys, client(), config);

    first
        .send("alice", &json!({"n": 1}), [url.clone()])
        .await
        .unwrap();
    second.send("alice", &json!({"n": 2}), [url]).await.unwrap();
    let (a, b) = tokio::join!(first.run_once(), second.run_once());
    assert_eq!((a.unwrap(), b.unwrap()), (1, 1));

    assert_eq!(inbox.received().len(), 2);
    assert_eq!(limit.available_permits(), 1, "every permit is returned");
}

#[tokio::test]
async fn run_until_returns_when_stopped_and_not_before_the_batch_is_done() {
    let inbox = Inbox::default();
    let url = serve(inbox.clone()).await;
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), fast());
    deliverer.send("alice", &json!({}), [url]).await.unwrap();

    let stop = Arc::new(tokio::sync::Notify::new());
    let stopping = stop.clone();
    let run = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            deliverer.run_until(async move { stopping.notified().await }),
            async {
                // Stop once the delivery has gone through.
                while inbox.received().is_empty() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                stop.notify_one();
            }
        )
    })
    .await;

    assert!(run.is_ok(), "the loop returned once stopped");
    assert!(deliverer.queue().records()[0].complete);
}
