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

/// A batch finishes by its deadline: a server that keeps failing is given
/// up on rather than retried for as long as the policy allows, and what is
/// claimed after the deadline is not sent at all.
#[tokio::test]
async fn a_batch_is_given_up_on_at_its_deadline() {
    use feder::deliverer::Batch;
    use std::time::SystemTime;

    let inbox = Inbox::answering([Answer::Status(503); 10]);
    let url = serve(inbox.clone()).await;
    let failures: Arc<Mutex<Vec<DeliveryFailure>>> = Arc::default();
    let seen = failures.clone();
    // Retries a minute apart, twelve of them: without a deadline, this
    // delivery would take hours to give up on.
    let config = DelivererConfig {
        retry: RetryPolicy {
            initial: Duration::from_secs(60),
            max_delay: Duration::from_secs(3600),
            max_attempts: 12,
        },
        ..DelivererConfig::default()
    };
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), config)
        .on_failure(move |failure| seen.lock().unwrap().push(failure.clone()));

    let batch = Batch {
        tag: Some("move:1".into()),
        deadline: Some(SystemTime::now() + Duration::from_secs(30)),
    };
    deliverer
        .send_batch("alice", &json!({}), [url.clone()], &batch)
        .await
        .unwrap();
    drain(&deliverer, 1).await;

    assert_eq!(inbox.received().len(), 1, "tried once");
    let records = deliverer.queue().records();
    assert!(records[0].failed, "its next try would be past the deadline");
    assert_eq!(records[0].job.payload["tag"], "move:1");
    {
        let failures = failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].deadline);
        assert_eq!(failures[0].tag.as_deref(), Some("move:1"));
        assert_eq!(failures[0].status, Some(503));
    }

    // Claimed after its deadline, a delivery is not sent.
    let late = Batch {
        tag: Some("move:2".into()),
        deadline: Some(SystemTime::now() - Duration::from_secs(1)),
    };
    deliverer
        .send_batch("alice", &json!({}), [url], &late)
        .await
        .unwrap();
    drain(&deliverer, 1).await;
    assert_eq!(inbox.received().len(), 1, "nothing sent past the deadline");
    assert_eq!(failures.lock().unwrap().len(), 2);
}

/// A server that never answers holds the one slot it is sent on, for as
/// long as the client waits on it; every other delivery goes on through the
/// rest. Sent a batch at a time, the forty below waited behind it.
#[tokio::test]
async fn a_silent_inbox_holds_one_slot_not_the_rest() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let answered = Arc::new(AtomicUsize::new(0));
    let counting = answered.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/silent",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                StatusCode::ACCEPTED
            }),
        )
        .route(
            "/inbox/{n}",
            post(move || {
                let counting = counting.clone();
                async move {
                    counting.fetch_add(1, Ordering::SeqCst);
                    StatusCode::ACCEPTED
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let config = DelivererConfig {
        concurrency: 4,
        per_host: 4,
        batch: 8,
        ..fast()
    };
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), config);
    let silent = Url::parse(&format!("http://{address}/silent")).unwrap();
    deliverer.send("alice", &json!({}), [silent]).await.unwrap();
    let inboxes: Vec<Url> = (0..40)
        .map(|n| Url::parse(&format!("http://{address}/inbox/{n}")).unwrap())
        .collect();
    deliverer.send("alice", &json!({}), inboxes).await.unwrap();

    let delivered = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            () = deliverer.run() => {}
            () = async {
                while answered.load(Ordering::SeqCst) < 40 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            } => {}
        }
    })
    .await;
    assert!(
        delivered.is_ok(),
        "{} of 40 delivered while one inbox stayed silent",
        answered.load(Ordering::SeqCst)
    );
}

/// A queue with one connection, which each call holds across an await, as a
/// database pool's connection is held across a query.
struct OneConnection {
    inner: MemoryQueue,
    connection: Arc<tokio::sync::Semaphore>,
}

impl OneConnection {
    async fn hold(&self) -> tokio::sync::SemaphorePermit<'_> {
        let permit = self.connection.acquire().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        permit
    }
}

impl feder::queue::Queue for OneConnection {
    async fn enqueue(
        &self,
        queue: &str,
        payloads: Vec<serde_json::Value>,
    ) -> Result<(), QueueError> {
        let _held = self.hold().await;
        self.inner.enqueue(queue, payloads).await
    }

    async fn claim(
        &self,
        queue: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<feder::queue::Job>, QueueError> {
        let _held = self.hold().await;
        self.inner.claim(queue, limit, lease).await
    }

    async fn complete(&self, id: &str) -> Result<(), QueueError> {
        let _held = self.hold().await;
        self.inner.complete(id).await
    }

    async fn retry(&self, id: &str, delay: Duration, error: &str) -> Result<(), QueueError> {
        let _held = self.hold().await;
        self.inner.retry(id, delay, error).await
    }

    async fn fail(&self, id: &str, error: &str) -> Result<(), QueueError> {
        let _held = self.hold().await;
        self.inner.fail(id, error).await
    }

    async fn next_due(&self, queue: &str) -> Result<Option<Duration>, QueueError> {
        let _held = self.hold().await;
        self.inner.next_due(queue).await
    }
}

/// Claiming more is not allowed to stop the deliveries in flight from being
/// polled: one of them may hold the connection the claim is waiting for, and
/// then neither would finish. With a pool of five connections and a hundred
/// and twenty-eight deliveries in flight, that stopped every delivery and
/// starved everything else of connections too.
#[tokio::test]
async fn a_claim_does_not_starve_the_deliveries_in_flight() {
    // Thirty inboxes: one named thirty times is sent to once.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route("/inbox/{n}", post(|| async { StatusCode::ACCEPTED }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let inboxes: Vec<Url> = (0..30)
        .map(|n| Url::parse(&format!("http://{address}/inbox/{n}")).unwrap())
        .collect();
    let queue = OneConnection {
        inner: MemoryQueue::new(),
        connection: Arc::new(tokio::sync::Semaphore::new(1)),
    };
    let config = DelivererConfig {
        concurrency: 8,
        per_host: 8,
        batch: 8,
        ..fast()
    };
    let deliverer = Deliverer::new(queue, Keys, client(), config);
    deliverer.send("alice", &json!({}), inboxes).await.unwrap();

    let finished = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = deliverer.run() => {}
            () = async {
                while deliverer.queue().inner.records().iter().filter(|r| r.complete).count() < 30 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            } => {}
        }
    })
    .await;
    assert!(
        finished.is_ok(),
        "{} of 30 completed",
        deliverer
            .queue()
            .inner
            .records()
            .iter()
            .filter(|r| r.complete)
            .count()
    );
}

/// With a priority lane, a send to one inbox queued behind a fan-out takes
/// the next free slot rather than waiting for the fan-out to be sent.
#[tokio::test]
async fn a_send_to_one_inbox_goes_ahead_of_a_fan_out() {
    use feder::deliverer::Priority;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    let arrived = Arc::new(AtomicBool::new(false));
    let noting = arrived.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/slow/{n}",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                StatusCode::ACCEPTED
            }),
        )
        .route(
            "/direct",
            post(move || {
                let noting = noting.clone();
                async move {
                    noting.store(true, Ordering::SeqCst);
                    StatusCode::ACCEPTED
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let config = DelivererConfig {
        concurrency: 2,
        per_host: 2,
        batch: 2,
        priority: Some(Priority {
            queue: "delivery-priority".to_owned(),
            max_inboxes: 4,
        }),
        ..fast()
    };
    let deliverer = Deliverer::new(MemoryQueue::new(), Keys, client(), config);
    // Forty deliveries of 200 ms each through two slots: four seconds.
    let fan_out: Vec<Url> = (0..40)
        .map(|n| Url::parse(&format!("http://{address}/slow/{n}")).unwrap())
        .collect();
    deliverer.send("alice", &json!({}), fan_out).await.unwrap();
    let direct = Url::parse(&format!("http://{address}/direct")).unwrap();
    deliverer.send("alice", &json!({}), [direct]).await.unwrap();

    let started = Instant::now();
    let sent = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = deliverer.run() => {}
            () = async {
                while !arrived.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            } => {}
        }
    })
    .await;
    assert!(sent.is_ok(), "the direct send never arrived");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the direct send waited {:?} behind the fan-out",
        started.elapsed()
    );
}
