//! What an application's tests, and a backend's, need.
//!
//!  -  [`Remote`]: another server, on the loopback interface, with actors
//!     that follow, reply and like the way a real server's do. It serves
//!     their documents and keys, keeps what is delivered to it, and signs
//!     activities for the application's inbox.
//!  -  [`signed_post`]: an activity POSTed to an inbox, signed as a server
//!     signs it.
//!  -  [`client_config`]: a client allowed to reach the loopback interface,
//!     which a real one refuses.
//!  -  [`check_queue`] and [`check_kv`]: the checks every [`Queue`] and
//!     [`KvStore`] backend has to pass. A backend that is right about the
//!     easy cases and wrong about a lease is the kind of bug that loses
//!     deliveries once a week, so each backend runs them in its own tests,
//!     over its own storage.

use crate::client::ClientConfig;
use crate::kv::KvStore;
use crate::queue::{Job, Queue};
use crate::sig::signature::{PrivateKey, sign_request_with_key};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;

/// The private key every [`Remote`] actor signs with: RFC 9421's test key,
/// which is public, and so fit for nothing but tests.
pub const PRIVATE_KEY_PEM: &str = include_str!("../tests/fixtures/rfc9421_test_key_rsa.pem");
/// Its public key, which every [`Remote`] actor publishes.
pub const PUBLIC_KEY_PEM: &str = include_str!("../tests/fixtures/rfc9421_test_key_rsa_public.pem");

/// A client configuration that may reach the loopback interface, where a
/// [`Remote`] runs. Never use it outside tests: the client refuses private
/// addresses so that nobody can make a server fetch from its own network.
#[must_use]
pub fn client_config() -> ClientConfig {
    ClientConfig {
        allow_private: vec![
            "127.0.0.0/8".parse().expect("a network"),
            "::1/128".parse().expect("a network"),
        ],
        ..ClientConfig::default()
    }
}

/// `activity`, POSTed to the inbox at `url` and signed with `key_id` and
/// the private key `pem`, as a server signs a delivery (draft-cavage, with
/// a digest of the body). The request's target is `url`'s path, with its
/// host in `Host`, as a server receives it.
///
/// # Panics
///
/// When `url` or `pem` cannot be read.
#[must_use]
pub fn signed_post(url: &str, activity: &Value, key_id: &str, pem: &str) -> http::Request<Vec<u8>> {
    let url = Url::parse(url).expect("an inbox URL");
    let body = serde_json::to_vec(activity).expect("JSON");
    let key = PrivateKey::from_pem(pem).expect("a private key");
    let signed = sign_request_with_key(
        "post",
        url.as_str(),
        &body,
        key_id,
        &key,
        &[],
        chrono::Utc::now().timestamp(),
    )
    .expect("a signature");
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    http::Request::post(target)
        .header("host", host)
        .header("content-type", "application/activity+json")
        .header("date", signed.date)
        .header("digest", signed.digest)
        .header("signature", signed.signature)
        .body(body)
        .expect("a request")
}

/// Another server, on the loopback interface, for an application's tests to
/// federate with.
///
/// Any name is an actor: `/users/{name}` serves a `Person` with an inbox, a
/// shared inbox and [`PUBLIC_KEY_PEM`] as its key. Whatever is POSTed to an
/// inbox is kept, for [`Remote::received`]. The server runs until the test's
/// runtime stops. The application's client has to be allowed to reach it,
/// with [`client_config`].
///
/// ~~~~ ignore
/// let remote = Remote::start().await;
/// let follow = json!({
///     "id": format!("{}/follows/1", remote.actor("alice")),
///     "type": "Follow",
///     "actor": remote.actor("alice").as_str(),
///     "object": "https://blog.test/users/blog",
/// });
/// let request = remote.sign("alice", "https://blog.test/users/blog/inbox", &follow);
/// // … hand `request` to the application, then:
/// assert_eq!(remote.received()[0]["type"], "Accept");
/// ~~~~
#[derive(Clone, Debug)]
pub struct Remote {
    origin: Url,
    received: Arc<Mutex<Vec<Value>>>,
}

impl Remote {
    /// Start one, on a port of its own.
    ///
    /// # Panics
    ///
    /// When no port is free.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let origin = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("an address")
        ))
        .expect("an origin");
        let remote = Self {
            origin,
            received: Arc::default(),
        };
        let server = remote.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let server = server.clone();
                tokio::spawn(async move { server.answer(stream).await });
            }
        });
        remote
    }

    /// Where it is, such as `http://127.0.0.1:49152/`.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.origin
    }

    /// The actor `name`'s IRI.
    ///
    /// # Panics
    ///
    /// When `name` cannot be a path segment.
    #[must_use]
    pub fn actor(&self, name: &str) -> Url {
        self.origin
            .join(&format!("users/{name}"))
            .expect("an actor IRI")
    }

    /// The ID of the key the actor `name` signs with.
    #[must_use]
    pub fn key_id(&self, name: &str) -> String {
        format!("{}#main-key", self.actor(name))
    }

    /// `activity`, POSTed to the inbox at `url` and signed by the actor
    /// `name`; see [`signed_post`].
    #[must_use]
    pub fn sign(&self, name: &str, url: &str, activity: &Value) -> http::Request<Vec<u8>> {
        signed_post(url, activity, &self.key_id(name), PRIVATE_KEY_PEM)
    }

    /// Everything delivered to any of its inboxes so far, oldest first.
    ///
    /// # Panics
    ///
    /// When a thread panicked while delivering.
    #[must_use]
    pub fn received(&self) -> Vec<Value> {
        self.received.lock().expect("not poisoned").clone()
    }

    fn actor_document(&self, name: &str) -> Value {
        let id = self.actor(name);
        json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1"
            ],
            "id": id.as_str(),
            "type": "Person",
            "preferredUsername": name,
            "inbox": format!("{id}/inbox"),
            "endpoints": {"sharedInbox": self.origin.join("inbox").expect("an inbox").as_str()},
            "publicKey": {
                "id": self.key_id(name),
                "owner": id.as_str(),
                "publicKeyPem": PUBLIC_KEY_PEM,
            },
        })
    }

    /// Answer one request on `stream`, and close it.
    async fn answer(&self, mut stream: tokio::net::TcpStream) {
        let mut buffer = Vec::new();
        let mut chunk = [0; 8192];
        let head_end = loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let mut lines = head.lines();
        let mut request_line = lines.next().unwrap_or_default().split(' ');
        let method = request_line.next().unwrap_or_default().to_owned();
        let path = request_line.next().unwrap_or_default().to_owned();
        let length = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buffer.len() < head_end + length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
        let body = &buffer[head_end..head_end + length];

        let (status, content) = match (method.as_str(), path.strip_prefix("/users/")) {
            ("GET", Some(name)) if !name.is_empty() && !name.contains('/') => {
                ("200 OK", self.actor_document(name).to_string())
            }
            ("POST", _) if path == "/inbox" || path.ends_with("/inbox") => {
                match serde_json::from_slice(body) {
                    Ok(activity) => {
                        self.received.lock().expect("not poisoned").push(activity);
                        ("202 Accepted", String::new())
                    }
                    Err(_) => ("400 Bad Request", String::new()),
                }
            }
            _ => ("404 Not Found", String::new()),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/activity+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{content}",
            content.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

/// Run every check against `queue`, which must be empty.
///
/// Leases and delays are short, so a backend whose clock is coarse may need
/// the real time of a few hundred milliseconds.
///
/// # Panics
///
/// When the backend breaks a rule, naming the rule.
pub async fn check_queue(queue: &impl Queue) {
    let lease = Duration::from_millis(300);
    let payload = json!({"nested": {"list": [1, "two", null]}, "text": "안녕"});

    queue
        .enqueue("a", vec![payload.clone(), json!(2), json!(3)])
        .await
        .expect("enqueue a");
    queue
        .enqueue("b", vec![json!("b")])
        .await
        .expect("enqueue b");

    // Claims are per queue, and limited.
    let first = queue.claim("a", 2, lease).await.expect("claim a");
    assert_eq!(first.len(), 2, "a claim takes at most its limit");
    assert!(
        first.iter().all(|job| job.queue == "a"),
        "a claim takes from its own queue"
    );
    let payloads: Vec<_> = first.iter().map(|job| job.payload.clone()).collect();
    assert!(
        payloads.contains(&payload),
        "a payload comes back as it was queued"
    );
    assert!(
        first.iter().all(|job| job.attempts == 0),
        "a new job has no attempts"
    );

    // What is leased is not handed out again while the lease holds.
    let second = queue.claim("a", 10, lease).await.expect("claim a again");
    assert_eq!(second.len(), 1, "leased jobs are not claimed twice");
    let b = queue.claim("b", 10, lease).await.expect("claim b");
    assert_eq!(b.len(), 1, "another queue is not held up by this one");

    let [done, retried] = [&first[0], &first[1]];
    let failed = &second[0];
    queue.complete(&done.id).await.expect("complete");
    queue
        .retry(&retried.id, Duration::from_millis(50), "try again")
        .await
        .expect("retry");
    queue.fail(&failed.id, "given up").await.expect("fail");

    // A retry is not due before its delay, and is after.
    let early = queue
        .claim("a", 10, lease)
        .await
        .expect("claim before delay");
    assert!(early.is_empty(), "a retried job waits for its delay");
    let due = queue.next_due("a").await.expect("next due");
    assert!(due.is_some(), "a waiting job has a due time");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let again: Vec<Job> = queue
        .claim("a", 10, lease)
        .await
        .expect("claim after delay");
    assert_eq!(again.len(), 1, "a retried job comes back after its delay");
    assert_eq!(
        again[0].id, retried.id,
        "the job that comes back is the retried one"
    );
    assert_eq!(again[0].attempts, 1, "a retry counts an attempt");

    // A lease that lapses hands the job out again; a completed or failed job
    // never comes back.
    tokio::time::sleep(lease + Duration::from_millis(100)).await;
    let lapsed = queue
        .claim("a", 10, lease)
        .await
        .expect("claim after lease");
    let ids: Vec<&str> = lapsed.iter().map(|job| job.id.as_str()).collect();
    assert_eq!(
        ids,
        [retried.id.as_str()],
        "only an uncompleted lease comes back"
    );

    queue.complete(&retried.id).await.expect("complete retried");
    let lapsed_b = queue
        .claim("b", 10, lease)
        .await
        .expect("claim b after lease");
    assert_eq!(
        lapsed_b.len(),
        1,
        "an unfinished job in another queue comes back too"
    );
    queue.complete(&lapsed_b[0].id).await.expect("complete b");

    tokio::time::sleep(lease + Duration::from_millis(100)).await;
    assert!(
        queue
            .claim("a", 10, lease)
            .await
            .expect("final claim")
            .is_empty(),
        "nothing completed or failed is claimed again"
    );
    assert_eq!(
        queue.next_due("a").await.expect("final next due"),
        None,
        "an empty queue has nothing due"
    );

    // What a peer can put in a document, NUL included, is queued and comes
    // back as it was: an activity that cannot be queued is lost.
    let peer = json!({"content": "a\u{0}b", "a\u{0}": [1]});
    queue
        .enqueue("c", vec![peer.clone()])
        .await
        .expect("enqueue what a peer sent");
    let claimed = queue.claim("c", 10, lease).await.expect("claim c");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].payload, peer, "a payload comes back as it was");
    queue.complete(&claimed[0].id).await.expect("complete c");
}

/// Run every check against `store`, which must be empty.
///
/// # Panics
///
/// When the backend breaks a rule, naming the rule.
pub async fn check_kv(store: &impl KvStore) {
    let ttl = Duration::from_millis(300);
    // What a peer can put in a document, NUL included, comes back as it was.
    let value = json!({"nested": {"list": [1, "two", null]}, "text": "안녕\u{0}"});

    assert_eq!(
        store.get(&["a"]).await.expect("get missing"),
        None,
        "nothing is there before it is set"
    );
    store
        .set(&["a", "b"], value.clone(), None)
        .await
        .expect("set");
    assert_eq!(
        store.get(&["a", "b"]).await.expect("get"),
        Some(value.clone()),
        "a value comes back as it was set"
    );

    // Keys are lists, and lists that would join to one string are distinct.
    for other in [&["a/b"][..], &["a", "b", ""], &["ab"], &["a"], &["b", "a"]] {
        assert_eq!(
            store.get(other).await.expect("get other"),
            None,
            "{other:?} is not [\"a\", \"b\"]"
        );
    }
    let odd: &[&str] = &["", "with\u{0}nul", "안녕", "\"quoted\""];
    store.set(odd, json!(1), None).await.expect("set odd key");
    assert_eq!(
        store.get(odd).await.expect("get odd key"),
        Some(json!(1)),
        "any string is a key segment"
    );

    store
        .set(&["a", "b"], json!("replaced"), None)
        .await
        .expect("replace");
    assert_eq!(
        store.get(&["a", "b"]).await.expect("get replaced"),
        Some(json!("replaced")),
        "set replaces"
    );

    // Expiry.
    store
        .set(&["expiring"], json!(true), Some(ttl))
        .await
        .expect("set expiring");
    assert_eq!(
        store.get(&["expiring"]).await.expect("get before expiry"),
        Some(json!(true)),
        "an entry is there until it expires"
    );

    // Insert puts only where nothing is.
    assert!(
        store
            .insert(&["once"], json!(1), Some(ttl))
            .await
            .expect("insert"),
        "insert into nothing puts"
    );
    assert!(
        !store
            .insert(&["once"], json!(2), None)
            .await
            .expect("insert again"),
        "insert over something does not"
    );
    assert_eq!(
        store.get(&["once"]).await.expect("get once"),
        Some(json!(1)),
        "a refused insert leaves the value alone"
    );

    tokio::time::sleep(ttl + Duration::from_millis(200)).await;
    assert_eq!(
        store.get(&["expiring"]).await.expect("get after expiry"),
        None,
        "an expired entry is absent"
    );
    assert!(
        store
            .insert(&["once"], json!(3), None)
            .await
            .expect("insert over expired"),
        "insert over an expired entry puts"
    );
    assert_eq!(
        store.get(&["once"]).await.expect("get reinserted"),
        Some(json!(3)),
        "and what it put is there, without expiry"
    );

    // Of inserts at once, exactly one puts.
    let racers =
        futures_util::future::join_all((0..8).map(|n| store.insert(&["race"], json!(n), None)))
            .await;
    let won = racers
        .into_iter()
        .map(|result| result.expect("racing insert"))
        .filter(|put| *put)
        .count();
    assert_eq!(won, 1, "exactly one of several inserts puts");

    store.delete(&["a", "b"]).await.expect("delete");
    store.delete(&["never set"]).await.expect("delete missing");
    assert_eq!(
        store.get(&["a", "b"]).await.expect("get deleted"),
        None,
        "a deleted entry is absent"
    );
    for key in [odd, &["once"], &["race"]] {
        store.delete(key).await.expect("clean up");
    }
}
