//! Checks every [`Queue`] and [`KvStore`] backend has to pass.
//!
//! A backend that is right about the easy cases and wrong about a lease is
//! the kind of bug that loses deliveries once a week, so each backend runs
//! [`check_queue`] or [`check_kv`] in its own tests, over its own storage.

use crate::kv::KvStore;
use crate::queue::{Job, Queue};
use serde_json::json;
use std::time::Duration;

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
