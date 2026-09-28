//! The in-memory key-value store passes the backend checks, and holds only
//! what has not expired, and no more than it is allowed.

use ojak::kv::{KvStore, MemoryKvStore};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn memory_kv_passes_the_checks() {
    ojak::testing::check_kv(&MemoryKvStore::new()).await;
    ojak::testing::check_kv(&MemoryKvStore::with_capacity(1_000)).await;
}

/// An entry nobody asks for again is removed once it has expired, as the
/// store goes on being written to: an activity processed once, an actor seen
/// once, do not stay for the life of the process.
#[tokio::test]
async fn an_expired_entry_goes_without_being_asked_for() {
    let store = MemoryKvStore::new();
    for n in 0..100 {
        let key = n.to_string();
        store
            .set(&["once", &key], json!(true), Some(Duration::from_millis(1)))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    for n in 0..5_000 {
        let key = n.to_string();
        store
            .set(
                &["kept", &key],
                json!(true),
                Some(Duration::from_secs(3_600)),
            )
            .await
            .unwrap();
    }
    assert!(
        store.len() <= 5_000,
        "{} entries: the expired ones were never swept",
        store.len()
    );
    assert_eq!(store.get(&["kept", "0"]).await.unwrap(), Some(json!(true)));
}

/// Over capacity, what is nearest to expiring goes first, and what never
/// expires goes last.
#[tokio::test]
async fn a_full_store_drops_what_expires_soonest() {
    let store = MemoryKvStore::with_capacity(100);
    store.set(&["forever"], json!(1), None).await.unwrap();
    for n in 0..150_u64 {
        let key = n.to_string();
        store
            .set(&["n", &key], json!(n), Some(Duration::from_secs(1_000 + n)))
            .await
            .unwrap();
    }
    assert!(store.len() <= 100, "{} entries", store.len());
    assert_eq!(store.get(&["forever"]).await.unwrap(), Some(json!(1)));
    assert_eq!(store.get(&["n", "149"]).await.unwrap(), Some(json!(149)));
    assert_eq!(
        store.get(&["n", "0"]).await.unwrap(),
        None,
        "the soonest to expire went first"
    );
}
