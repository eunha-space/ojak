//! The Redis key-value store against a real Redis.
//!
//! Run with a Redis to write to, which each test leaves as it found it, its
//! keys under a prefix of its own:
//!
//! ~~~~ sh
//! OJAK_TEST_REDIS_URL=redis://127.0.0.1/15 \
//!   cargo test -p ojak-redis -- --ignored
//! ~~~~

use ojak::kv::KvStore;
use ojak_redis::RedisKvStore;
use redis::aio::ConnectionManager;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

async fn connection() -> ConnectionManager {
    let url = std::env::var("OJAK_TEST_REDIS_URL")
        .expect("OJAK_TEST_REDIS_URL names a Redis the tests may write to");
    let client = redis::Client::open(url).expect("Redis URL");
    ConnectionManager::new(client).await.expect("connect")
}

/// A prefix no other run shares.
fn prefix(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("ojak-test-{name}-{nanos}:")
}

/// Remove every key under `prefix`.
async fn clean(connection: &mut ConnectionManager, prefix: &str) {
    let keys: Vec<Vec<u8>> = redis::cmd("KEYS")
        .arg(format!("{prefix}*"))
        .query_async(connection)
        .await
        .expect("keys");
    if !keys.is_empty() {
        redis::cmd("DEL")
            .arg(keys)
            .query_async::<()>(connection)
            .await
            .expect("del");
    }
}

#[tokio::test]
#[ignore = "needs OJAK_TEST_REDIS_URL"]
async fn redis_kv_passes_the_checks() {
    let mut connection = connection().await;
    let prefix = prefix("checks");
    ojak::testing::check_kv(&RedisKvStore::new(connection.clone(), prefix.clone())).await;
    clean(&mut connection, &prefix).await;
}

/// Entries are kept under the prefix, named as Redis keys are, with Redis's
/// own expiry.
#[tokio::test]
#[ignore = "needs OJAK_TEST_REDIS_URL"]
async fn entries_are_plain_redis_keys_under_the_prefix() {
    let mut connection = connection().await;
    let prefix = prefix("names");
    let store = RedisKvStore::new(connection.clone(), prefix.clone());
    store
        .set(
            &["jsonld", "context", "https://a.example/ns"],
            json!("{}"),
            Some(Duration::from_secs(60)),
        )
        .await
        .unwrap();
    let key = format!("{prefix}jsonld:context:https://a.example/ns");
    let ttl: i64 = redis::cmd("PTTL")
        .arg(&key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!((1..=60_000).contains(&ttl), "{ttl}");
    let stored: String = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(stored, "\"{}\"");
    clean(&mut connection, &prefix).await;
}

/// Inserts from separate connections at once: exactly one puts.
#[tokio::test]
#[ignore = "needs OJAK_TEST_REDIS_URL"]
async fn concurrent_inserts_put_once() {
    let mut connection = connection().await;
    let prefix = prefix("race");
    for round in 0..20 {
        let key = format!("activity-{round}");
        let mut tasks = Vec::new();
        for n in 0..8 {
            let store = RedisKvStore::new(self::connection().await, prefix.clone());
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                store.insert(&[&key], json!(n), None).await.unwrap()
            }));
        }
        let mut put = 0;
        for task in tasks {
            if task.await.unwrap() {
                put += 1;
            }
        }
        assert_eq!(put, 1, "round {round}");
    }
    clean(&mut connection, &prefix).await;
}
