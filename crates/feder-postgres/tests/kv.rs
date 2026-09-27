//! The PostgreSQL key-value store against a real database.
//!
//! Run with a database to write to, which each test leaves as it found it:
//!
//! ~~~~ sh
//! FEDER_TEST_DATABASE_URL=postgres:///feder_test \
//!   cargo test -p feder-postgres -- --ignored
//! ~~~~

use feder::kv::KvStore;
use feder_postgres::PostgresKvStore;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

async fn pool() -> PgPool {
    let url = std::env::var("FEDER_TEST_DATABASE_URL")
        .expect("FEDER_TEST_DATABASE_URL names a database the tests may write to");
    PgPool::connect(&url).await.expect("connect")
}

/// A store in a table of its own, dropped afterwards.
async fn scratch(pool: &PgPool, name: &str) -> PostgresKvStore {
    sqlx::query(&format!("DROP TABLE IF EXISTS {name}"))
        .execute(pool)
        .await
        .expect("drop");
    let store = PostgresKvStore::with_table(pool.clone(), name).expect("table name");
    store.initialize().await.expect("initialize");
    store
}

async fn drop_table(pool: &PgPool, name: &str) {
    sqlx::query(&format!("DROP TABLE {name}"))
        .execute(pool)
        .await
        .expect("drop");
}

#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn postgres_kv_passes_the_checks() {
    let pool = pool().await;
    let store = scratch(&pool, "feder_kv_checks").await;
    feder::testing::check_kv(&store).await;
    drop_table(&pool, "feder_kv_checks").await;
}

/// Inserts from separate connections at once: exactly one puts.
#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn concurrent_inserts_put_once() {
    let pool = pool().await;
    let store = scratch(&pool, "feder_kv_race").await;
    for round in 0..20 {
        let key = format!("activity-{round}");
        let tasks: Vec<_> = (0..8)
            .map(|n| {
                let store = store.clone();
                let key = key.clone();
                tokio::spawn(async move { store.insert(&["seen", &key], json!(n), None).await })
            })
            .collect();
        let mut put = 0;
        for task in tasks {
            if task.await.expect("task").expect("insert") {
                put += 1;
            }
        }
        assert_eq!(put, 1, "round {round}");
    }
    drop_table(&pool, "feder_kv_race").await;
}

#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn pruning_removes_only_what_has_expired() {
    let pool = pool().await;
    let store = scratch(&pool, "feder_kv_prune").await;
    store
        .set(&["short"], json!(1), Some(Duration::from_millis(10)))
        .await
        .expect("set short");
    store
        .set(&["long"], json!(2), Some(Duration::from_secs(3600)))
        .await
        .expect("set long");
    store.set(&["forever"], json!(3), None).await.expect("set");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(store.prune_expired().await.expect("prune"), 1);
    assert_eq!(store.get(&["long"]).await.expect("get"), Some(json!(2)));
    assert_eq!(store.get(&["forever"]).await.expect("get"), Some(json!(3)));
    drop_table(&pool, "feder_kv_prune").await;
}
