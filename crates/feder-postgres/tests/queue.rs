//! The PostgreSQL queue against a real database.
//!
//! Run with a database to write to, which each test leaves as it found it:
//!
//! ~~~~ sh
//! FEDER_TEST_DATABASE_URL=postgres:///feder_test \
//!   cargo test -p feder-postgres -- --ignored
//! ~~~~

use feder::queue::Queue;
use feder_postgres::PostgresQueue;
use sqlx::PgPool;
use std::time::Duration;

async fn pool() -> PgPool {
    let url = std::env::var("FEDER_TEST_DATABASE_URL")
        .expect("FEDER_TEST_DATABASE_URL names a database the tests may write to");
    PgPool::connect(&url).await.expect("connect")
}

/// A queue in a table of its own, dropped afterwards.
async fn scratch(pool: &PgPool, name: &str) -> PostgresQueue {
    sqlx::query(&format!("DROP TABLE IF EXISTS {name}"))
        .execute(pool)
        .await
        .expect("drop");
    let queue = PostgresQueue::with_table(pool.clone(), name).expect("table name");
    queue.initialize().await.expect("initialize");
    queue
}

async fn drop_table(pool: &PgPool, name: &str) {
    sqlx::query(&format!("DROP TABLE {name}"))
        .execute(pool)
        .await
        .expect("drop");
}

#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn postgres_queue_passes_the_checks() {
    let pool = pool().await;
    let queue = scratch(&pool, "feder_queue_checks").await;
    feder::testing::check_queue(&queue).await;
    drop_table(&pool, "feder_queue_checks").await;
}

#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn initializing_twice_is_harmless() {
    let pool = pool().await;
    let queue = scratch(&pool, "feder_queue_twice").await;
    queue.initialize().await.expect("initialize again");
    drop_table(&pool, "feder_queue_twice").await;
}

/// Workers claiming at once never take the same job.
#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn concurrent_claims_take_each_job_once() {
    let pool = pool().await;
    let queue = scratch(&pool, "feder_queue_concurrent").await;
    let payloads = (0..200).map(serde_json::Value::from).collect();
    queue.enqueue("q", payloads).await.expect("enqueue");

    let claims = (0..8).map(|_| {
        let queue = queue.clone();
        tokio::spawn(async move {
            let mut ids = Vec::new();
            loop {
                let jobs = queue
                    .claim("q", 7, Duration::from_secs(60))
                    .await
                    .expect("claim");
                if jobs.is_empty() {
                    break ids;
                }
                ids.extend(jobs.into_iter().map(|job| job.id));
            }
        })
    });
    let mut all = Vec::new();
    for claim in claims {
        all.extend(claim.await.expect("worker"));
    }
    let unique: std::collections::BTreeSet<_> = all.iter().collect();
    assert_eq!(all.len(), 200, "every job was claimed");
    assert_eq!(unique.len(), 200, "no job was claimed twice");
    drop_table(&pool, "feder_queue_concurrent").await;
}

#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn failed_jobs_are_pruned_by_age() {
    let pool = pool().await;
    let queue = scratch(&pool, "feder_queue_prune").await;
    queue.enqueue("q", vec![1.into()]).await.expect("enqueue");
    let job = queue
        .claim("q", 1, Duration::from_secs(60))
        .await
        .expect("claim")
        .remove(0);
    queue.fail(&job.id, "no").await.expect("fail");

    assert_eq!(
        queue
            .prune_failed(Duration::from_secs(3600))
            .await
            .expect("prune"),
        0
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        queue
            .prune_failed(Duration::from_millis(1))
            .await
            .expect("prune"),
        1
    );
    drop_table(&pool, "feder_queue_prune").await;
}

#[tokio::test]
async fn only_plain_table_names_are_accepted() {
    let options = sqlx::postgres::PgConnectOptions::new();
    let pool = sqlx::PgPool::connect_lazy_with(options);
    for name in ["feder_queue", "app.feder_queue", "q2"] {
        assert!(
            PostgresQueue::with_table(pool.clone(), name).is_ok(),
            "{name}"
        );
    }
    for name in ["", "2q", "a;drop table x", "a.b.c", "a-b", "quo\"te"] {
        assert!(
            PostgresQueue::with_table(pool.clone(), name).is_err(),
            "{name}"
        );
    }
}

/// A peer's response can hold a NUL, which PostgreSQL `text` refuses; a job
/// whose failure cannot be recorded would be retried forever.
#[tokio::test]
#[ignore = "needs FEDER_TEST_DATABASE_URL"]
async fn an_error_with_a_nul_is_recorded() {
    let pool = pool().await;
    let queue = scratch(&pool, "feder_queue_nul").await;
    queue
        .enqueue("q", vec![1.into(), 2.into()])
        .await
        .expect("enqueue");
    let jobs = queue
        .claim("q", 2, Duration::from_secs(60))
        .await
        .expect("claim");
    queue
        .retry(&jobs[0].id, Duration::from_secs(60), "bad\0response")
        .await
        .expect("retry with a NUL");
    queue
        .fail(&jobs[1].id, &"x\0".repeat(5000))
        .await
        .expect("fail with a NUL");
    let errors: Vec<String> =
        sqlx::query_scalar("SELECT last_error FROM feder_queue_nul ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read");
    assert_eq!(errors[0], "badresponse");
    assert_eq!(errors[1].chars().count(), 2001, "bounded, with an ellipsis");
    drop_table(&pool, "feder_queue_nul").await;
}
