//! Circuit breakers in a real Redis.
//!
//! Run with a Redis to write to, which each test leaves as it found it, its
//! keys under a prefix of its own:
//!
//! ~~~~ sh
//! OJAK_TEST_REDIS_URL=redis://127.0.0.1/15 \
//!   cargo test -p ojak-redis -- --ignored
//! ~~~~

use ojak::deliverer::{Admission, BreakerScope, CircuitBreaker};
use ojak_redis::{ProbeRelease, RedisBreakers};
use redis::aio::ConnectionManager;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

async fn connection() -> ConnectionManager {
    let url = std::env::var("OJAK_TEST_REDIS_URL")
        .expect("OJAK_TEST_REDIS_URL names a Redis the tests may write to");
    let client = redis::Client::open(url).expect("Redis URL");
    ConnectionManager::new(client).await.expect("connect")
}

fn prefix(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("ojak-test-{name}-{nanos}:")
}

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

/// Opens after the threshold, lets one probe through once the cool-off has
/// passed, holds the rest while it is under way, and closes when it
/// succeeds.
#[tokio::test]
#[ignore = "needs OJAK_TEST_REDIS_URL"]
async fn a_breaker_opens_probes_and_closes() {
    let mut connection = connection().await;
    let prefix = prefix("breakers");
    // A function that does not exist: releasing falls back to `EVAL`.
    let breakers = RedisBreakers::new(connection.clone(), prefix.clone())
        .release_with(ProbeRelease::Function("ojak_no_such_function".into()));
    let breaker = CircuitBreaker {
        threshold: 2,
        cool_off: Duration::from_millis(200),
        scope: BreakerScope::Inbox,
    };
    let inbox = "https://b.example/inbox";
    assert!(matches!(
        breakers.admit(&breaker, inbox).await,
        Admission::Pass
    ));
    breakers.record(&breaker, inbox, true, None).await.unwrap();
    assert!(matches!(
        breakers.admit(&breaker, inbox).await,
        Admission::Pass
    ));
    breakers.record(&breaker, inbox, true, None).await.unwrap();
    assert!(matches!(
        breakers.admit(&breaker, inbox).await,
        Admission::Held(_)
    ));

    tokio::time::sleep(Duration::from_millis(250)).await;
    let Admission::Probe(probe) = breakers.admit(&breaker, inbox).await else {
        panic!("a half-open breaker lets a probe through");
    };
    assert!(matches!(
        breakers.admit(&breaker, inbox).await,
        Admission::Held(_)
    ));
    breakers
        .record(&breaker, inbox, false, Some(probe))
        .await
        .unwrap();
    // The probe's lock is released with its outcome.
    let lock: Option<String> = redis::cmd("GET")
        .arg(breakers.redis_key(inbox, "probe"))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(lock, None);
    assert!(matches!(
        breakers.admit(&breaker, inbox).await,
        Admission::Pass
    ));
    clean(&mut connection, &prefix).await;
}
