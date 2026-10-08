//! Circuit breakers in Redis, as Stoplight keeps Mastodon's.

use ojak::deliverer::{Admission, BreakerFuture, BreakerStore, CircuitBreaker, Probe};
use redis::aio::ConnectionLike;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long Stoplight keeps a light's metadata after it last changed.
const TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// The script that releases a probe's lock only while it is still the one
/// that took it, so that a lock that lapsed and was taken by another probe
/// stays that probe's.
const COMPARE_DELETE: &str = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";

/// How a probe's lock is released.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ProbeRelease {
    /// With `EVAL` and the compare-and-delete script.
    #[default]
    Eval,
    /// With `FCALL` of a function the operator installed, taking the key and
    /// the lock's token and deleting the key only if it holds the token: for
    /// a Redis user that may call it and may not send scripts of its own. A
    /// call that fails falls back to [`ProbeRelease::Eval`].
    Function(String),
}

/// A [`BreakerStore`] in Redis, which the deliverers of every process
/// sharing it count their failures in, and let one probe through between, as
/// Mastodon's Sidekiq processes share their Stoplights.
///
/// A breaker is three keys, after the prefix the application gives, for each
/// destination its [`CircuitBreaker`] is kept for:
/// `stoplight:<key>:failures`, the failures in a row while it is closed;
/// `stoplight:<key>:recovery_after`, when an open breaker turns half-open,
/// in milliseconds since the epoch; and `stoplight:<key>:probe`, the lock
/// the probe through a half-open one holds, for at most the cool-off. Each
/// lasts a week after it last changed, as Stoplight's metadata does.
///
/// A breaker Redis cannot be asked about lets the delivery through. A probe
/// whose outcome is never recorded — its delivery was dropped mid-way —
/// keeps its lock until the cool-off lapses, and the next delivery probes.
///
/// The commands sent are `GET`, `SET` (with `NX`, `PX` and `EX`), `DEL`,
/// `INCRBY`, `EXPIRE`, and `EVAL` or `FCALL` as [`ProbeRelease`] says.
#[derive(Clone)]
pub struct RedisBreakers<C> {
    connection: C,
    prefix: String,
    release: ProbeRelease,
}

impl<C> fmt::Debug for RedisBreakers<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisBreakers")
            .field("prefix", &self.prefix)
            .field("release", &self.release)
            .finish_non_exhaustive()
    }
}

/// The lock a probe holds.
struct ProbeLock {
    key: String,
    token: String,
}

impl<C> RedisBreakers<C> {
    /// Breakers over `connection`, every key of which starts with `prefix`,
    /// separator included: `"tenant-a:"`, or `""` for none.
    pub fn new(connection: C, prefix: impl Into<String>) -> Self {
        Self {
            connection,
            prefix: prefix.into(),
            release: ProbeRelease::default(),
        }
    }

    /// Release probes' locks as `release` says.
    #[must_use]
    pub fn release_with(mut self, release: ProbeRelease) -> Self {
        self.release = release;
        self
    }

    /// The Redis key `part` of the breaker for `key` is kept under.
    #[must_use]
    pub fn redis_key(&self, key: &str, part: &str) -> String {
        format!("{}stoplight:{key}:{part}", self.prefix)
    }
}

impl<C> RedisBreakers<C>
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    /// `Light#run`'s choice of strategy: closed (green) lets the delivery
    /// through; open (red) holds it until the cool-off has passed; half-open
    /// (yellow) lets it through as the probe if it takes the probe's lock,
    /// which starts the count of failures again, and holds it otherwise.
    pub async fn admit(&self, breaker: &CircuitBreaker, key: &str) -> Admission {
        let mut connection = self.connection.clone();
        let recovery_after: redis::RedisResult<Option<u64>> = redis::cmd("GET")
            .arg(self.redis_key(key, "recovery_after"))
            .query_async(&mut connection)
            .await;
        let Ok(Some(recovery_after)) = recovery_after else {
            return Admission::Pass;
        };
        let now = now_millis();
        if now < recovery_after {
            return Admission::Held(Duration::from_millis(recovery_after - now));
        }
        let lock = ProbeLock {
            key: self.redis_key(key, "probe"),
            token: token(),
        };
        let taken: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&lock.key)
            .arg(&lock.token)
            .arg("NX")
            .arg("PX")
            .arg(millis(breaker.cool_off).max(1))
            .query_async(&mut connection)
            .await;
        if !matches!(taken, Ok(Some(_))) {
            return Admission::Held(breaker.cool_off);
        }
        // `YellowRunStrategy#enter_recovery`: `metrics_store.clear`.
        let _: redis::RedisResult<()> = redis::cmd("DEL")
            .arg(self.redis_key(key, "failures"))
            .query_async(&mut connection)
            .await;
        Admission::Probe(Probe::new(lock))
    }

    /// `Tracker::Request` for a delivery let through closed, and
    /// `Tracker::RecoveryProbe` for the probe, whose lock is released after.
    ///
    /// # Errors
    ///
    /// When Redis cannot be reached.
    pub async fn record(
        &self,
        breaker: &CircuitBreaker,
        key: &str,
        failed: bool,
        probe: Option<Probe>,
    ) -> redis::RedisResult<()> {
        let mut connection = self.connection.clone();
        let failures = self.redis_key(key, "failures");
        let recovery = self.redis_key(key, "recovery_after");
        let reopen = || {
            let mut command = redis::cmd("SET");
            command
                .arg(&recovery)
                .arg(now_millis().saturating_add(millis(breaker.cool_off)))
                .arg("EX")
                .arg(TTL_SECS);
            command
        };
        let recorded = match (probe.is_some(), failed) {
            // The probe failed: red for another cool-off.
            (true, true) => reopen().query_async(&mut connection).await,
            // The probe succeeded: green.
            (true, false) => {
                redis::cmd("DEL")
                    .arg(&recovery)
                    .query_async(&mut connection)
                    .await
            }
            // A success starts the count of failures again, and only that.
            (false, false) => {
                redis::pipe()
                    .cmd("DEL")
                    .arg(&failures)
                    .ignore()
                    .cmd("EXPIRE")
                    .arg(&recovery)
                    .arg(TTL_SECS)
                    .ignore()
                    .query_async(&mut connection)
                    .await
            }
            (false, true) => {
                let counted: redis::RedisResult<(u32,)> = redis::pipe()
                    .cmd("INCRBY")
                    .arg(&failures)
                    .arg(1)
                    .cmd("EXPIRE")
                    .arg(&failures)
                    .arg(TTL_SECS)
                    .ignore()
                    .query_async(&mut connection)
                    .await;
                match counted {
                    Ok((count,)) if count >= breaker.threshold.max(1) => {
                        reopen().query_async(&mut connection).await
                    }
                    Ok(_) => Ok(()),
                    Err(error) => Err(error),
                }
            }
        };
        if let Some(lock) = probe
            .as_ref()
            .and_then(|probe| probe.guard().downcast_ref::<ProbeLock>())
        {
            self.release(lock).await;
        }
        recorded
    }

    async fn release(&self, lock: &ProbeLock) {
        let mut connection = self.connection.clone();
        if let ProbeRelease::Function(function) = &self.release {
            let released: redis::RedisResult<i64> = redis::cmd("FCALL")
                .arg(function)
                .arg(1)
                .arg(&lock.key)
                .arg(&lock.token)
                .query_async(&mut connection)
                .await;
            if released.is_ok() {
                return;
            }
        }
        let _: redis::RedisResult<i64> = redis::cmd("EVAL")
            .arg(COMPARE_DELETE)
            .arg(1)
            .arg(&lock.key)
            .arg(&lock.token)
            .query_async(&mut connection)
            .await;
    }
}

impl<C> BreakerStore for RedisBreakers<C>
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    fn admit<'a>(
        &'a self,
        breaker: &'a CircuitBreaker,
        key: &'a str,
    ) -> BreakerFuture<'a, Admission> {
        Box::pin(RedisBreakers::admit(self, breaker, key))
    }

    fn record<'a>(
        &'a self,
        breaker: &'a CircuitBreaker,
        key: &'a str,
        failed: bool,
        probe: Option<Probe>,
    ) -> BreakerFuture<'a, ()> {
        Box::pin(async move {
            let _ = RedisBreakers::record(self, breaker, key, failed, probe).await;
        })
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, millis)
}

/// A token no other lock holds: this process, the time, and a count.
fn token() -> String {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        COUNT.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_breakers_keys_are_stoplights_after_the_prefix() {
        let breakers = RedisBreakers::new((), "tenant-a:");
        assert_eq!(
            breakers.redis_key("https://b.example/inbox", "failures"),
            "tenant-a:stoplight:https://b.example/inbox:failures"
        );
        assert_eq!(
            RedisBreakers::new((), "").redis_key("k", "recovery_after"),
            "stoplight:k:recovery_after"
        );
    }

    #[test]
    fn tokens_differ() {
        assert_ne!(token(), token());
    }
}
