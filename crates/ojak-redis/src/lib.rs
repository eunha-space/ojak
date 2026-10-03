//! A Redis backend for Ojak's key-value store, [`RedisKvStore`].
//!
//! What Ojak keeps in its store — the IDs of activities already processed
//! and forwarded, remote keys, fetched JSON-LD contexts — is then shared by
//! every process using the same Redis, as a Mastodon server's Redis is shared
//! by its web and Sidekiq processes: an activity two processes receive at
//! once is processed by one of them.
//!
//! A key is its segments joined by `:`, after a prefix the application
//! gives, the way Redis keys are conventionally named, so that
//! `["jsonld", "context", iri]` is `jsonld:context:<iri>`, the key Mastodon
//! names that cache entry by. The prefix is put before the key as it is: an
//! application sharing one Redis between several instances gives each its own
//! prefix, such as `"tenant-a:"`, and each a Redis user whose ACL reaches only
//! keys under it (`~tenant-a:*`). Joining is not escaped, so two keys whose
//! segments join to one string are one key; Ojak's own keys never contain `:`
//! but in their last segment, which is what keeps them apart.
//!
//! A value is stored as its JSON text, and a TTL as Redis's own expiry, so
//! an expired entry is gone without anything sweeping it. The commands sent
//! are `GET`, `SET` (with `PX` and `NX`) and `DEL`, which is all a Redis user
//! for this store needs to be granted.

use ojak::kv::{KvError, KvStore};
use redis::aio::ConnectionLike;
use serde_json::Value;
use std::fmt;
use std::time::Duration;

/// A [`KvStore`] in Redis.
///
/// `C` is the connection the commands go over: a
/// `redis::aio::ConnectionManager`, which reconnects by itself, or a
/// `redis::aio::MultiplexedConnection`. It is cloned for each command, which
/// for both is a handle on one shared connection.
#[derive(Clone)]
pub struct RedisKvStore<C> {
    connection: C,
    prefix: String,
}

impl<C> fmt::Debug for RedisKvStore<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisKvStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl<C> RedisKvStore<C> {
    /// A store over `connection`, every key of which starts with `prefix`,
    /// separator included: `"tenant-a:"`, or `""` for none.
    pub fn new(connection: C, prefix: impl Into<String>) -> Self {
        Self {
            connection,
            prefix: prefix.into(),
        }
    }

    /// The Redis key `key` is stored under.
    #[must_use]
    pub fn redis_key(&self, key: &[&str]) -> String {
        let mut joined = self.prefix.clone();
        for (n, segment) in key.iter().enumerate() {
            if n > 0 {
                joined.push(':');
            }
            joined.push_str(segment);
        }
        joined
    }
}

fn error(error: redis::RedisError) -> KvError {
    KvError(error.to_string())
}

fn encode(value: &Value) -> Result<String, KvError> {
    serde_json::to_string(value).map_err(|error| KvError(error.to_string()))
}

/// A TTL in Redis's milliseconds, at least one: `PX 0` is an error, and an
/// entry asked to last less than a millisecond lasts one.
fn milliseconds(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1)
}

/// `SET key value [NX] [PX ttl]`.
fn set_command(key: String, value: String, ttl: Option<Duration>, only_new: bool) -> redis::Cmd {
    let mut command = redis::cmd("SET");
    command.arg(key).arg(value);
    if only_new {
        command.arg("NX");
    }
    if let Some(ttl) = ttl {
        command.arg("PX").arg(milliseconds(ttl));
    }
    command
}

impl<C> KvStore for RedisKvStore<C>
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    async fn get(&self, key: &[&str]) -> Result<Option<Value>, KvError> {
        let mut connection = self.connection.clone();
        let text: Option<String> = redis::cmd("GET")
            .arg(self.redis_key(key))
            .query_async(&mut connection)
            .await
            .map_err(error)?;
        text.map(|text| serde_json::from_str(&text).map_err(|error| KvError(error.to_string())))
            .transpose()
    }

    async fn set(&self, key: &[&str], value: Value, ttl: Option<Duration>) -> Result<(), KvError> {
        let mut connection = self.connection.clone();
        set_command(self.redis_key(key), encode(&value)?, ttl, false)
            .query_async::<()>(&mut connection)
            .await
            .map_err(error)
    }

    async fn insert(
        &self,
        key: &[&str],
        value: Value,
        ttl: Option<Duration>,
    ) -> Result<bool, KvError> {
        // `SET … NX` is one command, so of any number at once, from any
        // number of processes, exactly one puts, and Redis answers it `OK`.
        let mut connection = self.connection.clone();
        let put: Option<String> = set_command(self.redis_key(key), encode(&value)?, ttl, true)
            .query_async(&mut connection)
            .await
            .map_err(error)?;
        Ok(put.is_some())
    }

    async fn delete(&self, key: &[&str]) -> Result<(), KvError> {
        let mut connection = self.connection.clone();
        redis::cmd("DEL")
            .arg(self.redis_key(key))
            .query_async::<()>(&mut connection)
            .await
            .map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_its_segments_after_the_prefix() {
        let store = RedisKvStore::new((), "tenant-a:");
        assert_eq!(
            store.redis_key(&["jsonld", "context", "https://a.example/ns"]),
            "tenant-a:jsonld:context:https://a.example/ns"
        );
        let unprefixed = RedisKvStore::new((), "");
        assert_eq!(unprefixed.redis_key(&["ojak", "key", "k"]), "ojak:key:k");
        assert_eq!(unprefixed.redis_key(&["a", "b", ""]), "a:b:");
    }

    #[test]
    fn a_ttl_is_at_least_a_millisecond() {
        assert_eq!(milliseconds(Duration::from_secs(30)), 30_000);
        assert_eq!(milliseconds(Duration::from_micros(10)), 1);
    }
}
