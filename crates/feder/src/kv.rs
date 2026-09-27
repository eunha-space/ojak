//! The key-value store Feder keeps its caches in: a backend the application
//! picks.
//!
//! What Feder remembers between requests — remote public keys, the IDs of
//! activities already processed, which signature scheme a host accepts — is
//! a cache: losing it costs a refetch, never a fact. It lives in a
//! [`KvStore`], pluggable as in Fedify: *feder-postgres* keeps it in a table,
//! and [`MemoryKvStore`] keeps it in memory for tests and for servers with
//! one process.
//!
//! A key is a list of segments, such as `["key", "https://a.example/users/bob#main-key"]`,
//! so that one store holds every kind of entry without their keys colliding.
//! A value is JSON, and may be set to expire.

use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A failure in the store backend itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvError(pub String);

impl fmt::Display for KvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KvError {}

/// A key-value store backend.
///
/// An entry past its expiry is absent, whether or not the backend has
/// removed it yet.
pub trait KvStore: Send + Sync + 'static {
    /// The value under `key`.
    fn get(&self, key: &[&str]) -> impl Future<Output = Result<Option<Value>, KvError>> + Send;

    /// Put `value` under `key`, replacing what was there, to expire after
    /// `ttl` if given.
    fn set(
        &self,
        key: &[&str],
        value: Value,
        ttl: Option<Duration>,
    ) -> impl Future<Output = Result<(), KvError>> + Send;

    /// Put `value` under `key` only if nothing is there, and say whether it
    /// was put. Of any number of callers at once, in any number of
    /// processes, exactly one is told it was: this is what makes "has this
    /// activity been processed?" safe to ask from two workers.
    fn insert(
        &self,
        key: &[&str],
        value: Value,
        ttl: Option<Duration>,
    ) -> impl Future<Output = Result<bool, KvError>> + Send;

    /// Remove what is under `key`, if anything is.
    fn delete(&self, key: &[&str]) -> impl Future<Output = Result<(), KvError>> + Send;
}

/// A [`KvStore`] in memory.
#[derive(Debug, Default)]
pub struct MemoryKvStore {
    entries: Mutex<HashMap<Vec<String>, Entry>>,
}

#[derive(Debug)]
struct Entry {
    value: Value,
    expires: Option<Instant>,
}

impl Entry {
    fn live(&self, now: Instant) -> bool {
        self.expires.is_none_or(|expires| expires > now)
    }
}

impl MemoryKvStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<String>, Entry>> {
        self.entries.lock().expect("memory kv lock")
    }
}

fn owned(key: &[&str]) -> Vec<String> {
    key.iter().map(|segment| (*segment).to_owned()).collect()
}

fn expiry(ttl: Option<Duration>) -> Option<Instant> {
    ttl.map(|ttl| Instant::now() + ttl)
}

impl KvStore for MemoryKvStore {
    async fn get(&self, key: &[&str]) -> Result<Option<Value>, KvError> {
        let mut entries = self.lock();
        let key = owned(key);
        match entries.get(&key) {
            Some(entry) if entry.live(Instant::now()) => Ok(Some(entry.value.clone())),
            Some(_) => {
                entries.remove(&key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &[&str], value: Value, ttl: Option<Duration>) -> Result<(), KvError> {
        self.lock().insert(
            owned(key),
            Entry {
                value,
                expires: expiry(ttl),
            },
        );
        Ok(())
    }

    async fn insert(
        &self,
        key: &[&str],
        value: Value,
        ttl: Option<Duration>,
    ) -> Result<bool, KvError> {
        let mut entries = self.lock();
        let key = owned(key);
        if entries
            .get(&key)
            .is_some_and(|entry| entry.live(Instant::now()))
        {
            return Ok(false);
        }
        entries.insert(
            key,
            Entry {
                value,
                expires: expiry(ttl),
            },
        );
        Ok(true)
    }

    async fn delete(&self, key: &[&str]) -> Result<(), KvError> {
        self.lock().remove(&owned(key));
        Ok(())
    }
}
