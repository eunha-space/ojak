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
///
/// An entry that has expired is removed as the store is written to, not only
/// when its own key is next asked for: most keys are never asked for again —
/// an actor seen once, an activity processed once — and a store that waited
/// for that would grow for as long as its process ran.
///
/// [`MemoryKvStore::with_capacity`] also bounds how many entries it holds,
/// dropping those nearest to expiring first. Everything Feder keeps here is a
/// cache, so an entry dropped early costs a refetch, or for an activity's ID,
/// a duplicate the application's own writes have to tolerate anyway.
#[derive(Debug, Default)]
pub struct MemoryKvStore {
    entries: Mutex<Entries>,
    capacity: Option<usize>,
}

#[derive(Debug, Default)]
struct Entries {
    map: HashMap<Vec<String>, Entry>,
    /// Writes since expired entries were last swept out.
    writes: usize,
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

/// Sweep at least this rarely, however small the store.
const SWEEP_EVERY: usize = 1_024;

impl Entries {
    /// Put an entry, then keep the store to what has not expired and to
    /// `capacity`. A sweep visits every entry, so it waits until the writes
    /// since the last one are half as many as the entries: each write pays for
    /// a bounded share of it.
    fn put(&mut self, key: Vec<String>, entry: Entry, capacity: Option<usize>) {
        self.map.insert(key, entry);
        self.writes += 1;
        let now = Instant::now();
        if self.writes >= SWEEP_EVERY.max(self.map.len() / 2) {
            self.map.retain(|_, entry| entry.live(now));
            self.writes = 0;
        }
        if let Some(capacity) = capacity
            && self.map.len() > capacity
        {
            self.map.retain(|_, entry| entry.live(now));
            self.shrink_to(capacity - capacity / 10);
        }
    }

    /// Drop the entries nearest to expiring until `target` remain. Evicting a
    /// tenth below capacity at a time, rather than one entry per write, keeps
    /// eviction's cost off every write once the store is full.
    fn shrink_to(&mut self, target: usize) {
        let excess = self.map.len().saturating_sub(target);
        if excess == 0 {
            return;
        }
        // Never-expiring entries sort last, so they go only when nothing else
        // is left to drop.
        let mut by_expiry: Vec<(Option<Instant>, &Vec<String>)> = self
            .map
            .iter()
            .map(|(key, entry)| (entry.expires, key))
            .collect();
        by_expiry.select_nth_unstable_by(excess - 1, |a, b| match (a.0, b.0) {
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        let doomed: Vec<Vec<String>> = by_expiry[..excess]
            .iter()
            .map(|(_, key)| (*key).clone())
            .collect();
        for key in doomed {
            self.map.remove(&key);
        }
    }
}

impl MemoryKvStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that holds at most `capacity` entries.
    ///
    /// # Panics
    /// If `capacity` is zero.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "a memory kv store holds at least one entry");
        Self {
            entries: Mutex::default(),
            capacity: Some(capacity),
        }
    }

    /// How many entries it holds, expired ones not yet swept out included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// Whether it holds no entries at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
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
        match entries.map.get(&key) {
            Some(entry) if entry.live(Instant::now()) => Ok(Some(entry.value.clone())),
            Some(_) => {
                entries.map.remove(&key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &[&str], value: Value, ttl: Option<Duration>) -> Result<(), KvError> {
        self.lock().put(
            owned(key),
            Entry {
                value,
                expires: expiry(ttl),
            },
            self.capacity,
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
            .map
            .get(&key)
            .is_some_and(|entry| entry.live(Instant::now()))
        {
            return Ok(false);
        }
        entries.put(
            key,
            Entry {
                value,
                expires: expiry(ttl),
            },
            self.capacity,
        );
        Ok(true)
    }

    async fn delete(&self, key: &[&str]) -> Result<(), KvError> {
        self.lock().map.remove(&owned(key));
        Ok(())
    }
}
