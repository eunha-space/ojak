//! Where deliveries wait: a store the application provides.
//!
//! Feder runs the delivery loop — claiming, retrying, giving up — and keeps
//! nothing between runs itself. The deliveries live in a [`DeliveryStore`],
//! so that they survive a restart, and so that an application with a table
//! for them already keeps using it. [`MemoryStore`] is for tests and for
//! servers that can afford to lose what is queued when they stop.

use serde_json::Value;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

/// A delivery to queue.
#[derive(Clone, Debug, PartialEq)]
pub struct NewDelivery {
    pub activity: Value,
    pub inbox: Url,
    /// The application's name for the actor that signs it; handed back to
    /// the application's key lookup when the delivery is sent.
    pub sender: String,
}

/// A queued delivery, claimed for sending.
#[derive(Clone, Debug, PartialEq)]
pub struct Delivery {
    /// The store's identifier for it.
    pub id: String,
    pub activity: Value,
    pub inbox: Url,
    pub sender: String,
    /// How many times it has been tried before.
    pub attempts: u32,
}

/// A failure in the store itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// Where deliveries wait between being sent and being done with.
///
/// A store is shared by every worker that runs, in every process: two
/// servers running the same application, or the two colours of a blue/green
/// deploy, claim from one store, and a claim is a lease so that what a worker
/// that stopped was holding is handed out again once it lapses.
pub trait DeliveryStore: Send + Sync + 'static {
    /// Queue deliveries, due now.
    fn enqueue(
        &self,
        deliveries: Vec<NewDelivery>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Claim up to `limit` due deliveries for `lease`. None of them is claimed
    /// again until the lease lapses.
    fn claim(
        &self,
        limit: usize,
        lease: Duration,
    ) -> impl Future<Output = Result<Vec<Delivery>, StoreError>> + Send;

    /// A delivery went through.
    fn delivered(&self, id: &str) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A delivery is to be tried again after `delay`.
    fn retry(
        &self,
        id: &str,
        delay: Duration,
        error: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A delivery will not be tried again.
    fn failed(&self, id: &str, error: &str) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// How long until the next delivery is due, if one is waiting: how long a
    /// worker with nothing to do may sleep.
    fn next_due(&self) -> impl Future<Output = Result<Option<Duration>, StoreError>> + Send;
}

/// When to try a failed delivery again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// The delay after the first failure.
    pub initial: Duration,
    /// The longest delay between two attempts.
    pub max_delay: Duration,
    /// Attempts in all, the first included.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    /// Thirty seconds, doubling to an hour, twelve attempts: about eight
    /// hours of a peer being down before a delivery is given up on.
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(30),
            max_delay: Duration::from_secs(3600),
            max_attempts: 12,
        }
    }
}

impl RetryPolicy {
    /// The delay before the next attempt, after `attempts` attempts have
    /// failed; `None` when there are to be no more.
    #[must_use]
    pub fn delay(&self, attempts: u32) -> Option<Duration> {
        if attempts >= self.max_attempts {
            return None;
        }
        let doublings = attempts.saturating_sub(1).min(31);
        Some(
            self.initial
                .saturating_mul(1u32 << doublings)
                .min(self.max_delay),
        )
    }
}

/// A [`DeliveryStore`] in memory.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    next_id: u64,
    entries: Vec<MemoryEntry>,
}

#[derive(Clone, Debug)]
struct MemoryEntry {
    delivery: Delivery,
    due: Instant,
    status: MemoryStatus,
    last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryStatus {
    Waiting,
    Delivered,
    Failed,
}

/// A delivery's state in a [`MemoryStore`], for tests to inspect.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryRecord {
    pub delivery: Delivery,
    pub delivered: bool,
    pub failed: bool,
    pub last_error: Option<String>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every delivery the store has held, in the order they were queued.
    ///
    /// # Panics
    ///
    /// When the store's lock was poisoned by a panic elsewhere.
    #[must_use]
    pub fn records(&self) -> Vec<MemoryRecord> {
        self.lock()
            .entries
            .iter()
            .map(|entry| MemoryRecord {
                delivery: entry.delivery.clone(),
                delivered: entry.status == MemoryStatus::Delivered,
                failed: entry.status == MemoryStatus::Failed,
                last_error: entry.last_error.clone(),
            })
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state.lock().expect("memory store lock")
    }

    fn update(&self, id: &str, change: impl FnOnce(&mut MemoryEntry)) -> Result<(), StoreError> {
        let mut state = self.lock();
        let entry = state
            .entries
            .iter_mut()
            .find(|entry| entry.delivery.id == id)
            .ok_or_else(|| StoreError(format!("no delivery {id}")))?;
        change(entry);
        Ok(())
    }
}

impl DeliveryStore for MemoryStore {
    async fn enqueue(&self, deliveries: Vec<NewDelivery>) -> Result<(), StoreError> {
        let mut state = self.lock();
        let now = Instant::now();
        for delivery in deliveries {
            state.next_id += 1;
            let id = state.next_id.to_string();
            state.entries.push(MemoryEntry {
                delivery: Delivery {
                    id,
                    activity: delivery.activity,
                    inbox: delivery.inbox,
                    sender: delivery.sender,
                    attempts: 0,
                },
                due: now,
                status: MemoryStatus::Waiting,
                last_error: None,
            });
        }
        Ok(())
    }

    async fn claim(&self, limit: usize, lease: Duration) -> Result<Vec<Delivery>, StoreError> {
        let mut state = self.lock();
        let now = Instant::now();
        let mut claimed = Vec::new();
        for entry in &mut state.entries {
            if claimed.len() == limit {
                break;
            }
            if entry.status == MemoryStatus::Waiting && entry.due <= now {
                entry.due = now + lease;
                claimed.push(entry.delivery.clone());
            }
        }
        Ok(claimed)
    }

    async fn delivered(&self, id: &str) -> Result<(), StoreError> {
        self.update(id, |entry| entry.status = MemoryStatus::Delivered)
    }

    async fn retry(&self, id: &str, delay: Duration, error: &str) -> Result<(), StoreError> {
        self.update(id, |entry| {
            entry.delivery.attempts += 1;
            entry.due = Instant::now() + delay;
            entry.last_error = Some(error.to_owned());
        })
    }

    async fn failed(&self, id: &str, error: &str) -> Result<(), StoreError> {
        self.update(id, |entry| {
            entry.delivery.attempts += 1;
            entry.status = MemoryStatus::Failed;
            entry.last_error = Some(error.to_owned());
        })
    }

    async fn next_due(&self) -> Result<Option<Duration>, StoreError> {
        let state = self.lock();
        let now = Instant::now();
        Ok(state
            .entries
            .iter()
            .filter(|entry| entry.status == MemoryStatus::Waiting)
            .map(|entry| entry.due.saturating_duration_since(now))
            .min())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_doubles_to_an_hour_and_stops_at_twelve() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.delay(1), Some(Duration::from_secs(30)));
        assert_eq!(policy.delay(2), Some(Duration::from_secs(60)));
        assert_eq!(policy.delay(7), Some(Duration::from_secs(1920)));
        assert_eq!(policy.delay(8), Some(Duration::from_secs(3600)));
        assert_eq!(policy.delay(11), Some(Duration::from_secs(3600)));
        assert_eq!(policy.delay(12), None);
    }
}
