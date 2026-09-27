//! The queue work waits in until it is done: a backend the application picks.
//!
//! Feder runs the loops — claiming, retrying, giving up — and keeps nothing
//! between runs itself. What is queued lives in a [`Queue`], so that it
//! survives a restart. As in Fedify, the queue is pluggable: *feder-postgres*
//! keeps it in a table of its own, [`MemoryQueue`] keeps it in memory for
//! tests and for servers that can afford to lose it, and an application with
//! tables for the purpose already implements the trait over them.
//!
//! Unlike Fedify's, a queue here is claimed from rather than listened to. A
//! worker claims jobs for a lease and then reports each one done, to be
//! retried after a delay, or failed. A lease is what lets any number of
//! workers in any number of processes share one queue: the two colours of a
//! blue/green deploy both run one, and what a colour was holding when it
//! stopped is handed out again when the lease lapses, not lost.

use serde_json::Value;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A job, claimed for processing.
#[derive(Clone, Debug, PartialEq)]
pub struct Job {
    /// The backend's identifier for it.
    pub id: String,
    /// Which queue it is in, such as `delivery`.
    pub queue: String,
    /// What the job is, as the code that queued it wrote it.
    pub payload: Value,
    /// How many times it has been tried before.
    pub attempts: u32,
}

/// A failure in the queue backend itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueError(pub String);

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QueueError {}

/// A queue backend.
///
/// One backend holds any number of named queues, each claimed separately, so
/// that deliveries and incoming activities can share a table without one
/// starving the other.
pub trait Queue: Send + Sync + 'static {
    /// Queue `payloads` in `queue`, due now.
    fn enqueue(
        &self,
        queue: &str,
        payloads: Vec<Value>,
    ) -> impl Future<Output = Result<(), QueueError>> + Send;

    /// Claim up to `limit` due jobs from `queue` for `lease`. None of them is
    /// claimed again until the lease lapses.
    fn claim(
        &self,
        queue: &str,
        limit: usize,
        lease: Duration,
    ) -> impl Future<Output = Result<Vec<Job>, QueueError>> + Send;

    /// A job is done; it will not be seen again.
    fn complete(&self, id: &str) -> impl Future<Output = Result<(), QueueError>> + Send;

    /// A job is to be tried again after `delay`.
    fn retry(
        &self,
        id: &str,
        delay: Duration,
        error: &str,
    ) -> impl Future<Output = Result<(), QueueError>> + Send;

    /// A job will not be tried again.
    fn fail(&self, id: &str, error: &str) -> impl Future<Output = Result<(), QueueError>> + Send;

    /// How long until the next job in `queue` is due, if one is waiting: how
    /// long a worker with nothing to do may sleep.
    fn next_due(
        &self,
        queue: &str,
    ) -> impl Future<Output = Result<Option<Duration>, QueueError>> + Send;
}

/// When to try a failed job again.
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

/// A [`Queue`] in memory.
#[derive(Debug, Default)]
pub struct MemoryQueue {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    next_id: u64,
    entries: Vec<MemoryEntry>,
}

#[derive(Clone, Debug)]
struct MemoryEntry {
    job: Job,
    due: Instant,
    status: MemoryStatus,
    last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryStatus {
    Waiting,
    Complete,
    Failed,
}

/// A job's state in a [`MemoryQueue`], for tests to inspect.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryRecord {
    pub job: Job,
    pub complete: bool,
    pub failed: bool,
    pub last_error: Option<String>,
}

impl MemoryQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every job the queue has held, in the order they were queued.
    ///
    /// # Panics
    ///
    /// When the queue's lock was poisoned by a panic elsewhere.
    #[must_use]
    pub fn records(&self) -> Vec<MemoryRecord> {
        self.lock()
            .entries
            .iter()
            .map(|entry| MemoryRecord {
                job: entry.job.clone(),
                complete: entry.status == MemoryStatus::Complete,
                failed: entry.status == MemoryStatus::Failed,
                last_error: entry.last_error.clone(),
            })
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state.lock().expect("memory queue lock")
    }

    fn update(&self, id: &str, change: impl FnOnce(&mut MemoryEntry)) -> Result<(), QueueError> {
        let mut state = self.lock();
        let entry = state
            .entries
            .iter_mut()
            .find(|entry| entry.job.id == id)
            .ok_or_else(|| QueueError(format!("no job {id}")))?;
        change(entry);
        Ok(())
    }
}

impl Queue for MemoryQueue {
    async fn enqueue(&self, queue: &str, payloads: Vec<Value>) -> Result<(), QueueError> {
        let mut state = self.lock();
        let now = Instant::now();
        for payload in payloads {
            state.next_id += 1;
            let id = state.next_id.to_string();
            state.entries.push(MemoryEntry {
                job: Job {
                    id,
                    queue: queue.to_owned(),
                    payload,
                    attempts: 0,
                },
                due: now,
                status: MemoryStatus::Waiting,
                last_error: None,
            });
        }
        Ok(())
    }

    async fn claim(
        &self,
        queue: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<Job>, QueueError> {
        let mut state = self.lock();
        let now = Instant::now();
        let mut claimed = Vec::new();
        for entry in &mut state.entries {
            if claimed.len() == limit {
                break;
            }
            if entry.job.queue == queue && entry.status == MemoryStatus::Waiting && entry.due <= now
            {
                entry.due = now + lease;
                claimed.push(entry.job.clone());
            }
        }
        Ok(claimed)
    }

    async fn complete(&self, id: &str) -> Result<(), QueueError> {
        self.update(id, |entry| entry.status = MemoryStatus::Complete)
    }

    async fn retry(&self, id: &str, delay: Duration, error: &str) -> Result<(), QueueError> {
        self.update(id, |entry| {
            entry.job.attempts += 1;
            entry.due = Instant::now() + delay;
            entry.last_error = Some(error.to_owned());
        })
    }

    async fn fail(&self, id: &str, error: &str) -> Result<(), QueueError> {
        self.update(id, |entry| {
            entry.job.attempts += 1;
            entry.status = MemoryStatus::Failed;
            entry.last_error = Some(error.to_owned());
        })
    }

    async fn next_due(&self, queue: &str) -> Result<Option<Duration>, QueueError> {
        let state = self.lock();
        let now = Instant::now();
        Ok(state
            .entries
            .iter()
            .filter(|entry| entry.job.queue == queue && entry.status == MemoryStatus::Waiting)
            .map(|entry| entry.due.saturating_duration_since(now))
            .min())
    }
}

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A [`Queue`] behind a pointer, for where the backend is chosen at run time:
/// an application with a database per tenant hands Feder a different queue
/// for each request. Any [`Queue`] is one; [`shared`] makes a [`SharedQueue`].
pub trait DynQueue: Send + Sync {
    /// [`Queue::enqueue`].
    fn enqueue<'a>(
        &'a self,
        queue: &'a str,
        payloads: Vec<Value>,
    ) -> BoxFuture<'a, Result<(), QueueError>>;
    /// [`Queue::claim`].
    fn claim<'a>(
        &'a self,
        queue: &'a str,
        limit: usize,
        lease: Duration,
    ) -> BoxFuture<'a, Result<Vec<Job>, QueueError>>;
    /// [`Queue::complete`].
    fn complete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), QueueError>>;
    /// [`Queue::retry`].
    fn retry<'a>(
        &'a self,
        id: &'a str,
        delay: Duration,
        error: &'a str,
    ) -> BoxFuture<'a, Result<(), QueueError>>;
    /// [`Queue::fail`].
    fn fail<'a>(&'a self, id: &'a str, error: &'a str) -> BoxFuture<'a, Result<(), QueueError>>;
    /// [`Queue::next_due`].
    fn next_due<'a>(
        &'a self,
        queue: &'a str,
    ) -> BoxFuture<'a, Result<Option<Duration>, QueueError>>;
}

impl<Q: Queue> DynQueue for Q {
    fn enqueue<'a>(
        &'a self,
        queue: &'a str,
        payloads: Vec<Value>,
    ) -> BoxFuture<'a, Result<(), QueueError>> {
        Box::pin(Queue::enqueue(self, queue, payloads))
    }

    fn claim<'a>(
        &'a self,
        queue: &'a str,
        limit: usize,
        lease: Duration,
    ) -> BoxFuture<'a, Result<Vec<Job>, QueueError>> {
        Box::pin(Queue::claim(self, queue, limit, lease))
    }

    fn complete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), QueueError>> {
        Box::pin(Queue::complete(self, id))
    }

    fn retry<'a>(
        &'a self,
        id: &'a str,
        delay: Duration,
        error: &'a str,
    ) -> BoxFuture<'a, Result<(), QueueError>> {
        Box::pin(Queue::retry(self, id, delay, error))
    }

    fn fail<'a>(&'a self, id: &'a str, error: &'a str) -> BoxFuture<'a, Result<(), QueueError>> {
        Box::pin(Queue::fail(self, id, error))
    }

    fn next_due<'a>(
        &'a self,
        queue: &'a str,
    ) -> BoxFuture<'a, Result<Option<Duration>, QueueError>> {
        Box::pin(Queue::next_due(self, queue))
    }
}

/// A queue shared behind a pointer; see [`DynQueue`].
pub type SharedQueue = std::sync::Arc<dyn DynQueue>;

/// `queue` as a [`SharedQueue`].
pub fn shared(queue: impl Queue) -> SharedQueue {
    std::sync::Arc::new(queue)
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
