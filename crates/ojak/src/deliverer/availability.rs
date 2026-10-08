//! Which servers have stopped answering, as Mastodon's
//! `DeliveryFailureTracker` keeps account of them.
//!
//! Every attempt at a delivery that fails in a way that may pass — and every
//! one a circuit breaker holds back — adds the day it failed on to its
//! host's failures. A host with failures on seven different days is marked
//! unavailable, and an application leaves it out of what it sends from then
//! on ([`Deliverer::skip_if`](super::Deliverer::skip_if) is where it drops a
//! delivery queued before). A delivery to it that goes through clears both,
//! as an application may when the host is otherwise heard from. An answer
//! that will not change, such as a 404, is the server working, and counts
//! for nothing.
//!
//! The days and the marks are kept wherever the application keeps them, by
//! an [`AvailabilityStore`]: Mastodon keeps the days in a Redis set for each
//! host and the marks in a table. [`Availability`] is the rule over it; it
//! is told of attempts from [`Deliverer::on_attempt`](super::Deliverer::on_attempt),
//! whose handler is called synchronously, so the application runs
//! [`Availability::record`] in a task of its own.

use super::{AttemptOutcome, DeliveryAttempt};
use std::future::Future;
use url::Url;

/// What a host's failures are counted in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// Days: seven different days with failures mark a host unavailable.
    /// What deliveries are tracked in.
    Days,
    /// Minutes: five different minutes with failures do. What Mastodon
    /// tracks requests to an auxiliary service provider in.
    Minutes,
}

impl Resolution {
    /// How many different days or minutes with failures mark a host
    /// unavailable (`FAILURE_THRESHOLDS`).
    #[must_use]
    pub fn threshold(self) -> usize {
        match self {
            Self::Days => 7,
            Self::Minutes => 5,
        }
    }

    /// The day or minute `at` falls in, in UTC, as Mastodon writes it into
    /// a host's failures: `20250102`, or `202501021504`.
    #[must_use]
    pub fn stamp(self, at: chrono::DateTime<chrono::Utc>) -> String {
        match self {
            Self::Days => at.format("%Y%m%d").to_string(),
            Self::Minutes => at.format("%Y%m%d%H%M").to_string(),
        }
    }
}

/// Where hosts' failures and the hosts marked unavailable are kept.
pub trait AvailabilityStore: Send + Sync + 'static {
    /// What went wrong reaching the store.
    type Error: Send;

    /// Add `stamp` to `host`'s failures, if it is not among them, and answer
    /// how many different stamps it then has.
    fn add_failure(
        &self,
        host: &str,
        stamp: &str,
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;

    /// Forget `host`'s failures, answering whether it had any.
    fn clear_failures(&self, host: &str) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Mark `host` unavailable, answering whether it was not already.
    fn mark_unavailable(
        &self,
        host: &str,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Take `host`'s mark away, answering whether it had one.
    fn mark_available(&self, host: &str) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Whether `host` is marked unavailable. Asked whenever a delivery comes
    /// due, so it is to answer from memory: a store keeping its marks
    /// elsewhere keeps a copy of them, read again now and then.
    fn is_unavailable(&self, host: &str) -> bool;
}

/// What came of tracking a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// How many different days or minutes the host has failures on now.
    pub failures: usize,
    /// Whether this failure marked it unavailable.
    pub marked: bool,
}

/// Mastodon's delivery failure rule, over a store.
#[derive(Clone, Debug)]
pub struct Availability<S> {
    store: S,
    resolution: Resolution,
}

impl<S: AvailabilityStore> Availability<S> {
    /// Failures counted in `resolution`, kept in `store`.
    pub fn new(store: S, resolution: Resolution) -> Self {
        Self { store, resolution }
    }

    /// Where the failures and the marks are kept.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Count a failure reaching `host` now (`track_failure!`).
    ///
    /// # Errors
    ///
    /// When the store cannot be reached.
    pub async fn track_failure(&self, host: &str) -> Result<Failure, S::Error> {
        self.track_failure_at(host, chrono::Utc::now()).await
    }

    /// Count a failure reaching `host` at `at`. A host is marked once it
    /// has failures on as many different days or minutes as the
    /// resolution's threshold; one already marked stays as it is.
    ///
    /// # Errors
    ///
    /// When the store cannot be reached.
    pub async fn track_failure_at(
        &self,
        host: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Failure, S::Error> {
        let failures = self
            .store
            .add_failure(host, &self.resolution.stamp(at))
            .await?;
        let marked =
            failures >= self.resolution.threshold() && self.store.mark_unavailable(host).await?;
        Ok(Failure { failures, marked })
    }

    /// Clear `host`'s failures, and its mark if it has one (`track_success!`
    /// and `reset!`), answering whether a mark was taken away.
    ///
    /// A host is marked only once it has failures, and only a success or a
    /// reset clears them; so with none to clear and no mark remembered,
    /// the store is not asked to take a mark away, and a fan-out to
    /// thousands of servers that answer does not ask it thousands of times.
    ///
    /// # Errors
    ///
    /// When the store cannot be reached.
    pub async fn track_success(&self, host: &str) -> Result<bool, S::Error> {
        let cleared = self.store.clear_failures(host).await?;
        if cleared || self.store.is_unavailable(host) {
            return self.store.mark_available(host).await;
        }
        Ok(false)
    }

    /// Whether deliveries to `inbox` are no longer to be sent: its host is
    /// marked unavailable.
    #[must_use]
    pub fn is_unavailable(&self, inbox: &Url) -> bool {
        crate::origin::host_of(inbox.as_str()).is_some_and(|host| self.store.is_unavailable(&host))
    }

    /// Track what `attempt` says about its host: a success or a failure, or
    /// nothing for an answer that will not change.
    ///
    /// # Errors
    ///
    /// When the store cannot be reached.
    pub async fn record(&self, attempt: &DeliveryAttempt) -> Result<(), S::Error> {
        let Some(host) = crate::origin::host_of(attempt.inbox.as_str()) else {
            return Ok(());
        };
        match succeeded(attempt) {
            Some(true) => self.track_success(&host).await.map(drop),
            Some(false) => self.track_failure(&host).await.map(drop),
            None => Ok(()),
        }
    }
}

/// Whether `attempt` counts as reaching its host (`Some(true)`), as failing
/// to (`Some(false)`) — a failure that may pass, or one a circuit breaker
/// held — or as neither, an answer that will not change (`None`, Mastodon's
/// `@unsalvageable`).
#[must_use]
pub fn succeeded(attempt: &DeliveryAttempt) -> Option<bool> {
    match attempt.outcome {
        AttemptOutcome::Delivered => Some(true),
        AttemptOutcome::Failed {
            permanent: false, ..
        }
        | AttemptOutcome::Held => Some(false),
        AttemptOutcome::Failed {
            permanent: true, ..
        } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Memory {
        failures: Arc<Mutex<HashMap<String, BTreeSet<String>>>>,
        marked: Arc<Mutex<HashSet<String>>>,
        unmarks: Arc<Mutex<usize>>,
    }

    impl AvailabilityStore for Memory {
        type Error = ();

        async fn add_failure(&self, host: &str, stamp: &str) -> Result<usize, ()> {
            let mut failures = self.failures.lock().unwrap();
            let days = failures.entry(host.to_owned()).or_default();
            days.insert(stamp.to_owned());
            Ok(days.len())
        }

        async fn clear_failures(&self, host: &str) -> Result<bool, ()> {
            Ok(self.failures.lock().unwrap().remove(host).is_some())
        }

        async fn mark_unavailable(&self, host: &str) -> Result<bool, ()> {
            Ok(self.marked.lock().unwrap().insert(host.to_owned()))
        }

        async fn mark_available(&self, host: &str) -> Result<bool, ()> {
            *self.unmarks.lock().unwrap() += 1;
            Ok(self.marked.lock().unwrap().remove(host))
        }

        fn is_unavailable(&self, host: &str) -> bool {
            self.marked.lock().unwrap().contains(host)
        }
    }

    fn day(n: u32) -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone as _;
        chrono::Utc.with_ymd_and_hms(2025, 1, n, 12, 0, 0).unwrap()
    }

    #[tokio::test]
    async fn seven_days_with_failures_mark_a_host() {
        let tracker = Availability::new(Memory::default(), Resolution::Days);
        for n in 1..=6 {
            let failure = tracker.track_failure_at("a.example", day(n)).await.unwrap();
            assert!(!failure.marked);
            // Failing again the same day is the same day.
            tracker.track_failure_at("a.example", day(n)).await.unwrap();
        }
        let inbox = Url::parse("https://A.example/inbox").unwrap();
        assert!(!tracker.is_unavailable(&inbox));
        let failure = tracker.track_failure_at("a.example", day(7)).await.unwrap();
        assert_eq!(
            failure,
            Failure {
                failures: 7,
                marked: true
            }
        );
        assert!(tracker.is_unavailable(&inbox));
        let again = tracker.track_failure_at("a.example", day(8)).await.unwrap();
        assert!(!again.marked);

        assert!(tracker.track_success("a.example").await.unwrap());
        assert!(!tracker.is_unavailable(&inbox));
        assert!(tracker.store().failures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_success_with_nothing_to_clear_asks_nothing() {
        let tracker = Availability::new(Memory::default(), Resolution::Days);
        assert!(!tracker.track_success("a.example").await.unwrap());
        assert_eq!(*tracker.store().unmarks.lock().unwrap(), 0);
    }

    #[test]
    fn stamps_are_mastodons() {
        assert_eq!(Resolution::Days.stamp(day(2)), "20250102");
        assert_eq!(Resolution::Minutes.stamp(day(2)), "202501021200");
        assert_eq!(Resolution::Minutes.threshold(), 5);
    }

    #[test]
    fn an_answer_that_will_not_change_counts_for_nothing() {
        let attempt = |outcome| DeliveryAttempt {
            inbox: Url::parse("https://a.example/inbox").unwrap(),
            sender: "alice".into(),
            outcome,
        };
        assert_eq!(succeeded(&attempt(AttemptOutcome::Delivered)), Some(true));
        assert_eq!(succeeded(&attempt(AttemptOutcome::Held)), Some(false));
        let failed = |permanent| AttemptOutcome::Failed {
            status: Some(500),
            permanent,
            error: String::new(),
        };
        assert_eq!(succeeded(&attempt(failed(false))), Some(false));
        assert_eq!(succeeded(&attempt(failed(true))), None);
    }
}
