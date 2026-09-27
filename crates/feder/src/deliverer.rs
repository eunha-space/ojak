//! Sending activities through the queue.
//!
//! [`Deliverer::send`] queues an activity for a set of inboxes and returns;
//! [`Deliverer::run`] is the loop that sends what is queued, and the
//! application spawns it on whatever runtime and in whatever task context it
//! uses — Feder does not spawn tasks of its own. Any number of loops may run,
//! in any number of processes, over one queue.

use crate::client::Client;
use crate::delivery::{self, DeliveryError, Scheme, SenderKey};
use crate::queue::{Job, Queue, QueueError, RetryPolicy};
use futures_util::StreamExt as _;
use futures_util::stream;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};
use url::Url;

/// Where a sender's signing key comes from: the application.
pub trait SenderKeys: Send + Sync + 'static {
    /// The key `sender` signs with, or `None` when there is no such sender.
    fn key(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<Option<SenderKey>, QueueError>> + Send;
}

/// A delivery that will not be tried again.
#[derive(Clone, Debug)]
pub struct DeliveryFailure {
    pub inbox: Url,
    pub sender: String,
    /// The status the inbox last answered with, if it answered. A 410 says
    /// the inbox, or its whole server, is gone for good.
    pub status: Option<u16>,
    pub error: String,
}

/// How the delivery loop behaves.
#[derive(Clone, Debug)]
pub struct DelivererConfig {
    /// The queue deliveries wait in, within the backend.
    pub queue: String,
    pub retry: RetryPolicy,
    /// How many deliveries one claim takes.
    pub batch: usize,
    /// How long a claimed delivery is held before another worker may take it.
    pub lease: Duration,
    /// Deliveries in flight at once, in all.
    pub concurrency: usize,
    /// Deliveries in flight at once to one host.
    pub per_host: usize,
    /// The scheme a host is tried in until it has accepted one.
    pub first_scheme: Scheme,
    /// The longest the loop sleeps with nothing due, so that deliveries
    /// queued by another process are picked up. Each sleep is up to a quarter
    /// shorter, at random, so that the loops of many servers in one process
    /// do not all wake at once.
    pub idle_poll: Duration,
    /// A limit on deliveries in flight shared with other deliverers, such as
    /// every tenant's in a process that serves several; a delivery holds one
    /// of its permits while it is being sent.
    pub shared_limit: Option<Arc<Semaphore>>,
}

impl Default for DelivererConfig {
    fn default() -> Self {
        Self {
            queue: "delivery".to_owned(),
            retry: RetryPolicy::default(),
            batch: 64,
            lease: Duration::from_secs(300),
            concurrency: 16,
            per_host: 2,
            first_scheme: Scheme::DraftCavage,
            idle_poll: Duration::from_secs(30),
            shared_limit: None,
        }
    }
}

/// One delivery, as it waits in the queue.
struct Delivery {
    activity: Value,
    inbox: Url,
    sender: String,
}

impl Delivery {
    fn payload(&self) -> Value {
        json!({
            "activity": self.activity,
            "inbox": self.inbox.as_str(),
            "sender": self.sender,
        })
    }

    fn from_payload(payload: &Value) -> Option<Self> {
        Some(Self {
            activity: payload.get("activity")?.clone(),
            inbox: Url::parse(payload.get("inbox")?.as_str()?).ok()?,
            sender: payload.get("sender")?.as_str()?.to_owned(),
        })
    }
}

type FailureHandler = Arc<dyn Fn(&DeliveryFailure) + Send + Sync>;

/// Queues activities and sends them.
pub struct Deliverer<Q, K> {
    queue: Q,
    keys: K,
    client: Client,
    config: DelivererConfig,
    wake: Notify,
    /// The scheme each host last accepted.
    schemes: Mutex<HashMap<String, Scheme>>,
    hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
    on_failure: Option<FailureHandler>,
}

impl<Q: Queue, K: SenderKeys> Deliverer<Q, K> {
    pub fn new(queue: Q, keys: K, client: Client, config: DelivererConfig) -> Self {
        Self {
            queue,
            keys,
            client,
            config,
            wake: Notify::new(),
            schemes: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
            on_failure: None,
        }
    }

    /// Call `handler` for every delivery given up on, which is where an
    /// application marks a server that answered 410 as gone.
    #[must_use]
    pub fn on_failure(
        mut self,
        handler: impl Fn(&DeliveryFailure) + Send + Sync + 'static,
    ) -> Self {
        self.on_failure = Some(Arc::new(handler));
        self
    }

    /// The queue backend deliveries wait in.
    pub fn queue(&self) -> &Q {
        &self.queue
    }

    /// Queue `activity`, signed by `sender`, for each of `inboxes`, once each.
    ///
    /// # Errors
    ///
    /// When the backend cannot queue them.
    pub async fn send(
        &self,
        sender: &str,
        activity: &Value,
        inboxes: impl IntoIterator<Item = Url>,
    ) -> Result<(), QueueError> {
        let inboxes: BTreeSet<Url> = inboxes.into_iter().collect();
        if inboxes.is_empty() {
            return Ok(());
        }
        let payloads = inboxes
            .into_iter()
            .map(|inbox| {
                Delivery {
                    activity: activity.clone(),
                    inbox,
                    sender: sender.to_owned(),
                }
                .payload()
            })
            .collect();
        self.queue.enqueue(&self.config.queue, payloads).await?;
        self.wake.notify_one();
        Ok(())
    }

    /// Send what is queued, forever.
    ///
    /// A backend error is waited out and retried, never returned: the loop is
    /// what keeps federation going, and a database that is briefly away should
    /// not stop it.
    pub async fn run(&self) {
        self.run_until(std::future::pending()).await;
    }

    /// Send what is queued until `stop` completes.
    ///
    /// Once `stop` has completed no new batch is claimed, and the batch in
    /// hand is finished first, so that a server shutting down does not drop
    /// deliveries in the middle of sending them. What it had claimed and not
    /// reached is leased, and comes back when the lease lapses.
    pub async fn run_until(&self, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        loop {
            // Between batches, a stop that has come wins.
            tokio::select! {
                biased;
                () = &mut stop => return,
                () = std::future::ready(()) => {}
            }
            match self.run_once().await {
                Ok(0) => {
                    tokio::select! {
                        () = &mut stop => return,
                        () = self.idle() => {}
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    tokio::select! {
                        () = &mut stop => return,
                        () = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                }
            }
        }
    }

    /// Claim one batch and send it. Returns how many deliveries it held.
    ///
    /// # Errors
    ///
    /// When the backend cannot be read.
    pub async fn run_once(&self) -> Result<usize, QueueError> {
        let batch = self
            .queue
            .claim(&self.config.queue, self.config.batch, self.config.lease)
            .await?;
        let count = batch.len();
        stream::iter(batch)
            .for_each_concurrent(self.config.concurrency, |job| self.process(job))
            .await;
        Ok(count)
    }

    async fn idle(&self) {
        let due = self.queue.next_due(&self.config.queue).await.ok().flatten();
        let sleep = jitter(due.map_or(self.config.idle_poll, |due| due.min(self.config.idle_poll)));
        tokio::select! {
            () = tokio::time::sleep(sleep) => {}
            () = self.wake.notified() => {}
        }
    }

    async fn process(&self, job: Job) {
        let Some(delivery) = Delivery::from_payload(&job.payload) else {
            let _ = self.queue.fail(&job.id, "not a delivery").await;
            return;
        };
        let outcome = self.attempt(&delivery).await;
        // A backend error here leaves the job claimed; its lease lapses and it
        // is tried again, which is the safe way to be wrong.
        let _ = match outcome {
            Ok(()) => self.queue.complete(&job.id).await,
            Err(error) => self.record_failure(&job, &delivery, &error).await,
        };
    }

    async fn attempt(&self, delivery: &Delivery) -> Result<(), DeliveryError> {
        let key = match self.keys.key(&delivery.sender).await {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Err(DeliveryError::Signing(format!(
                    "no key for sender {}",
                    delivery.sender
                )));
            }
            // The key store is the application's database; it being away
            // for a moment does not make the delivery wrong.
            Err(error) => {
                return Err(DeliveryError::Unavailable(format!("key lookup: {error}")));
            }
        };
        let host = delivery.inbox.host_str().unwrap_or_default().to_owned();
        let permit = self.host_semaphore(&host).acquire_owned().await;
        let shared_permit = match &self.config.shared_limit {
            Some(limit) => Some(limit.clone().acquire_owned().await),
            None => None,
        };
        let first = self
            .schemes
            .lock()
            .expect("scheme lock")
            .get(&host)
            .copied()
            .unwrap_or(self.config.first_scheme);
        let body = serde_json::to_vec(&delivery.activity)
            .map_err(|error| DeliveryError::Signing(error.to_string()))?;
        let result = delivery::deliver(&self.client, &delivery.inbox, &body, &key, first).await;
        drop(shared_permit);
        drop(permit);
        let accepted = result?;
        self.schemes
            .lock()
            .expect("scheme lock")
            .insert(host, accepted);
        Ok(())
    }

    fn host_semaphore(&self, host: &str) -> Arc<Semaphore> {
        self.hosts
            .lock()
            .expect("host lock")
            .entry(host.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.per_host)))
            .clone()
    }

    async fn record_failure(
        &self,
        job: &Job,
        delivery: &Delivery,
        error: &DeliveryError,
    ) -> Result<(), QueueError> {
        let attempts = job.attempts + 1;
        let delay = if error.is_permanent() {
            None
        } else {
            self.config.retry.delay(attempts)
        };
        let message = error.to_string();
        match delay {
            Some(delay) => {
                let delay = error.retry_after().map_or(delay, |asked| asked.max(delay));
                self.queue.retry(&job.id, delay, &message).await
            }
            None => {
                if let Some(handler) = &self.on_failure {
                    handler(&DeliveryFailure {
                        inbox: delivery.inbox.clone(),
                        sender: delivery.sender.clone(),
                        status: error.status(),
                        error: message.clone(),
                    });
                }
                self.queue.fail(&job.id, &message).await
            }
        }
    }
}

/// `duration`, up to a quarter shorter at random.
fn jitter(duration: Duration) -> Duration {
    use std::hash::{BuildHasher as _, RandomState};

    // A fresh RandomState is seeded from the operating system's randomness,
    // which is all a wake-up time needs; no random-number crate for this.
    let random = RandomState::new().hash_one(std::time::SystemTime::now());
    let quarter = duration / 4;
    let cut = quarter.mul_f64((random % 1_000_000) as f64 / 1_000_000.0);
    duration.saturating_sub(cut)
}

#[cfg(test)]
mod tests {
    use super::jitter;
    use std::time::Duration;

    #[test]
    fn jitter_shortens_by_at_most_a_quarter() {
        let base = Duration::from_secs(300);
        for _ in 0..100 {
            let slept = jitter(base);
            assert!(slept <= base && slept >= base * 3 / 4, "{slept:?}");
        }
    }
}
