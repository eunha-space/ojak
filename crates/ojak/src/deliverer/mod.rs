//! Sending activities through the queue.
//!
//! [`Deliverer::send`] queues an activity for a set of inboxes and returns;
//! [`Deliverer::run`] is the loop that sends what is queued, and the
//! application spawns it on whatever runtime and in whatever task context it
//! uses — Ojak does not spawn tasks of its own. Any number of loops may run,
//! in any number of processes, over one queue.
//!
//! A batch, such as moving every account's followers, has to finish:
//! [`Deliverer::send_batch`] tags each delivery so that the batch can be
//! followed, and gives it a deadline, past which it is given up on rather
//! than retried, so that one server that is down or too slow does not hold
//! the batch open for as long as the retry policy would.
//!
//! A portable inbox (FEP-ef61) has no host of its own, only the gateways its
//! actor lists; [`Deliverer::send_portable`] queues it with them, and one
//! attempt tries each in order until one accepts.

mod post;

pub use post::{DeliveryError, deliver};

use crate::client::Client;
use crate::portable::ApUri;
use crate::queue::{Job, Queue, QueueError, RetryPolicy};
use crate::sig::{Scheme, SenderKey};
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

/// One key, for an application with one sender: it signs whatever is sent.
impl SenderKeys for SenderKey {
    fn key(
        &self,
        _sender: &str,
    ) -> impl Future<Output = Result<Option<SenderKey>, QueueError>> + Send {
        std::future::ready(Ok(Some(self.clone())))
    }
}

/// A key for each sender, by the name it is sent as.
impl<S: std::hash::BuildHasher + Send + Sync + 'static> SenderKeys
    for HashMap<String, SenderKey, S>
{
    fn key(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<Option<SenderKey>, QueueError>> + Send {
        std::future::ready(Ok(self.get(sender).cloned()))
    }
}

/// A key for each sender, by the name it is sent as.
impl SenderKeys for std::collections::BTreeMap<String, SenderKey> {
    fn key(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<Option<SenderKey>, QueueError>> + Send {
        std::future::ready(Ok(self.get(sender).cloned()))
    }
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
    /// The tag of the batch it was sent in, if any.
    pub tag: Option<String>,
    /// Whether it was given up on for its batch's deadline, rather than for
    /// the retry policy or an answer that will not change.
    pub deadline: bool,
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
    /// A lane for sends to few inboxes — a direct message, a reply, a follow
    /// — whose deliveries take free slots before any other's.
    ///
    /// Deliveries are otherwise sent in the order they were queued, so a
    /// message to one person queued just after a post to thousands of
    /// servers waits for every one of those: two and a half minutes behind
    /// three posts to 9,258 servers. Off unless given.
    pub priority: Option<Priority>,
}

/// Where sends to few inboxes go, and how few is few.
#[derive(Clone, Debug)]
pub struct Priority {
    /// The queue they wait in, within the backend.
    pub queue: String,
    /// A send to this many inboxes or fewer goes to the priority queue.
    pub max_inboxes: usize,
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
            priority: None,
        }
    }
}

/// A portable actor's inbox, and the gateways that accept deliveries to it,
/// in the order its actor lists them.
#[derive(Clone, Debug)]
pub struct PortableInbox {
    pub inbox: ApUri,
    pub gateways: Vec<Url>,
}

/// What a batch of deliveries shares: a tag to find them by, and when to
/// give up on the ones that have not gone through.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    /// Kept with each delivery, as `tag` in its payload, for the application
    /// to follow the batch by.
    pub tag: Option<String>,
    /// A delivery that has not gone through by then is given up on, reported
    /// to the failure handler with [`DeliveryFailure::deadline`] set. One that
    /// would next be tried after it is given up on at once.
    pub deadline: Option<std::time::SystemTime>,
}

/// One delivery, as it waits in the queue.
struct Delivery {
    activity: Value,
    /// The inbox; a portable one's `ap` URI, percent-encoded as a `Url`.
    inbox: Url,
    /// Where to send it, in order, when that is not `inbox` itself: a
    /// portable inbox at each of its gateways.
    via: Vec<Url>,
    sender: String,
    tag: Option<String>,
    /// Seconds since the Unix epoch.
    deadline: Option<u64>,
}

impl Delivery {
    fn new(activity: &Value, inbox: Url, via: Vec<Url>, sender: &str, batch: &Batch) -> Self {
        Self {
            activity: activity.clone(),
            inbox,
            via,
            sender: sender.to_owned(),
            tag: batch.tag.clone(),
            deadline: batch.deadline.map(unix),
        }
    }

    /// Whether the deadline, if there is one, is past at `now`.
    fn expired(&self, now: std::time::SystemTime) -> bool {
        self.deadline.is_some_and(|deadline| unix(now) >= deadline)
    }

    fn payload(&self) -> Value {
        let mut payload = json!({
            "activity": self.activity,
            "inbox": self.inbox.as_str(),
            "sender": self.sender,
        });
        if !self.via.is_empty() {
            payload["via"] = self.via.iter().map(Url::as_str).collect::<Vec<_>>().into();
        }
        if let Some(tag) = &self.tag {
            payload["tag"] = tag.as_str().into();
        }
        if let Some(deadline) = self.deadline {
            payload["deadline"] = deadline.into();
        }
        payload
    }

    fn from_payload(payload: &Value) -> Option<Self> {
        let via = match payload.get("via") {
            Some(Value::Array(via)) => via
                .iter()
                .map(|url| Url::parse(url.as_str()?).ok())
                .collect::<Option<Vec<_>>>()?,
            _ => Vec::new(),
        };
        Some(Self {
            activity: payload.get("activity")?.clone(),
            inbox: Url::parse(payload.get("inbox")?.as_str()?).ok()?,
            via,
            sender: payload.get("sender")?.as_str()?.to_owned(),
            tag: payload
                .get("tag")
                .and_then(Value::as_str)
                .map(str::to_owned),
            deadline: payload.get("deadline").and_then(Value::as_u64),
        })
    }

    /// Where the delivery is sent, in the order to try.
    fn targets(&self) -> Vec<&Url> {
        if self.via.is_empty() {
            vec![&self.inbox]
        } else {
            self.via.iter().collect()
        }
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
        self.send_batch(sender, activity, inboxes, &Batch::default())
            .await
    }

    /// [`Deliverer::send`], in `batch`: tagged, and given up on at its
    /// deadline.
    ///
    /// # Errors
    ///
    /// When the backend cannot queue them.
    pub async fn send_batch(
        &self,
        sender: &str,
        activity: &Value,
        inboxes: impl IntoIterator<Item = Url>,
        batch: &Batch,
    ) -> Result<(), QueueError> {
        let inboxes: BTreeSet<Url> = inboxes.into_iter().collect();
        if inboxes.is_empty() {
            return Ok(());
        }
        let queue = self.queue_for(inboxes.len());
        let payloads = inboxes
            .into_iter()
            .map(|inbox| Delivery::new(activity, inbox, Vec::new(), sender, batch).payload())
            .collect();
        self.queue.enqueue(queue, payloads).await?;
        self.wake.notify_one();
        Ok(())
    }

    /// Queue `activity`, signed by `sender`, for each portable inbox, once
    /// each: sent to the inbox at its first gateway that accepts it.
    ///
    /// # Errors
    ///
    /// When the backend cannot queue them.
    pub async fn send_portable(
        &self,
        sender: &str,
        activity: &Value,
        inboxes: impl IntoIterator<Item = PortableInbox>,
    ) -> Result<(), QueueError> {
        let mut seen = BTreeSet::new();
        let mut payloads = Vec::new();
        for PortableInbox { inbox, gateways } in inboxes {
            if !seen.insert(inbox.canonical()) {
                continue;
            }
            let via: Vec<Url> = gateways
                .iter()
                .filter_map(|gateway| Url::parse(&inbox.at_gateway(gateway.as_str())).ok())
                .collect();
            let Ok(encoded) = Url::parse(&inbox.encoded()) else {
                continue;
            };
            if via.is_empty() {
                continue;
            }
            payloads
                .push(Delivery::new(activity, encoded, via, sender, &Batch::default()).payload());
        }
        if payloads.is_empty() {
            return Ok(());
        }
        self.queue
            .enqueue(self.queue_for(payloads.len()), payloads)
            .await?;
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
    /// `concurrency` deliveries are kept in flight: as each finishes, its
    /// slot is taken by the next due delivery, claimed a few slots at a time
    /// rather than one round trip per delivery. A slow or silent inbox holds
    /// one slot for as long as it takes, not a whole batch — sending a batch
    /// and waiting for all of it held every healthy delivery claimed with a
    /// server that never answered until the client gave up on it.
    ///
    /// Once `stop` has completed nothing more is claimed, and what is in
    /// flight is finished first, so that a server shutting down does not drop
    /// deliveries in the middle of sending them.
    pub async fn run_until(&self, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        let concurrency = self.config.concurrency.max(1);
        // Claim once this many slots are free, or none are busy.
        let refill = (concurrency / 4).max(1);
        let mut in_flight = stream::FuturesUnordered::new();
        // A claim under way, with how many it asked for. It is polled
        // alongside the deliveries in flight, never instead of them: they may
        // hold the database connections it is waiting for, and a delivery not
        // polled holds its connection for as long. Nor is it ever dropped part
        // way, which would strand what it had claimed until the lease lapsed.
        let mut claiming: Option<(usize, Claim<'_>)> = None;
        let mut stopping = false;
        // Whether the last claim found the queue with nothing more due.
        let mut dry = false;
        loop {
            let free = concurrency.saturating_sub(in_flight.len());
            // Not after a claim that found nothing more due: until a delivery
            // finishes, one is queued, or the idle wait ends, the next would
            // find the same, and with nothing in flight would be asked for
            // again at once, for ever.
            if claiming.is_none()
                && !stopping
                && !dry
                && free > 0
                && (in_flight.is_empty() || free >= refill)
            {
                let asked = free.min(self.config.batch.max(1));
                claiming = Some((asked, Box::pin(self.claim_due(asked))));
            }
            if in_flight.is_empty() && claiming.is_none() {
                if stopping {
                    return;
                }
                tokio::select! {
                    () = &mut stop => return,
                    () = self.idle() => {}
                }
                dry = false;
                continue;
            }
            tokio::select! {
                biased;
                () = &mut stop, if !stopping => stopping = true,
                result = poll_claim(&mut claiming), if claiming.is_some() => {
                    let (asked, _) = claiming.take().expect("a claim was under way");
                    match result {
                        // What a claim took after a stop is sent too: it is
                        // claimed, and would otherwise wait out its lease.
                        Ok(jobs) => {
                            dry = jobs.len() < asked;
                            for job in jobs {
                                in_flight.push(self.process(job));
                            }
                        }
                        Err(_) if in_flight.is_empty() => {
                            tokio::select! {
                                () = &mut stop, if !stopping => return,
                                () = tokio::time::sleep(Duration::from_secs(5)) => {}
                            }
                        }
                        Err(_) => dry = true,
                    }
                }
                // A delivery that finishes may leave room for a retry that has
                // come due since the last claim.
                Some(()) = in_flight.next(), if !in_flight.is_empty() => dry = false,
                // New deliveries queued while slots are free are sent now,
                // not when the next one in flight happens to finish.
                () = self.wake.notified(), if dry && !stopping && claiming.is_none() => dry = false,
            }
        }
    }

    /// Claim one batch and send it. Returns how many deliveries it held.
    ///
    /// # Errors
    ///
    /// When the backend cannot be read.
    pub async fn run_once(&self) -> Result<usize, QueueError> {
        let batch = self.claim_due(self.config.batch).await?;
        let count = batch.len();
        stream::iter(batch)
            .for_each_concurrent(self.config.concurrency, |job| self.process(job))
            .await;
        Ok(count)
    }

    /// The queue a send to `inboxes` inboxes waits in.
    fn queue_for(&self, inboxes: usize) -> &str {
        match &self.config.priority {
            Some(priority) if inboxes <= priority.max_inboxes => &priority.queue,
            _ => &self.config.queue,
        }
    }

    /// Claim up to `limit` due deliveries, the priority queue's first.
    async fn claim_due(&self, limit: usize) -> Result<Vec<Job>, QueueError> {
        let mut jobs = match &self.config.priority {
            Some(priority) => {
                self.queue
                    .claim(&priority.queue, limit, self.config.lease)
                    .await?
            }
            None => Vec::new(),
        };
        if jobs.len() < limit {
            jobs.extend(
                self.queue
                    .claim(&self.config.queue, limit - jobs.len(), self.config.lease)
                    .await?,
            );
        }
        Ok(jobs)
    }

    async fn idle(&self) {
        let mut due = self.queue.next_due(&self.config.queue).await.ok().flatten();
        if let Some(priority) = &self.config.priority {
            let first = self.queue.next_due(&priority.queue).await.ok().flatten();
            due = match (due, first) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
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
        // Past its batch's deadline, it is given up on unsent: the batch is
        // to have finished by now.
        if delivery.expired(std::time::SystemTime::now()) {
            let _ = self
                .give_up(
                    &job,
                    &delivery,
                    None,
                    "the batch's deadline passed before it was sent",
                    true,
                )
                .await;
            return;
        }
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
        let body = serde_json::to_vec(&delivery.activity)
            .map_err(|error| DeliveryError::Signing(error.to_string()))?;
        // Each gateway in turn: the first that accepts completes the
        // delivery, and one that fails is passed over rather than retried.
        let mut last = None;
        for target in delivery.targets() {
            match self.attempt_at(target, &body, &key).await {
                Ok(()) => return Ok(()),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| DeliveryError::Signing("nowhere to deliver".into())))
    }

    async fn attempt_at(
        &self,
        target: &Url,
        body: &[u8],
        key: &SenderKey,
    ) -> Result<(), DeliveryError> {
        let host = target.host_str().unwrap_or_default().to_owned();
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
        let result = post::deliver(&self.client, target, body, key, first).await;
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
                // A retry that would come after the batch's deadline is not
                // made: the batch finishes on time, not when the server
                // comes back.
                if delivery.expired(std::time::SystemTime::now() + delay) {
                    let message = format!("the batch's deadline passed: {message}");
                    return self
                        .give_up(job, delivery, error.status(), &message, true)
                        .await;
                }
                self.queue.retry(&job.id, delay, &message).await
            }
            None => {
                self.give_up(job, delivery, error.status(), &message, false)
                    .await
            }
        }
    }

    /// Fail `job` for good, and tell the failure handler.
    async fn give_up(
        &self,
        job: &Job,
        delivery: &Delivery,
        status: Option<u16>,
        message: &str,
        deadline: bool,
    ) -> Result<(), QueueError> {
        if let Some(handler) = &self.on_failure {
            handler(&DeliveryFailure {
                inbox: delivery.inbox.clone(),
                sender: delivery.sender.clone(),
                status,
                error: message.to_owned(),
                tag: delivery.tag.clone(),
                deadline,
            });
        }
        self.queue.fail(&job.id, message).await
    }
}

/// `time` as whole seconds since the Unix epoch.
fn unix(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
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

/// A claim under way in [`Deliverer::run_until`].
type Claim<'a> = std::pin::Pin<Box<dyn Future<Output = Result<Vec<Job>, QueueError>> + Send + 'a>>;

/// Wait on the claim under way, leaving it in place: the caller takes it once
/// it has finished.
async fn poll_claim(claiming: &mut Option<(usize, Claim<'_>)>) -> Result<Vec<Job>, QueueError> {
    match claiming {
        Some((_, claim)) => claim.as_mut().await,
        None => std::future::pending().await,
    }
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
