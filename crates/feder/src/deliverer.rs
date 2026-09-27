//! Sending activities through the queue.
//!
//! [`Deliverer::send`] queues an activity for a set of inboxes and returns;
//! [`Deliverer::run`] is the loop that sends what is queued, and the
//! application spawns it on whatever runtime and in whatever task context it
//! uses — Feder does not spawn tasks of its own. Any number of loops may run,
//! in any number of processes, over one store.

use crate::client::Client;
use crate::delivery::{self, DeliveryError, Scheme, SenderKey};
use crate::queue::{Delivery, DeliveryStore, NewDelivery, RetryPolicy, StoreError};
use futures_util::StreamExt as _;
use futures_util::stream;
use serde_json::Value;
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
    ) -> impl Future<Output = Result<Option<SenderKey>, StoreError>> + Send;
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
    /// queued by another process are picked up.
    pub idle_poll: Duration,
}

impl Default for DelivererConfig {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::default(),
            batch: 64,
            lease: Duration::from_secs(300),
            concurrency: 16,
            per_host: 2,
            first_scheme: Scheme::DraftCavage,
            idle_poll: Duration::from_secs(30),
        }
    }
}

type FailureHandler = Arc<dyn Fn(&DeliveryFailure) + Send + Sync>;

/// Queues activities and sends them.
pub struct Deliverer<S, K> {
    store: S,
    keys: K,
    client: Client,
    config: DelivererConfig,
    wake: Notify,
    /// The scheme each host last accepted.
    schemes: Mutex<HashMap<String, Scheme>>,
    hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
    on_failure: Option<FailureHandler>,
}

impl<S: DeliveryStore, K: SenderKeys> Deliverer<S, K> {
    pub fn new(store: S, keys: K, client: Client, config: DelivererConfig) -> Self {
        Self {
            store,
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

    /// The store deliveries are queued in.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Queue `activity`, signed by `sender`, for each of `inboxes`, once each.
    ///
    /// # Errors
    ///
    /// When the store cannot queue them.
    pub async fn send(
        &self,
        sender: &str,
        activity: &Value,
        inboxes: impl IntoIterator<Item = Url>,
    ) -> Result<(), StoreError> {
        let inboxes: BTreeSet<Url> = inboxes.into_iter().collect();
        if inboxes.is_empty() {
            return Ok(());
        }
        let deliveries = inboxes
            .into_iter()
            .map(|inbox| NewDelivery {
                activity: activity.clone(),
                inbox,
                sender: sender.to_owned(),
            })
            .collect();
        self.store.enqueue(deliveries).await?;
        self.wake.notify_one();
        Ok(())
    }

    /// Send what is queued, forever.
    ///
    /// A store error is waited out and retried, never returned: the loop is
    /// what keeps federation going, and a database that is briefly away should
    /// not stop it.
    pub async fn run(&self) {
        loop {
            match self.run_once().await {
                Ok(0) => self.idle().await,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
            }
        }
    }

    /// Claim one batch and send it. Returns how many deliveries it held.
    ///
    /// # Errors
    ///
    /// When the store cannot be read.
    pub async fn run_once(&self) -> Result<usize, StoreError> {
        let batch = self
            .store
            .claim(self.config.batch, self.config.lease)
            .await?;
        let count = batch.len();
        stream::iter(batch)
            .for_each_concurrent(self.config.concurrency, |delivery| self.process(delivery))
            .await;
        Ok(count)
    }

    async fn idle(&self) {
        let due = self.store.next_due().await.ok().flatten();
        let sleep = due.map_or(self.config.idle_poll, |due| due.min(self.config.idle_poll));
        tokio::select! {
            () = tokio::time::sleep(sleep) => {}
            () = self.wake.notified() => {}
        }
    }

    async fn process(&self, delivery: Delivery) {
        let outcome = self.attempt(&delivery).await;
        // A store error here leaves the delivery claimed; its lease lapses
        // and it is tried again, which is the safe way to be wrong.
        let _ = match outcome {
            Ok(()) => self.store.delivered(&delivery.id).await,
            Err(error) => self.record_failure(&delivery, &error).await,
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
        delivery: &Delivery,
        error: &DeliveryError,
    ) -> Result<(), StoreError> {
        let attempts = delivery.attempts + 1;
        let delay = if error.is_permanent() {
            None
        } else {
            self.config.retry.delay(attempts)
        };
        let message = error.to_string();
        match delay {
            Some(delay) => {
                let delay = error.retry_after().map_or(delay, |asked| asked.max(delay));
                self.store.retry(&delivery.id, delay, &message).await
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
                self.store.failed(&delivery.id, &message).await
            }
        }
    }
}
