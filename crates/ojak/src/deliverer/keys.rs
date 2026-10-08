//! Keeping the keys deliveries are signed with, once loaded.

use super::SenderKeys;
use crate::queue::QueueError;
use crate::sig::SenderKey;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// [`SenderKeys`] that keeps each key `inner` gives for `ttl` after loading
/// it, so that it is not loaded again for every delivery it signs.
///
/// A post fans out to thousands of inboxes signed with one key; loading it
/// for each — from a database, decrypting it, parsing its PEM — costs as
/// many queries and as much work, and with many deliveries in flight can
/// hold every connection an application has. A key replaced at its source is
/// signed with once its `ttl` has run out. Only keys are kept: a sender with
/// none, and an error, are asked about again next time. Whether a sender is
/// [gone](SenderKeys::gone) is always asked of `inner`.
pub struct CachingSenderKeys<K> {
    inner: K,
    ttl: Duration,
    loaded: Mutex<HashMap<String, (Instant, SenderKey)>>,
}

impl<K> CachingSenderKeys<K> {
    /// `inner`'s keys, each kept for `ttl`.
    pub fn new(inner: K, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    /// Where the keys come from.
    pub fn inner(&self) -> &K {
        &self.inner
    }

    fn cached(&self, sender: &str) -> Option<SenderKey> {
        let loaded = self.loaded.lock().expect("sender keys");
        let (at, key) = loaded.get(sender)?;
        (at.elapsed() < self.ttl).then(|| key.clone())
    }

    fn keep(&self, sender: &str, key: &SenderKey) {
        let mut loaded = self.loaded.lock().expect("sender keys");
        // Only the keys signing now are worth keeping.
        loaded.retain(|_, (at, _)| at.elapsed() < self.ttl);
        loaded.insert(sender.to_owned(), (Instant::now(), key.clone()));
    }
}

impl<K: SenderKeys> SenderKeys for CachingSenderKeys<K> {
    async fn key(&self, sender: &str) -> Result<Option<SenderKey>, QueueError> {
        if let Some(key) = self.cached(sender) {
            return Ok(Some(key));
        }
        let key = self.inner.key(sender).await?;
        if let Some(key) = &key {
            self.keep(sender, key);
        }
        Ok(key)
    }

    async fn gone(&self, sender: &str) -> bool {
        self.inner.gone(sender).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        key: SenderKey,
        loads: Arc<AtomicUsize>,
    }

    impl SenderKeys for Counting {
        async fn key(&self, sender: &str) -> Result<Option<SenderKey>, QueueError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok((sender == "alice").then(|| self.key.clone()))
        }

        async fn gone(&self, sender: &str) -> bool {
            sender == "gone"
        }
    }

    fn key() -> SenderKey {
        let pem = crate::sig::signature::generate_rsa_keypair(&mut rand_core::OsRng)
            .unwrap()
            .0;
        SenderKey {
            key_id: "https://a.example/users/alice#main-key".into(),
            private_key: Arc::new(crate::sig::PrivateKey::from_pem(&pem).unwrap()),
        }
    }

    #[tokio::test]
    async fn a_key_is_loaded_once_until_it_is_stale() {
        let loads = Arc::new(AtomicUsize::new(0));
        let keys = CachingSenderKeys::new(
            Counting {
                key: key(),
                loads: loads.clone(),
            },
            Duration::from_secs(300),
        );
        assert!(keys.key("alice").await.unwrap().is_some());
        assert!(keys.key("alice").await.unwrap().is_some());
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        // A sender with no key is asked about each time.
        assert!(keys.key("bob").await.unwrap().is_none());
        assert!(keys.key("bob").await.unwrap().is_none());
        assert_eq!(loads.load(Ordering::SeqCst), 3);
        assert!(keys.gone("gone").await);

        let stale = CachingSenderKeys::new(
            Counting {
                key: key(),
                loads: loads.clone(),
            },
            Duration::ZERO,
        );
        stale.key("alice").await.unwrap();
        stale.key("alice").await.unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 5);
    }
}
