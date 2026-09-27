//! Who signed a GET: verified only when a dispatcher asks.
//!
//! The checks are the inbox's, for a request without a body: the signature's
//! shape, that it was made for this host and recently, that the key is one its
//! actor publishes, and the signature against the key. Keys are kept in the
//! key-value store, the cache the inbox will share, and a key that no longer
//! verifies is fetched again once, since its actor may have rotated it.

use super::{BoxFuture, Context, DynKv, Error, authority};
use crate::delivery::SenderKey;
use crate::fetch::Fetcher;
use feder_runtime::verification::{self, Key, Policy, Request, Signature};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

type KeyFn<D> =
    Arc<dyn Fn(Context<D>) -> BoxFuture<'static, Result<Option<SenderKey>, Error>> + Send + Sync>;

pub(super) struct SignedFetch<D> {
    pub(super) fetcher: Arc<Fetcher>,
    pub(super) kv: Arc<dyn DynKv>,
    pub(super) key_ttl: Duration,
    pub(super) key: KeyFn<D>,
}

/// A key, as it is cached: its PEM and the actor that publishes it.
struct Published {
    pem: String,
    actor: Url,
}

impl Published {
    fn to_json(&self) -> Value {
        json!({"pem": self.pem, "actor": self.actor.as_str()})
    }

    fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            pem: value.get("pem")?.as_str()?.to_owned(),
            actor: Url::parse(value.get("actor")?.as_str()?).ok()?,
        })
    }
}

pub(super) async fn verify<D: Clone + Send + Sync + 'static>(context: &Context<D>) -> Option<Url> {
    let settings = context.inner.federation.signed_fetch.as_ref()?;
    let info = context.inner.request.as_ref()?;
    let headers: Vec<(&str, &str)> = info
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let request = Request {
        method: &info.method,
        path_and_query: &info.path_and_query,
        headers: &headers,
        body: b"",
    };
    let signature = verification::parse(&request).ok()?;
    let canonical = authority(context.origin());
    let hosts = [info.host.as_str(), canonical.as_str()];
    verification::check(
        &signature,
        &request,
        &Policy::new(&hosts),
        chrono::Utc::now().timestamp(),
    )
    .ok()?;

    let cache_key = ["feder", "key", signature.key_id.as_str()];
    match settings.kv.get(&cache_key).await {
        Ok(Some(cached)) => {
            if let Some(published) = Published::from_json(&cached)
                && check(&signature, &request, &published)
            {
                return Some(published.actor);
            }
        }
        Ok(None) => {}
        Err(error) => context.report(&Error::from(error)),
    }

    let published = fetch_key(context, settings, &signature).await?;
    if let Err(error) = settings
        .kv
        .set(&cache_key, published.to_json(), Some(settings.key_ttl))
        .await
    {
        context.report(&Error::from(error));
    }
    check(&signature, &request, &published).then_some(published.actor)
}

fn check(signature: &Signature, request: &Request<'_>, published: &Published) -> bool {
    verification::verify(signature, request, Key::RsaPem(&published.pem)).is_ok()
}

/// Fetch the actor the key ID points at, and read the key from it if the
/// actor publishes it as its own.
async fn fetch_key<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    settings: &SignedFetch<D>,
    signature: &Signature,
) -> Option<Published> {
    let owner = Url::parse(verification::key_owner(&signature.key_id)).ok()?;
    let key = match (settings.key)(context.clone()).await {
        Ok(key) => key,
        Err(error) => {
            context.report(&error);
            None
        }
    };
    let document = settings.fetcher.document(&owner, key.as_ref()).await.ok()?;
    let pem = verification::published_key_pem(&document.json, &signature.key_id)?;
    Some(Published {
        pem,
        actor: Url::parse(&document.id).ok()?,
    })
}
