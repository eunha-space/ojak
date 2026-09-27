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

pub(super) type FetcherFn<D> = Arc<dyn Fn(&D) -> Arc<Fetcher> + Send + Sync>;
pub(super) type KnownKeyFn<D> = Arc<
    dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<Option<KnownKey>, Error>> + Send + Sync,
>;

pub(super) struct SignedFetch<D> {
    pub(super) fetcher: Arc<Fetcher>,
    pub(super) kv: Arc<dyn DynKv>,
    pub(super) key_ttl: Duration,
    pub(super) key: KeyFn<D>,
    pub(super) fetcher_for: Option<FetcherFn<D>>,
    pub(super) known_key: Option<KnownKeyFn<D>>,
}

impl<D> SignedFetch<D> {
    /// The fetcher for a request's data.
    fn fetcher(&self, data: &D) -> Arc<Fetcher> {
        match &self.fetcher_for {
            Some(fetcher) => fetcher(data),
            None => self.fetcher.clone(),
        }
    }
}

/// A key the application already holds for a key ID: its PEM, and the actor
/// that published it.
#[derive(Clone, Debug)]
pub struct KnownKey {
    pub pem: String,
    pub actor: Url,
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
    authenticate(context, b"").await.ok()
}

/// Who signed the request `context` was made for, carrying `body`: the actor
/// whose published key the signature verifies with, after the signature has
/// been held to the policy. Why not, when it is not.
pub(super) async fn authenticate<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    body: &[u8],
) -> Result<Url, String> {
    let settings = context
        .inner
        .federation
        .signed_fetch
        .as_ref()
        .ok_or("signed fetches are not configured")?;
    let info = context.inner.request.as_ref().ok_or("no request")?;
    let headers: Vec<(&str, &str)> = info
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let request = Request {
        method: &info.method,
        path_and_query: &info.path_and_query,
        headers: &headers,
        body,
    };
    let signature = verification::parse(&request).map_err(|error| error.to_string())?;
    let canonical = authority(context.origin());
    let hosts = [info.host.as_str(), canonical.as_str()];
    verification::check(
        &signature,
        &request,
        &Policy::new(&hosts),
        chrono::Utc::now().timestamp(),
    )
    .map_err(|error| error.to_string())?;

    // A key the application holds, as eunha holds remote accounts' keys, is
    // tried first; one that does not verify is fetched fresh below.
    if let Some(known) = &settings.known_key {
        match known(context.clone(), signature.key_id.clone()).await {
            Ok(Some(known)) => {
                let published = Published {
                    pem: known.pem,
                    actor: known.actor,
                };
                if check(&signature, &request, &published) {
                    return Ok(published.actor);
                }
            }
            Ok(None) => {}
            Err(error) => context.report(&error),
        }
    }

    let cache_key = ["feder", "key", signature.key_id.as_str()];
    match settings.kv.get(&cache_key).await {
        Ok(Some(cached)) => {
            if let Some(published) = Published::from_json(&cached)
                && check(&signature, &request, &published)
            {
                return Ok(published.actor);
            }
        }
        Ok(None) => {}
        Err(error) => context.report(&Error::from(error)),
    }

    let published = fetch_key(context, settings, &signature)
        .await
        .ok_or_else(|| format!("no key {} published by its actor", signature.key_id))?;
    if let Err(error) = settings
        .kv
        .set(&cache_key, published.to_json(), Some(settings.key_ttl))
        .await
    {
        context.report(&Error::from(error));
    }
    if check(&signature, &request, &published) {
        Ok(published.actor)
    } else {
        Err("the signature does not verify".into())
    }
}

/// Who an FEP-8b32 integrity proof on `document` says made it: the actor
/// `actor`, when the proof verifies with a key the actor lists as an
/// `assertionMethod` and that key is on the actor's origin.
pub(super) async fn prove<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    document: &Value,
    actor: &str,
) -> Result<Url, String> {
    use feder_runtime::integrity;

    let settings = context
        .inner
        .federation
        .signed_fetch
        .as_ref()
        .ok_or("signed fetches are not configured")?;
    let (proof, _, method) =
        integrity::extract_integrity_proof(document).ok_or("no usable integrity proof")?;
    if !feder_core::origin::same_origin(&method, actor) {
        return Err(format!("proof key {method} is not on {actor}'s origin"));
    }
    let actor_url = Url::parse(actor).map_err(|error| error.to_string())?;
    let key = match (settings.key)(context.clone()).await {
        Ok(key) => key,
        Err(error) => {
            context.report(&error);
            None
        }
    };
    let fetched = settings
        .fetcher(context.data())
        .document(&actor_url, key.as_ref())
        .await
        .map_err(|error| error.to_string())?;
    let multibase = assertion_method(&fetched.json, &method)
        .ok_or_else(|| format!("{actor} does not list {method} as an assertionMethod"))?;
    let public_key = integrity::decode_multikey(&multibase).map_err(|error| error.to_string())?;
    integrity::verify_object_integrity_proof(document, &proof, &public_key)
        .map_err(|error| error.to_string())?;
    Url::parse(&fetched.id).map_err(|error| error.to_string())
}

/// The `publicKeyMultibase` of the `assertionMethod` `method` an actor lists.
fn assertion_method(actor: &Value, method: &str) -> Option<String> {
    let methods = match actor.get("assertionMethod")? {
        Value::Array(items) => items.iter().collect(),
        item => vec![item],
    };
    methods.into_iter().find_map(|item| {
        (item.get("id").and_then(Value::as_str) == Some(method))
            .then(|| item.get("publicKeyMultibase")?.as_str().map(str::to_owned))
            .flatten()
    })
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
    let document = settings
        .fetcher(context.data())
        .document(&owner, key.as_ref())
        .await
        .ok()?;
    let pem = verification::published_key_pem(&document.json, &signature.key_id)?;
    Some(Published {
        pem,
        actor: Url::parse(&document.id).ok()?,
    })
}
