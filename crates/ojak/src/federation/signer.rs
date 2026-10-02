//! Who signed a GET: verified only when a dispatcher asks.
//!
//! The checks are the inbox's, for a request without a body: the signature's
//! shape, that it was made for this host and recently, that the key is one its
//! actor publishes, and the signature against the key. Keys are kept in the
//! key-value store, the cache the inbox will share, and a key that no longer
//! verifies is fetched again once, since its actor may have rotated it.

use super::{BoxFuture, Context, DynKv, Error, authority};
use crate::fetch::Fetcher;
use crate::sig::SenderKey;
use crate::sig::verification::{self, Policy, PublishedKey, Request};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

type KeyFn<D> =
    Arc<dyn Fn(Context<D>) -> BoxFuture<'static, Result<Option<SenderKey>, Error>> + Send + Sync>;

pub(super) type FetcherFn<D> = Arc<dyn Fn(&D) -> Arc<Fetcher> + Send + Sync>;
pub(super) type KeyFetchedFn<D> =
    Arc<dyn Fn(Context<D>, Value) -> BoxFuture<'static, ()> + Send + Sync>;
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
    pub(super) key_fetched: Option<KeyFetchedFn<D>>,
}

impl<D> SignedFetch<D> {
    /// The fetcher for a request's data.
    pub(super) fn fetcher(&self, data: &D) -> Arc<Fetcher> {
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

/// A key, as it is cached: the key and the actor that publishes it, and
/// the actor's document when it was just fetched.
struct Published {
    key: PublishedKey,
    actor: Url,
    document: Option<Value>,
}

impl Published {
    fn to_json(&self) -> Value {
        match &self.key {
            PublishedKey::RsaPem(pem) => json!({"pem": pem, "actor": self.actor.as_str()}),
            PublishedKey::Ed25519(bytes) => json!({
                "ed25519": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
                "actor": self.actor.as_str(),
            }),
        }
    }

    fn from_json(value: &Value) -> Option<Self> {
        let key = match (value.get("pem"), value.get("ed25519")) {
            (Some(pem), _) => PublishedKey::RsaPem(pem.as_str()?.to_owned()),
            (None, Some(bytes)) => PublishedKey::Ed25519(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bytes.as_str()?)
                    .ok()?
                    .try_into()
                    .ok()?,
            ),
            (None, None) => return None,
        };
        Some(Self {
            key,
            actor: Url::parse(value.get("actor")?.as_str()?).ok()?,
            document: None,
        })
    }
}

/// How a GET was signed, as [`Context::signing`] tells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signing {
    /// Not signed.
    Unsigned,
    /// Signed by this actor, whose published key verifies the signature.
    Verified(Url),
    /// Signed with a key on this host, which [`super::Builder::blocked`]
    /// refuses: nothing was fetched from it, and nothing verified.
    Blocked(String),
    /// Signed, but the signature does not hold, for this reason.
    Invalid(String),
}

pub(super) async fn verify<D: Clone + Send + Sync + 'static>(context: &Context<D>) -> Signing {
    let signed = context.inner.request.as_ref().is_some_and(|info| {
        info.headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("signature"))
    });
    if !signed {
        return Signing::Unsigned;
    }
    match authenticate_signed(context, b"").await {
        Ok(signer) => Signing::Verified(signer),
        Err(Refusal::Blocked(host)) => Signing::Blocked(host),
        Err(Refusal::Invalid(why)) => Signing::Invalid(why),
    }
}

/// Why a signature was not taken.
enum Refusal {
    /// Its key is on a blocked host.
    Blocked(String),
    Invalid(String),
}

impl From<String> for Refusal {
    fn from(why: String) -> Self {
        Self::Invalid(why)
    }
}

impl From<&str> for Refusal {
    fn from(why: &str) -> Self {
        Self::Invalid(why.to_owned())
    }
}

/// Who signed the request `context` was made for, carrying `body`: the actor
/// whose published key the signature verifies with, after the signature has
/// been held to the policy. Why not, when it is not.
pub(super) async fn authenticate<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    body: &[u8],
) -> Result<Url, String> {
    authenticate_signed(context, body)
        .await
        .map_err(|refusal| match refusal {
            Refusal::Blocked(host) => format!("signed with a key on {host}, which is blocked"),
            Refusal::Invalid(why) => why,
        })
}

async fn authenticate_signed<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    body: &[u8],
) -> Result<Url, Refusal> {
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
    // A key on a blocked server is neither looked for nor fetched, as the
    // inbox fetches nothing for an activity from one.
    if let (Some(blocked), Some(host)) = (
        &context.inner.federation.blocked,
        Url::parse(&signature.key_id)
            .ok()
            .and_then(|key| key.host_str().map(str::to_owned)),
    ) {
        match blocked(context.clone(), host.clone()).await {
            Ok(true) => return Err(Refusal::Blocked(host)),
            Ok(false) => {}
            Err(error) => {
                context.report(&error);
                return Err(format!("could not tell whether {host} is blocked").into());
            }
        }
    }
    let canonical = authority(context.origin());
    let hosts = [info.host.as_str(), canonical.as_str()];
    verification::check(
        &signature,
        &request,
        &Policy::new(&hosts),
        chrono::Utc::now().timestamp(),
    )
    .map_err(|error| error.to_string())?;

    find_key(context, settings, &signature.key_id, |key| {
        verification::verify(&signature, &request, key.as_key()).is_ok()
    })
    .await
    .map_err(Refusal::from)
}

/// The actor publishing `key_id`, when the key passes `check`: the copy the
/// application holds first, then a cached one, then one fetched from its
/// actor, since a key that no longer passes may have been rotated.
async fn find_key<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    settings: &SignedFetch<D>,
    key_id: &str,
    check: impl Fn(&PublishedKey) -> bool,
) -> Result<Url, String> {
    // A key the application holds, as eunha holds remote accounts' keys, is
    // tried first; one that does not verify is fetched fresh below.
    if let Some(known) = &settings.known_key {
        match known(context.clone(), key_id.to_owned()).await {
            Ok(Some(known)) => {
                if check(&PublishedKey::RsaPem(known.pem)) {
                    return Ok(known.actor);
                }
            }
            Ok(None) => {}
            Err(error) => context.report(&error),
        }
    }

    let cache_key = ["ojak", "key", key_id];
    match settings.kv.get(&cache_key).await {
        Ok(Some(cached)) => {
            if let Some(published) = Published::from_json(&cached)
                && check(&published.key)
            {
                return Ok(published.actor);
            }
        }
        Ok(None) => {}
        Err(error) => context.report(&Error::from(error)),
    }

    let published = fetch_key(context, settings, key_id)
        .await
        .ok_or_else(|| format!("no key {key_id} published by its actor"))?;
    let verified = check(&published.key);
    // A verified key that came with its actor's document, handed to an
    // application that stores actors and gives their keys back through
    // `known_key`, is the application's to keep. Caching it here as well held
    // every new actor's key twice, and in memory for `key_ttl`. A key that
    // does not verify is still cached, so that a run of forged requests does
    // not fetch it again for each one.
    let kept_by_application = verified
        && settings.known_key.is_some()
        && settings.key_fetched.is_some()
        && published.document.is_some();
    if !kept_by_application
        && let Err(error) = settings
            .kv
            .set(&cache_key, published.to_json(), Some(settings.key_ttl))
            .await
    {
        context.report(&Error::from(error));
    }
    if verified {
        // The actor's document, fetched for its key and established as served
        // from its own origin: an application that stores actors stores this
        // one now rather than fetching it again.
        if let (Some(hook), Some(document)) = (&settings.key_fetched, published.document) {
            hook(context.clone(), document).await;
        }
        Ok(published.actor)
    } else {
        Err("the signature does not verify".into())
    }
}

/// Who the Linked Data Signature (`RsaSignature2017`) on `document` says
/// made it: the actor `actor`, when the signature verifies with a key `actor`
/// publishes. Mastodon's `actor_from_verified_ld_signature`, for an activity
/// passed on by a server other than its actor's.
pub(super) async fn verify_linked_data<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    document: &Value,
    actor: &str,
) -> Result<Url, String> {
    use crate::sig::linked_data::Signed;

    let settings = context
        .inner
        .federation
        .signed_fetch
        .as_ref()
        .ok_or("signed fetches are not configured")?;
    let Some(creator) = crate::sig::linked_data::creator(document) else {
        return Err("no RsaSignature2017".into());
    };
    // A key on a blocked server is neither looked for nor fetched, as
    // Mastodon checks `domain_not_allowed?` on the signature's creator.
    if let (Some(blocked), Some(host)) = (
        &context.inner.federation.blocked,
        Url::parse(creator)
            .ok()
            .and_then(|key| key.host_str().map(str::to_owned)),
    ) {
        match blocked(context.clone(), host.clone()).await {
            Ok(true) => return Err(format!("signed with a key on {host}, which is blocked")),
            Ok(false) => {}
            Err(error) => {
                context.report(&error);
                return Err(format!("could not tell whether {host} is blocked"));
            }
        }
    }
    let signed = Signed::read(
        &crate::fetch::REGISTRY,
        document,
        chrono::Utc::now().timestamp(),
    )
    .map_err(|error| error.to_string())?;
    let signer = find_key(context, settings, signed.creator(), |key| match key {
        PublishedKey::RsaPem(pem) => signed.verify(pem).is_ok(),
        PublishedKey::Ed25519(_) => false,
    })
    .await?;
    if signer.as_str() != actor {
        return Err(format!("signed by {signer}, not {actor}"));
    }
    Ok(signer)
}

/// Who an FEP-8b32 integrity proof on `document` says made it: the actor
/// `actor`, when the proof verifies with a key the actor lists as an
/// `assertionMethod` and that key is on the actor's origin.
pub(super) async fn prove<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    document: &Value,
    actor: &str,
) -> Result<Url, String> {
    use crate::sig::integrity;

    let settings = context
        .inner
        .federation
        .signed_fetch
        .as_ref()
        .ok_or("signed fetches are not configured")?;
    // Every proof by a key on the actor's origin is tried, in order; a
    // document may carry one per suite, or one by a key its actor no longer
    // lists beside one by the key it does.
    let proofs: Vec<_> = integrity::integrity_proofs(document, chrono::Utc::now().timestamp())
        .into_iter()
        .filter(|(_, _, method)| crate::origin::same_origin(method, actor))
        .collect();
    if proofs.is_empty() {
        return Err(format!(
            "no usable integrity proof by a key on {actor}'s origin"
        ));
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
    let mut why = String::new();
    for (proof, _, method) in proofs {
        let Some(multibase) = assertion_method(&fetched.json, &method) else {
            why = format!("{actor} does not list {method} as an assertionMethod");
            continue;
        };
        let verified = integrity::decode_multikey(&multibase).and_then(|public_key| {
            integrity::verify_object_integrity_proof(document, &proof, &public_key)
        });
        match verified {
            Ok(()) => return Url::parse(&fetched.id).map_err(|error| error.to_string()),
            Err(error) => why = error.to_string(),
        }
    }
    Err(why)
}

/// Fetch an activity forwarded by a server other than its actor's from
/// where its `id` says it lives, and establish it there: served from its own
/// origin, by the actor the forwarded copy named. What comes back is the
/// activity to process, and its actor; the forwarded copy was only a claim.
pub(super) async fn establish<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    document: &Value,
    actor: &str,
) -> Result<(Value, Url), String> {
    let settings = context
        .inner
        .federation
        .signed_fetch
        .as_ref()
        .ok_or("signed fetches are not configured")?;
    let id = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or("a forwarded activity with no id cannot be fetched")?;
    let url = Url::parse(id).map_err(|error| format!("{id}: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{id} cannot be fetched from its origin"));
    }
    let key = match (settings.key)(context.clone()).await {
        Ok(key) => key,
        Err(error) => {
            context.report(&error);
            None
        }
    };
    let fetched = settings
        .fetcher(context.data())
        .document(&url, key.as_ref())
        .await
        .map_err(|error| format!("{id}: {error}"))?;
    if fetched.id != id {
        return Err(format!("{id} is served as {}", fetched.id));
    }
    if super::inbox::actor_of(&fetched.json) != Some(actor) {
        return Err(format!("{id} as its origin serves it is not by {actor}"));
    }
    let actor = Url::parse(actor).map_err(|error| error.to_string())?;
    Ok((fetched.json, actor))
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

/// Fetch the actor the key ID points at, and read the key from it if the
/// actor publishes it as its own.
async fn fetch_key<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    settings: &SignedFetch<D>,
    key_id: &str,
) -> Option<Published> {
    let owner = Url::parse(verification::key_owner(key_id)).ok()?;
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
    let key = verification::published_key(&document.json, key_id)?;
    Some(Published {
        key,
        actor: Url::parse(&document.id).ok()?,
        document: Some(document.json),
    })
}
