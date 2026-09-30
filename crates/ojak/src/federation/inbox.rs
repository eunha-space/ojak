//! The inbox: what Ojak does with an activity another server POSTs.
//!
//! A listener registered for the activity's type receives it typed, from a
//! sender Ojak has authenticated, with nothing embedded in it that the
//! sender could not vouch for; *docs/guide/inbox.md* explains it.
//! Activities are queued, when the application gives Ojak a queue, and run
//! by an [`InboxWorker`]; otherwise inside the request.

use super::{ActorRef, BoxFuture, Context, Error, Federation, Inner, RequestInfo, empty, signer};
use crate::deliverer::PortableInbox;
use crate::origin::same_origin;
use crate::portable::ApUri;
use crate::queue::{Job, QueueError, RetryPolicy, SharedQueue};
use futures_util::StreamExt as _;
use futures_util::stream;
use http::{HeaderValue, StatusCode, header};
use ojak_vocab::json::{FromJson, ToJson, Typed};
use ojak_vocab::loss::{self, Loss};
use serde_json::{Value, json};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// The largest activity an inbox reads.
pub const MAX_BODY: usize = 1024 * 1024;

/// How long an activity's `id` is remembered, so that it is processed once.
const SEEN_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// The queue activities wait in, within the application's backend.
pub const QUEUE: &str = "inbox";

/// An activity, as a listener receives it.
#[derive(Clone, Debug)]
pub struct Received<T> {
    /// The activity, read into the listener's type.
    pub activity: T,
    /// The actor Ojak authenticated as its sender. Everything the activity
    /// says about anyone else is a claim. A portable actor's is its `ap` URI
    /// with the DID's colons percent-encoded, which is how a `Url` holds one;
    /// `crate::portable::ApUri::parse` reads it back.
    pub sender: Url,
    /// The actor whose inbox it arrived at; `None` for the shared inbox,
    /// where the recipients are worked out from the addressing.
    pub recipient: Option<ActorRef>,
    /// The activity as it arrived, for forwarding.
    pub document: Value,
    /// The activity as it arrived, in its sender's spelling, with what the
    /// sender could not vouch for reduced to references as in `activity`:
    /// for an application whose handlers read JSON.
    pub vouched: Value,
    /// What reading it into the listener's type did not keep.
    pub lost: Vec<Loss>,
}

/// An authenticated activity, before it is read into a listener's type.
pub(super) struct Incoming {
    /// Normalised, with what the sender could not vouch for reduced to
    /// references.
    normalized: Value,
    document: Value,
    vouched: Value,
    sender: Url,
    recipient: Option<ActorRef>,
}

pub(super) type ListenerFn<D> =
    Arc<dyn Fn(Context<D>, Incoming) -> BoxFuture<'static, Result<(), Error>> + Send + Sync>;
pub(super) type BlockedFn<D> =
    Arc<dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<bool, Error>> + Send + Sync>;
pub(super) type UnverifiedFn<D> =
    Arc<dyn Fn(Context<D>, Value) -> BoxFuture<'static, ()> + Send + Sync>;
pub(super) type QueueFn<D> = Arc<dyn Fn(&D) -> Option<SharedQueue> + Send + Sync>;
pub(super) type ForwardFn<D> =
    Arc<dyn Fn(Context<D>, Forward) -> BoxFuture<'static, Result<(), Error>> + Send + Sync>;

/// A portable inbox this server is a gateway for, as the application
/// describes it: who receives what arrives there, and every gateway the
/// actor lists, this one included.
#[derive(Clone, Debug)]
pub struct GatewayInbox {
    pub recipient: ActorRef,
    pub gateways: Vec<Url>,
}

/// An activity to forward, as it was authenticated here: the receiver
/// establishes it for itself, from its proof or from its origin, since the
/// signature on the forward is this server's.
#[derive(Clone, Debug)]
pub struct Forward {
    pub activity: Value,
    pub to: ForwardTo,
}

/// Where an activity is forwarded.
#[derive(Clone, Debug)]
pub enum ForwardTo {
    /// A portable actor's other gateways, as FEP-ef61 asks of the gateway it
    /// arrived at, this one left out: sent with `Deliverer::send_portable`.
    Gateways(PortableInbox),
    /// The members of collections of this server's that the activity is
    /// addressed to, as ActivityPub asks (§7.1.2) when it concerns something
    /// of this server's: a reply to a local post, addressed to its author's
    /// followers, is sent on to those followers, signed by the collection's
    /// owner.
    Collections(Vec<CollectionRef>),
}

/// A collection of this server's, as the application registered it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionRef {
    pub kind: String,
    pub identifier: String,
}

/// How long an activity's forwarding is remembered: once is the rule.
const FORWARDED_FOR: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Wrap a typed listener for the registry.
pub(super) fn listener<D, T, F, Fut, E>(listen: F) -> ListenerFn<D>
where
    D: Clone + Send + Sync + 'static,
    T: Typed + FromJson + ToJson + Send + 'static,
    F: Fn(Context<D>, Received<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<Error>,
{
    reading(T::TYPE, listen)
}

/// A listener reading its activity into `T`, named `name` when it cannot.
fn reading<D, T, F, Fut, E>(name: &'static str, listen: F) -> ListenerFn<D>
where
    D: Clone + Send + Sync + 'static,
    T: FromJson + ToJson + Send + 'static,
    F: Fn(Context<D>, Received<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<Error>,
{
    Arc::new(move |context: Context<D>, incoming: Incoming| {
        let activity = match T::from_json(&incoming.normalized) {
            Ok(activity) => activity,
            Err(error) => {
                // Not an error to retry: the same document will read the
                // same way next time.
                let error: Error = format!("not a {name}: {error}").into();
                context.report(&error);
                return Box::pin(async { Ok(()) }) as BoxFuture<'static, _>;
            }
        };
        let lost = loss::losses(&incoming.normalized, &activity.to_json());
        let received = Received {
            activity,
            sender: incoming.sender,
            recipient: incoming.recipient,
            document: incoming.document,
            vouched: incoming.vouched,
            lost,
        };
        let future = listen(context, received);
        Box::pin(async move { future.await.map_err(Into::into) })
    })
}

/// Wrap a listener for every type no typed listener takes.
pub(super) fn any_listener<D, F, Fut, E>(listen: F) -> ListenerFn<D>
where
    D: Clone + Send + Sync + 'static,
    F: Fn(Context<D>, Received<ojak_vocab::generated::AnyObject>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<Error>,
{
    reading("known activity", listen)
}

/// The `actor` of an activity: an IRI, or an object's `id`.
pub(super) fn actor_of(document: &Value) -> Option<&str> {
    match document.get("actor")? {
        Value::String(actor) => Some(actor),
        Value::Object(actor) => actor.get("id")?.as_str(),
        Value::Array(actors) => actors.first().and_then(|actor| match actor {
            Value::String(actor) => Some(actor.as_str()),
            actor => actor.get("id")?.as_str(),
        }),
        _ => None,
    }
}

/// The IRIs a property names: strings, and objects' `id`s.
fn ids(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::String(id)) => vec![id.as_str()],
        Some(Value::Object(object)) => object
            .get("id")
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
        Some(Value::Array(items)) => items.iter().flat_map(|item| ids(Some(item))).collect(),
        _ => Vec::new(),
    }
}

/// Reduce what the activity embeds to what `sender` can vouch for: an object
/// whose `id`, or any author it names, is on another origin is replaced by
/// its `id`, for the listener to fetch from its owner; one with no `id` that
/// names such an author is dropped.
pub(super) fn reduce(activity: &mut Value, sender: &Url) {
    if let Some(object) = activity.get_mut("object") {
        reduce_value(object, sender);
    }
}

fn reduce_value(value: &mut Value, sender: &Url) {
    match value {
        Value::Array(items) => {
            for item in items.iter_mut() {
                reduce_value(item, sender);
            }
            items.retain(|item| !item.is_null());
        }
        Value::Object(object) => {
            let authors_vouched = ["attributedTo", "actor"].iter().all(|key| {
                ids(object.get(*key))
                    .into_iter()
                    .all(|author| same_origin(author, sender.as_str()))
            });
            match object.get("id").and_then(Value::as_str) {
                Some(id) if !(authors_vouched && same_origin(id, sender.as_str())) => {
                    *value = Value::String(id.to_owned());
                }
                None if !authors_vouched => *value = Value::Null,
                _ => {}
            }
        }
        _ => {}
    }
}

/// The listener for a normalised activity's `type`.
fn listener_for<'a, D>(inner: &'a Inner<D>, normalized: &Value) -> Option<&'a ListenerFn<D>> {
    let types: Vec<&str> = match normalized.get("type")? {
        Value::String(kind) => vec![kind.as_str()],
        Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => return None,
    };
    types
        .into_iter()
        .find_map(|kind| inner.listeners.get(kind))
        .or(inner.fallback_listener.as_ref())
}

/// Normalise an activity and reduce it to what its sender vouches for — or,
/// `as_written`, only reduce it.
fn prepare(document: &Value, sender: &Url, as_written: bool) -> Result<Value, String> {
    let mut normalized = if as_written {
        document.clone()
    } else {
        ojak_jsonld::normalize_with_cache(
            &crate::fetch::REGISTRY,
            document,
            ojak_jsonld::Limits::default(),
            &*crate::fetch::CONTEXTS,
        )
        .map_err(|error| error.to_string())?
        .into_document()
    };
    if let Some(members) = normalized.as_object_mut() {
        members.remove("@context");
    }
    reduce(&mut normalized, sender);
    Ok(normalized)
}

fn status(code: StatusCode, why: &str) -> http::Response<Vec<u8>> {
    let mut response = empty(code);
    if !why.is_empty() {
        *response.body_mut() = why.as_bytes().to_vec();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    response
}

fn accepted() -> http::Response<Vec<u8>> {
    empty(StatusCode::ACCEPTED)
}

/// Receive `body`, POSTed to `recipient`'s inbox or the shared one.
pub(super) async fn receive<D: Clone + Send + Sync + 'static>(
    context: Context<D>,
    recipient: Option<ActorRef>,
    body: &[u8],
) -> http::Response<Vec<u8>> {
    receive_at(context, recipient, body, None).await
}

/// Receive `body`, POSTed to a portable inbox this server is a gateway for:
/// as any inbox receives it, and forwarded to the actor's other gateways.
pub(super) async fn receive_at_gateway<D: Clone + Send + Sync + 'static>(
    context: Context<D>,
    inbox: ApUri,
    gateway: GatewayInbox,
    body: &[u8],
) -> http::Response<Vec<u8>> {
    let recipient = Some(gateway.recipient.clone());
    receive_at(context, recipient, body, Some((inbox, gateway.gateways))).await
}

async fn receive_at<D: Clone + Send + Sync + 'static>(
    context: Context<D>,
    recipient: Option<ActorRef>,
    body: &[u8],
    gateway: Option<(ApUri, Vec<Url>)>,
) -> http::Response<Vec<u8>> {
    let inner = context.inner.federation.clone();
    if body.len() > MAX_BODY {
        return empty(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut document: Value = match serde_json::from_slice(body) {
        Ok(document @ Value::Object(_)) => document,
        _ => return status(StatusCode::BAD_REQUEST, "not a JSON object"),
    };
    let Some(actor) = actor_of(&document).map(str::to_owned) else {
        return status(StatusCode::BAD_REQUEST, "no actor");
    };

    let portable = ApUri::parse(&actor);

    // A blocked server costs nothing: no key is fetched for it. A portable
    // actor has no server, and is blocked by its DID.
    if let Some(blocked) = &inner.blocked {
        let host = match &portable {
            Some(uri) => uri.did().to_owned(),
            None => Url::parse(&actor)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_default(),
        };
        match blocked(context.clone(), host).await {
            Ok(true) => return accepted(),
            Ok(false) => {}
            Err(error) => {
                context.report(&error);
                return empty(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    let sender = if let Some(uri) = &portable {
        // A portable actor is vouched for by its key alone: the HTTP
        // signature, if there is one, is the gateway's that sent it.
        let resolver = inner
            .signed_fetch
            .as_ref()
            .map(|settings| settings.fetcher(context.data()));
        let resolver = resolver
            .as_deref()
            .and_then(crate::fetch::Fetcher::resolver);
        match crate::portable::verify_by(&document, uri.did(), resolver).await {
            Ok(()) => match Url::parse(&uri.encoded()) {
                Ok(sender) => sender,
                Err(error) => return status(StatusCode::BAD_REQUEST, &error.to_string()),
            },
            Err(unproven) => {
                if let Some(hook) = &inner.on_unverified {
                    hook(context.clone(), document.clone()).await;
                }
                // Unlike a server's actor, a DID does not go away and take
                // its key with it, so a Delete is refused like anything else.
                return status(StatusCode::UNAUTHORIZED, &format!("proof: {unproven}"));
            }
        }
    } else {
        let signed = signer::authenticate(&context, body).await;
        match signed {
            Ok(sender) if same_origin(&actor, sender.as_str()) => sender,
            signed => match signer::prove(&context, &document, &actor).await {
                Ok(sender) => sender,
                // Signed by a server other than the actor's: forwarded, by
                // a gateway or a server passing on a reply. The forwarder
                // vouches for nothing of the actor's; the activity is taken
                // from where its id says it lives instead. Only a signed
                // request gets this far, so an unsigned POST cannot make
                // this server fetch.
                Err(unproven) if signed.is_ok() => {
                    match signer::establish(&context, &document, &actor).await {
                        Ok((established, sender)) => {
                            document = established;
                            sender
                        }
                        // Dropped, and answered 202 as Mastodon answers it:
                        // the forwarder's own signature verified, so there is
                        // nothing for it to retry, and a 401 had forwarders
                        // sending the same activity dozens of times. Mastodon
                        // accepts a delivery once its signature verifies and
                        // drops a relayed activity it cannot verify later
                        // (ActivityPub::ProcessActivityService). The reason
                        // goes back in the body, for the application to log.
                        Err(unfetched) => {
                            return status(
                                StatusCode::ACCEPTED,
                                &format!(
                                    "dropped: forwarded; proof: {unproven}; origin: {unfetched}"
                                ),
                            );
                        }
                    }
                }
                Err(unproven) => {
                    let unsigned = signed.err().unwrap_or_default();
                    if let Some(hook) = &inner.on_unverified {
                        hook(context.clone(), document.clone()).await;
                    }
                    // A Delete that does not verify is most often one whose
                    // actor is gone, key and all; the server would retry it
                    // until told otherwise.
                    if document.get("type").and_then(Value::as_str) == Some("Delete") {
                        return accepted();
                    }
                    return status(
                        StatusCode::UNAUTHORIZED,
                        &format!("signature: {unsigned}; proof: {unproven}"),
                    );
                }
            },
        }
    };

    // A server vouches for its own actors and activities, and nobody else's.
    if !same_origin(&actor, sender.as_str()) {
        return status(
            StatusCode::UNAUTHORIZED,
            &format!("actor {actor} is not on the origin of {sender}"),
        );
    }
    let id = document
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(id) = &id
        && !same_origin(id, sender.as_str())
    {
        return status(
            StatusCode::UNAUTHORIZED,
            &format!("activity {id} is not on the origin of {sender}"),
        );
    }

    let normalized = match prepare(&document, &sender, inner.read_as_written) {
        Ok(normalized) => normalized,
        Err(error) => return status(StatusCode::BAD_REQUEST, &error),
    };
    let mut vouched = document.clone();
    reduce(&mut vouched, &sender);

    // Forwarded before anything else is decided, whether or not a listener
    // wants it: the other gateways keep the actor's data too.
    let origin = context.origin().to_string();
    if let Some(id) = &id {
        if let Some((inbox, gateways)) = gateway {
            let ours = context.origin().clone();
            let others: Vec<Url> = gateways
                .into_iter()
                .filter(|gateway| !same_origin(gateway.as_str(), ours.as_str()))
                .collect();
            if !others.is_empty() {
                let to = ForwardTo::Gateways(PortableInbox {
                    inbox,
                    gateways: others,
                });
                forward(&context, &origin, id, &document, to).await;
            }
        }
        let collections = forwarded_to(&context, &document);
        if !collections.is_empty() {
            let to = ForwardTo::Collections(collections);
            forward(&context, &origin, id, &document, to).await;
        }
    }

    if listener_for(&inner, &normalized).is_none() {
        return accepted();
    }

    // Once each: the id is remembered under the origin it arrived at, so
    // that the same activity delivered to two instances in one process is
    // processed by both.
    let seen = id
        .as_deref()
        .map(|id| ["ojak", "inbox", origin.as_str(), id]);
    if let (Some(seen), Some(settings)) = (&seen, &inner.signed_fetch) {
        match settings
            .kv
            .insert(seen, Value::Bool(true), Some(SEEN_FOR))
            .await
        {
            Ok(true) => {}
            Ok(false) => return accepted(),
            Err(error) => context.report(&Error::from(error)),
        }
    }

    let queue = inner
        .inbox_queue
        .as_ref()
        .and_then(|queue| queue(context.data()));
    let outcome = match queue {
        Some(queue) => {
            let payload = json!({
                "document": document,
                "sender": sender.as_str(),
                "recipient": recipient.as_ref().map(|r| json!({"kind": r.kind, "identifier": r.identifier})),
                "origin": origin,
            });
            queue
                .enqueue(QUEUE, vec![payload])
                .await
                .map_err(Error::from)
        }
        None => {
            let listener = listener_for(&inner, &normalized)
                .expect("found above")
                .clone();
            listener(
                context.clone(),
                Incoming {
                    normalized,
                    document,
                    vouched,
                    sender,
                    recipient,
                },
            )
            .await
        }
    };
    match outcome {
        Ok(()) => accepted(),
        Err(error) => {
            context.report(&error);
            // Not processed, so not seen: the sender's retry is processed.
            if let (Some(seen), Some(settings)) = (&seen, &inner.signed_fetch) {
                let _ = settings.kv.delete(seen).await;
            }
            empty(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Hand `activity` to the application to forward `to` where it says: once
/// for each kind of forward, however many times the activity arrives, so
/// that servers forwarding to each other stop.
async fn forward<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    origin: &str,
    id: &str,
    activity: &Value,
    to: ForwardTo,
) {
    let inner = &context.inner.federation;
    let (Some(hook), Some(settings)) = (&inner.forward, &inner.signed_fetch) else {
        return;
    };
    let kind = match to {
        ForwardTo::Gateways(_) => "gateways",
        ForwardTo::Collections(_) => "collections",
    };
    let key = ["ojak", "forwarded", kind, origin, id];
    match settings
        .kv
        .insert(&key, Value::Bool(true), Some(FORWARDED_FOR))
        .await
    {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            // Not knowing whether it was forwarded, it is not forwarded
            // again: once is the rule, and the others forward too.
            context.report(&Error::from(error));
            return;
        }
    }
    let forward = Forward {
        activity: activity.clone(),
        to,
    };
    if let Err(error) = hook(context.clone(), forward).await {
        context.report(&error);
    }
}

/// The collections of ours `activity` is to be forwarded to (ActivityPub
/// §7.1.2): those it is addressed to, when it concerns something of ours,
/// in its `object`, `target`, `inReplyTo` or `tag`, or in those of an object
/// it embeds.
fn forwarded_to<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    activity: &Value,
) -> Vec<CollectionRef> {
    if context.inner.federation.forward.is_none() {
        return Vec::new();
    }
    let mut collections = Vec::new();
    for key in ["to", "cc", "audience"] {
        for iri in ids(activity.get(key)) {
            if let Some(super::Route::Collection { kind, identifier }) = context.parse_uri(iri) {
                let collection = CollectionRef { kind, identifier };
                if !collections.contains(&collection) {
                    collections.push(collection);
                }
            }
        }
    }
    if collections.is_empty() {
        return collections;
    }
    let concerning = |value: &Value| {
        ["object", "target", "inReplyTo", "tag"]
            .iter()
            .flat_map(|key| ids(value.get(*key)))
            .any(|iri| context.parse_uri(iri).is_some())
    };
    let embedded = match activity.get("object") {
        Some(Value::Array(items)) => items
            .iter()
            .any(|item| item.is_object() && concerning(item)),
        Some(item @ Value::Object(_)) => concerning(item),
        _ => false,
    };
    if concerning(activity) || embedded {
        collections
    } else {
        Vec::new()
    }
}

/// How an [`InboxWorker`] runs.
#[derive(Clone, Debug)]
pub struct InboxWorkerConfig {
    /// How many activities one claim takes.
    pub batch: usize,
    /// How long a claimed activity is held before another worker may take it.
    pub lease: Duration,
    /// Listeners running at once.
    pub concurrency: usize,
    pub retry: RetryPolicy,
    /// The longest the worker sleeps with nothing due.
    pub idle_poll: Duration,
}

impl Default for InboxWorkerConfig {
    fn default() -> Self {
        Self {
            batch: 32,
            lease: Duration::from_secs(300),
            concurrency: 4,
            retry: RetryPolicy::default(),
            idle_poll: Duration::from_secs(5),
        }
    }
}

/// Runs the listeners for activities queued in an inbox's queue.
pub struct InboxWorker<D> {
    federation: Federation<D>,
    data: D,
    queue: SharedQueue,
    config: InboxWorkerConfig,
}

impl<D: Clone + Send + Sync + 'static> InboxWorker<D> {
    /// A worker for the activities queued in `queue`, running listeners with
    /// `data`.
    #[must_use]
    pub fn new(federation: Federation<D>, data: D, queue: SharedQueue) -> Self {
        Self {
            federation,
            data,
            queue,
            config: InboxWorkerConfig::default(),
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: InboxWorkerConfig) -> Self {
        self.config = config;
        self
    }

    /// Run queued activities until `stop` completes, finishing the batch in
    /// hand first.
    pub async fn run_until(&self, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                () = &mut stop => return,
                () = std::future::ready(()) => {}
            }
            let pause = match self.run_once().await {
                Ok(0) => {
                    let due = self.queue.next_due(QUEUE).await.ok().flatten();
                    due.map_or(self.config.idle_poll, |due| due.min(self.config.idle_poll))
                }
                Ok(_) => continue,
                Err(_) => Duration::from_secs(5),
            };
            tokio::select! {
                () = &mut stop => return,
                () = tokio::time::sleep(pause) => {}
            }
        }
    }

    /// Claim one batch and run it. Returns how many activities it held.
    ///
    /// # Errors
    ///
    /// When the queue cannot be read.
    pub async fn run_once(&self) -> Result<usize, QueueError> {
        let batch = self
            .queue
            .claim(QUEUE, self.config.batch, self.config.lease)
            .await?;
        let count = batch.len();
        stream::iter(batch)
            .for_each_concurrent(self.config.concurrency, |job| self.process(job))
            .await;
        Ok(count)
    }

    async fn process(&self, job: Job) {
        let outcome = self.run(&job.payload).await;
        // A queue that cannot be written to leaves the job leased; it comes
        // back when the lease lapses.
        let _ = match outcome {
            Ok(()) => self.queue.complete(&job.id).await,
            Err(error) => {
                let message = error.to_string();
                match self.config.retry.delay(job.attempts + 1) {
                    Some(delay) => self.queue.retry(&job.id, delay, &message).await,
                    None => self.queue.fail(&job.id, &message).await,
                }
            }
        };
    }

    async fn run(&self, payload: &Value) -> Result<(), Error> {
        let document = payload.get("document").cloned().ok_or("no document")?;
        let sender = Url::parse(
            payload
                .get("sender")
                .and_then(Value::as_str)
                .ok_or("no sender")?,
        )?;
        let origin = Url::parse(
            payload
                .get("origin")
                .and_then(Value::as_str)
                .ok_or("no origin")?,
        )?;
        let recipient = payload.get("recipient").and_then(|r| {
            Some(ActorRef::new(
                r.get("kind")?.as_str()?,
                r.get("identifier")?.as_str()?,
            ))
        });
        let normalized = prepare(&document, &sender, self.federation.inner.read_as_written)?;
        let mut vouched = document.clone();
        reduce(&mut vouched, &sender);
        let inner = &self.federation.inner;
        let Some(listener) = listener_for(inner, &normalized) else {
            return Ok(());
        };
        let context = Context::new(
            inner.clone(),
            self.data.clone(),
            origin,
            None::<RequestInfo>,
        );
        let outcome = listener(
            context.clone(),
            Incoming {
                normalized,
                document,
                vouched,
                sender,
                recipient,
            },
        )
        .await;
        if let Err(error) = &outcome {
            context.report(error);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Url {
        Url::parse("https://a.example/users/alice").unwrap()
    }

    #[test]
    fn what_the_sender_cannot_vouch_for_is_reduced_to_a_reference() {
        let mut activity = json!({
            "type": "Create",
            "actor": "https://a.example/users/alice",
            "object": {
                "id": "https://b.example/notes/1",
                "type": "Note",
                "attributedTo": "https://b.example/users/bob",
                "content": "words put in bob's mouth"
            }
        });
        reduce(&mut activity, &sender());
        assert_eq!(activity["object"], "https://b.example/notes/1");

        // On the sender's origin, but naming an author elsewhere.
        let mut activity = json!({
            "type": "Create",
            "object": {
                "id": "https://a.example/notes/2",
                "type": "Note",
                "attributedTo": ["https://a.example/users/alice", "https://b.example/users/bob"]
            }
        });
        reduce(&mut activity, &sender());
        assert_eq!(activity["object"], "https://a.example/notes/2");

        // Anonymous, and naming someone else as its actor: dropped.
        let mut activity = json!({
            "type": "Undo",
            "object": [{"type": "Follow", "actor": "https://b.example/users/bob"}]
        });
        reduce(&mut activity, &sender());
        assert_eq!(activity["object"], json!([]));
    }

    #[test]
    fn what_the_sender_vouches_for_is_kept() {
        let object = json!({
            "id": "https://a.example/notes/3",
            "type": "Note",
            "attributedTo": {"id": "https://a.example/users/alice"},
            "content": "mine"
        });
        let mut activity = json!({"type": "Create", "object": object.clone()});
        reduce(&mut activity, &sender());
        assert_eq!(activity["object"], object);
    }
}
