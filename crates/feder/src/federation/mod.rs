//! Serving: what Feder answers when another server, or a person, sends a
//! GET.
//!
//! An application builds one [`Federation`] at start-up, registering a
//! dispatcher for each kind of actor, object and collection it serves, each
//! with the URI template that both routes requests to it and builds its URIs.
//! WebFinger and host-meta follow from the actors, and NodeInfo from one more
//! dispatcher. *docs/design/serving.md* has the reasoning.
//!
//! [`Federation::handle`] answers a request in `http` types, so that it works
//! under any server framework; *feder-axum* adapts it to axum.

mod collection;
mod inbox;
mod negotiate;
mod nodeinfo;
mod signer;
mod webfinger;

pub use collection::{Collection, First, Page};
pub use inbox::{
    Forward, GatewayInbox, InboxWorker, InboxWorkerConfig, MAX_BODY as MAX_INBOX_BODY, Received,
};
pub use nodeinfo::{NodeInfo, Software, Usage};
pub use signer::KnownKey;

use crate::fetch::Fetcher;
use crate::kv::{KvError, KvStore};
use crate::template::{Template, TemplateError, Values};
use chrono::{DateTime, SecondsFormat, Utc};
use feder_core::portable::ApUri;
use http::{HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// What a dispatcher's error is turned into: anything that is an error, a
/// `String`, or an `anyhow::Error`.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The media type every ActivityPub document is served as.
pub const ACTIVITY_JSON: &str = "application/activity+json";

/// The `@context` a document gets when its dispatcher gave it none:
/// ActivityStreams, with the security and Multikey vocabularies that keys
/// are written in.
#[must_use]
pub fn default_context() -> Value {
    json!([
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
        "https://w3id.org/security/multikey/v1",
    ])
}

/// What a dispatcher found.
#[derive(Clone, Debug, PartialEq)]
pub enum Found<T> {
    Found(T),
    /// It existed and was deleted: served as a Tombstone with 410, with when
    /// it was deleted if that is known.
    Gone(Option<DateTime<Utc>>),
    NotFound,
}

/// An actor, as the application names it: its kind and its identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActorRef {
    pub kind: String,
    pub identifier: String,
}

impl ActorRef {
    #[must_use]
    pub fn new(kind: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            identifier: identifier.into(),
        }
    }
}

/// What an IRI of ours is, from [`Context::parse_uri`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Route {
    Actor(ActorRef),
    Object { kind: String, values: Values },
    Collection { kind: String, identifier: String },
}

/// A public key an actor publishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKey {
    /// An RSA key, published as `publicKey`, which HTTP signatures verify
    /// with. The first one an actor has is the one published.
    Rsa { id: String, pem: String },
    /// A key published in `assertionMethod` as a Multikey (FEP-521a), which
    /// integrity proofs verify with.
    Multikey { id: String, multibase: String },
}

/// Put `keys` into `actor`, a document whose `id` is set: the first RSA key
/// as `publicKey`, and every Multikey in `assertionMethod`.
pub fn with_keys(actor: &mut Value, keys: &[PublicKey]) {
    let Some(members) = actor.as_object_mut() else {
        return;
    };
    let id = members.get("id").cloned().unwrap_or(Value::Null);
    if let Some((key_id, pem)) = keys.iter().find_map(|key| match key {
        PublicKey::Rsa { id, pem } => Some((id, pem)),
        PublicKey::Multikey { .. } => None,
    }) {
        members.insert(
            "publicKey".into(),
            json!({"id": key_id, "owner": id, "publicKeyPem": pem}),
        );
    }
    let methods: Vec<Value> = keys
        .iter()
        .filter_map(|key| match key {
            PublicKey::Multikey {
                id: key_id,
                multibase,
            } => Some(json!({
                "id": key_id,
                "type": "Multikey",
                "controller": id,
                "publicKeyMultibase": multibase,
            })),
            PublicKey::Rsa { .. } => None,
        })
        .collect();
    if !methods.is_empty() {
        members.insert("assertionMethod".into(), Value::Array(methods));
    }
}

/// What [`Federation::handle`] made of a request.
#[derive(Debug)]
pub enum Handled {
    /// Feder's answer.
    Response(http::Response<Vec<u8>>),
    /// A route of Feder's matched, but the request did not ask for
    /// ActivityPub: the application serves its page at this URL, or 406.
    NotAcceptable,
    /// Nothing of Feder's is at this URL, or on this host.
    NotFound,
}

/// Why a URI could not be built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UriError {
    /// No dispatcher of this kind is registered.
    UnknownKind(String),
    /// The values do not fill the template.
    Template(TemplateError),
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind(kind) => write!(f, "no dispatcher of kind {kind:?}"),
            Self::Template(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for UriError {}

/// Why a federation could not be built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildError(pub Vec<String>);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("; "))
    }
}

impl std::error::Error for BuildError {}

type ActorFn<D> = Arc<
    dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<Found<Value>, Error>> + Send + Sync,
>;
type ObjectFn<D> = Arc<
    dyn Fn(Context<D>, Values) -> BoxFuture<'static, Result<Found<Value>, Error>> + Send + Sync,
>;
type AuthorizeFn<D> = Arc<
    dyn Fn(Context<D>, Values, Option<Url>) -> BoxFuture<'static, Result<bool, Error>>
        + Send
        + Sync,
>;
type KeysFn<D> = Arc<
    dyn Fn(Context<D>, ActorRef) -> BoxFuture<'static, Result<Vec<PublicKey>, Error>> + Send + Sync,
>;
type LookupFn<D, A> =
    Arc<dyn Fn(Context<D>, A) -> BoxFuture<'static, Result<Option<ActorRef>, Error>> + Send + Sync>;
type LinksFn<D> = Arc<dyn Fn(&Context<D>, &ActorRef, &Value) -> Vec<Value> + Send + Sync>;
type NodeInfoFn<D> =
    Arc<dyn Fn(Context<D>) -> BoxFuture<'static, Result<NodeInfo, Error>> + Send + Sync>;
type OriginFn<D> = Arc<dyn Fn(&str, &D) -> Option<Url> + Send + Sync>;
type ErrorFn = Arc<dyn Fn(&Error) + Send + Sync>;
type GatewayFn<D> =
    Arc<dyn Fn(Context<D>, ApUri) -> BoxFuture<'static, Result<Found<Value>, Error>> + Send + Sync>;
type GatewayInboxFn<D> = Arc<
    dyn Fn(Context<D>, ApUri) -> BoxFuture<'static, Result<Option<GatewayInbox>, Error>>
        + Send
        + Sync,
>;

enum Dispatcher<D> {
    Actor(ActorFn<D>),
    Object(ObjectFn<D>),
    Collection(Collection<D>),
}

struct Entry<D> {
    kind: String,
    template: Template,
    dispatcher: Dispatcher<D>,
    authorize: Option<AuthorizeFn<D>>,
}

impl<D> Entry<D> {
    fn noun(&self) -> &'static str {
        match self.dispatcher {
            Dispatcher::Actor(_) => "actor",
            Dispatcher::Object(_) => "object",
            Dispatcher::Collection(_) => "collection",
        }
    }
}

enum OriginRule<D> {
    Fixed(Url),
    PerHost(OriginFn<D>),
}

struct Inner<D> {
    origin: OriginRule<D>,
    entries: Vec<Entry<D>>,
    key_pairs: Option<KeysFn<D>>,
    handle: Option<LookupFn<D, String>>,
    map_alias: Option<LookupFn<D, Url>>,
    webfinger_links: Option<LinksFn<D>>,
    nodeinfo: Option<NodeInfoFn<D>>,
    signed_fetch: Option<signer::SignedFetch<D>>,
    on_error: Option<ErrorFn>,
    inboxes: Vec<(String, Template)>,
    shared_inbox: Option<Template>,
    listeners: std::collections::HashMap<&'static str, inbox::ListenerFn<D>>,
    fallback_listener: Option<inbox::ListenerFn<D>>,
    blocked: Option<inbox::BlockedFn<D>>,
    on_unverified: Option<inbox::UnverifiedFn<D>>,
    inbox_queue: Option<inbox::QueueFn<D>>,
    gateway: Option<GatewayFn<D>>,
    gateway_inbox: Option<GatewayInboxFn<D>>,
    forward: Option<inbox::ForwardFn<D>>,
}

/// Everything Feder serves, and the URIs it builds. Cheap to clone.
pub struct Federation<D> {
    inner: Arc<Inner<D>>,
}

impl<D> Clone for Federation<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Wrap an application's async function as a stored dispatcher.
fn boxed<A, T, E, F, Fut>(
    f: F,
) -> Arc<dyn Fn(A) -> BoxFuture<'static, Result<T, Error>> + Send + Sync>
where
    F: Fn(A) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    E: Into<Error>,
{
    Arc::new(move |a| {
        let future = f(a);
        Box::pin(async move { future.await.map_err(Into::into) })
    })
}

/// Builds a [`Federation`].
pub struct Builder<D> {
    origin: Option<OriginRule<D>>,
    entries: Vec<Entry<D>>,
    authorize: Vec<(String, AuthorizeFn<D>)>,
    key_pairs: Option<KeysFn<D>>,
    handle: Option<LookupFn<D, String>>,
    map_alias: Option<LookupFn<D, Url>>,
    webfinger_links: Option<LinksFn<D>>,
    nodeinfo: Option<NodeInfoFn<D>>,
    signed_fetch: Option<signer::SignedFetch<D>>,
    on_error: Option<ErrorFn>,
    inboxes: Vec<(String, String)>,
    shared_inbox: Option<String>,
    listeners: std::collections::HashMap<&'static str, inbox::ListenerFn<D>>,
    fallback_listener: Option<inbox::ListenerFn<D>>,
    blocked: Option<inbox::BlockedFn<D>>,
    on_unverified: Option<inbox::UnverifiedFn<D>>,
    inbox_queue: Option<inbox::QueueFn<D>>,
    gateway: Option<GatewayFn<D>>,
    gateway_inbox: Option<GatewayInboxFn<D>>,
    forward: Option<inbox::ForwardFn<D>>,
    errors: Vec<String>,
}

impl<D: Clone + Send + Sync + 'static> Federation<D> {
    #[must_use]
    pub fn builder() -> Builder<D> {
        Builder {
            origin: None,
            entries: Vec::new(),
            authorize: Vec::new(),
            key_pairs: None,
            handle: None,
            map_alias: None,
            webfinger_links: None,
            nodeinfo: None,
            signed_fetch: None,
            on_error: None,
            inboxes: Vec::new(),
            shared_inbox: None,
            listeners: std::collections::HashMap::new(),
            fallback_listener: None,
            blocked: None,
            on_unverified: None,
            inbox_queue: None,
            gateway: None,
            gateway_inbox: None,
            forward: None,
            errors: Vec::new(),
        }
    }

    /// A context outside any request, for building URIs in a background job:
    /// `origin` is the canonical origin they are built in.
    #[must_use]
    pub fn context(&self, origin: Url, data: D) -> Context<D> {
        Context::new(self.inner.clone(), data, origin, None)
    }

    /// The canonical origin for a request to `host`, if Feder serves it.
    fn origin_for(&self, host: &str, data: &D) -> Option<Url> {
        match &self.inner.origin {
            OriginRule::Fixed(origin) => Some(origin.clone()),
            OriginRule::PerHost(origin) => origin(host, data),
        }
    }

    /// The inbox `path` is, if it is one: `Some(Some(actor))` for an actor's,
    /// `Some(None)` for the shared inbox.
    fn inbox_at(&self, path: &str) -> Option<Option<ActorRef>> {
        if self
            .inner
            .shared_inbox
            .as_ref()
            .is_some_and(|shared| shared.matches(path).is_some())
        {
            return Some(None);
        }
        self.inner.inboxes.iter().find_map(|(kind, template)| {
            let values = template.matches(path)?;
            Some(Some(ActorRef::new(
                kind.clone(),
                values.single().unwrap_or_default(),
            )))
        })
    }

    /// Whether `path` is an inbox, whose POSTs [`Federation::handle_with_body`]
    /// answers: what an adapter asks before reading a request's body. Every
    /// gateway path is one when the application accepts portable
    /// deliveries, since which of them are inboxes is the application's to
    /// say.
    #[must_use]
    pub fn is_inbox(&self, path: &str) -> bool {
        self.inbox_at(path).is_some()
            || (self.inner.gateway_inbox.is_some() && is_gateway_path(path))
    }

    /// Answer a request to `/.well-known/apgateway/{did}/{+path}`: a GET for
    /// a portable object, a POST to a portable inbox.
    async fn gateway(&self, request: &http::request::Parts, body: &[u8], data: D) -> Handled {
        let host = request_host(request);
        let Some(origin) = self.origin_for(&host, &data) else {
            return Handled::NotFound;
        };
        let compatible = format!(
            "{}{}",
            origin.as_str().trim_end_matches('/'),
            request.uri.path()
        );
        let Some(uri) = ApUri::parse(&compatible) else {
            return Handled::NotFound;
        };
        let context = Context::new(
            self.inner.clone(),
            data,
            origin,
            Some(RequestInfo::of(request, host)),
        );
        let head = request.method == Method::HEAD;
        let response = if request.method == Method::GET || head {
            let Some(load) = &self.inner.gateway else {
                return Handled::NotFound;
            };
            match load(context.clone(), uri.clone()).await {
                Ok(found) => without_body_if(head, portable_found(found, &uri)),
                Err(error) => {
                    context.report(&error);
                    empty(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        } else if request.method == Method::POST {
            let Some(inbox_for) = &self.inner.gateway_inbox else {
                return Handled::Response(method_not_allowed());
            };
            match inbox_for(context.clone(), uri.clone()).await {
                Ok(Some(gateway)) => inbox::receive_at_gateway(context, uri, gateway, body).await,
                // Not an inbox this server accepts deliveries for.
                Ok(None) => empty(StatusCode::NOT_FOUND),
                Err(error) => {
                    context.report(&error);
                    empty(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        } else {
            let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD, POST"));
            response
        };
        Handled::Response(response)
    }

    /// Answer `request` with its `body`: an activity POSTed to an inbox is
    /// received; anything else is answered as [`Federation::handle`] does.
    pub async fn handle_with_body(
        &self,
        request: &http::request::Parts,
        body: &[u8],
        data: D,
    ) -> Handled {
        if self.serves_gateway() && is_gateway_path(request.uri.path()) {
            return self.gateway(request, body, data).await;
        }
        let Some(recipient) = self.inbox_at(request.uri.path()) else {
            return self.handle(request, data).await;
        };
        let host = request_host(request);
        let Some(origin) = self.origin_for(&host, &data) else {
            return Handled::NotFound;
        };
        if request.method != Method::POST {
            let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST"));
            return Handled::Response(response);
        }
        let context = Context::new(
            self.inner.clone(),
            data,
            origin,
            Some(RequestInfo::of(request, host)),
        );
        Handled::Response(inbox::receive(context, recipient, body).await)
    }

    /// Answer `request`, or say why it is not Feder's to answer. An inbox's
    /// POST needs its body: [`Federation::handle_with_body`].
    pub async fn handle(&self, request: &http::request::Parts, data: D) -> Handled {
        let path = request.uri.path();
        if self.serves_gateway() && is_gateway_path(path) {
            return self.gateway(request, b"", data).await;
        }
        if self.is_inbox(path) {
            return Box::pin(self.handle_with_body(request, b"", data)).await;
        }
        let special = self.special(path);
        let matched = if special.is_some() {
            None
        } else {
            let found = self
                .inner
                .entries
                .iter()
                .enumerate()
                .find_map(|(index, entry)| Some((index, entry.template.matches(path)?)));
            if found.is_none() {
                return Handled::NotFound;
            }
            found
        };

        let host = request_host(request);
        let Some(origin) = self.origin_for(&host, &data) else {
            return Handled::NotFound;
        };
        let head = request.method == Method::HEAD;
        if request.method != Method::GET && !head {
            return Handled::Response(method_not_allowed());
        }

        if let Some(special) = special {
            let context = Context::new(
                self.inner.clone(),
                data,
                origin,
                Some(RequestInfo::of(request, host)),
            );
            let response = match special {
                Special::WebFinger => webfinger::webfinger(&context, request.uri.query()).await,
                Special::HostMeta => webfinger::host_meta(&context),
                Special::NodeInfoLinks => nodeinfo::links(&context),
                Special::NodeInfo(version) => nodeinfo::document(&context, version).await,
            };
            return Handled::Response(without_body_if(head, response));
        }

        let Some((index, values)) = matched else {
            return Handled::NotFound;
        };
        let accept = request
            .headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok());
        if !negotiate::wants_activity(accept) {
            return Handled::NotAcceptable;
        }
        let context = Context::new(
            self.inner.clone(),
            data,
            origin,
            Some(RequestInfo::of(request, host)),
        );
        let entry = &self.inner.entries[index];
        let response = self
            .dispatch(&context, entry, values, request.uri.query())
            .await
            .unwrap_or_else(|error| {
                context.report(&error);
                empty(StatusCode::INTERNAL_SERVER_ERROR)
            });
        Handled::Response(without_body_if(head, response))
    }

    async fn dispatch(
        &self,
        context: &Context<D>,
        entry: &Entry<D>,
        values: Values,
        query: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        if let Some(authorize) = &entry.authorize {
            let signer = context.signer().await;
            let signed = signer.is_some();
            if !authorize(context.clone(), values.clone(), signer).await? {
                return Ok(unauthorized(signed));
            }
        }
        let url = context.request_url();
        match &entry.dispatcher {
            Dispatcher::Actor(load) => {
                let identifier = values.single().unwrap_or_default().to_owned();
                Ok(found(load(context.clone(), identifier).await?, &url))
            }
            Dispatcher::Object(load) => Ok(found(load(context.clone(), values).await?, &url)),
            Dispatcher::Collection(collection) => {
                let identifier = values.single().unwrap_or_default().to_owned();
                collection
                    .serve(context, &entry.kind, &identifier, query)
                    .await
            }
        }
    }

    fn serves_gateway(&self) -> bool {
        self.inner.gateway.is_some() || self.inner.gateway_inbox.is_some()
    }

    fn special(&self, path: &str) -> Option<Special> {
        let serves_webfinger = self
            .inner
            .entries
            .iter()
            .any(|entry| matches!(entry.dispatcher, Dispatcher::Actor(_)));
        match path {
            webfinger::WEBFINGER_PATH if serves_webfinger => Some(Special::WebFinger),
            webfinger::HOST_META_PATH if serves_webfinger => Some(Special::HostMeta),
            nodeinfo::LINKS_PATH if self.inner.nodeinfo.is_some() => Some(Special::NodeInfoLinks),
            nodeinfo::PATH_2_0 if self.inner.nodeinfo.is_some() => {
                Some(Special::NodeInfo(nodeinfo::Version::V2_0))
            }
            nodeinfo::PATH_2_1 if self.inner.nodeinfo.is_some() => {
                Some(Special::NodeInfo(nodeinfo::Version::V2_1))
            }
            _ => None,
        }
    }
}

enum Special {
    WebFinger,
    HostMeta,
    NodeInfoLinks,
    NodeInfo(nodeinfo::Version),
}

/// The paths Feder serves itself, which no template may claim.
const RESERVED: [&str; 5] = [
    webfinger::WEBFINGER_PATH,
    webfinger::HOST_META_PATH,
    nodeinfo::LINKS_PATH,
    nodeinfo::PATH_2_0,
    nodeinfo::PATH_2_1,
];

impl<D: Clone + Send + Sync + 'static> Builder<D> {
    /// Serve every request in `origin`'s URIs, whatever host it came to: for
    /// an application with one host.
    #[must_use]
    pub fn origin(mut self, origin: Url) -> Self {
        self.origin = Some(OriginRule::Fixed(origin));
        self
    }

    /// The canonical origin for a request to a host, or `None` for a host
    /// Feder should not answer for. A host this maps to the canonical origin
    /// is one of its aliases: its IRIs are ours, and its handles are.
    #[must_use]
    pub fn origin_with(
        mut self,
        origin: impl Fn(&str, &D) -> Option<Url> + Send + Sync + 'static,
    ) -> Self {
        self.origin = Some(OriginRule::PerHost(Arc::new(origin)));
        self
    }

    fn add(&mut self, kind: &str, template: &str, dispatcher: Dispatcher<D>) {
        match Template::parse(template) {
            Ok(template) => self.entries.push(Entry {
                kind: kind.to_owned(),
                template,
                dispatcher,
                authorize: None,
            }),
            Err(error) => self.errors.push(error.to_string()),
        }
    }

    /// Serve actors of `kind` at `template`, whose one expression, if it has
    /// one, is the actor's identifier.
    #[must_use]
    pub fn actor<F, Fut, E>(mut self, kind: &str, template: &str, load: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Found<Value>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let load = boxed(move |(context, identifier)| load(context, identifier));
        self.add(
            kind,
            template,
            Dispatcher::Actor(Arc::new(move |context, identifier| {
                load((context, identifier))
            })),
        );
        self
    }

    /// Serve objects of `kind` at `template`, whose expressions the
    /// dispatcher receives by name.
    #[must_use]
    pub fn object<F, Fut, E>(mut self, kind: &str, template: &str, load: F) -> Self
    where
        F: Fn(Context<D>, Values) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Found<Value>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let load = boxed(move |(context, values)| load(context, values));
        self.add(
            kind,
            template,
            Dispatcher::Object(Arc::new(move |context, values| load((context, values)))),
        );
        self
    }

    /// Serve the collection `kind` at `template`, whose one expression, if it
    /// has one, is the identifier of what it belongs to.
    #[must_use]
    pub fn collection(mut self, kind: &str, template: &str, collection: Collection<D>) -> Self {
        self.add(kind, template, Dispatcher::Collection(collection));
        self
    }

    /// Serve what is registered as `kind` only to requests `authorize` allows.
    /// It receives the verified signer of the request, if it was signed and
    /// signed fetches are configured. A request it refuses is 401.
    #[must_use]
    pub fn authorize<F, Fut, E>(mut self, kind: &str, authorize: F) -> Self
    where
        F: Fn(Context<D>, Values, Option<Url>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, E>> + Send + 'static,
        E: Into<Error>,
    {
        let authorize = boxed(move |(context, values, signer)| authorize(context, values, signer));
        self.authorize.push((
            kind.to_owned(),
            Arc::new(move |context, values, signer| authorize((context, values, signer))),
        ));
        self
    }

    /// Where actors' public keys come from, read by [`Context::actor_keys`].
    #[must_use]
    pub fn key_pairs<F, Fut, E>(mut self, keys: F) -> Self
    where
        F: Fn(Context<D>, ActorRef) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<PublicKey>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let keys = boxed(move |(context, actor)| keys(context, actor));
        self.key_pairs = Some(Arc::new(move |context, actor| keys((context, actor))));
        self
    }

    /// Which actor a WebFinger handle's username names.
    #[must_use]
    pub fn handle<F, Fut, E>(mut self, lookup: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<ActorRef>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let lookup = boxed(move |(context, username)| lookup(context, username));
        self.handle = Some(Arc::new(move |context, username| {
            lookup((context, username))
        }));
        self
    }

    /// Which actor another URL of ours, such as a profile page, names, for
    /// WebFinger.
    #[must_use]
    pub fn map_alias<F, Fut, E>(mut self, lookup: F) -> Self
    where
        F: Fn(Context<D>, Url) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<ActorRef>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let lookup = boxed(move |(context, url)| lookup(context, url));
        self.map_alias = Some(Arc::new(move |context, url| lookup((context, url))));
        self
    }

    /// Links a WebFinger answer carries beside `self` and `profile-page`,
    /// such as Mastodon's `subscribe` template.
    #[must_use]
    pub fn webfinger_links(
        mut self,
        links: impl Fn(&Context<D>, &ActorRef, &Value) -> Vec<Value> + Send + Sync + 'static,
    ) -> Self {
        self.webfinger_links = Some(Arc::new(links));
        self
    }

    /// Serve NodeInfo, 2.0 and 2.1, from `nodeinfo`.
    #[must_use]
    pub fn nodeinfo<F, Fut, E>(mut self, nodeinfo: F) -> Self
    where
        F: Fn(Context<D>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<NodeInfo, E>> + Send + 'static,
        E: Into<Error>,
    {
        self.nodeinfo = Some(boxed(nodeinfo));
        self
    }

    /// Verify signed GETs, for [`Context::signer`] and `authorize`: keys are
    /// fetched with `fetcher`, signed with the key `key` returns when there is
    /// one, and kept in `kv` for `key_ttl`.
    #[must_use]
    pub fn signed_fetch<K, F, Fut, E>(
        mut self,
        fetcher: Arc<Fetcher>,
        kv: K,
        key_ttl: Duration,
        key: F,
    ) -> Self
    where
        K: KvStore,
        F: Fn(Context<D>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<crate::delivery::SenderKey>, E>> + Send + 'static,
        E: Into<Error>,
    {
        self.signed_fetch = Some(signer::SignedFetch {
            fetcher,
            kv: Arc::new(kv),
            key_ttl,
            key: boxed(key),
            fetcher_for: None,
            known_key: None,
            key_fetched: None,
        });
        self
    }

    /// The fetcher for a request's data, in place of the one given to
    /// [`Builder::signed_fetch`]: an application serving several instances
    /// fetches with each one's own. Call after `signed_fetch`.
    #[must_use]
    pub fn fetcher_for(
        mut self,
        fetcher: impl Fn(&D) -> Arc<Fetcher> + Send + Sync + 'static,
    ) -> Self {
        match &mut self.signed_fetch {
            Some(settings) => settings.fetcher_for = Some(Arc::new(fetcher)),
            None => self.errors.push("fetcher_for before signed_fetch".into()),
        }
        self
    }

    /// A key the application already holds for a key ID, tried before the
    /// key-value store and a fetch: an application that stores remote
    /// actors' keys, as Mastodon's schema does, need not fetch them again. A
    /// key that does not verify is fetched fresh. Call after `signed_fetch`.
    #[must_use]
    pub fn known_key<F, Fut, E>(mut self, known: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<KnownKey>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let known = boxed(move |(context, key_id)| known(context, key_id));
        match &mut self.signed_fetch {
            Some(settings) => {
                settings.known_key =
                    Some(Arc::new(move |context, key_id| known((context, key_id))));
            }
            None => self.errors.push("known_key before signed_fetch".into()),
        }
        self
    }

    /// See the document of an actor Feder fetched for its key, once the key
    /// has verified a request: an application that stores actors stores this
    /// one, so a new actor's first activity does not fetch it twice. Call
    /// after `signed_fetch`.
    #[must_use]
    pub fn key_fetched<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Context<D>, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        match &mut self.signed_fetch {
            Some(settings) => {
                settings.key_fetched = Some(Arc::new(move |context, document| {
                    Box::pin(hook(context, document))
                }));
            }
            None => self.errors.push("key_fetched before signed_fetch".into()),
        }
        self
    }

    /// Run `listen` for every activity no typed listener is registered for,
    /// read as whatever it is: for an application with a dispatcher of its
    /// own, which reads [`Received::vouched`].
    #[must_use]
    pub fn on_any<F, Fut, E>(mut self, listen: F) -> Self
    where
        F: Fn(Context<D>, Received<feder_vocab::generated::AnyObject>) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: Into<Error>,
    {
        self.fallback_listener = Some(inbox::any_listener(listen));
        self
    }

    /// Receive activities at `template`, the inbox of the actors of `kind`,
    /// whose one expression is the actor's identifier.
    #[must_use]
    pub fn inbox(mut self, kind: &str, template: &str) -> Self {
        self.inboxes.push((kind.to_owned(), template.to_owned()));
        self
    }

    /// Receive activities at `path`, the shared inbox.
    #[must_use]
    pub fn shared_inbox(mut self, path: &str) -> Self {
        self.shared_inbox = Some(path.to_owned());
        self
    }

    /// Run `listen` for every activity of type `T` an inbox receives from a
    /// sender Feder has authenticated. Types with no listener are accepted
    /// and dropped.
    #[must_use]
    pub fn on<T, F, Fut, E>(mut self, listen: F) -> Self
    where
        T: feder_vocab::json::Typed
            + feder_vocab::json::FromJson
            + feder_vocab::json::ToJson
            + Send
            + 'static,
        F: Fn(Context<D>, Received<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: Into<Error>,
    {
        if self
            .listeners
            .insert(T::TYPE, inbox::listener(listen))
            .is_some()
        {
            self.errors.push(format!("two listeners for {}", T::TYPE));
        }
        self
    }

    /// Whether activities from `host` are refused, asked before any key is
    /// fetched for them. A refused activity is answered 202 and dropped.
    #[must_use]
    pub fn blocked<F, Fut, E>(mut self, blocked: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, E>> + Send + 'static,
        E: Into<Error>,
    {
        let blocked = boxed(move |(context, host)| blocked(context, host));
        self.blocked = Some(Arc::new(move |context, host| blocked((context, host))));
        self
    }

    /// See every activity whose sender could not be authenticated, which is
    /// where an application removes an actor whose Delete it could not
    /// verify because the actor, key and all, is gone.
    #[must_use]
    pub fn on_unverified<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Context<D>, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on_unverified = Some(Arc::new(move |context, document| {
            Box::pin(hook(context, document))
        }));
        self
    }

    /// The queue activities wait in for an [`InboxWorker`], for the data of a
    /// request: an application with a database per tenant has a queue per
    /// tenant. Without one, or when it gives `None`, listeners run inside the
    /// request.
    #[must_use]
    pub fn inbox_queue(
        mut self,
        queue: impl Fn(&D) -> Option<crate::queue::SharedQueue> + Send + Sync + 'static,
    ) -> Self {
        self.inbox_queue = Some(Arc::new(queue));
        self
    }

    /// Serve the portable objects (FEP-ef61) this server is a gateway for,
    /// at `/.well-known/apgateway/{did}/{+path}`. `load` returns the object
    /// an `ap` URI names, as the signed document the application stored: its
    /// proof covers it, and Feder serves it as it is. An object that is not
    /// public is the application's to refuse, as for any dispatcher.
    #[must_use]
    pub fn gateway<F, Fut, E>(mut self, load: F) -> Self
    where
        F: Fn(Context<D>, ApUri) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Found<Value>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let load = boxed(move |(context, uri)| load(context, uri));
        self.gateway = Some(Arc::new(move |context, uri| load((context, uri))));
        self
    }

    /// Accept deliveries to portable inboxes: `inbox_for` maps the `ap` URI
    /// of an inbox POSTed to at `/.well-known/apgateway/…` to the actor the
    /// application hosts it for, who the listeners see as the recipient, and
    /// the gateways that actor lists, which what arrives is forwarded to.
    /// An inbox it maps to `None` is answered 404.
    #[must_use]
    pub fn gateway_inbox<F, Fut, E>(mut self, inbox_for: F) -> Self
    where
        F: Fn(Context<D>, ApUri) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<GatewayInbox>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let inbox_for = boxed(move |(context, uri)| inbox_for(context, uri));
        self.gateway_inbox = Some(Arc::new(move |context, uri| inbox_for((context, uri))));
        self
    }

    /// Send what arrives at a portable inbox on to the actor's other
    /// gateways, as FEP-ef61 asks: `forward` is called once for each
    /// activity, however many times it arrives, with the gateways to send it
    /// to, and sends it, usually with `Deliverer::send_portable`. Without
    /// it, nothing is forwarded.
    #[must_use]
    pub fn forward<F, Fut, E>(mut self, forward: F) -> Self
    where
        F: Fn(Context<D>, Forward) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: Into<Error>,
    {
        let forward = boxed(move |(context, activity)| forward(context, activity));
        self.forward = Some(Arc::new(move |context, activity| {
            forward((context, activity))
        }));
        self
    }

    /// See every error a dispatcher returns, which is otherwise a bare 500.
    #[must_use]
    pub fn on_error(mut self, report: impl Fn(&Error) + Send + Sync + 'static) -> Self {
        self.on_error = Some(Arc::new(report));
        self
    }

    /// The federation.
    ///
    /// # Errors
    ///
    /// When there is no origin, a template is malformed, two templates could
    /// match one path, a template claims a path Feder serves itself, two
    /// dispatchers share a kind, an actor or collection template has more
    /// than one expression, or `authorize` names no kind.
    pub fn build(mut self) -> Result<Federation<D>, BuildError> {
        let mut errors = std::mem::take(&mut self.errors);
        let origin = self.origin.take();
        if origin.is_none() {
            errors.push("no origin: call origin or origin_with".into());
        }
        for (index, entry) in self.entries.iter().enumerate() {
            let expressions = entry.template.names().count();
            if !matches!(entry.dispatcher, Dispatcher::Object(_)) && expressions > 1 {
                errors.push(format!(
                    "{} {:?}: {} has more than one expression",
                    entry.noun(),
                    entry.kind,
                    entry.template.as_str()
                ));
            }
            for reserved in RESERVED {
                if entry.template.matches(reserved).is_some() {
                    errors.push(format!(
                        "{} claims {reserved}, which Feder serves",
                        entry.template.as_str()
                    ));
                }
            }
            for other in &self.entries[index + 1..] {
                if entry.kind == other.kind {
                    errors.push(format!("two dispatchers of kind {:?}", entry.kind));
                }
                if entry.template.overlaps(&other.template) {
                    errors.push(format!(
                        "{} and {} could match one path",
                        entry.template.as_str(),
                        other.template.as_str()
                    ));
                }
            }
        }
        let mut inboxes = Vec::new();
        for (kind, template) in std::mem::take(&mut self.inboxes) {
            match Template::parse(&template) {
                Ok(template) => {
                    if template.names().count() != 1 {
                        errors.push(format!(
                            "inbox {}: has to name its actor in one expression",
                            template.as_str()
                        ));
                    }
                    if !self.entries.iter().any(|entry| {
                        entry.kind == kind && matches!(entry.dispatcher, Dispatcher::Actor(_))
                    }) {
                        errors.push(format!("inbox for {kind:?}, which is no actor kind"));
                    }
                    inboxes.push((kind, template));
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        let shared_inbox = match self.shared_inbox.take().map(|path| Template::parse(&path)) {
            Some(Ok(template)) if template.names().count() == 0 => Some(template),
            Some(Ok(template)) => {
                errors.push(format!(
                    "shared inbox {} has an expression",
                    template.as_str()
                ));
                None
            }
            Some(Err(error)) => {
                errors.push(error.to_string());
                None
            }
            None => None,
        };
        let inbox_templates: Vec<&Template> = inboxes
            .iter()
            .map(|(_, template)| template)
            .chain(shared_inbox.as_ref())
            .collect();
        for (n, template) in inbox_templates.iter().enumerate() {
            for other in self
                .entries
                .iter()
                .map(|entry| &entry.template)
                .chain(inbox_templates[n + 1..].iter().copied())
            {
                if template.overlaps(other) {
                    errors.push(format!(
                        "{} and {} could match one path",
                        template.as_str(),
                        other.as_str()
                    ));
                }
            }
            for reserved in RESERVED {
                if template.matches(reserved).is_some() {
                    errors.push(format!(
                        "{} claims {reserved}, which Feder serves",
                        template.as_str()
                    ));
                }
            }
        }
        if !inbox_templates.is_empty() && self.signed_fetch.is_none() {
            errors.push("an inbox needs signed_fetch, to fetch and cache senders' keys".into());
        }
        for (kind, authorize) in std::mem::take(&mut self.authorize) {
            match self.entries.iter_mut().find(|entry| entry.kind == kind) {
                Some(entry) => entry.authorize = Some(authorize),
                None => errors.push(format!("authorize names no dispatcher of kind {kind:?}")),
            }
        }
        match origin {
            Some(origin) if errors.is_empty() => Ok(Federation {
                inner: Arc::new(Inner {
                    origin,
                    entries: self.entries,
                    key_pairs: self.key_pairs,
                    handle: self.handle,
                    map_alias: self.map_alias,
                    webfinger_links: self.webfinger_links,
                    nodeinfo: self.nodeinfo,
                    signed_fetch: self.signed_fetch,
                    on_error: self.on_error,
                    inboxes,
                    shared_inbox,
                    listeners: self.listeners,
                    fallback_listener: self.fallback_listener,
                    blocked: self.blocked,
                    on_unverified: self.on_unverified,
                    inbox_queue: self.inbox_queue,
                    gateway: self.gateway,
                    gateway_inbox: self.gateway_inbox,
                    forward: self.forward,
                }),
            }),
            _ => Err(BuildError(errors)),
        }
    }
}

/// What a context remembers of the request it was made for.
struct RequestInfo {
    method: String,
    path_and_query: String,
    host: String,
    headers: Vec<(String, String)>,
}

impl RequestInfo {
    fn of(request: &http::request::Parts, host: String) -> Self {
        Self {
            method: request.method.as_str().to_owned(),
            path_and_query: request.uri.path_and_query().map_or_else(
                || request.uri.path().to_owned(),
                |pq| pq.as_str().to_owned(),
            ),
            host,
            headers: request
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect(),
        }
    }
}

struct ContextInner<D> {
    federation: Arc<Inner<D>>,
    data: D,
    origin: Url,
    request: Option<RequestInfo>,
    signer: tokio::sync::OnceCell<Option<Url>>,
}

/// What every callback receives: the application's data, the canonical
/// origin, and the request, if there is one. Cheap to clone.
pub struct Context<D> {
    inner: Arc<ContextInner<D>>,
}

impl<D> Clone for Context<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Clone + Send + Sync + 'static> Context<D> {
    fn new(federation: Arc<Inner<D>>, data: D, origin: Url, request: Option<RequestInfo>) -> Self {
        Self {
            inner: Arc::new(ContextInner {
                federation,
                data,
                origin,
                request,
                signer: tokio::sync::OnceCell::new(),
            }),
        }
    }

    /// The application's data.
    #[must_use]
    pub fn data(&self) -> &D {
        &self.inner.data
    }

    /// The canonical origin every URI is built in.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.inner.origin
    }

    fn entry(&self, kind: &str, noun: &str) -> Result<&Entry<D>, UriError> {
        self.inner
            .federation
            .entries
            .iter()
            .find(|entry| entry.kind == kind && entry.noun() == noun)
            .ok_or_else(|| UriError::UnknownKind(kind.to_owned()))
    }

    fn uri(&self, template: &Template, values: &Values) -> Result<Url, UriError> {
        let path = template.expand(values).map_err(UriError::Template)?;
        let mut url = self.inner.origin.clone();
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    fn single(template: &Template, identifier: &str) -> Values {
        template
            .names()
            .map(|name| (name.to_owned(), identifier.to_owned()))
            .collect()
    }

    /// The URI of the actor of `kind` with `identifier`.
    ///
    /// # Errors
    ///
    /// When no actor dispatcher is of `kind`, or `identifier` is empty for a
    /// template that needs one.
    pub fn actor_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        let entry = self.entry(kind, "actor")?;
        self.uri(&entry.template, &Self::single(&entry.template, identifier))
    }

    /// The URI of the object of `kind` with `values`.
    ///
    /// # Errors
    ///
    /// When no object dispatcher is of `kind`, or `values` do not fill its
    /// template.
    pub fn object_uri(&self, kind: &str, values: &[(&str, &str)]) -> Result<Url, UriError> {
        let entry = self.entry(kind, "object")?;
        self.uri(&entry.template, &values.iter().copied().collect())
    }

    /// The URI of the collection `kind` of what `identifier` names.
    ///
    /// # Errors
    ///
    /// As [`Context::actor_uri`], for collections.
    pub fn collection_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        let entry = self.entry(kind, "collection")?;
        self.uri(&entry.template, &Self::single(&entry.template, identifier))
    }

    /// Whether `host`, with its port if it has one, is the canonical
    /// origin's or one of its aliases.
    #[must_use]
    pub fn is_our_host(&self, host: &str) -> bool {
        let host = normalize_host(host);
        match &self.inner.federation.origin {
            OriginRule::Fixed(origin) => authority(origin) == host,
            OriginRule::PerHost(origin_for) => {
                origin_for(&host, &self.inner.data).as_ref() == Some(&self.inner.origin)
            }
        }
    }

    /// What `iri` is, if it is ours: on the canonical origin or an alias, and
    /// matching a registered template.
    #[must_use]
    pub fn parse_uri(&self, iri: &str) -> Option<Route> {
        let url = Url::parse(iri).ok()?;
        if url.scheme() != self.inner.origin.scheme() || !self.is_our_host(&authority(&url)) {
            return None;
        }
        self.inner.federation.entries.iter().find_map(|entry| {
            let values = entry.template.matches(url.path())?;
            Some(match entry.dispatcher {
                Dispatcher::Actor(_) => Route::Actor(ActorRef::new(
                    entry.kind.clone(),
                    values.single().unwrap_or_default(),
                )),
                Dispatcher::Object(_) => Route::Object {
                    kind: entry.kind.clone(),
                    values,
                },
                Dispatcher::Collection(_) => Route::Collection {
                    kind: entry.kind.clone(),
                    identifier: values.single().unwrap_or_default().to_owned(),
                },
            })
        })
    }

    /// The public keys `actor` publishes, from the key-pairs dispatcher; none
    /// when there is no such dispatcher.
    ///
    /// # Errors
    ///
    /// What the dispatcher returns.
    pub async fn actor_keys(&self, actor: &ActorRef) -> Result<Vec<PublicKey>, Error> {
        match &self.inner.federation.key_pairs {
            Some(keys) => keys(self.clone(), actor.clone()).await,
            None => Ok(Vec::new()),
        }
    }

    /// The actor who signed the request, verified: the signature is sound,
    /// made for this host and recently, and made with a key its actor
    /// publishes. `None` when the request is unsigned, the signature fails,
    /// there is no request, or signed fetches are not configured. Verified
    /// once per request, however often it is asked.
    pub async fn signer(&self) -> Option<Url> {
        self.inner
            .signer
            .get_or_init(|| signer::verify(self))
            .await
            .clone()
    }

    /// Load the actor `actor` through its dispatcher.
    async fn load_actor(&self, actor: &ActorRef) -> Result<Found<Value>, Error> {
        let Ok(entry) = self.entry(&actor.kind, "actor") else {
            return Ok(Found::NotFound);
        };
        match &entry.dispatcher {
            Dispatcher::Actor(load) => load(self.clone(), actor.identifier.clone()).await,
            _ => Ok(Found::NotFound),
        }
    }

    /// The URL the request was for, in the canonical origin.
    fn request_url(&self) -> Url {
        let mut url = self.inner.origin.clone();
        if let Some(request) = &self.inner.request {
            let (path, query) = request
                .path_and_query
                .split_once('?')
                .map_or((request.path_and_query.as_str(), None), |(p, q)| {
                    (p, Some(q))
                });
            url.set_path(path);
            url.set_query(query);
        }
        url
    }

    fn report(&self, error: &Error) {
        if let Some(report) = &self.inner.federation.on_error {
            report(error);
        }
    }
}

/// `host` lower-cased, without a trailing dot on its name.
fn normalize_host(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.starts_with('[') {
        // An IPv6 literal, whose colons are not a port's.
        return host;
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            format!("{}:{port}", name.trim_end_matches('.'))
        }
        _ => host.trim_end_matches('.').to_owned(),
    }
}

/// The host a request was sent to: `Host`, or the URI's authority, as
/// HTTP/2 sends it.
fn request_host(request: &http::request::Parts) -> String {
    let host = request
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri.authority().map(http::uri::Authority::as_str))
        .unwrap_or_default();
    normalize_host(host)
}

/// A URL's host, with its port when it has one other than its scheme's.
fn authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

fn response(status: StatusCode, content_type: &str, body: Vec<u8>) -> http::Response<Vec<u8>> {
    let mut response = http::Response::new(body);
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}

fn empty(status: StatusCode) -> http::Response<Vec<u8>> {
    let mut response = http::Response::new(Vec::new());
    *response.status_mut() = status;
    response
}

fn method_not_allowed() -> http::Response<Vec<u8>> {
    let mut response = empty(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
    response
}

fn unauthorized(signed: bool) -> http::Response<Vec<u8>> {
    let mut response = empty(StatusCode::UNAUTHORIZED);
    if !signed {
        // What a peer needs to know to try again, signed.
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Signature realm=\"ActivityPub\""),
        );
    }
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept, Signature"));
    response
}

fn without_body_if(head: bool, mut response: http::Response<Vec<u8>>) -> http::Response<Vec<u8>> {
    if head {
        let length = response.body().len();
        response.body_mut().clear();
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    response
}

/// An ActivityPub document, with the default `@context` when it has none.
pub(crate) fn activity(status: StatusCode, mut document: Value) -> http::Response<Vec<u8>> {
    if let Some(members) = document.as_object_mut()
        && !members.contains_key("@context")
    {
        let mut with_context = serde_json::Map::new();
        with_context.insert("@context".into(), default_context());
        with_context.append(members);
        *members = with_context;
    }
    let mut response = response(
        status,
        ACTIVITY_JSON,
        serde_json::to_vec(&document).unwrap_or_default(),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
    response
}

/// Whether `path` is under the well-known path gateways serve at.
fn is_gateway_path(path: &str) -> bool {
    path.starts_with(feder_core::portable::GATEWAY_PATH)
}

/// The media type a gateway serves portable objects as (FEP-ef61).
pub const PORTABLE_JSON: &str =
    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

/// A portable object as a gateway serves it: the document as the
/// application stored it, since its proof covers it.
fn portable_found(found: Found<Value>, uri: &ApUri) -> http::Response<Vec<u8>> {
    match found {
        Found::Found(document) => {
            let body = serde_json::to_vec(&document).unwrap_or_default();
            response(StatusCode::OK, PORTABLE_JSON, body)
        }
        Found::Gone(deleted) => {
            let mut tombstone = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": uri.canonical(),
                "type": "Tombstone",
            });
            if let Some(deleted) = deleted {
                tombstone["deleted"] = deleted.to_rfc3339_opts(SecondsFormat::Secs, true).into();
            }
            let body = serde_json::to_vec(&tombstone).unwrap_or_default();
            response(StatusCode::GONE, PORTABLE_JSON, body)
        }
        Found::NotFound => empty(StatusCode::NOT_FOUND),
    }
}

fn found(found: Found<Value>, url: &Url) -> http::Response<Vec<u8>> {
    match found {
        Found::Found(document) => activity(StatusCode::OK, document),
        Found::Gone(deleted) => {
            let mut tombstone = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": url.as_str(),
                "type": "Tombstone",
            });
            if let Some(deleted) = deleted {
                tombstone["deleted"] = deleted.to_rfc3339_opts(SecondsFormat::Secs, true).into();
            }
            activity(StatusCode::GONE, tombstone)
        }
        Found::NotFound => {
            let mut response = empty(StatusCode::NOT_FOUND);
            response
                .headers_mut()
                .insert(header::VARY, HeaderValue::from_static("Accept"));
            response
        }
    }
}

/// A key-value store, object-safe, for what the federation keeps.
trait DynKv: Send + Sync {
    fn get<'a>(&'a self, key: &'a [&'a str]) -> BoxFuture<'a, Result<Option<Value>, KvError>>;
    fn set<'a>(
        &'a self,
        key: &'a [&'a str],
        value: Value,
        ttl: Option<Duration>,
    ) -> BoxFuture<'a, Result<(), KvError>>;
    fn insert<'a>(
        &'a self,
        key: &'a [&'a str],
        value: Value,
        ttl: Option<Duration>,
    ) -> BoxFuture<'a, Result<bool, KvError>>;
    fn delete<'a>(&'a self, key: &'a [&'a str]) -> BoxFuture<'a, Result<(), KvError>>;
}

impl<K: KvStore> DynKv for K {
    fn get<'a>(&'a self, key: &'a [&'a str]) -> BoxFuture<'a, Result<Option<Value>, KvError>> {
        Box::pin(KvStore::get(self, key))
    }

    fn set<'a>(
        &'a self,
        key: &'a [&'a str],
        value: Value,
        ttl: Option<Duration>,
    ) -> BoxFuture<'a, Result<(), KvError>> {
        Box::pin(KvStore::set(self, key, value, ttl))
    }

    fn insert<'a>(
        &'a self,
        key: &'a [&'a str],
        value: Value,
        ttl: Option<Duration>,
    ) -> BoxFuture<'a, Result<bool, KvError>> {
        Box::pin(KvStore::insert(self, key, value, ttl))
    }

    fn delete<'a>(&'a self, key: &'a [&'a str]) -> BoxFuture<'a, Result<(), KvError>> {
        Box::pin(KvStore::delete(self, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_compared_without_case_or_a_trailing_dot() {
        assert_eq!(normalize_host("Oeee.Cafe."), "oeee.cafe");
        assert_eq!(normalize_host("oeee.cafe.:8443"), "oeee.cafe:8443");
        assert_eq!(normalize_host("127.0.0.1:3000"), "127.0.0.1:3000");
        assert_eq!(normalize_host("[::1]:3000"), "[::1]:3000");
        assert_eq!(normalize_host("[::1]"), "[::1]");
    }

    #[test]
    fn keys_go_where_each_is_read() {
        let mut actor = json!({"id": "https://a.example/users/1", "type": "Person"});
        with_keys(
            &mut actor,
            &[
                PublicKey::Multikey {
                    id: "https://a.example/users/1#ed25519-key".into(),
                    multibase: "z6Mk".into(),
                },
                PublicKey::Rsa {
                    id: "https://a.example/users/1#main-key".into(),
                    pem: "PEM".into(),
                },
            ],
        );
        assert_eq!(
            actor["publicKey"],
            json!({"id": "https://a.example/users/1#main-key", "owner": "https://a.example/users/1", "publicKeyPem": "PEM"})
        );
        assert_eq!(
            actor["assertionMethod"][0]["controller"],
            "https://a.example/users/1"
        );
        assert_eq!(actor["assertionMethod"][0]["type"], "Multikey");
    }
}
