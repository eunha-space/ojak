//! Serving: what Ojak answers when another server, or a person, sends a
//! GET.
//!
//! An application builds one [`Federation`] at start-up, registering a
//! dispatcher for each kind of actor, object and collection it serves, each
//! with the URI template that both routes requests to it and builds its URIs.
//! WebFinger and host-meta follow from the actors, and NodeInfo from one more
//! dispatcher. *docs/guide/serving.md* explains it.
//!
//! [`Federation::handle`] answers a request in `http` types, so that it works
//! under any server framework; *ojak-axum* adapts it to axum.

mod collection;
mod inbox;
mod negotiate;
mod nodeinfo;
mod signer;
mod webfinger;

pub use crate::template::Values;
pub use collection::{Collection, First, Page};
pub use inbox::{
    CollectionRef, Forward, ForwardTo, GatewayInbox, InboxWorker, InboxWorkerConfig,
    MAX_BODY as MAX_INBOX_BODY, Received,
};
pub use nodeinfo::{NodeInfo, Software, Usage};
pub use signer::{KnownKey, Signing};

use crate::fetch::Fetcher;
use crate::kv::{KvError, KvStore};
use crate::portable::{ApUri, Hashlink, Media};
use crate::template::{Template, TemplateError};
use chrono::{DateTime, SecondsFormat, Utc};
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

/// What a guard ([`Builder::guard`]) makes of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Serve it.
    Allow,
    /// Refuse it as unauthorized, 401: it has to be signed, or signed by
    /// someone else.
    Unauthorized,
    /// Refuse it as forbidden, 403: whoever signed it is refused.
    Forbidden,
    /// Answer it as if nothing were there, 404.
    NotFound,
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
    /// Ojak's answer.
    Response(http::Response<Vec<u8>>),
    /// A route of Ojak's matched, but the request did not ask for
    /// ActivityPub: the application serves its page at this URL, or 406.
    NotAcceptable,
    /// Nothing of Ojak's is at this URL, or on this host.
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
type AuthorizeFn<D> =
    Arc<dyn Fn(Context<D>, Values) -> BoxFuture<'static, Result<Access, Error>> + Send + Sync>;
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
type GatewayMediaFn<D> = Arc<
    dyn Fn(Context<D>, Hashlink) -> BoxFuture<'static, Result<Option<Media>, Error>> + Send + Sync,
>;
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
    /// Another path the kind is served and recognised at, never built.
    alias: bool,
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
    templates: Arc<Templates>,
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
    gateway_media: Option<GatewayMediaFn<D>>,
    gateway_inbox: Option<GatewayInboxFn<D>>,
    forward: Option<inbox::ForwardFn<D>>,
    read_as_written: bool,
    remote_contexts: Option<RemoteContexts<D>>,
}

/// How contexts ojak does not ship are loaded to check a Linked Data
/// Signature: [`Builder::remote_contexts`].
pub(super) struct RemoteContexts<D> {
    pub(super) limits: crate::contexts::Limits,
    pub(super) load: LoadContextFn<D>,
}

/// A loader of the context an IRI names.
type LoadContextFn<D> =
    Arc<dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<String, Error>> + Send + Sync>;

impl<D> Inner<D> {
    /// The entry `path` is routed to, with its values: of every template it
    /// matches, the most specific, as `build` made sure there is one.
    fn route(&self, path: &str) -> Option<(usize, Values)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| Some((index, entry.template.matches(path)?)))
            .max_by(|(a, _), (b, _)| {
                self.entries[*a]
                    .template
                    .specificity(&self.entries[*b].template)
            })
    }
}

/// Everything Ojak serves, and the URIs it builds. Cheap to clone.
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
    aliases: Vec<(String, &'static str, String)>,
    listeners: std::collections::HashMap<&'static str, inbox::ListenerFn<D>>,
    fallback_listener: Option<inbox::ListenerFn<D>>,
    blocked: Option<inbox::BlockedFn<D>>,
    on_unverified: Option<inbox::UnverifiedFn<D>>,
    inbox_queue: Option<inbox::QueueFn<D>>,
    gateway: Option<GatewayFn<D>>,
    gateway_media: Option<GatewayMediaFn<D>>,
    gateway_inbox: Option<GatewayInboxFn<D>>,
    forward: Option<inbox::ForwardFn<D>>,
    read_as_written: bool,
    remote_contexts: Option<RemoteContexts<D>>,
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
            aliases: Vec::new(),
            listeners: std::collections::HashMap::new(),
            fallback_listener: None,
            blocked: None,
            on_unverified: None,
            inbox_queue: None,
            gateway: None,
            gateway_media: None,
            gateway_inbox: None,
            forward: None,
            read_as_written: false,
            remote_contexts: None,
            errors: Vec::new(),
        }
    }

    /// The URIs of what is registered, in `origin`, with no request and no
    /// data: for what has to be named before the application's data
    /// exists, such as the ID of the key an actor signs with.
    #[must_use]
    pub fn uris(&self, origin: Url) -> Uris {
        Uris {
            templates: self.inner.templates.clone(),
            origin,
        }
    }

    /// A context outside any request, for building URIs in a background job:
    /// `origin` is the canonical origin they are built in.
    #[must_use]
    pub fn context(&self, origin: Url, data: D) -> Context<D> {
        Context::new(self.inner.clone(), data, origin, None)
    }

    /// The canonical origin for a request to `host`, if Ojak serves it.
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
        if let Some(hashlink) = request
            .uri
            .path()
            .strip_prefix(crate::portable::GATEWAY_PATH)
            .filter(|rest| rest.starts_with("hl:"))
        {
            let context = Context::new(
                self.inner.clone(),
                data,
                origin,
                Some(RequestInfo::of(request, host)),
            );
            return Handled::Response(self.media(context, request, hashlink).await);
        }
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
                Ok(Found::Found(document)) => match servable(&context, &document, &uri).await {
                    Ok(()) => without_body_if(head, portable_found(Found::Found(document), &uri)),
                    Err(refused) => {
                        context.report(&refused.to_string().into());
                        empty(refused.status())
                    }
                },
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

    /// Answer a request for media by its hashlink,
    /// `/.well-known/apgateway/hl:zQm…`.
    async fn media(
        &self,
        context: Context<D>,
        request: &http::request::Parts,
        hashlink: &str,
    ) -> http::Response<Vec<u8>> {
        let head = request.method == Method::HEAD;
        if request.method != Method::GET && !head {
            return method_not_allowed();
        }
        let (Some(load), Some(hashlink)) = (&self.inner.gateway_media, Hashlink::parse(hashlink))
        else {
            return empty(StatusCode::NOT_FOUND);
        };
        match load(context.clone(), hashlink.clone()).await {
            // What the hashlink names, and nothing else: whoever fetches it
            // checks it against the digest, and would refuse anything else.
            Ok(Some(media)) if hashlink.matches(&media.bytes) => {
                let mut response = response(StatusCode::OK, &media.content_type, media.bytes);
                // Whatever is served at a digest is always the same.
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=31536000, immutable"),
                );
                without_body_if(head, response)
            }
            Ok(Some(_)) => {
                context.report(
                    &format!("gateway: media found for {hashlink} is not what it names").into(),
                );
                empty(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Ok(None) => empty(StatusCode::NOT_FOUND),
            Err(error) => {
                context.report(&error);
                empty(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
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

    /// Answer `request`, or say why it is not Ojak's to answer. An inbox's
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
            let found = self.inner.route(path);
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
        // An alias is a path the application serves too, such as a post's
        // page, whose other methods are the application's.
        let alias = matched
            .as_ref()
            .is_some_and(|(index, _)| self.inner.entries[*index].alias);
        if request.method != Method::GET && !head {
            if alias {
                return Handled::NotFound;
            }
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
        // What an alias's dispatcher does not find is the application's to
        // answer at that path, as if the alias did not match.
        if entry.alias && response.status() == StatusCode::NOT_FOUND {
            return Handled::NotFound;
        }
        Handled::Response(without_body_if(head, response))
    }

    async fn dispatch(
        &self,
        context: &Context<D>,
        entry: &Entry<D>,
        values: Values,
        query: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        let url = context.request_url();
        if let Some(authorize) = &entry.authorize {
            match authorize(context.clone(), values.clone()).await? {
                Access::Allow => {}
                Access::Unauthorized => {
                    return Ok(unauthorized(context.signer().await.is_some()));
                }
                Access::Forbidden => return Ok(forbidden()),
                Access::NotFound => return Ok(found(Found::NotFound, &url)),
            }
        }
        match &entry.dispatcher {
            Dispatcher::Actor(load) => {
                let identifier = values.single().unwrap_or_default().to_owned();
                Ok(found(load(context.clone(), identifier).await?, &url))
            }
            Dispatcher::Object(load) => {
                // A Tombstone names the object, and an alias is not its name.
                let url = if entry.alias {
                    let values: Vec<(&str, &str)> = values.iter().collect();
                    context.object_uri(&entry.kind, &values).unwrap_or(url)
                } else {
                    url
                };
                Ok(found(load(context.clone(), values).await?, &url))
            }
            Dispatcher::Collection(collection) => {
                let identifier = values.single().unwrap_or_default().to_owned();
                collection
                    .serve(context, &entry.kind, &identifier, query)
                    .await
            }
        }
    }

    fn serves_gateway(&self) -> bool {
        self.inner.gateway.is_some()
            || self.inner.gateway_media.is_some()
            || self.inner.gateway_inbox.is_some()
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

/// The paths Ojak serves itself, which no template may claim.
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
    /// Ojak should not answer for. A host this maps to the canonical origin
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
                alias: false,
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

    /// Serve the objects of `kind` at `template` as well, and recognise it
    /// in [`Context::parse_uri`] and [`Context::parse_object`]: another path
    /// the same objects are known by, such as Mastodon's `/@{username}/{id}`
    /// beside `/users/{username}/statuses/{id}`. URIs are still built from
    /// the template `kind` was registered with. The dispatcher receives this
    /// template's values, so it has to name every expression the first
    /// template does, and may name more.
    #[must_use]
    pub fn object_alias(mut self, kind: &str, template: &str) -> Self {
        self.aliases
            .push((kind.to_owned(), "object", template.to_owned()));
        self
    }

    /// Serve the collection `kind` at `template` as well, and recognise it in
    /// [`Context::parse_uri`]: another path the same collection is known by,
    /// such as Mastodon's `/@{username}/followers` beside
    /// `/users/{username}/followers`. The collection is still named by the
    /// template `kind` was registered with, in its `id` and its pages'
    /// links. The alias names the owner in as many expressions as that
    /// template does: one, or none.
    #[must_use]
    pub fn collection_alias(mut self, kind: &str, template: &str) -> Self {
        self.aliases
            .push((kind.to_owned(), "collection", template.to_owned()));
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
    pub fn authorize<F, Fut, E>(self, kind: &str, authorize: F) -> Self
    where
        F: Fn(Context<D>, Values, Option<Url>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, E>> + Send + 'static,
        E: Into<Error>,
    {
        let authorize = Arc::new(authorize);
        self.guard(kind, move |context: Context<D>, values| {
            let authorize = authorize.clone();
            async move {
                let signer = context.signer().await;
                Ok::<_, Error>(
                    if authorize(context, values, signer)
                        .await
                        .map_err(Into::into)?
                    {
                        Access::Allow
                    } else {
                        Access::Unauthorized
                    },
                )
            }
        })
    }

    /// Serve what is registered as `kind` only as `guard` says: to all, or
    /// refused as unauthorized (401), forbidden (403) or not there (404).
    /// Unlike [`Builder::authorize`], nothing is verified before it is asked:
    /// the guard asks [`Context::signing`] or [`Context::signer`] when it
    /// needs to know who signed, so a guard that lets everyone through costs
    /// no signature check, nor a key fetched to make one.
    #[must_use]
    pub fn guard<F, Fut, E>(mut self, kind: &str, guard: F) -> Self
    where
        F: Fn(Context<D>, Values) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Access, E>> + Send + 'static,
        E: Into<Error>,
    {
        let guard = boxed(move |(context, values)| guard(context, values));
        self.authorize.push((
            kind.to_owned(),
            Arc::new(move |context, values| guard((context, values))),
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
        Fut: Future<Output = Result<Option<crate::sig::SenderKey>, E>> + Send + 'static,
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

    /// See the document of an actor Ojak fetched for its key, once the key
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
        F: Fn(Context<D>, Received<ojak_vocab::generated::AnyObject>) -> Fut
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
    /// sender Ojak has authenticated. Types with no listener are accepted
    /// and dropped.
    #[must_use]
    pub fn on<T, F, Fut, E>(mut self, listen: F) -> Self
    where
        T: ojak_vocab::json::Typed
            + ojak_vocab::json::FromJson
            + ojak_vocab::json::ToJson
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

    /// Hand listeners each activity as its sender wrote it, without JSON-LD
    /// processing: its `@context` removed and what it embeds reduced to what
    /// the sender can vouch for, as always, but its terms left as spelled.
    ///
    /// By default an activity is expanded and compacted against ojak's
    /// context first, so that a sender's aliases, prefixes and extension terms
    /// read as ojak's vocabulary expects. That is what a listener typed to a
    /// vocabulary type relies on. An application that reads the JSON itself,
    /// as Mastodon reads it, needs none of it, and this skips the work — and
    /// the refusal of a document whose context cannot be processed.
    #[must_use]
    pub fn read_inbox_as_written(mut self) -> Self {
        self.read_as_written = true;
        self
    }

    /// Whether activities from `host` are refused, asked before any key is
    /// fetched for them. A refused activity is answered 202 and dropped.
    ///
    /// A request signed with a key on `host` is refused too, before the key
    /// is looked for: its signer is not verified, an inbox POST is answered
    /// as one that does not verify, and a GET's signing is
    /// [`Signing::Blocked`].
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

    /// Check a Linked Data Signature over contexts ojak does not ship, as
    /// Mastodon does: `load` returns the context an IRI names, the body
    /// [`crate::contexts::fetch`] returns, from the application's cache or
    /// fetched with its client ([`crate::contexts::fetch_cached`] does both).
    /// Without it, an activity naming such a context is not taken on its
    /// signature, and is fetched from its origin instead.
    ///
    /// Only that check loads contexts, and only within `limits`; the
    /// activity is then read over the same contexts, so that what it is
    /// taken to say is what was signed.
    #[must_use]
    pub fn remote_contexts<F, Fut, E>(mut self, limits: crate::contexts::Limits, load: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, E>> + Send + 'static,
        E: Into<Error>,
    {
        let load = boxed(move |(context, iri)| load(context, iri));
        self.remote_contexts = Some(RemoteContexts {
            limits,
            load: Arc::new(move |context, iri| load((context, iri))),
        });
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
    /// proof covers it, and Ojak serves it as it is. An object that is not
    /// public is the application's to refuse, as for any dispatcher.
    ///
    /// What is served is checked first, as whoever fetches it will check it:
    /// a document whose `id` is another object is answered 404, and one
    /// whose proof does not verify, 500, both reported to `on_error`. A
    /// collection may have no proof. A signed Tombstone is served with 410;
    /// `Found::Gone` serves an unsigned one, which says the object is gone
    /// but that nobody can take for its owner's word.
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

    /// Serve the media portable objects refer to by hashlink (FEP-ef61), at
    /// `/.well-known/apgateway/hl:zQm…`. `load` returns what the hashlink
    /// names; it is served only if it is that, since it is checked against
    /// the digest wherever it is fetched, and a mismatch is reported to
    /// `on_error` and answered 500. Anyone who knows a digest can fetch what
    /// it names: media with an audience is the application's to refuse.
    #[must_use]
    pub fn gateway_media<F, Fut, E>(mut self, load: F) -> Self
    where
        F: Fn(Context<D>, Hashlink) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<Media>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let load = boxed(move |(context, hashlink)| load(context, hashlink));
        self.gateway_media = Some(Arc::new(move |context, hashlink| load((context, hashlink))));
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

    /// Forward what arrives to where it has to go on to: a portable actor's
    /// other gateways, as FEP-ef61 asks, and the members of collections of
    /// ours an activity concerning something of ours is addressed to, as
    /// ActivityPub asks (§7.1.2). `forward` is called once for each activity
    /// and kind of forward, however many times it arrives, and sends it.
    /// Without it, nothing is forwarded.
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
    /// match one path, a template claims a path Ojak serves itself, two
    /// dispatchers share a kind, an actor or collection template has more
    /// than one expression, or `authorize` names no kind.
    pub fn build(mut self) -> Result<Federation<D>, BuildError> {
        let mut errors = std::mem::take(&mut self.errors);
        let origin = self.origin.take();
        if origin.is_none() {
            errors.push("no origin: call origin or origin_with".into());
        }
        for (kind, noun, template) in std::mem::take(&mut self.aliases) {
            let template = match Template::parse(&template) {
                Ok(template) => template,
                Err(error) => {
                    errors.push(error.to_string());
                    continue;
                }
            };
            let Some(primary) = self
                .entries
                .iter()
                .find(|entry| entry.kind == kind && entry.noun() == noun && !entry.alias)
            else {
                errors.push(format!(
                    "{noun}_alias for {kind:?}, which is no {noun} kind"
                ));
                continue;
            };
            let problem = match &primary.dispatcher {
                // An object's dispatcher reads its values by name.
                Dispatcher::Object(_) => primary
                    .template
                    .names()
                    .find(|name| !template.names().any(|alias| alias == *name))
                    .map(|missing| {
                        format!(
                            "object_alias {} does not name {missing}, which {} does",
                            template.as_str(),
                            primary.template.as_str()
                        )
                    }),
                // A collection's reads its one expression, whatever its name.
                _ => (template.names().count() != primary.template.names().count()).then(|| {
                    format!(
                        "collection_alias {} has to name its owner as {} does",
                        template.as_str(),
                        primary.template.as_str()
                    )
                }),
            };
            if let Some(problem) = problem {
                errors.push(problem);
                continue;
            }
            let dispatcher = match &primary.dispatcher {
                Dispatcher::Object(load) => Dispatcher::Object(load.clone()),
                Dispatcher::Collection(collection) => Dispatcher::Collection(collection.clone()),
                Dispatcher::Actor(load) => Dispatcher::Actor(load.clone()),
            };
            self.entries.push(Entry {
                kind,
                template,
                dispatcher,
                authorize: None,
                alias: true,
            });
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
                        "{} claims {reserved}, which Ojak serves",
                        entry.template.as_str()
                    ));
                }
            }
            for other in &self.entries[index + 1..] {
                if entry.kind == other.kind && !entry.alias && !other.alias {
                    errors.push(format!("two dispatchers of kind {:?}", entry.kind));
                }
                // A path both match goes to the more specific; two that
                // nothing tells apart are ambiguous.
                if entry.template.overlaps(&other.template)
                    && entry.template.specificity(&other.template).is_eq()
                {
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
                        "{} claims {reserved}, which Ojak serves",
                        template.as_str()
                    ));
                }
            }
        }
        if !inbox_templates.is_empty() && self.signed_fetch.is_none() {
            errors.push("an inbox needs signed_fetch, to fetch and cache senders' keys".into());
        }
        for (kind, authorize) in std::mem::take(&mut self.authorize) {
            let mut found = false;
            for entry in self.entries.iter_mut().filter(|entry| entry.kind == kind) {
                entry.authorize = Some(authorize.clone());
                found = true;
            }
            if !found {
                errors.push(format!("authorize names no dispatcher of kind {kind:?}"));
            }
        }
        let templates = Arc::new(Templates {
            routes: self
                .entries
                .iter()
                .filter(|entry| !entry.alias)
                .map(|entry| (entry.kind.clone(), entry.noun(), entry.template.clone()))
                .collect(),
            inboxes: inboxes.clone(),
            shared_inbox: shared_inbox.clone(),
        });
        match origin {
            Some(origin) if errors.is_empty() => Ok(Federation {
                inner: Arc::new(Inner {
                    origin,
                    entries: self.entries,
                    templates,
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
                    gateway_media: self.gateway_media,
                    gateway_inbox: self.gateway_inbox,
                    forward: self.forward,
                    read_as_written: self.read_as_written,
                    remote_contexts: self.remote_contexts,
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
    signer: tokio::sync::OnceCell<Signing>,
}

/// The templates URIs are built from, apart from what serves them.
#[derive(Debug)]
struct Templates {
    /// Each kind's template, by kind and noun; aliases are not built.
    routes: Vec<(String, &'static str, Template)>,
    inboxes: Vec<(String, Template)>,
    shared_inbox: Option<Template>,
}

/// The fragment of an actor's IRI its key is named by, as Mastodon names
/// it.
const KEY_FRAGMENT: &str = "main-key";

/// The URIs of what a federation serves, in one origin, built from the
/// templates their routes were registered with.
///
/// [`Federation::uris`] gives them where there is no request, and
/// [`Context::uris`] within one. They carry none of the application's data
/// and are cheap to clone, so an application can keep them in its own
/// state, for code that runs outside any request: creating an account,
/// sending a post from a background job. An application serving several
/// hosts keeps one and takes each tenant's with [`Uris::with_origin`].
#[derive(Clone, Debug)]
pub struct Uris {
    templates: Arc<Templates>,
    origin: Url,
}

impl Uris {
    /// The origin these URIs are in.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.origin
    }

    /// The same URIs, in `origin`.
    #[must_use]
    pub fn with_origin(&self, origin: Url) -> Self {
        Self {
            templates: self.templates.clone(),
            origin,
        }
    }

    fn template(&self, kind: &str, noun: &str) -> Result<&Template, UriError> {
        self.templates
            .routes
            .iter()
            .find_map(|(k, n, template)| (k == kind && *n == noun).then_some(template))
            .ok_or_else(|| UriError::UnknownKind(kind.to_owned()))
    }

    fn uri(&self, template: &Template, values: &Values) -> Result<Url, UriError> {
        let path = template.expand(values).map_err(UriError::Template)?;
        let mut url = self.origin.clone();
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
        let template = self.template(kind, "actor")?;
        self.uri(template, &Self::single(template, identifier))
    }

    /// The ID of the key the actor of `kind` with `identifier` signs with:
    /// its IRI with the fragment `main-key`, as Mastodon names it, and as
    /// the actor document should publish it.
    ///
    /// # Errors
    ///
    /// As [`Uris::actor_uri`].
    pub fn key_id(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        let mut uri = self.actor_uri(kind, identifier)?;
        uri.set_fragment(Some(KEY_FRAGMENT));
        Ok(uri)
    }

    /// The URI of the object of `kind` with `values`.
    ///
    /// # Errors
    ///
    /// When no object dispatcher is of `kind`, or `values` do not fill its
    /// template.
    pub fn object_uri(&self, kind: &str, values: &[(&str, &str)]) -> Result<Url, UriError> {
        let template = self.template(kind, "object")?;
        self.uri(template, &values.iter().copied().collect())
    }

    /// The URI of the collection `kind` of what `identifier` names.
    ///
    /// # Errors
    ///
    /// As [`Uris::actor_uri`], for collections.
    pub fn collection_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        let template = self.template(kind, "collection")?;
        self.uri(template, &Self::single(template, identifier))
    }

    /// The URI of the inbox of the actor of `kind` with `identifier`.
    ///
    /// # Errors
    ///
    /// When no inbox is registered for `kind`, or `identifier` does not fill
    /// its template.
    pub fn inbox_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        let template = self
            .templates
            .inboxes
            .iter()
            .find_map(|(inbox, template)| (inbox == kind).then_some(template))
            .ok_or_else(|| UriError::UnknownKind(kind.to_owned()))?;
        self.uri(template, &Self::single(template, identifier))
    }

    /// The URI of the shared inbox.
    ///
    /// # Errors
    ///
    /// When no shared inbox is registered.
    pub fn shared_inbox_uri(&self) -> Result<Url, UriError> {
        let template = self
            .templates
            .shared_inbox
            .as_ref()
            .ok_or_else(|| UriError::UnknownKind("shared inbox".to_owned()))?;
        self.uri(template, &Values::new())
    }
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

    /// The URIs of what is registered, in the canonical origin.
    #[must_use]
    pub fn uris(&self) -> Uris {
        Uris {
            templates: self.inner.federation.templates.clone(),
            origin: self.inner.origin.clone(),
        }
    }

    /// The URI of the actor of `kind` with `identifier`.
    ///
    /// # Errors
    ///
    /// When no actor dispatcher is of `kind`, or `identifier` is empty for a
    /// template that needs one.
    pub fn actor_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        self.uris().actor_uri(kind, identifier)
    }

    /// The ID of the key the actor of `kind` with `identifier` signs with;
    /// see [`Uris::key_id`].
    ///
    /// # Errors
    ///
    /// As [`Context::actor_uri`].
    pub fn key_id(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        self.uris().key_id(kind, identifier)
    }

    /// The URI of the object of `kind` with `values`.
    ///
    /// # Errors
    ///
    /// When no object dispatcher is of `kind`, or `values` do not fill its
    /// template.
    pub fn object_uri(&self, kind: &str, values: &[(&str, &str)]) -> Result<Url, UriError> {
        self.uris().object_uri(kind, values)
    }

    /// The URI of the collection `kind` of what `identifier` names.
    ///
    /// # Errors
    ///
    /// As [`Context::actor_uri`], for collections.
    pub fn collection_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        self.uris().collection_uri(kind, identifier)
    }

    /// The URI of the inbox of the actor of `kind` with `identifier`.
    ///
    /// # Errors
    ///
    /// As [`Context::actor_uri`], for inboxes.
    pub fn inbox_uri(&self, kind: &str, identifier: &str) -> Result<Url, UriError> {
        self.uris().inbox_uri(kind, identifier)
    }

    /// The URI of the shared inbox.
    ///
    /// # Errors
    ///
    /// When no shared inbox is registered.
    pub fn shared_inbox_uri(&self) -> Result<Url, UriError> {
        self.uris().shared_inbox_uri()
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
        let (index, values) = self.inner.federation.route(url.path())?;
        let entry = &self.inner.federation.entries[index];
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
    }

    /// The identifier of the actor of `kind` that `iri` is, if it is one of
    /// ours: what a listener checks a `Follow`'s object against.
    #[must_use]
    pub fn parse_actor(&self, kind: &str, iri: &str) -> Option<String> {
        match self.parse_uri(iri)? {
            Route::Actor(actor) if actor.kind == kind => Some(actor.identifier),
            _ => None,
        }
    }

    /// The values of the object of `kind` that `iri` is, if it is one of
    /// ours: what a listener checks an `inReplyTo` or a `Like`'s object
    /// against.
    #[must_use]
    pub fn parse_object(&self, kind: &str, iri: &str) -> Option<Values> {
        match self.parse_uri(iri)? {
            Route::Object {
                kind: found,
                values,
            } if found == kind => Some(values),
            _ => None,
        }
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
        match self.signing().await {
            Signing::Verified(signer) => Some(signer),
            _ => None,
        }
    }

    /// How the request was signed: not at all, by an actor whose signature
    /// verifies, with a key on a server [`Builder::blocked`] refuses, or with
    /// a signature that does not hold. Verified once per request, however
    /// often it is asked, and as [`Context::signer`] verifies it.
    pub async fn signing(&self) -> Signing {
        self.inner
            .signer
            .get_or_init(|| signer::verify(self))
            .await
            .clone()
    }

    /// Load the actor `actor` through its dispatcher.
    async fn load_actor(&self, actor: &ActorRef) -> Result<Found<Value>, Error> {
        let Some(entry) = self
            .inner
            .federation
            .entries
            .iter()
            .find(|entry| entry.kind == actor.kind && entry.noun() == "actor")
        else {
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

fn forbidden() -> http::Response<Vec<u8>> {
    let mut response = empty(StatusCode::FORBIDDEN);
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
    path.starts_with(crate::portable::GATEWAY_PATH)
}

/// The media type a gateway serves portable objects as (FEP-ef61).
pub const PORTABLE_JSON: &str =
    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

/// Why a gateway does not serve what the application found.
#[derive(Debug)]
enum Unservable {
    /// It is another object than the one asked for: answered as one the
    /// gateway does not have.
    Another { id: Option<String>, uri: String },
    /// It is not authentic, and anyone it was served to would refuse it.
    Unproven {
        uri: String,
        why: crate::portable::PortableError,
    },
}

impl Unservable {
    fn status(&self) -> StatusCode {
        match self {
            Self::Another { .. } => StatusCode::NOT_FOUND,
            Self::Unproven { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for Unservable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Another { id: Some(id), uri } => {
                write!(f, "gateway: found {id} for {uri}, not serving it")
            }
            Self::Another { id: None, uri } => {
                write!(
                    f,
                    "gateway: found a document with no id for {uri}, not serving it"
                )
            }
            Self::Unproven { uri, why } => write!(f, "gateway: not serving {uri}: {why}"),
        }
    }
}

/// Whether `document` may be served as `uri`: it is that object, and it is
/// authentic, as whoever it is served to will check. A collection needs no
/// proof, as FEP-ef61 has it, since its consumers take it only from its
/// owner's gateways; one with a proof is held to it.
async fn servable<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    document: &Value,
    uri: &ApUri,
) -> Result<(), Unservable> {
    let id = document.get("id").and_then(Value::as_str);
    if id.and_then(ApUri::parse).as_ref() != Some(uri) {
        return Err(Unservable::Another {
            id: id.map(str::to_owned),
            uri: uri.canonical(),
        });
    }
    if document.get("proof").is_none() && is_collection(document) {
        return Ok(());
    }
    let fetcher = context
        .inner
        .federation
        .signed_fetch
        .as_ref()
        .map(|settings| settings.fetcher(context.data()));
    let resolver = fetcher.as_deref().and_then(crate::fetch::Fetcher::resolver);
    crate::portable::verify(document, resolver)
        .await
        .map(drop)
        .map_err(|why| Unservable::Unproven {
            uri: uri.canonical(),
            why,
        })
}

fn is_collection(document: &Value) -> bool {
    const COLLECTIONS: [&str; 4] = [
        "Collection",
        "OrderedCollection",
        "CollectionPage",
        "OrderedCollectionPage",
    ];
    crate::portable::has_type(document, &COLLECTIONS)
}

/// A portable object as a gateway serves it: the document as the
/// application stored it, since its proof covers it. A signed Tombstone is
/// served as what is gone.
fn portable_found(found: Found<Value>, uri: &ApUri) -> http::Response<Vec<u8>> {
    match found {
        Found::Found(document) => {
            let status = if crate::portable::has_type(&document, &["Tombstone"]) {
                StatusCode::GONE
            } else {
                StatusCode::OK
            };
            let body = serde_json::to_vec(&document).unwrap_or_default();
            response(status, PORTABLE_JSON, body)
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
