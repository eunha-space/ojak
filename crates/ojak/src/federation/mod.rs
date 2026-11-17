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

mod builder;
mod collection;
mod context;
mod inbox;
mod negotiate;
mod nodeinfo;
mod serve;
mod signer;
mod uris;
mod webfinger;

pub use crate::template::Values;
pub use collection::{Collection, CollectionDocument, First, Page};
pub use inbox::{
    CollectionRef, Forward, ForwardTo, GatewayInbox, InboxDisposition, InboxReport, InboxWorker,
    InboxWorkerConfig, MAX_BODY as MAX_INBOX_BODY, Received, VouchedBy,
};
pub use nodeinfo::{NodeInfo, Software, Usage};
pub use signer::{KnownKey, Signing};

use crate::fetch::Fetcher;
use crate::kv::{KvError, KvStore};
use crate::portable::{ApUri, Hashlink, Media};
use crate::template::{Template, TemplateError};
use chrono::{DateTime, SecondsFormat, Utc};
use http::{HeaderName, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// What a callback's error is turned into: anything that is a
/// `std::error::Error`, an `anyhow::Error`, or has a `From` impl of its own.
pub use crate::Error;

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
    /// It is served elsewhere: answered with a `302 Found` to this URL, as
    /// Mastodon sends whoever asks for a boost to the post it boosted.
    Redirect(Url),
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
type HandleHostFn<D> = Arc<dyn Fn(&Context<D>) -> Option<String> + Send + Sync>;
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
    handle_host: Option<HandleHostFn<D>>,
    nodeinfo: Option<NodeInfoFn<D>>,
    signed_fetch: Option<signer::SignedFetch<D>>,
    on_error: Option<ErrorFn>,
    inboxes: Vec<(String, Template)>,
    shared_inbox: Option<Template>,
    listeners: std::collections::HashMap<&'static str, inbox::ListenerFn<D>>,
    fallback_listener: Option<inbox::ListenerFn<D>>,
    blocked: Option<inbox::BlockedFn<D>>,
    on_unverified: Option<inbox::UnverifiedFn<D>>,
    inbox_observer: Option<inbox::ObserveFn<D>>,
    inbox_recipient: Option<inbox::RecipientFn<D>>,
    inbox_queue: Option<inbox::QueueFn<D>>,
    gateway: Option<GatewayFn<D>>,
    gateway_media: Option<GatewayMediaFn<D>>,
    gateway_inbox: Option<GatewayInboxFn<D>>,
    forward: Option<inbox::ForwardFn<D>>,
    read_as_written: bool,
    linked_data_first: bool,
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
    handle_host: Option<HandleHostFn<D>>,
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
    inbox_observer: Option<inbox::ObserveFn<D>>,
    inbox_recipient: Option<inbox::RecipientFn<D>>,
    inbox_queue: Option<inbox::QueueFn<D>>,
    gateway: Option<GatewayFn<D>>,
    gateway_media: Option<GatewayMediaFn<D>>,
    gateway_inbox: Option<GatewayInboxFn<D>>,
    forward: Option<inbox::ForwardFn<D>>,
    read_as_written: bool,
    linked_data_first: bool,
    remote_contexts: Option<RemoteContexts<D>>,
    errors: Vec<String>,
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
    /// Headers the application set on the response, in the order set: a
    /// value, or `None` to send none.
    response_headers: std::sync::Mutex<Vec<(HeaderName, Option<HeaderValue>)>>,
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
        Found::Redirect(location) => redirect(&location),
    }
}

/// A `302 Found` to `location`.
fn redirect(location: &Url) -> http::Response<Vec<u8>> {
    let mut response = empty(StatusCode::FOUND);
    if let Ok(value) = HeaderValue::from_str(location.as_str()) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
    response
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
        Found::Redirect(location) => redirect(&location),
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
