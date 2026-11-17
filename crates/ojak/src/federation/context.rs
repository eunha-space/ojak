//! [`Context`]: what every callback receives.

#[allow(clippy::wildcard_imports)]
use super::*;

impl<D: Clone + Send + Sync + 'static> Context<D> {
    pub(super) fn new(
        federation: Arc<Inner<D>>,
        data: D,
        origin: Url,
        request: Option<RequestInfo>,
    ) -> Self {
        Self {
            inner: Arc::new(ContextInner {
                federation,
                data,
                origin,
                request,
                signer: tokio::sync::OnceCell::new(),
                response_headers: std::sync::Mutex::new(Vec::new()),
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
    pub(super) async fn load_actor(&self, actor: &ActorRef) -> Result<Found<Value>, Error> {
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

    /// The query of the request, if there is a request and it has one: for a
    /// dispatcher that reads parameters of its own, such as how a collection
    /// it writes itself is paged.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        let request = self.inner.request.as_ref()?;
        request
            .path_and_query
            .split_once('?')
            .map(|(_, query)| query)
    }

    /// The value of the query parameter `name`, decoded, if the request has
    /// it: the first, when it has it more than once.
    #[must_use]
    pub fn query_value(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(self.query()?.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }

    /// The value of the request's header `name`, if it has one and it is
    /// text.
    #[must_use]
    pub fn request_header(&self, name: &str) -> Option<String> {
        let request = self.inner.request.as_ref()?;
        request
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }

    /// Send `value` as the response's header `name`, or no such header
    /// when it is `None`, in place of what Ojak would send: for a
    /// dispatcher or guard saying how the response may be cached, such as
    /// its `Cache-Control` and the request headers it `Vary`s on. It
    /// applies to whatever the request is answered with, a refusal or a 404
    /// included. A name or value that is no header is ignored.
    pub fn set_response_header(&self, name: &str, value: Option<&str>) {
        let Ok(name) = HeaderName::try_from(name) else {
            return;
        };
        let value = match value.map(HeaderValue::try_from) {
            Some(Ok(value)) => Some(value),
            Some(Err(_)) => return,
            None => None,
        };
        if let Ok(mut headers) = self.inner.response_headers.lock() {
            headers.push((name, value));
        }
    }

    /// `response` with the headers the application set.
    pub(super) fn with_response_headers(
        &self,
        mut response: http::Response<Vec<u8>>,
    ) -> http::Response<Vec<u8>> {
        if let Ok(headers) = self.inner.response_headers.lock() {
            for (name, value) in headers.iter() {
                match value {
                    Some(value) => {
                        response.headers_mut().insert(name.clone(), value.clone());
                    }
                    None => {
                        response.headers_mut().remove(name);
                    }
                }
            }
        }
        response
    }

    /// The URL the request was for, in the canonical origin.
    pub(super) fn request_url(&self) -> Url {
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

    pub(super) fn report(&self, error: &Error) {
        if let Some(report) = &self.inner.federation.on_error {
            report(error);
        }
    }
}
