//! Answering requests: what [`Federation::handle`] serves.

#[allow(clippy::wildcard_imports)]
use super::*;

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
            handle_host: None,
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
            inbox_observer: None,
            inbox_recipient: None,
            inbox_queue: None,
            gateway: None,
            gateway_media: None,
            gateway_inbox: None,
            forward: None,
            read_as_written: false,
            linked_data_first: false,
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
    pub(super) fn origin_for(&self, host: &str, data: &D) -> Option<Url> {
        match &self.inner.origin {
            OriginRule::Fixed(origin) => Some(origin.clone()),
            OriginRule::PerHost(origin) => origin(host, data),
        }
    }

    /// The inbox `path` is, if it is one: `Some(Some(actor))` for an actor's,
    /// `Some(None)` for the shared inbox.
    pub(super) fn inbox_at(&self, path: &str) -> Option<Option<ActorRef>> {
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
    pub(super) async fn gateway(
        &self,
        request: &http::request::Parts,
        body: &[u8],
        data: D,
    ) -> Handled {
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
    pub(super) async fn media(
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
        let response = context.with_response_headers(response);
        Handled::Response(without_body_if(head, response))
    }

    pub(super) async fn dispatch(
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

    pub(super) fn serves_gateway(&self) -> bool {
        self.inner.gateway.is_some()
            || self.inner.gateway_media.is_some()
            || self.inner.gateway_inbox.is_some()
    }

    pub(super) fn special(&self, path: &str) -> Option<Special> {
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
