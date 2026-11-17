//! [`Builder`]: registering what a federation serves and receives.

#[allow(clippy::wildcard_imports)]
use super::*;

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

    pub(super) fn add(&mut self, kind: &str, template: &str, dispatcher: Dispatcher<D>) {
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

    /// The host handles are in, when it is not the canonical origin's: the
    /// host in the `acct:` URI a WebFinger answer gives as its `subject`.
    /// Mastodon's `LOCAL_DOMAIN`, where the origin is its `WEB_DOMAIN`, so
    /// that `alice@example.com` is served from `social.example.com`. `None`
    /// keeps the canonical origin's host.
    ///
    /// Ojak answers `acct:` URIs only on hosts the origin function maps to
    /// the canonical origin, so the handle host must be one of them.
    #[must_use]
    pub fn handle_host(
        mut self,
        host: impl Fn(&Context<D>) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.handle_host = Some(Arc::new(host));
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
            kv_for: None,
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

    /// The key-value store for a request's data, in place of the one given
    /// to [`Builder::signed_fetch`]: an application serving several
    /// instances keeps each one's cached keys and the activities it has seen
    /// in that instance's own store, such as its own namespace of a shared
    /// Redis. Call after `signed_fetch`.
    #[must_use]
    pub fn kv_for<K: KvStore>(mut self, kv: impl Fn(&D) -> Arc<K> + Send + Sync + 'static) -> Self {
        match &mut self.signed_fetch {
            Some(settings) => {
                settings.kv_for = Some(Arc::new(move |data: &D| -> Arc<dyn DynKv> { kv(data) }));
            }
            None => self.errors.push("kv_for before signed_fetch".into()),
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
    /// whose one expression is the actor's identifier; or, for an actor
    /// whose own template has no expression, such as an instance actor at
    /// `/actor`, with none.
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

    /// Check a forwarded activity's Linked Data signature before its
    /// FEP-8b32 proof, rather than after.
    ///
    /// An activity signed by a server other than its actor's is taken on its
    /// actor's proof by default, and on its Linked Data signature only when it
    /// has no proof that holds: a proof is the cheaper check, needing no
    /// JSON-LD processing. Mastodon and Fedify check the signature first, and
    /// what an activity is taken on decides whether it can be passed on
    /// (`Received::vouched_by`): Mastodon passes on only an activity taken on
    /// its Linked Data signature. An application that forwards as Mastodon
    /// does asks for this, so that an activity carrying both is taken on its
    /// signature. A request signed by the actor's own server, and one whose
    /// signature does not verify, are unaffected.
    #[must_use]
    pub fn linked_data_before_proof(mut self) -> Self {
        self.linked_data_first = true;
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

    /// Check whether a personal inbox has a local recipient. By default,
    /// Ojak checks the actor dispatcher. Supply a lightweight lookup when
    /// rendering an actor is expensive or has side effects.
    #[must_use]
    pub fn inbox_recipient<F, Fut, E>(mut self, lookup: F) -> Self
    where
        F: Fn(Context<D>, ActorRef) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, E>> + Send + 'static,
        E: Into<Error>,
    {
        self.inbox_recipient = Some(Arc::new(move |context, actor| {
            let lookup = lookup(context, actor);
            Box::pin(async move { lookup.await.map_err(Into::into) })
        }));
        self
    }

    /// Observe the recipient and HTTP result of each processed inbox request.
    #[must_use]
    pub fn observe_inbox(
        mut self,
        observer: impl Fn(&D, InboxReport) + Send + Sync + 'static,
    ) -> Self {
        self.inbox_observer = Some(Arc::new(observer));
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
                    // One expression, or none for an actor whose template
                    // has none, such as an instance actor at `/actor` with
                    // its inbox at `/actor/inbox`.
                    match self.entries.iter().find(|entry| {
                        entry.kind == kind && matches!(entry.dispatcher, Dispatcher::Actor(_))
                    }) {
                        Some(actor) => {
                            let expected = actor.template.names().count().min(1);
                            if template.names().count() != expected {
                                errors.push(format!(
                                    "inbox {}: has to name its actor in as many expressions \
                                     as its actor's template does",
                                    template.as_str()
                                ));
                            }
                        }
                        None => {
                            errors.push(format!("inbox for {kind:?}, which is no actor kind"));
                        }
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
                    handle_host: self.handle_host,
                    nodeinfo: self.nodeinfo,
                    signed_fetch: self.signed_fetch,
                    on_error: self.on_error,
                    inboxes,
                    shared_inbox,
                    listeners: self.listeners,
                    fallback_listener: self.fallback_listener,
                    blocked: self.blocked,
                    on_unverified: self.on_unverified,
                    inbox_observer: self.inbox_observer,
                    inbox_recipient: self.inbox_recipient,
                    inbox_queue: self.inbox_queue,
                    gateway: self.gateway,
                    gateway_media: self.gateway_media,
                    gateway_inbox: self.gateway_inbox,
                    forward: self.forward,
                    read_as_written: self.read_as_written,
                    linked_data_first: self.linked_data_first,
                    remote_contexts: self.remote_contexts,
                }),
            }),
            _ => Err(BuildError(errors)),
        }
    }
}
