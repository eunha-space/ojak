//! [`Uris`]: building the URIs of what a federation serves.

#[allow(clippy::wildcard_imports)]
use super::*;

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

    pub(super) fn template(&self, kind: &'static str, noun: &str) -> &Template {
        self.templates
            .routes
            .iter()
            .find_map(|(k, n, template)| (*k == kind && *n == noun).then_some(template))
            .unwrap_or_else(|| panic!("no {noun} of kind {kind:?} is registered"))
    }

    pub(super) fn uri(&self, template: &Template, values: &Values) -> Url {
        let path = template
            .expand(values)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut url = self.origin.clone();
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    pub(super) fn single(template: &Template, identifier: &str) -> Values {
        template
            .names()
            .map(|name| (name.to_owned(), identifier.to_owned()))
            .collect()
    }

    /// The URI of the actor of `kind` with `identifier`.
    ///
    /// # Panics
    ///
    /// When no actor of `kind` is registered, or `identifier` is empty and
    /// its template needs one: both mistakes in the application, which a
    /// test of the code that builds the URI finds.
    #[must_use]
    pub fn actor_uri(&self, kind: ActorKind, identifier: &str) -> Url {
        let template = self.template(kind.name(), ActorKind::NOUN);
        self.uri(template, &Self::single(template, identifier))
    }

    /// The ID of the key the actor of `kind` with `identifier` signs with:
    /// its IRI with the fragment `main-key`, as Mastodon names it, and as
    /// the actor document should publish it.
    ///
    /// # Panics
    ///
    /// As [`Uris::actor_uri`].
    #[must_use]
    pub fn key_id(&self, kind: ActorKind, identifier: &str) -> Url {
        let mut uri = self.actor_uri(kind, identifier);
        uri.set_fragment(Some(KEY_FRAGMENT));
        uri
    }

    /// The URI of the object of `kind` with `values`.
    ///
    /// # Panics
    ///
    /// When no object of `kind` is registered, or `values` leave one of its
    /// template's expressions empty.
    #[must_use]
    pub fn object_uri(&self, kind: ObjectKind, values: &[(&str, &str)]) -> Url {
        let template = self.template(kind.name(), ObjectKind::NOUN);
        self.uri(template, &values.iter().copied().collect())
    }

    /// The URI of the collection `kind` of what `identifier` names.
    ///
    /// # Panics
    ///
    /// As [`Uris::actor_uri`], for collections.
    #[must_use]
    pub fn collection_uri(&self, kind: CollectionKind, identifier: &str) -> Url {
        let template = self.template(kind.name(), CollectionKind::NOUN);
        self.uri(template, &Self::single(template, identifier))
    }

    /// The URI of the inbox of the actor of `kind` with `identifier`.
    ///
    /// # Panics
    ///
    /// When no inbox is registered for `kind`, or as [`Uris::actor_uri`].
    #[must_use]
    pub fn inbox_uri(&self, kind: ActorKind, identifier: &str) -> Url {
        let template = self
            .templates
            .inboxes
            .iter()
            .find_map(|(inbox, template)| (*inbox == kind).then_some(template))
            .unwrap_or_else(|| panic!("no inbox for {kind:?} is registered"));
        self.uri(template, &Self::single(template, identifier))
    }

    /// The URI of the shared inbox.
    ///
    /// # Panics
    ///
    /// When no shared inbox is registered.
    #[must_use]
    pub fn shared_inbox_uri(&self) -> Url {
        let template = self
            .templates
            .shared_inbox
            .as_ref()
            .expect("no shared inbox is registered");
        self.uri(template, &Values::new())
    }
}
