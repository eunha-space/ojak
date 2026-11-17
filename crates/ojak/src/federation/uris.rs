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

    pub(super) fn template(&self, kind: &str, noun: &str) -> Result<&Template, UriError> {
        self.templates
            .routes
            .iter()
            .find_map(|(k, n, template)| (k == kind && *n == noun).then_some(template))
            .ok_or_else(|| UriError::UnknownKind(kind.to_owned()))
    }

    pub(super) fn uri(&self, template: &Template, values: &Values) -> Result<Url, UriError> {
        let path = template.expand(values).map_err(UriError::Template)?;
        let mut url = self.origin.clone();
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    pub(super) fn single(template: &Template, identifier: &str) -> Values {
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
