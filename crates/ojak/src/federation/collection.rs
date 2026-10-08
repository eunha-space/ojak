//! Collections, paged by cursor.
//!
//! The application writes one page function, and optionally a counter and
//! the cursors of the first and last pages; Ojak writes the
//! `OrderedCollection` at the template's URI and the `OrderedCollectionPage`s
//! at the same URI with `?cursor=`, or the `Collection` and its
//! `CollectionPage`s when it is [unordered](Collection::unordered).
//!
//! A collection whose URIs Ojak does not write, such as one paged by a query
//! of the application's own, is a document the application builds, as a
//! [`CollectionDocument`], and serves as an object.

use super::{BoxFuture, Context, Error, activity, boxed, empty};
use http::StatusCode;
use serde_json::Value;
use std::future::Future;
use std::sync::Arc;
use url::Url;

/// One page of a collection.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Page {
    /// Its items, in order: IRIs as strings, or embedded objects.
    pub items: Vec<Value>,
    /// The cursor of the page after this one, if there is one.
    pub next: Option<String>,
    /// The cursor of the page before this one, if there is one.
    pub prev: Option<String>,
}

/// Where a paged collection starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum First {
    /// At the page with this cursor.
    At(String),
    /// Nowhere a requester may see: the collection's members are hidden, and
    /// only its count, if it has a counter, is shown.
    Hidden,
}

type PageFn<D> = Arc<
    dyn Fn(Context<D>, String, Option<String>) -> BoxFuture<'static, Result<Option<Page>, Error>>
        + Send
        + Sync,
>;
type CountFn<D> =
    Arc<dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<Option<u64>, Error>> + Send + Sync>;
type FirstFn<D> = Arc<
    dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<Option<First>, Error>> + Send + Sync,
>;
type UriFn<D> =
    Arc<dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<Option<Url>, Error>> + Send + Sync>;
type ContextFn = Arc<dyn Fn(&[Value]) -> Value + Send + Sync>;
type ToQueryFn = Arc<dyn Fn(&str) -> String + Send + Sync>;
type FromQueryFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
type LastFn<D> = Arc<
    dyn Fn(Context<D>, String) -> BoxFuture<'static, Result<Option<String>, Error>> + Send + Sync,
>;

/// A collection's dispatchers.
pub struct Collection<D> {
    page: PageFn<D>,
    count: Option<CountFn<D>>,
    first: Option<FirstFn<D>>,
    last: Option<LastFn<D>>,
    uri: Option<UriFn<D>>,
    ordered: bool,
    context: Option<ContextFn>,
    query: Option<(ToQueryFn, FromQueryFn)>,
    count_pages: bool,
}

impl<D> Clone for Collection<D> {
    fn clone(&self) -> Self {
        Self {
            page: self.page.clone(),
            count: self.count.clone(),
            first: self.first.clone(),
            last: self.last.clone(),
            uri: self.uri.clone(),
            ordered: self.ordered,
            context: self.context.clone(),
            query: self.query.clone(),
            count_pages: self.count_pages,
        }
    }
}

impl<D: Clone + Send + Sync + 'static> Collection<D> {
    /// A collection read through `page`, which receives the identifier of
    /// what the collection belongs to and a cursor, and returns that page, or
    /// `None` when there is no such collection.
    ///
    /// Without [`Collection::first_cursor`], the collection is one document:
    /// `page` is called once, with no cursor, and every item is in it.
    pub fn new<F, Fut, E>(page: F) -> Self
    where
        F: Fn(Context<D>, String, Option<String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<Page>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let page = boxed(move |(context, identifier, cursor)| page(context, identifier, cursor));
        Self {
            page: Arc::new(move |context, identifier, cursor| page((context, identifier, cursor))),
            count: None,
            first: None,
            last: None,
            uri: None,
            ordered: true,
            context: None,
            query: None,
            count_pages: false,
        }
    }

    /// Serve it as a `Collection`, whose pages are `CollectionPage`s and
    /// whose members are `items`, rather than ordered: for a collection
    /// whose order means nothing, such as an account's featured hashtags or
    /// who liked a post.
    #[must_use]
    pub fn unordered(mut self) -> Self {
        self.ordered = false;
        self
    }

    /// The `@context` of the collection and its pages, from the members a
    /// document has (none, for a collection that only links its pages):
    /// for an application whose context says what its members use, as
    /// Mastodon's names `Hashtag` only for a collection of hashtags that
    /// has any. Without it, a document gets [`default_context`].
    ///
    /// [`default_context`]: super::default_context
    #[must_use]
    pub fn context(mut self, context: impl Fn(&[Value]) -> Value + Send + Sync + 'static) -> Self {
        self.context = Some(Arc::new(context));
        self
    }

    /// Write a page's cursor into its URI's query, and read it back, with
    /// `to_query` and `from_query`, rather than as `?cursor=`: for a
    /// collection whose pages peers already know by a query of their own,
    /// such as Mastodon's outbox at `?page=true&max_id=`. `to_query` gives
    /// the whole query for a cursor; `from_query` is given a request's
    /// whole query, and says which page it asks for, or `None` for the
    /// collection itself.
    #[must_use]
    pub fn page_query(
        mut self,
        to_query: impl Fn(&str) -> String + Send + Sync + 'static,
        from_query: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.query = Some((Arc::new(to_query), Arc::new(from_query)));
        self
    }

    /// Say `totalItems` on each page as well as on the collection, from the
    /// counter, as Mastodon's followers and following pages do.
    #[must_use]
    pub fn count_pages(mut self) -> Self {
        self.count_pages = true;
        self
    }

    /// The URI of the page at `cursor` of the collection at `collection`.
    fn page_uri(&self, collection: &Url, cursor: &str) -> Url {
        let mut url = collection.clone();
        match &self.query {
            Some((to_query, _)) => {
                let query = to_query(cursor);
                url.set_query((!query.is_empty()).then_some(query.as_str()));
            }
            None => {
                url.query_pairs_mut().clear().append_pair("cursor", cursor);
            }
        }
        url
    }

    /// `document` with the `@context` the collection gives it, if it gives
    /// one, before its other members.
    fn with_context(&self, document: &CollectionDocument) -> Value {
        let value = document.to_value();
        let Some(context) = &self.context else {
            return value;
        };
        let mut with_context = serde_json::Map::new();
        with_context.insert(
            "@context".into(),
            context(document.items.as_deref().unwrap_or_default()),
        );
        if let Value::Object(members) = value {
            with_context.extend(members);
        }
        Value::Object(with_context)
    }

    /// How many items the collection has, for `totalItems`.
    #[must_use]
    pub fn count<F, Fut, E>(mut self, count: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<u64>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let count = boxed(move |(context, identifier)| count(context, identifier));
        self.count = Some(Arc::new(move |context, identifier| {
            count((context, identifier))
        }));
        self
    }

    /// Where the collection starts, which makes it paged; `None` when there is
    /// no such collection.
    #[must_use]
    pub fn first_cursor<F, Fut, E>(mut self, first: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<First>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let first = boxed(move |(context, identifier)| first(context, identifier));
        self.first = Some(Arc::new(move |context, identifier| {
            first((context, identifier))
        }));
        self
    }

    /// The cursor of its last page, for `last`.
    #[must_use]
    pub fn last_cursor<F, Fut, E>(mut self, last: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<String>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let last = boxed(move |(context, identifier)| last(context, identifier));
        self.last = Some(Arc::new(move |context, identifier| {
            last((context, identifier))
        }));
        self
    }

    /// The collection's own URI, when it is not the one it was asked at: an
    /// actor served under two templates, as Mastodon serves an account at
    /// `/users/{username}` and `/ap/users/{id}`, names each of its collections
    /// by one of them. `None` keeps the URI of the template it was asked at.
    /// The collection and its pages are named, and linked, by this URI.
    #[must_use]
    pub fn uri<F, Fut, E>(mut self, uri: F) -> Self
    where
        F: Fn(Context<D>, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<Url>, E>> + Send + 'static,
        E: Into<Error>,
    {
        let uri = boxed(move |(context, identifier)| uri(context, identifier));
        self.uri = Some(Arc::new(move |context, identifier| {
            uri((context, identifier))
        }));
        self
    }

    pub(super) async fn serve(
        &self,
        context: &Context<D>,
        kind: &str,
        identifier: &str,
        query: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        let own = match &self.uri {
            Some(uri) => uri(context.clone(), identifier.to_owned()).await?,
            None => None,
        };
        let uri = match own {
            Some(uri) => uri,
            None => context.collection_uri(kind, identifier)?,
        };
        let cursor = match &self.query {
            Some((_, from_query)) => from_query(query.unwrap_or_default()),
            None => query.and_then(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find(|(name, _)| name == "cursor")
                    .map(|(_, value)| value.into_owned())
            }),
        };
        let identifier = identifier.to_owned();

        if let Some(cursor) = cursor {
            let Some(page) =
                (self.page)(context.clone(), identifier.clone(), Some(cursor.clone())).await?
            else {
                return Ok(empty(StatusCode::NOT_FOUND));
            };
            let total_items = match &self.count {
                Some(count) if self.count_pages => {
                    count(context.clone(), identifier.clone()).await?
                }
                _ => None,
            };
            let document = CollectionDocument {
                id: Some(self.page_uri(&uri, &cursor)),
                total_items,
                ordered: self.ordered,
                part_of: Some(uri.clone()),
                next: page.next.map(|next| self.page_uri(&uri, &next)),
                prev: page.prev.map(|prev| self.page_uri(&uri, &prev)),
                items: Some(page.items),
                ..CollectionDocument::default()
            };
            return Ok(activity(StatusCode::OK, self.with_context(&document)));
        }

        let Some(first) = &self.first else {
            let Some(page) = (self.page)(context.clone(), identifier.clone(), None).await? else {
                return Ok(empty(StatusCode::NOT_FOUND));
            };
            let total = match &self.count {
                Some(count) => count(context.clone(), identifier).await?,
                None => None,
            }
            .unwrap_or(page.items.len() as u64);
            let document = CollectionDocument {
                id: Some(uri),
                ordered: self.ordered,
                total_items: Some(total),
                items: Some(page.items),
                ..CollectionDocument::default()
            };
            return Ok(activity(StatusCode::OK, self.with_context(&document)));
        };

        let Some(start) = first(context.clone(), identifier.clone()).await? else {
            return Ok(empty(StatusCode::NOT_FOUND));
        };
        let mut document = CollectionDocument {
            ordered: self.ordered,
            ..CollectionDocument::default()
        };
        if let Some(count) = &self.count {
            document.total_items = count(context.clone(), identifier.clone()).await?;
        }
        if let First::At(cursor) = start {
            document.first = Some(self.page_uri(&uri, &cursor).as_str().into());
            if let Some(last) = &self.last
                && let Some(cursor) = last(context.clone(), identifier).await?
            {
                document.last = Some(self.page_uri(&uri, &cursor).as_str().into());
            }
        }
        document.id = Some(uri);
        Ok(activity(StatusCode::OK, self.with_context(&document)))
    }
}

/// An ActivityStreams collection or collection page, written as a document:
/// what Ojak serves a [`Collection`] as, for an application that serves one
/// itself, such as a collection paged by a query of its own or embedded in
/// another object.
///
/// It is a page when it is part of a collection ([`part_of`]) or says it is
/// ([`page`]), and ordered or not as [`ordered`] says. Its members are
/// written whenever there are [`items`], even none; a collection that only
/// counts its members, or only links its pages, has `None`.
///
/// [`part_of`]: CollectionDocument::part_of
/// [`page`]: CollectionDocument::page
/// [`ordered`]: CollectionDocument::ordered
/// [`items`]: CollectionDocument::items
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CollectionDocument {
    /// Its `id`. An embedded page may have none.
    pub id: Option<Url>,
    /// An `OrderedCollection` or `OrderedCollectionPage`, whose members are
    /// `orderedItems`, rather than a `Collection` or `CollectionPage`, whose
    /// members are `items`.
    pub ordered: bool,
    /// A page, even with no [`part_of`](CollectionDocument::part_of).
    pub page: bool,
    /// Its `totalItems`.
    pub total_items: Option<u64>,
    /// Its `next` page.
    pub next: Option<Url>,
    /// Its `prev` page.
    pub prev: Option<Url>,
    /// The collection it is a page of.
    pub part_of: Option<Url>,
    /// Its `first` page: a URI, or the page embedded.
    pub first: Option<Value>,
    /// Its `last` page: a URI, or the page embedded.
    pub last: Option<Value>,
    /// Its members, in order: IRIs as strings, or embedded objects.
    pub items: Option<Vec<Value>>,
}

impl CollectionDocument {
    /// Whether it is a page rather than a collection.
    #[must_use]
    pub fn is_page(&self) -> bool {
        self.page || self.part_of.is_some()
    }

    /// Its `type`.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match (self.ordered, self.is_page()) {
            (true, true) => "OrderedCollectionPage",
            (true, false) => "OrderedCollection",
            (false, true) => "CollectionPage",
            (false, false) => "Collection",
        }
    }

    /// The document, without an `@context`: `id`, `type`, `totalItems`,
    /// `next`, `prev`, `partOf`, `first`, `last` and the members, in that
    /// order, each only when there is one.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut document = serde_json::Map::new();
        if let Some(id) = &self.id {
            document.insert("id".into(), id.as_str().into());
        }
        document.insert("type".into(), self.type_name().into());
        if let Some(total) = self.total_items {
            document.insert("totalItems".into(), total.into());
        }
        if let Some(next) = &self.next {
            document.insert("next".into(), next.as_str().into());
        }
        if let Some(prev) = &self.prev {
            document.insert("prev".into(), prev.as_str().into());
        }
        if let Some(part_of) = &self.part_of {
            document.insert("partOf".into(), part_of.as_str().into());
        }
        if let Some(first) = &self.first {
            document.insert("first".into(), first.clone());
        }
        if let Some(last) = &self.last {
            document.insert("last".into(), last.clone());
        }
        if let Some(items) = &self.items {
            let key = if self.ordered {
                "orderedItems"
            } else {
                "items"
            };
            document.insert(key.into(), Value::Array(items.clone()));
        }
        Value::Object(document)
    }
}
