//! Collections, paged by cursor.
//!
//! The application writes one page function, and optionally a counter and
//! the cursors of the first and last pages; Feder writes the
//! `OrderedCollection` at the template's URI and the `OrderedCollectionPage`s
//! at the same URI with `?cursor=`.

use super::{BoxFuture, Context, Error, activity, boxed, empty};
use http::StatusCode;
use serde_json::{Value, json};
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
        }
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
        let cursor = query.and_then(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(name, _)| name == "cursor")
                .map(|(_, value)| value.into_owned())
        });
        let identifier = identifier.to_owned();

        if let Some(cursor) = cursor {
            let Some(page) = (self.page)(context.clone(), identifier, Some(cursor.clone())).await?
            else {
                return Ok(empty(StatusCode::NOT_FOUND));
            };
            let mut document = json!({
                "id": page_uri(&uri, &cursor).as_str(),
                "type": "OrderedCollectionPage",
                "partOf": uri.as_str(),
                "orderedItems": page.items,
            });
            if let Some(next) = page.next {
                document["next"] = page_uri(&uri, &next).as_str().into();
            }
            if let Some(prev) = page.prev {
                document["prev"] = page_uri(&uri, &prev).as_str().into();
            }
            return Ok(activity(StatusCode::OK, document));
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
            return Ok(activity(
                StatusCode::OK,
                json!({
                    "id": uri.as_str(),
                    "type": "OrderedCollection",
                    "totalItems": total,
                    "orderedItems": page.items,
                }),
            ));
        };

        let Some(start) = first(context.clone(), identifier.clone()).await? else {
            return Ok(empty(StatusCode::NOT_FOUND));
        };
        let mut document = json!({"id": uri.as_str(), "type": "OrderedCollection"});
        if let Some(count) = &self.count
            && let Some(total) = count(context.clone(), identifier.clone()).await?
        {
            document["totalItems"] = total.into();
        }
        if let First::At(cursor) = start {
            document["first"] = page_uri(&uri, &cursor).as_str().into();
            if let Some(last) = &self.last
                && let Some(cursor) = last(context.clone(), identifier).await?
            {
                document["last"] = page_uri(&uri, &cursor).as_str().into();
            }
        }
        Ok(activity(StatusCode::OK, document))
    }
}

fn page_uri(collection: &Url, cursor: &str) -> Url {
    let mut url = collection.clone();
    url.query_pairs_mut().clear().append_pair("cursor", cursor);
    url
}
