//! Walking another server's collection, page by page.
//!
//! A collection is served as one document whose items are in it, or as
//! pages: `first` names the first, and each page's `next` the one after. A
//! [`Walk`] fetches them as they are needed and hands out the items in
//! order, so that reading the first few of a collection of thousands fetches
//! only its first page. It hands them out one at a time ([`Walk::next`]), or
//! a page at a time ([`Walk::next_page`]) for a caller whose limits are
//! counted in pages.
//!
//! A walk starts from the collection's IRI ([`Fetcher::walk`]), or from the
//! collection as another object embeds it ([`Fetcher::walk_embedded`]), as a
//! post embeds its `replies` with their first page.
//!
//! Every page is fetched as [`Fetcher::lookup`] fetches a document, and has
//! to be on the collection's origin: a page elsewhere would be another
//! server's say about what the collection holds. A walk stops at its limits,
//! and at a page it has seen before, rather than follow a server round a
//! loop of its own making.

use super::{FetchError, Fetcher};
use crate::origin::same_origin;
use crate::sig::SenderKey;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use url::Url;

/// How far a [`Walk`] goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkLimits {
    /// The most pages fetched, the collection itself included. Pages that
    /// come embedded in the one before cost no fetch, and do not count.
    pub pages: usize,
    /// The most items handed out. [`Walk::next_page`] stops at the end of
    /// the page that reaches it, rather than in the middle of one.
    pub items: usize,
}

impl Default for WalkLimits {
    /// A hundred pages, and ten thousand items.
    fn default() -> Self {
        Self {
            pages: 100,
            items: 10_000,
        }
    }
}

/// A walk through a collection's items; see [`Fetcher::walk`].
///
/// An item is as the collection gives it: an IRI, or an object embedded in
/// the page. An embedded object whose `id` is on another origin than the
/// collection is the collection's server's claim about it, not its owner's,
/// and is fetched from its `id` before it is trusted.
pub struct Walk<'a> {
    fetcher: &'a Fetcher,
    key: Option<&'a SenderKey>,
    limits: WalkLimits,
    /// The collection's `id`, or the object that embeds it, whose origin
    /// every page has to be on.
    collection: Option<String>,
    /// Kept to the embedder's origin, whatever the collection's `id` says.
    anchored: bool,
    /// Pages compared with the collection by host rather than by origin.
    by_host: bool,
    /// Read as Mastodon's `JsonLdHelper#collection_items` reads.
    mastodon: bool,
    /// The page to read next, if there is one.
    next: Option<Next>,
    /// Items read and not yet handed out by [`Walk::next`].
    items: VecDeque<Value>,
    seen: HashSet<String>,
    pages: usize,
    /// Items read from pages.
    read: usize,
    /// Items handed out one at a time.
    handed: usize,
    total: Option<u64>,
}

enum Next {
    /// The collection, not yet fetched.
    Collection(Url),
    /// A page, by its IRI.
    Page(String),
    /// A document in hand: the collection as it was embedded, whose page
    /// after it is its `first`, or a page embedded in the one before, whose
    /// page after it is its `next`.
    InHand(Value, &'static str),
}

impl Fetcher {
    /// Walk the collection at `url`, from its first page to its last, within
    /// `limits`, signing each fetch with `key` when one is given.
    #[must_use]
    pub fn walk<'a>(
        &'a self,
        url: &Url,
        key: Option<&'a SenderKey>,
        limits: WalkLimits,
    ) -> Walk<'a> {
        Walk::new(self, key, limits, None, Some(Next::Collection(url.clone())))
    }

    /// Walk a collection as the object `embedder` embeds it: its IRI, or
    /// the collection itself, perhaps with its first page in it, as a post
    /// embeds its `replies`.
    ///
    /// What an object embeds is its own say, and the walk keeps to the
    /// object's server: the collection, and every page of it, is fetched
    /// only from `embedder`'s origin. The items of a collection embedded in
    /// hand are the embedder's claim, to be fetched from their own `id`s
    /// before they are trusted, as any item on another origin is.
    #[must_use]
    pub fn walk_embedded<'a>(
        &'a self,
        collection: &Value,
        embedder: &str,
        key: Option<&'a SenderKey>,
        limits: WalkLimits,
    ) -> Walk<'a> {
        let mut walk = Walk::new(self, key, limits, Some(embedder.to_owned()), None);
        walk.anchored = true;
        match collection {
            Value::String(id) => walk.next = Url::parse(id).ok().map(Next::Collection),
            Value::Object(object) => {
                if let Some(id) = object.get("id").and_then(Value::as_str) {
                    walk.seen.insert(id.to_owned());
                }
                walk.total = object.get("totalItems").and_then(Value::as_u64);
                walk.next = Some(Next::InHand(collection.clone(), "first"));
            }
            _ => {}
        }
        walk
    }
}

impl<'a> Walk<'a> {
    fn new(
        fetcher: &'a Fetcher,
        key: Option<&'a SenderKey>,
        limits: WalkLimits,
        collection: Option<String>,
        next: Option<Next>,
    ) -> Self {
        Walk {
            fetcher,
            key,
            limits,
            collection,
            anchored: false,
            by_host: false,
            mastodon: false,
            next,
            items: VecDeque::new(),
            seen: HashSet::new(),
            pages: 0,
            read: 0,
            handed: 0,
            total: None,
        }
    }
}

impl Walk<'_> {
    /// Take a page on the collection's host as its own, whatever its scheme
    /// and port, as Mastodon's `non_matching_uri_hosts?` does, rather than
    /// only a page on the collection's origin. Either way, only an `http` or
    /// `https` page is taken.
    #[must_use]
    pub fn by_host(mut self) -> Self {
        self.by_host = true;
        self
    }

    /// Read the collection exactly as Mastodon's
    /// `JsonLdHelper#collection_items` does, for a server that has to agree
    /// with Mastodon about what a collection holds:
    ///
    ///  -  pages are compared by host ([`Walk::by_host`]), and only a page
    ///     fetched by its IRI is: a page embedded in the one before is taken
    ///     as it is, and a page elsewhere ends the walk rather than failing
    ///     it;
    ///  -  pages are fetched as [`Fetcher::unverified_json`] fetches, and
    ///     whatever JSON object comes back is a page, whatever its `id` and
    ///     type;
    ///  -  a collection whose `first` is present holds nothing of its own;
    ///  -  a `Collection` or `CollectionPage` holds its `items`, an
    ///     `OrderedCollection` or `OrderedCollectionPage` its `orderedItems`,
    ///     and anything else nothing;
    ///  -  a link is followed when it is present, as Rails' `present?` says:
    ///     not null, and not an empty or blank string, object or array;
    ///  -  pages seen before are read again: the limits are what end a loop.
    #[must_use]
    pub fn mastodon_compatible(mut self) -> Self {
        self.by_host = true;
        self.mastodon = true;
        self
    }

    /// The next item, or `None` when the collection has no more, or a limit
    /// has been reached.
    ///
    /// # Errors
    ///
    /// When a page cannot be fetched, is not a collection or a page of one,
    /// or is on another origin than the collection: [`FetchError::Invalid`]
    /// for those, and as [`Fetcher::lookup`] for a fetch.
    pub async fn next(&mut self) -> Result<Option<Value>, FetchError> {
        loop {
            if self.handed >= self.limits.items {
                return Ok(None);
            }
            if let Some(item) = self.items.pop_front() {
                self.handed += 1;
                return Ok(Some(item));
            }
            match self.read_page().await? {
                Some(page) => self.items.extend(page),
                None => return Ok(None),
            }
        }
    }

    /// The items of the next page, or `None` when the collection has no
    /// more pages, or a limit has been reached. A collection with a `first`
    /// page is not a page of its own unless it holds items too; one without
    /// is its only page, even when empty. Items [`Walk::next`] has read and
    /// not handed out come first, as a page of their own.
    ///
    /// # Errors
    ///
    /// As [`Walk::next`].
    pub async fn next_page(&mut self) -> Result<Option<Vec<Value>>, FetchError> {
        if !self.items.is_empty() {
            let page: Vec<Value> = self.items.drain(..).collect();
            self.handed += page.len();
            return Ok(Some(page));
        }
        if self.read >= self.limits.items {
            return Ok(None);
        }
        self.read_page().await
    }

    /// The pages fetched so far, the collection itself included.
    #[must_use]
    pub fn pages_fetched(&self) -> usize {
        self.pages
    }

    /// The items the collection says it holds, `totalItems`, once its first
    /// document has been fetched; it may differ from what the walk finds.
    #[must_use]
    pub fn total(&self) -> Option<u64> {
        self.total
    }

    /// Every item left, within the walk's limits.
    ///
    /// # Errors
    ///
    /// As [`Walk::next`].
    pub async fn collect(mut self) -> Result<Vec<Value>, FetchError> {
        let mut items = Vec::new();
        while let Some(item) = self.next().await? {
            items.push(item);
        }
        Ok(items)
    }

    /// Read the next page, fetching it if it is not in hand, and find the
    /// one after it.
    async fn read_page(&mut self) -> Result<Option<Vec<Value>>, FetchError> {
        if self.mastodon {
            return self.read_page_as_mastodon().await;
        }
        loop {
            let Some(next) = self.next.take() else {
                return Ok(None);
            };
            let (document, link) = match next {
                Next::InHand(document, link) => (document, link),
                Next::Collection(url) => {
                    if self.anchored {
                        self.check_origin(url.as_str())?;
                    }
                    let Some(document) = self.fetch(&url).await? else {
                        return Ok(None);
                    };
                    if !is_collection(&document.json) {
                        return Err(FetchError::Invalid(format!(
                            "{} is not a collection",
                            document.id
                        )));
                    }
                    if self.anchored {
                        self.check_origin(&document.id)?;
                    } else {
                        self.collection = Some(document.id.clone());
                    }
                    self.seen.insert(document.id.clone());
                    self.total = document.json.get("totalItems").and_then(Value::as_u64);
                    (document.json, "first")
                }
                Next::Page(iri) => {
                    let url = Url::parse(&iri)
                        .map_err(|error| FetchError::Invalid(format!("page {iri}: {error}")))?;
                    let Some(document) = self.fetch(&url).await? else {
                        return Ok(None);
                    };
                    if !is_collection(&document.json) {
                        return Err(FetchError::Invalid(format!(
                            "{} is not a collection page",
                            document.id
                        )));
                    }
                    self.check_origin(&document.id)?;
                    self.seen.insert(document.id.clone());
                    (document.json, "next")
                }
            };
            let page = items(&document);
            self.follow(&document, link)?;
            if link == "first" && page.is_empty() && document.get("first").is_some() {
                continue;
            }
            self.read += page.len();
            return Ok(Some(page));
        }
    }

    /// [`Walk::read_page`] as [`Walk::mastodon_compatible`] says.
    async fn read_page_as_mastodon(&mut self) -> Result<Option<Vec<Value>>, FetchError> {
        let document = loop {
            let Some(next) = self.next.take() else {
                return Ok(None);
            };
            let (document, is_collection) = match next {
                Next::InHand(document, "first") => (document, true),
                Next::InHand(document, _) => (document, false),
                Next::Collection(url) => match self.fetch_unverified(url.as_str()).await? {
                    Some(document) => (document, true),
                    None => return Ok(None),
                },
                Next::Page(iri) => match self.fetch_unverified(&iri).await? {
                    Some(document) => (document, false),
                    None => return Ok(None),
                },
            };
            // The collection: its `first` page, or itself when it has none.
            if is_collection
                && let Some(first) = document.get("first").filter(|first| present(first))
            {
                self.next = Some(match first {
                    Value::String(iri) => Next::Page(iri.clone()),
                    page => Next::InHand(page.clone(), "next"),
                });
                continue;
            }
            break document;
        };
        let items = match document.get("type").and_then(Value::as_str) {
            Some("Collection" | "CollectionPage") => document.get("items"),
            Some("OrderedCollection" | "OrderedCollectionPage") => document.get("orderedItems"),
            _ => None,
        };
        let page = match items {
            Some(Value::Array(items)) => items.clone(),
            Some(Value::Null) | None => Vec::new(),
            Some(item) => vec![item.clone()],
        };
        self.next = document
            .get("next")
            .filter(|next| present(next))
            .map(|next| match next {
                Value::String(iri) => Next::Page(iri.clone()),
                page => Next::InHand(page.clone(), "next"),
            });
        self.read += page.len();
        Ok(Some(page))
    }

    /// Fetch a page as [`Walk::mastodon_compatible`] does: `None` when it is
    /// not on the collection's host, when the walk may fetch no more, and
    /// when what comes back is not a JSON object.
    async fn fetch_unverified(&mut self, iri: &str) -> Result<Option<Value>, FetchError> {
        if self
            .collection
            .as_deref()
            .is_some_and(|collection| !crate::origin::same_host(collection, iri))
        {
            return Ok(None);
        }
        let Ok(url) = Url::parse(iri) else {
            return Ok(None);
        };
        if self.pages >= self.limits.pages {
            return Ok(None);
        }
        self.pages += 1;
        Ok(self
            .fetcher
            .unverified_json(&url, self.key)
            .await?
            .filter(Value::is_object))
    }

    /// Fetch a page, or `None` when the walk may fetch no more.
    async fn fetch(&mut self, url: &Url) -> Result<Option<super::Document>, FetchError> {
        if self.pages >= self.limits.pages {
            return Ok(None);
        }
        self.pages += 1;
        Ok(Some(self.fetcher.lookup(url, self.key).await?))
    }

    /// Find the page after `document` by `link`: `first` from a collection,
    /// `next` from a page. A page embedded with its items is read from where
    /// it is; one named by its IRI is fetched when its items are wanted.
    fn follow(&mut self, document: &Value, link: &'static str) -> Result<(), FetchError> {
        let Some(after) = document.get(link) else {
            return Ok(());
        };
        let id = match after {
            Value::String(id) => Some(id.clone()),
            Value::Object(object) => object.get("id").and_then(Value::as_str).map(str::to_owned),
            _ => return Ok(()),
        };
        if let Some(id) = &id {
            self.check_origin(id)?;
            if !self.seen.insert(id.clone()) {
                return Ok(());
            }
        }
        self.next = match after {
            Value::Object(object)
                if object.contains_key("orderedItems") || object.contains_key("items") =>
            {
                Some(Next::InHand(after.clone(), "next"))
            }
            _ => id.map(Next::Page),
        };
        Ok(())
    }

    fn check_origin(&self, id: &str) -> Result<(), FetchError> {
        let Some(collection) = &self.collection else {
            return Ok(());
        };
        let same = if self.by_host {
            same_host(id, collection)
        } else {
            same_origin(id, collection)
        };
        if same {
            Ok(())
        } else {
            Err(FetchError::Invalid(format!(
                "page {id} is not on the {} of {collection}",
                if self.by_host { "host" } else { "origin" }
            )))
        }
    }
}

/// Whether two `http` or `https` URLs name the same host.
fn same_host(a: &str, b: &str) -> bool {
    let host = |url: &str| {
        Url::parse(url)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
    };
    matches!((host(a), host(b)), (Some(a), Some(b)) if a == b)
}

fn is_collection(document: &Value) -> bool {
    crate::portable::has_type(
        document,
        &[
            "Collection",
            "OrderedCollection",
            "CollectionPage",
            "OrderedCollectionPage",
        ],
    )
}

fn items(page: &Value) -> Vec<Value> {
    match page.get("orderedItems").or_else(|| page.get("items")) {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(item) => vec![item.clone()],
    }
}

/// Rails' `present?` for a JSON value: not null, and not a blank string or
/// an empty object or array.
fn present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}
