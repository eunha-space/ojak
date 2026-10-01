//! Walking another server's collection, page by page.
//!
//! A collection is served as one document whose items are in it, or as
//! pages: `first` names the first, and each page's `next` the one after. A
//! [`Walk`] fetches them as they are needed and hands out the items in
//! order, so that reading the first few of a collection of thousands fetches
//! only its first page.
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
    /// The most pages fetched, the collection itself included.
    pub pages: usize,
    /// The most items handed out.
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
    /// The collection's `id`, whose origin every page has to be on.
    collection: Option<String>,
    /// The page to fetch next, if there is one.
    next: Option<Next>,
    /// Items fetched and not yet handed out.
    items: VecDeque<Value>,
    seen: HashSet<String>,
    pages: usize,
    handed: usize,
    total: Option<u64>,
}

enum Next {
    /// The collection, not yet fetched.
    Collection(Url),
    /// A page, by its IRI.
    Page(String),
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
        Walk {
            fetcher: self,
            key,
            limits,
            collection: None,
            next: Some(Next::Collection(url.clone())),
            items: VecDeque::new(),
            seen: HashSet::new(),
            pages: 0,
            handed: 0,
            total: None,
        }
    }
}

impl Walk<'_> {
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
            let Some(next) = self.next.take() else {
                return Ok(None);
            };
            if self.pages >= self.limits.pages {
                return Ok(None);
            }
            self.pages += 1;
            match next {
                Next::Collection(url) => {
                    let document = self.fetcher.lookup(&url, self.key).await?;
                    if !is_collection(&document.json) {
                        return Err(FetchError::Invalid(format!(
                            "{} is not a collection",
                            document.id
                        )));
                    }
                    self.seen.insert(document.id.clone());
                    self.total = document.json.get("totalItems").and_then(Value::as_u64);
                    self.collection = Some(document.id.clone());
                    self.read(&document.json, "first")?;
                }
                Next::Page(iri) => {
                    let url = Url::parse(&iri)
                        .map_err(|error| FetchError::Invalid(format!("page {iri}: {error}")))?;
                    let document = self.fetcher.lookup(&url, self.key).await?;
                    if !is_collection(&document.json) {
                        return Err(FetchError::Invalid(format!(
                            "{} is not a collection page",
                            document.id
                        )));
                    }
                    self.check_origin(&document.id)?;
                    self.seen.insert(document.id.clone());
                    self.read(&document.json, "next")?;
                }
            }
        }
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

    /// Take the items of `document`, and find the page after it by `link`:
    /// `first` from a collection, `next` from a page. A page embedded with
    /// its items is read at once, and the walk goes on from it; one named by
    /// its IRI is fetched when its items are wanted.
    fn read(&mut self, document: &Value, mut link: &str) -> Result<(), FetchError> {
        let mut page = document.clone();
        for _ in 0..self.limits.pages {
            self.items.extend(items(&page));
            let Some(after) = page.get(link).cloned() else {
                return Ok(());
            };
            link = "next";
            let id = match &after {
                Value::String(id) => Some(id.clone()),
                Value::Object(object) => {
                    object.get("id").and_then(Value::as_str).map(str::to_owned)
                }
                _ => return Ok(()),
            };
            if let Some(id) = &id {
                self.check_origin(id)?;
                if !self.seen.insert(id.clone()) {
                    return Ok(());
                }
            }
            match after {
                Value::Object(object)
                    if object.contains_key("orderedItems") || object.contains_key("items") =>
                {
                    page = Value::Object(object);
                }
                _ => {
                    self.next = id.map(Next::Page);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn check_origin(&self, id: &str) -> Result<(), FetchError> {
        match &self.collection {
            Some(collection) if !same_origin(id, collection) => Err(FetchError::Invalid(format!(
                "page {id} is not on the origin of {collection}"
            ))),
            _ => Ok(()),
        }
    }
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
