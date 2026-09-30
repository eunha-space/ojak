//! What the blog knows: its posts, and what the fediverse has said about
//! them.
//!
//! This is the application's data, and Ojak never holds any of it. It is
//! kept in memory so that the example has no database to set up; a real
//! application keeps the same things in its own tables.

use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

/// A post the author published.
#[derive(Clone, Debug)]
pub struct Post {
    pub id: u64,
    pub title: String,
    /// The body, as plain text; paragraphs are separated by blank lines.
    pub body: String,
    pub published: DateTime<Utc>,
}

/// Someone who follows the blog, and where to deliver to them.
#[derive(Clone, Debug)]
pub struct Follower {
    /// The `id` of their `Follow`, which an `Undo` names.
    pub follow: String,
    /// Their shared inbox if their server has one, else their own.
    pub inbox: Url,
}

/// A reply to a post, from somewhere in the fediverse.
#[derive(Clone, Debug)]
pub struct Comment {
    /// The reply's own `id`, which a `Delete` names.
    pub id: String,
    /// The actor who wrote it: the sender Ojak authenticated.
    pub author: Url,
    /// Its text, with any HTML removed.
    pub text: String,
}

#[derive(Debug, Default)]
pub struct Store {
    posts: Vec<Post>,
    /// By the follower's actor IRI.
    followers: BTreeMap<Url, Follower>,
    /// By post.
    comments: BTreeMap<u64, Vec<Comment>>,
    /// By post: the actors who liked it.
    likes: BTreeMap<u64, BTreeSet<Url>>,
    /// The last number [`Store::next_id`] gave out.
    sequence: u64,
}

impl Store {
    /// A number not given out before, for the IDs of activities the blog
    /// sends.
    pub fn next_id(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    pub fn publish(&mut self, title: String, body: String) -> Post {
        let post = Post {
            id: self.posts.len() as u64 + 1,
            title,
            body,
            published: Utc::now(),
        };
        self.posts.push(post.clone());
        post
    }

    pub fn post(&self, id: u64) -> Option<&Post> {
        id.checked_sub(1)
            .and_then(|index| self.posts.get(usize::try_from(index).ok()?))
    }

    /// Every post, newest first.
    pub fn posts(&self) -> impl Iterator<Item = &Post> {
        self.posts.iter().rev()
    }

    pub fn follow(&mut self, actor: Url, follower: Follower) {
        self.followers.insert(actor, follower);
    }

    /// Remove `actor`'s follow, if `follow` is the one they sent.
    pub fn unfollow(&mut self, actor: &Url, follow: &str) -> bool {
        match self.followers.get(actor) {
            Some(follower) if follower.follow == follow => {
                self.followers.remove(actor);
                true
            }
            _ => false,
        }
    }

    pub fn follower_count(&self) -> usize {
        self.followers.len()
    }

    /// Every follower's inbox, once each: followers on one server share
    /// its shared inbox, and one delivery reaches them all.
    pub fn inboxes(&self) -> BTreeSet<Url> {
        self.followers.values().map(|f| f.inbox.clone()).collect()
    }

    pub fn comment(&mut self, post: u64, comment: Comment) {
        let comments = self.comments.entry(post).or_default();
        if !comments.iter().any(|c| c.id == comment.id) {
            comments.push(comment);
        }
    }

    /// Remove the comment `id`, if `author` wrote it.
    pub fn uncomment(&mut self, id: &str, author: &Url) -> bool {
        for comments in self.comments.values_mut() {
            if let Some(index) = comments
                .iter()
                .position(|c| c.id == id && &c.author == author)
            {
                comments.remove(index);
                return true;
            }
        }
        false
    }

    pub fn comments(&self, post: u64) -> &[Comment] {
        self.comments.get(&post).map_or(&[], Vec::as_slice)
    }

    pub fn like(&mut self, post: u64, actor: Url) {
        self.likes.entry(post).or_default().insert(actor);
    }

    pub fn like_count(&self, post: u64) -> usize {
        self.likes.get(&post).map_or(0, BTreeSet::len)
    }
}
