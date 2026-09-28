//! What a post or a reaction means, where the fediverse says it more than
//! one way.
//!
//! Reading gives every property a document carries; it does not decide which
//! of several properties an application should treat as the quote, or
//! whether a `Like` is a like or a reaction. These do, the way Mastodon,
//! Misskey and Pleroma between them say those things, so that an application
//! does not learn each spelling from a bug report. Each is a small function
//! over the generated types, and an application that disagrees reads the
//! fields itself.

use alloc::{string::String, vec::Vec};
use ojak_vocab::Iri;
use ojak_vocab::generated::{
    AnyObject, Article, ChatMessage, Emoji, EmojiReact, Like, LinkOrObject, Note, Page, Question,
};
use ojak_vocab::json::Text;

/// Someone a post mentions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mention<'a> {
    /// The actor.
    pub href: &'a Iri,
    /// How the post names them, such as `@alice@example.com`, if it does.
    pub name: Option<&'a str>,
}

/// What a post says, the same way for every kind of post.
pub trait Post {
    /// The post's content warning: its `summary`, which Mastodon and Misskey
    /// both show in front of the content, collapsed. `None` when it has none.
    fn content_warning(&self) -> Option<&str>;

    /// Whether the post's media is marked sensitive.
    fn is_sensitive(&self) -> bool;

    /// The people the post mentions, from its `tag`.
    fn mentions(&self) -> Vec<Mention<'_>>;

    /// The hashtags the post carries, from its `tag`, without their `#`.
    fn hashtags(&self) -> Vec<&str>;

    /// The post this one quotes: FEP-044f's `quote`, and failing that the
    /// property Misskey (`_misskey_quote`), Fedibird (`quoteUri`) or Akkoma
    /// (`quoteUrl`) sends it under, which reading merges into one.
    fn quote(&self) -> Option<&Iri>;
}

/// The first value of a text, in no language or else in any.
fn first(text: &Text) -> Option<&str> {
    text.value
        .as_deref()
        .or_else(|| text.languages.values().next().map(String::as_str))
        .filter(|value| !value.is_empty())
}

fn mentions(tags: &[LinkOrObject]) -> Vec<Mention<'_>> {
    tags.iter()
        .filter_map(|tag| match tag {
            LinkOrObject::Mention(mention) => Some(Mention {
                href: mention.href.as_ref()?,
                name: first(&mention.name),
            }),
            _ => None,
        })
        .collect()
}

fn hashtags(tags: &[LinkOrObject]) -> Vec<&str> {
    tags.iter()
        .filter_map(|tag| match tag {
            LinkOrObject::Hashtag(hashtag) => {
                let name = first(&hashtag.name)?;
                let name = name.strip_prefix('#').unwrap_or(name);
                (!name.is_empty()).then_some(name)
            }
            _ => None,
        })
        .collect()
}

macro_rules! post {
    ($($type:ty),*) => {$(
        impl Post for $type {
            fn content_warning(&self) -> Option<&str> {
                first(&self.summary)
            }

            fn is_sensitive(&self) -> bool {
                self.sensitive.unwrap_or(false)
            }

            fn mentions(&self) -> Vec<Mention<'_>> {
                mentions(&self.tags)
            }

            fn hashtags(&self) -> Vec<&str> {
                hashtags(&self.tags)
            }

            fn quote(&self) -> Option<&Iri> {
                self.quote
                    .as_ref()
                    .and_then(AnyObject::id)
                    .or(self.quote_url.as_ref())
            }
        }
    )*};
}

post!(Note, Article, Question, ChatMessage);

// Lemmy's posts, which quote nothing.
impl Post for Page {
    fn content_warning(&self) -> Option<&str> {
        first(&self.summary)
    }

    fn is_sensitive(&self) -> bool {
        self.sensitive.unwrap_or(false)
    }

    fn mentions(&self) -> Vec<Mention<'_>> {
        mentions(&self.tags)
    }

    fn hashtags(&self) -> Vec<&str> {
        hashtags(&self.tags)
    }

    fn quote(&self) -> Option<&Iri> {
        None
    }
}

/// An emoji reaction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reaction<'a> {
    /// The emoji: a Unicode emoji, or a custom one's shortcode, `:name:`.
    pub content: &'a str,
    /// The custom emoji the shortcode names, with its image, when it is one.
    pub emoji: Option<&'a Emoji>,
}

fn reaction<'a>(content: &'a Text, tags: &'a [LinkOrObject]) -> Option<Reaction<'a>> {
    let content = first(content)?;
    let emoji = tags.iter().find_map(|tag| match tag {
        LinkOrObject::Emoji(emoji) if first(&emoji.name) == Some(content) => Some(&**emoji),
        _ => None,
    });
    Some(Reaction { content, emoji })
}

/// The reaction a `Like` carries, if it carries one: Misskey sends every
/// reaction as a `Like` with the emoji as its `content`, and a `Like` with
/// no content is a like.
#[must_use]
pub fn like_reaction(like: &Like) -> Option<Reaction<'_>> {
    reaction(&like.content, &like.tags)
}

/// The reaction an `EmojiReact` carries, as Pleroma, Akkoma and Misskey send
/// it.
#[must_use]
pub fn emoji_reaction(react: &EmojiReact) -> Option<Reaction<'_>> {
    reaction(&react.content, &react.tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ojak_vocab::generated::AnyObject;
    use ojak_vocab::{Registry, read_reporting};
    use serde_json::{Value, json};

    fn read(document: Value) -> AnyObject {
        read_reporting::<AnyObject>(&Registry::bundled(), &document)
            .expect("read")
            .into_value()
    }

    fn note(document: Value) -> Note {
        match read(document) {
            AnyObject::Note(note) => *note,
            other => panic!("not a Note: {other:?}"),
        }
    }

    const MASTODON: &str = "https://www.w3.org/ns/activitystreams";

    #[test]
    fn a_mastodon_post_says_its_warning_mentions_and_tags() {
        let note = note(json!({
            "@context": [MASTODON, {"sensitive": "as:sensitive", "Hashtag": "as:Hashtag"}],
            "id": "https://m.example/users/a/statuses/1",
            "type": "Note",
            "summary": "spoilers",
            "sensitive": true,
            "content": "<p>hi @b #Art</p>",
            "tag": [
                {"type": "Mention", "href": "https://n.example/users/b", "name": "@b@n.example"},
                {"type": "Hashtag", "href": "https://m.example/tags/art", "name": "#Art"}
            ]
        }));
        assert_eq!(note.content_warning(), Some("spoilers"));
        assert!(note.is_sensitive());
        let mentions = note.mentions();
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].href.as_str(), "https://n.example/users/b");
        assert_eq!(mentions[0].name, Some("@b@n.example"));
        assert_eq!(note.hashtags(), ["Art"]);
        assert_eq!(note.quote(), None);
    }

    #[test]
    fn a_quote_is_found_under_every_name_it_is_sent_by() {
        let quoted = "https://q.example/notes/1";
        for (context, key) in [
            (
                json!({"quote": {"@id": "https://w3id.org/fep/044f#quote", "@type": "@id"}}),
                "quote",
            ),
            (json!({"quoteUrl": "as:quoteUrl"}), "quoteUrl"),
            (
                json!({"misskey": "https://misskey-hub.net/ns#", "_misskey_quote": "misskey:_misskey_quote"}),
                "_misskey_quote",
            ),
            (
                json!({"fedibird": "http://fedibird.com/ns#", "quoteUri": "fedibird:quoteUri"}),
                "quoteUri",
            ),
        ] {
            let note = note(json!({
                "@context": [MASTODON, context],
                "id": "https://p.example/notes/2",
                "type": "Note",
                key: quoted,
            }));
            assert_eq!(note.quote().map(|iri| iri.as_str()), Some(quoted), "{key}");
        }
    }

    #[test]
    fn a_misskey_like_with_an_emoji_is_a_reaction() {
        let like = match read(json!({
            "@context": [MASTODON, {"toot": "http://joinmastodon.org/ns#", "Emoji": "toot:Emoji"}],
            "id": "https://mk.example/likes/1",
            "type": "Like",
            "actor": "https://mk.example/users/1",
            "object": "https://m.example/users/a/statuses/1",
            "content": ":blobcat:",
            "tag": [{
                "id": "https://mk.example/emojis/blobcat",
                "type": "Emoji",
                "name": ":blobcat:",
                "icon": {"type": "Image", "url": "https://mk.example/files/blobcat.png"}
            }]
        })) {
            AnyObject::Like(like) => like,
            other => panic!("{other:?}"),
        };
        let reaction = like_reaction(&like).expect("a reaction");
        assert_eq!(reaction.content, ":blobcat:");
        assert!(reaction.emoji.is_some_and(|emoji| !emoji.icons.is_empty()));

        let plain = match read(json!({
            "@context": MASTODON,
            "id": "https://m.example/likes/2",
            "type": "Like",
            "actor": "https://m.example/users/a",
            "object": "https://m.example/users/a/statuses/1"
        })) {
            AnyObject::Like(like) => like,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            like_reaction(&plain),
            None,
            "a like with no content is a like"
        );
    }

    #[test]
    fn a_pleroma_emoji_react_is_a_reaction() {
        let react = match read(json!({
            "@context": [MASTODON, {"litepub": "http://litepub.social/ns#", "EmojiReact": "litepub:EmojiReact"}],
            "id": "https://p.example/activities/1",
            "type": "EmojiReact",
            "actor": "https://p.example/users/a",
            "object": "https://m.example/users/a/statuses/1",
            "content": "👍"
        })) {
            AnyObject::EmojiReact(react) => react,
            other => panic!("{other:?}"),
        };
        let reaction = emoji_reaction(&react).expect("a reaction");
        assert_eq!(reaction.content, "👍");
        assert_eq!(reaction.emoji, None);
    }
}
