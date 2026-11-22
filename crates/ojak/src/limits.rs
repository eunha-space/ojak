//! Bounds on the parts of an activity or object a sender can inflate.
//!
//! An inbox reads at most [`crate::federation::MAX_INBOX_BODY`], and the
//! client reads at most [`crate::client::ClientConfig::max_response_bytes`]
//! of a response, but a megabyte of JSON still holds thousands of `Mention`s
//! of distinct actors, each of which an application resolving mentions
//! fetches, or a few hundred kilobytes of `content` for every client to lay
//! out. [`PayloadLimits`] bounds those parts of each object a document holds:
//! the activity, the object it embeds, and every object inside those, so
//! that a document over them is refused before an application sees it. The
//! inbox refuses one with a 422 (*docs/guide/inbox.md*), and the fetcher
//! with [`crate::fetch::FetchError::Oversized`].
//!
//! The defaults are far above what Mastodon, Misskey, Pleroma and their
//! like send: Mastodon's posts are 500 characters long, Misskey's are 3,000
//! and mention at most 20 accounts by default, and a long-form article is
//! tens of kilobytes of HTML.

use core::fmt;
use serde_json::Value;

/// How much of each part a sender can inflate one object may hold.
///
/// Each bound applies to every JSON object in a document on its own, the
/// activity and the object it embeds alike: a `Create` and its `Note` each
/// address their recipients, and each is held to
/// [`PayloadLimits::max_recipients`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadLimits {
    /// How many entries an object's `tag` may hold, of any type: mentions,
    /// hashtags and custom emoji together.
    pub max_tags: usize,
    /// How many of an object's `tag` entries may be `Mention`s.
    pub max_mentions: usize,
    /// How many recipients an object may name in `to`, `cc`, `bto`, `bcc`
    /// and `audience` together.
    pub max_recipients: usize,
    /// How long, in bytes, an object's `content` may be, and each value of
    /// its `contentMap`.
    pub max_content_bytes: usize,
    /// How long, in bytes, an object's `summary` may be, and each value of
    /// its `summaryMap`.
    pub max_summary_bytes: usize,
    /// How long, in bytes, an object's `name` may be, and each value of its
    /// `nameMap`.
    pub max_name_bytes: usize,
}

impl PayloadLimits {
    /// No bounds at all, for an application that applies its own.
    pub const UNLIMITED: Self = Self {
        max_tags: usize::MAX,
        max_mentions: usize::MAX,
        max_recipients: usize::MAX,
        max_content_bytes: usize::MAX,
        max_summary_bytes: usize::MAX,
        max_name_bytes: usize::MAX,
    };

    /// Check every object in `document` against the bounds.
    ///
    /// # Errors
    ///
    /// The first bound an object in `document` is over.
    pub fn check(&self, document: &Value) -> Result<(), LimitExceeded> {
        match document {
            Value::Object(members) => {
                self.check_object(members)?;
                for (key, value) in members {
                    if key != "@context" {
                        self.check(value)?;
                    }
                }
                Ok(())
            }
            Value::Array(items) => items.iter().try_for_each(|item| self.check(item)),
            _ => Ok(()),
        }
    }

    fn check_object(&self, object: &serde_json::Map<String, Value>) -> Result<(), LimitExceeded> {
        let over = |limit, found: usize, max: usize| {
            if found > max {
                Err(LimitExceeded { limit, found, max })
            } else {
                Ok(())
            }
        };
        if let Some(tag) = object.get("tag") {
            let tags = entries(tag);
            over(Limit::Tags, tags.len(), self.max_tags)?;
            let mentions = tags.iter().filter(|tag| is_mention(tag)).count();
            over(Limit::Mentions, mentions, self.max_mentions)?;
        }
        let recipients = ["to", "cc", "bto", "bcc", "audience"]
            .iter()
            .filter_map(|key| object.get(*key))
            .map(|value| entries(value).len())
            .sum();
        over(Limit::Recipients, recipients, self.max_recipients)?;
        for (limit, key, map, max) in [
            (
                Limit::Content,
                "content",
                "contentMap",
                self.max_content_bytes,
            ),
            (
                Limit::Summary,
                "summary",
                "summaryMap",
                self.max_summary_bytes,
            ),
            (Limit::Name, "name", "nameMap", self.max_name_bytes),
        ] {
            let longest = [key, map]
                .iter()
                .filter_map(|key| object.get(*key))
                .map(longest_text)
                .max()
                .unwrap_or(0);
            over(limit, longest, max)?;
        }
        Ok(())
    }
}

impl Default for PayloadLimits {
    fn default() -> Self {
        Self {
            max_tags: 1_000,
            max_mentions: 500,
            max_recipients: 1_000,
            max_content_bytes: 512 * 1024,
            max_summary_bytes: 64 * 1024,
            max_name_bytes: 16 * 1024,
        }
    }
}

/// The values a property holds: an array's items, or the one value.
fn entries(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        Value::Null => &[],
        value => core::slice::from_ref(value),
    }
}

/// Whether a `tag` entry is a `Mention`, as its `type` says, in whichever
/// spelling.
fn is_mention(tag: &Value) -> bool {
    let named = |kind: &Value| {
        kind.as_str().is_some_and(|kind| {
            matches!(
                kind,
                "Mention" | "as:Mention" | "https://www.w3.org/ns/activitystreams#Mention"
            )
        })
    };
    match tag.get("type").or_else(|| tag.get("@type")) {
        Some(Value::Array(kinds)) => kinds.iter().any(named),
        Some(kind) => named(kind),
        None => false,
    }
}

/// The length in bytes of the longest text a property holds: a string, the
/// strings of an array, or the values of a language map.
fn longest_text(value: &Value) -> usize {
    match value {
        Value::String(text) => text.len(),
        Value::Array(items) => items.iter().map(longest_text).max().unwrap_or(0),
        Value::Object(map) => map
            .get("@value")
            .map_or_else(
                || map.values().map(longest_text).max(),
                |v| Some(longest_text(v)),
            )
            .unwrap_or(0),
        _ => 0,
    }
}

/// A bound [`PayloadLimits`] sets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Limit {
    /// [`PayloadLimits::max_tags`].
    Tags,
    /// [`PayloadLimits::max_mentions`].
    Mentions,
    /// [`PayloadLimits::max_recipients`].
    Recipients,
    /// [`PayloadLimits::max_content_bytes`].
    Content,
    /// [`PayloadLimits::max_summary_bytes`].
    Summary,
    /// [`PayloadLimits::max_name_bytes`].
    Name,
}

impl Limit {
    /// Its name, as the `limit` label of `ojak_payloads_refused_total` has
    /// it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tags => "tags",
            Self::Mentions => "mentions",
            Self::Recipients => "recipients",
            Self::Content => "content",
            Self::Summary => "summary",
            Self::Name => "name",
        }
    }
}

/// An object over one of the bounds [`PayloadLimits`] sets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitExceeded {
    /// The bound it is over.
    pub limit: Limit,
    /// How many entries, or bytes, it has.
    pub found: usize,
    /// How many the bound allows.
    pub max: usize,
}

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { found, max, .. } = self;
        match self.limit {
            Limit::Tags => write!(f, "{found} tags, more than {max}"),
            Limit::Mentions => write!(f, "{found} mentions, more than {max}"),
            Limit::Recipients => write!(f, "{found} recipients, more than {max}"),
            Limit::Content => write!(f, "content of {found} bytes, more than {max}"),
            Limit::Summary => write!(f, "summary of {found} bytes, more than {max}"),
            Limit::Name => write!(f, "name of {found} bytes, more than {max}"),
        }
    }
}

impl std::error::Error for LimitExceeded {}

/// Count a refusal in `ojak_payloads_refused_total`, by where it was refused
/// (`inbox` or `fetch`) and which bound it was over.
#[cfg_attr(not(feature = "metrics"), allow(unused_variables))]
pub(crate) fn count_refusal(source: &'static str, exceeded: &LimitExceeded) {
    #[cfg(feature = "metrics")]
    {
        static DESCRIBED: std::sync::Once = std::sync::Once::new();
        DESCRIBED.call_once(|| {
            metrics::describe_counter!(
                "ojak_payloads_refused_total",
                "Activities and objects refused for being over a payload limit."
            );
        });
        metrics::counter!(
            "ojak_payloads_refused_total",
            "source" => source,
            "limit" => exceeded.limit.as_str(),
        )
        .increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mentions(n: usize) -> Vec<Value> {
        (0..n)
            .map(|i| json!({"type": "Mention", "href": format!("https://s{i}.example/u/{i}")}))
            .collect()
    }

    #[test]
    fn an_ordinary_post_is_within_the_defaults() {
        let note = json!({
            "type": "Create",
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "cc": ["https://a.example/users/alice/followers"],
            "object": {
                "type": "Note",
                "content": "<p>hello</p>",
                "contentMap": {"en": "<p>hello</p>"},
                "tag": mentions(20),
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
            }
        });
        assert_eq!(PayloadLimits::default().check(&note), Ok(()));
    }

    #[test]
    fn each_bound_is_checked_in_embedded_objects() {
        let limits = PayloadLimits {
            max_tags: 4,
            max_mentions: 2,
            max_recipients: 3,
            max_content_bytes: 5,
            max_summary_bytes: 5,
            max_name_bytes: 5,
        };
        let within = json!({"object": {"tag": mentions(2), "to": ["a", "b"], "cc": "c"}});
        assert_eq!(limits.check(&within), Ok(()));
        let cases = [
            (json!({"object": {"tag": mentions(3)}}), Limit::Mentions, 3),
            (
                json!({"object": {"tag": [{"type": "Hashtag"}, {}, {}, {}, {}]}}),
                Limit::Tags,
                5,
            ),
            (
                json!({"object": [{"to": ["a", "b"], "bcc": ["c"], "audience": "d"}]}),
                Limit::Recipients,
                4,
            ),
            (
                json!({"object": {"contentMap": {"en": "short", "ko": "longer"}}}),
                Limit::Content,
                6,
            ),
            (json!({"summary": "longer"}), Limit::Summary, 6),
            (
                json!({"tag": [{"type": "Emoji", "name": ":longer:"}]}),
                Limit::Name,
                8,
            ),
            (
                json!({"tag": [{"@type": ["as:Mention"]}, {"type": "Mention"}, {"type": ["Mention"]}]}),
                Limit::Mentions,
                3,
            ),
        ];
        for (document, limit, found) in cases {
            let exceeded = limits.check(&document).expect_err(&document.to_string());
            assert_eq!(
                (exceeded.limit, exceeded.found),
                (limit, found),
                "{document}"
            );
        }
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn a_refusal_is_counted_by_where_and_which_bound() {
        use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, SharedString, Unit};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Captured(Mutex<Vec<(Key, Arc<AtomicU64>)>>);
        impl metrics::Recorder for Captured {
            fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
                let mut captured = self.0.lock().unwrap();
                if let Some((_, value)) = captured.iter().find(|(k, _)| k == key) {
                    return Counter::from_arc(value.clone());
                }
                let value = Arc::new(AtomicU64::new(0));
                captured.push((key.clone(), value.clone()));
                Counter::from_arc(value)
            }
            fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
                Gauge::noop()
            }
            fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
                Histogram::noop()
            }
        }

        let recorder = Captured::default();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let exceeded = PayloadLimits::default()
            .check(&json!({"tag": mentions(600)}))
            .unwrap_err();
        count_refusal("inbox", &exceeded);
        count_refusal("inbox", &exceeded);
        let captured = recorder.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (key, value) = &captured[0];
        assert_eq!(key.name(), "ojak_payloads_refused_total");
        let labels: Vec<(&str, &str)> = key.labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels, [("source", "inbox"), ("limit", "mentions")]);
        assert_eq!(value.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn nothing_is_over_no_bounds() {
        let document = json!({"tag": mentions(5_000), "content": "x".repeat(1 << 20)});
        assert_eq!(PayloadLimits::UNLIMITED.check(&document), Ok(()));
        assert_eq!(
            PayloadLimits::default().check(&document).unwrap_err().limit,
            Limit::Tags
        );
    }
}
