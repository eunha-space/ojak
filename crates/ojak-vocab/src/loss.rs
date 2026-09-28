//! What a typed value did not keep of the document it was read from.
//!
//! Reading is tolerant: a value that is not the shape its property allows is
//! read as absent, and a property the vocabulary does not define is not read
//! at all, so that one odd property does not cost the whole object. That
//! tolerance is silent unless something says what it cost. This compares
//! the normalised document with the value written back, and lists what the
//! document said that the value does not.
//!
//! The comparison is by meaning, not spelling: one value and an array of
//! one are the same, a JSON-LD value object is the value it wraps, a number
//! and its decimal string are one number, and a node that is only an `id` is
//! that IRI. A value the document gave as `null`, or an empty array, is no
//! value, and nothing is lost by not keeping it.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use serde_json::{Map, Value};

/// Something the document said that the value read from it does not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Loss {
    /// Where, in the normalised document: `object.attachment[1].url`.
    pub path: String,
    /// What was there.
    pub value: Value,
}

impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() {
            "(document)"
        } else {
            &self.path
        };
        write!(f, "{path}: {}", self.value)
    }
}

/// What `input` says that `output` does not.
#[must_use]
pub fn losses(input: &Value, output: &Value) -> Vec<Loss> {
    let mut found = Vec::new();
    compare(
        input,
        &merge_language_maps(output),
        String::new(),
        &mut found,
    );
    found
}

/// `value` with each `{key}Map` of language-tagged text folded into `key`, as
/// language-tagged value objects: the form a normalised document gives text
/// in, where the written form splits it into `content` and `contentMap`.
fn merge_language_maps(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(merge_language_maps).collect()),
        Value::Object(object) => {
            let mut merged: Map<String, Value> = object
                .iter()
                .map(|(key, value)| (key.clone(), merge_language_maps(value)))
                .collect();
            for (key, map) in object {
                let (Some(base), Value::Object(languages)) = (key.strip_suffix("Map"), map) else {
                    continue;
                };
                let mut values = items(merged.get(base).unwrap_or(&Value::Null))
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
                for (language, text) in languages {
                    values.push(serde_json::json!({"@language": language, "@value": text}));
                }
                merged.insert(base.into(), Value::Array(values));
            }
            Value::Object(merged)
        }
        other => other.clone(),
    }
}

fn nothing(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.iter().all(nothing),
        _ => false,
    }
}

fn items(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(values) => values.iter().filter(|v| !nothing(v)).collect(),
        value if nothing(value) => Vec::new(),
        value => alloc::vec![value],
    }
}

/// The scalar a value stands for: a value object's `@value`, and a node
/// that is only an `id`, its IRI.
fn scalar(value: &Value) -> &Value {
    match value {
        Value::Object(object) if object.len() == 1 && object.contains_key("id") => &object["id"],
        Value::Object(object) if object.contains_key("@value") => &object["@value"],
        other => other,
    }
}

fn same_scalar(input: &Value, output: &Value) -> bool {
    match (scalar(input), scalar(output)) {
        (Value::String(a), Value::Number(b)) | (Value::Number(b), Value::String(a)) => {
            *a == b.to_string() || a.parse::<f64>().ok() == b.as_f64()
        }
        (Value::String(a), Value::Bool(b)) | (Value::Bool(b), Value::String(a)) => {
            *a == if *b { "true" } else { "false" }
        }
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (a, b) => a == b,
    }
}

/// Whether `output` says everything `input` does.
fn covers(output: &Value, input: &Value) -> bool {
    if nothing(input) || same_scalar(input, output) {
        return true;
    }
    match (input, output) {
        (Value::Array(_), _) | (_, Value::Array(_)) => {
            let outputs = items(output);
            items(input)
                .into_iter()
                .all(|i| outputs.iter().any(|o| covers(o, i)))
        }
        (Value::Object(i), Value::Object(o)) => covers_object(o, i),
        // An IRI given where the value is written as a link or an image.
        (Value::String(text), Value::Object(o)) => {
            ["id", "href", "url"]
                .iter()
                .any(|key| o.get(*key).is_some_and(|v| covers(v, input)))
                || o.get("@value").and_then(Value::as_str) == Some(text)
        }
        _ => false,
    }
}

fn covers_object(output: &Map<String, Value>, input: &Map<String, Value>) -> bool {
    input.iter().all(|(key, value)| {
        key == "@context" || nothing(value) || output.get(key).is_some_and(|out| covers(out, value))
    })
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.into()
    } else {
        format!("{path}.{key}")
    }
}

fn compare(input: &Value, output: &Value, path: String, found: &mut Vec<Loss>) {
    if covers(output, input) {
        return;
    }
    match (input, output) {
        (Value::Object(i), Value::Object(o)) => {
            for (key, value) in i {
                if key == "@context" || nothing(value) {
                    continue;
                }
                let at = join(&path, key);
                match o.get(key) {
                    Some(out) => compare(value, out, at, found),
                    None => found.push(Loss {
                        path: at,
                        value: value.clone(),
                    }),
                }
            }
        }
        (Value::Array(_), _) | (_, Value::Array(_)) => {
            let inputs = items(input);
            let outputs = items(output);
            let listed = matches!(input, Value::Array(values) if values.len() > 1);
            let at = |n: usize| {
                if listed {
                    format!("{path}[{n}]")
                } else {
                    path.clone()
                }
            };
            if inputs.len() == outputs.len() {
                for (n, (i, o)) in inputs.into_iter().zip(outputs).enumerate() {
                    compare(i, o, at(n), found);
                }
            } else {
                for (n, i) in inputs.into_iter().enumerate() {
                    if !outputs.iter().any(|o| covers(o, i)) {
                        found.push(Loss {
                            path: at(n),
                            value: i.clone(),
                        });
                    }
                }
            }
        }
        // Two scalars that differ, or a scalar and an object.
        _ => found.push(Loss {
            path,
            value: input.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_same_meaning_in_another_spelling_is_nothing_lost() {
        let input = json!({
            "id": "https://a.example/1",
            "to": "https://a.example/followers",
            "sensitive": {"@value": true},
            "width": "300",
            "inReplyTo": null,
            "tag": [],
            "attributedTo": {"id": "https://a.example/users/1"},
        });
        let output = json!({
            "id": "https://a.example/1",
            "to": ["https://a.example/followers"],
            "sensitive": true,
            "width": 300,
            "attributedTo": "https://a.example/users/1",
        });
        assert_eq!(losses(&input, &output), []);
    }

    #[test]
    fn text_by_language_is_kept_in_its_map() {
        let input = json!({"content": ["hello", {"@language": "ko", "@value": "안녕"}]});
        let output = json!({"content": "hello", "contentMap": {"ko": "안녕"}});
        assert_eq!(losses(&input, &output), []);
        let output = json!({"content": "hello"});
        assert_eq!(losses(&input, &output).len(), 1);
    }

    #[test]
    fn what_was_not_kept_is_listed_where_it_was() {
        let input = json!({
            "name": "a",
            "unknownTerm": 1,
            "attachment": [
                {"type": "Image", "url": "https://a.example/1.png", "blurhash": "xyz"},
                {"type": "Image", "url": "https://a.example/2.png"},
            ],
            "published": "yesterday",
        });
        let output = json!({
            "name": "a",
            "attachment": [
                {"type": "Image", "url": "https://a.example/1.png"},
                {"type": "Image", "url": "https://a.example/2.png"},
            ],
            "published": "2026-01-01T00:00:00Z",
        });
        let paths: Vec<String> = losses(&input, &output)
            .into_iter()
            .map(|l| l.path)
            .collect();
        assert_eq!(
            paths,
            ["attachment[0].blurhash", "published", "unknownTerm"]
        );
    }
}
