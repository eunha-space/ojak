//! URI templates: the one description of a route that both matches requests
//! and builds URIs.
//!
//! A template is a path in RFC 6570's level 1: literal segments, and `{name}`
//! expressions, each the whole of a segment or the end of one
//! (`/users/{user_id}`, `/@{handle}`). Expanding percent-encodes each value,
//! everything but RFC 3986's unreserved characters, and matching decodes it,
//! so an identifier can be a UUID, a login name or a DID and come back as it
//! went in.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use std::collections::BTreeMap;
use std::fmt;

/// What expansion encodes: everything but ALPHA, DIGIT, `-`, `.`, `_`, `~`.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The values of a template's expressions, by name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Values(BTreeMap<String, String>);

impl Values {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The value of `name`, if the template has it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.insert(name.into(), value.into());
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The only value, for a template with one expression.
    #[must_use]
    pub fn single(&self) -> Option<&str> {
        let mut values = self.0.values();
        match (values.next(), values.next()) {
            (Some(value), None) => Some(value),
            _ => None,
        }
    }
}

impl std::ops::Index<&str> for Values {
    type Output = str;

    /// # Panics
    ///
    /// When the template has no expression `name`.
    fn index(&self, name: &str) -> &str {
        self.get(name)
            .unwrap_or_else(|| panic!("no template value {name:?}"))
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Values {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

/// Why a template is not one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateError(pub String);

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TemplateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    Literal(String),
    /// A literal prefix, possibly empty, and then an expression.
    Expression {
        prefix: String,
        name: String,
    },
}

/// A parsed template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Template {
    source: String,
    segments: Vec<Segment>,
}

impl Template {
    /// Parse `source`.
    ///
    /// # Errors
    ///
    /// When it does not start with `/`, has an empty segment, a query or
    /// fragment, an expression that is not the end of its segment, one that
    /// is not a plain name, or two expressions of one name.
    pub fn parse(source: &str) -> Result<Self, TemplateError> {
        let error = |why: &str| Err(TemplateError(format!("{source:?}: {why}")));
        let Some(path) = source.strip_prefix('/') else {
            return error("a template is a path starting with /");
        };
        if source.contains(['?', '#']) {
            return error("a template has no query or fragment");
        }
        let mut segments = Vec::new();
        let mut names = Vec::new();
        if !path.is_empty() {
            for segment in path.split('/') {
                if segment.is_empty() {
                    return error("empty segment");
                }
                match segment.find('{') {
                    None if segment.contains('}') => return error("unmatched }"),
                    None => segments.push(Segment::Literal(segment.to_owned())),
                    Some(open) => {
                        let (prefix, expression) = segment.split_at(open);
                        let Some(name) = expression
                            .strip_prefix('{')
                            .and_then(|rest| rest.strip_suffix('}'))
                        else {
                            return error("an expression is the end of its segment");
                        };
                        if name.is_empty()
                            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            return error("an expression is {name}, with a plain name");
                        }
                        if names.contains(&name) {
                            return error("an expression name appears twice");
                        }
                        names.push(name);
                        segments.push(Segment::Expression {
                            prefix: prefix.to_owned(),
                            name: name.to_owned(),
                        });
                    }
                }
            }
        }
        Ok(Self {
            source: source.to_owned(),
            segments,
        })
    }

    /// The template as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The names of its expressions, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.segments.iter().filter_map(|segment| match segment {
            Segment::Expression { name, .. } => Some(name.as_str()),
            Segment::Literal(_) => None,
        })
    }

    /// The path with each expression replaced by its value, encoded.
    ///
    /// # Errors
    ///
    /// When a value is missing or empty.
    pub fn expand(&self, values: &Values) -> Result<String, TemplateError> {
        let mut path = String::new();
        for segment in &self.segments {
            path.push('/');
            match segment {
                Segment::Literal(literal) => path.push_str(literal),
                Segment::Expression { prefix, name } => {
                    let value = values.get(name).filter(|value| !value.is_empty());
                    let Some(value) = value else {
                        return Err(TemplateError(format!(
                            "{:?}: no value for {{{name}}}",
                            self.source
                        )));
                    };
                    path.push_str(prefix);
                    path.extend(utf8_percent_encode(value, COMPONENT));
                }
            }
        }
        if path.is_empty() {
            path.push('/');
        }
        Ok(path)
    }

    /// The values of `path`, if it matches. `path` has no query.
    #[must_use]
    pub fn matches(&self, path: &str) -> Option<Values> {
        let path = path.strip_prefix('/')?;
        let parts: Vec<&str> = if path.is_empty() {
            Vec::new()
        } else {
            path.split('/').collect()
        };
        if parts.len() != self.segments.len() {
            return None;
        }
        let mut values = Values::new();
        for (segment, part) in self.segments.iter().zip(parts) {
            match segment {
                Segment::Literal(literal) => {
                    if literal != part {
                        return None;
                    }
                }
                Segment::Expression { prefix, name } => {
                    let encoded = part.strip_prefix(prefix.as_str())?;
                    if encoded.is_empty() {
                        return None;
                    }
                    let value = percent_decode_str(encoded).decode_utf8().ok()?;
                    values.insert(name.clone(), value.into_owned());
                }
            }
        }
        Some(values)
    }

    /// Whether some path matches both `self` and `other`.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.segments.len() == other.segments.len()
            && self
                .segments
                .iter()
                .zip(&other.segments)
                .all(|pair| match pair {
                    (Segment::Literal(a), Segment::Literal(b)) => a == b,
                    (Segment::Literal(literal), Segment::Expression { prefix, .. })
                    | (Segment::Expression { prefix, .. }, Segment::Literal(literal)) => {
                        literal.len() > prefix.len() && literal.starts_with(prefix.as_str())
                    }
                    (
                        Segment::Expression { prefix: a, .. },
                        Segment::Expression { prefix: b, .. },
                    ) => a.starts_with(b.as_str()) || b.starts_with(a.as_str()),
                })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(source: &str) -> Template {
        Template::parse(source).unwrap()
    }

    fn values(pairs: &[(&str, &str)]) -> Values {
        pairs.iter().copied().collect()
    }

    #[test]
    fn a_value_survives_the_round_trip() {
        let t = template("/ap/users/{user_id}");
        for id in [
            "0190c2f0-6f3b-7c3e-9d61-3c1b0f6e1a2b",
            "alice",
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "그림 쟁이",
            "a/b?c#d%e",
        ] {
            let path = t.expand(&values(&[("user_id", id)])).unwrap();
            assert!(!path[10..].contains(['/', '?', '#', ':', ' ']), "{path}");
            assert_eq!(t.matches(&path).unwrap().get("user_id"), Some(id), "{path}");
        }
    }

    #[test]
    fn a_prefix_is_part_of_its_segment() {
        let t = template("/@{handle}");
        assert_eq!(t.expand(&values(&[("handle", "bob")])).unwrap(), "/@bob");
        assert_eq!(t.matches("/@bob").unwrap().get("handle"), Some("bob"));
        assert_eq!(t.matches("/bob"), None);
        assert_eq!(t.matches("/@"), None, "an expression is never empty");
    }

    #[test]
    fn several_expressions_are_read_by_name() {
        let t = template("/users/{username}/statuses/{id}/activity");
        let v = t.matches("/users/alice/statuses/42/activity").unwrap();
        assert_eq!((&v["username"], &v["id"]), ("alice", "42"));
        assert_eq!(t.names().collect::<Vec<_>>(), ["username", "id"]);
        assert_eq!(t.matches("/users/alice/statuses/42"), None);
        assert!(t.expand(&values(&[("username", "alice")])).is_err());
    }

    #[test]
    fn a_template_without_expressions_is_a_fixed_path() {
        let t = template("/actor");
        assert_eq!(t.expand(&Values::new()).unwrap(), "/actor");
        assert_eq!(t.matches("/actor"), Some(Values::new()));
        assert_eq!(template("/").expand(&Values::new()).unwrap(), "/");
        assert_eq!(template("/").matches("/"), Some(Values::new()));
    }

    #[test]
    fn malformed_templates_are_refused() {
        for source in [
            "users/{id}",
            "/users//{id}",
            "/users/{id}/",
            "/users/{id}x",
            "/users/{}",
            "/users/{a-b}",
            "/users/{id}/{id}",
            "/users/id}",
            "/users/{id}?page",
        ] {
            assert!(Template::parse(source).is_err(), "{source}");
        }
    }

    #[test]
    fn templates_that_could_match_one_path_overlap() {
        let overlapping = [
            ("/users/{a}", "/users/{b}"),
            ("/users/{a}", "/users/alice"),
            ("/@{a}", "/{b}"),
            ("/@{a}", "/@alice"),
        ];
        for (a, b) in overlapping {
            assert!(template(a).overlaps(&template(b)), "{a} {b}");
            assert!(template(b).overlaps(&template(a)), "{b} {a}");
        }
        let apart = [
            ("/users/{a}", "/users/{a}/followers"),
            ("/users/{a}", "/groups/{a}"),
            ("/@{a}", "/!{a}"),
            ("/@{a}", "/@"),
            ("/actor", "/inbox"),
        ];
        for (a, b) in apart {
            assert!(!template(a).overlaps(&template(b)), "{a} {b}");
        }
    }
}
