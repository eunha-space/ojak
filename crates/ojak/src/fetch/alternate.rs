//! Finding the ActivityPub representation a web page links to.
//!
//! A URL someone pastes into a search box is rarely an object's `id`: it is
//! the page they were reading. A server that serves its pages and its
//! objects at different paths names the object from the page with a
//! `rel="alternate"` link of an ActivityStreams type, in a `Link` header or
//! in the page's own `<link>` elements, and Mastodon's
//! `FetchResourceService` looks in that order. [`link_header_alternate`]
//! reads the header, and [`html_alternate`], with the `html` feature, the
//! page.

use reqwest::header::HeaderMap;

/// The types an alternate link has to carry to name an ActivityPub object,
/// in the order they are looked for: Mastodon's
/// `FetchResourceService::ACTIVITY_STREAM_LINK_TYPES`.
pub const ACTIVITY_LINK_TYPES: [&str; 2] = [
    "application/activity+json",
    "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
];

/// The target of the first `Link` header's `rel="alternate"` entry of an
/// [`ACTIVITY_LINK_TYPES`] type, as written.
///
/// As in Mastodon, only the first `Link` header is read when there are
/// several, and `application/activity+json` is looked for across all its
/// entries before the JSON-LD spelling: the order of the types decides, not
/// the order of the links.
#[must_use]
pub fn link_header_alternate(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("link")?.to_str().ok()?;
    let links = parse_link_header(raw);
    ACTIVITY_LINK_TYPES.iter().find_map(|wanted| {
        links
            .iter()
            .find(|link| link.rel_includes("alternate") && link.param("type") == Some(*wanted))
            .map(|link| link.href.clone())
    })
}

/// One entry of a `Link` header (RFC 8288).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebLink {
    /// The target, as written between `<` and `>`.
    pub href: String,
    /// The parameters, names lowercased and values unquoted, in order.
    pub params: Vec<(String, String)>,
}

impl WebLink {
    /// The first parameter named `name`, which is lowercase.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether `rel`, a space-separated list of tokens, includes `token`,
    /// so that `rel="alternate me"` is an alternate link.
    #[must_use]
    pub fn rel_includes(&self, token: &str) -> bool {
        self.param("rel")
            .is_some_and(|rel| rel.split_whitespace().any(|t| t == token))
    }
}

/// The entries of a `Link` header. A comma inside `<…>` or a quoted
/// parameter value does not separate entries, and an entry without a
/// `<target>` is passed over.
#[must_use]
pub fn parse_link_header(raw: &str) -> Vec<WebLink> {
    let mut links = Vec::new();
    for entry in split_outside_quotes(raw, ',') {
        let entry = entry.trim();
        let Some(rest) = entry.strip_prefix('<') else {
            continue;
        };
        let Some((href, params)) = rest.split_once('>') else {
            continue;
        };
        let params = split_outside_quotes(params, ';')
            .into_iter()
            .filter_map(|param| {
                let (key, value) = param.trim().split_once('=')?;
                Some((
                    key.trim().to_ascii_lowercase(),
                    value.trim().trim_matches('"').to_owned(),
                ))
            })
            .collect();
        links.push(WebLink {
            href: href.trim().to_owned(),
            params,
        });
    }
    links
}

fn split_outside_quotes(raw: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut in_quotes, mut in_angles) = (0, false, false);
    for (i, c) in raw.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => in_angles = true,
            '>' if !in_quotes => in_angles = false,
            c if c == separator && !in_quotes && !in_angles => {
                parts.push(&raw[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&raw[start..]);
    parts
}

/// The target of the page's first `<link rel="alternate">` of an
/// [`ACTIVITY_LINK_TYPES`] type, resolved against `base`, the URL the page
/// was served from. Mastodon only meets absolute targets here, and resolving
/// a relative one costs nothing.
#[cfg(feature = "html")]
#[must_use]
pub fn html_alternate(html: &str, base: &url::Url) -> Option<String> {
    let document = scraper::Html::parse_document(html);
    // `rel` is a token list; `~=` is the selector for "contains this token".
    let selector = scraper::Selector::parse(r#"link[rel~="alternate"]"#).ok()?;
    let href = document
        .select(&selector)
        .find(|link| {
            link.value()
                .attr("type")
                .is_some_and(|kind| ACTIVITY_LINK_TYPES.contains(&kind))
        })
        .and_then(|link| link.value().attr("href"))?;
    base.join(href).ok().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("link", value.parse().unwrap());
        headers
    }

    #[test]
    fn finds_the_alternate_link_in_a_link_header() {
        let headers = link(
            r#"<https://a.test/style.css>; rel="preload", <https://a.test/ap/1>; rel="alternate"; type="application/activity+json""#,
        );
        assert_eq!(
            link_header_alternate(&headers).as_deref(),
            Some("https://a.test/ap/1")
        );
    }

    /// `application/activity+json` wins over the JSON-LD spelling wherever
    /// each appears in the header, because that is the order Mastodon asks
    /// in.
    #[test]
    fn link_header_prefers_activity_json_over_ld_json() {
        let headers = link(concat!(
            r#"<https://a.test/ld>; rel="alternate"; type="application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", "#,
            r#"<https://a.test/ap>; rel="alternate"; type="application/activity+json""#
        ));
        assert_eq!(
            link_header_alternate(&headers).as_deref(),
            Some("https://a.test/ap")
        );
    }

    #[test]
    fn link_header_alternate_needs_an_activitystreams_type() {
        let headers =
            link(r#"<https://a.test/feed.xml>; rel="alternate"; type="application/rss+xml""#);
        assert_eq!(link_header_alternate(&headers), None);
    }

    #[test]
    fn link_header_commas_inside_quotes_do_not_split_entries() {
        let links = parse_link_header(r#"<https://a.test/1>; rel="alternate"; title="one, two""#);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href, "https://a.test/1");
        assert_eq!(links[0].param("title"), Some("one, two"));
    }

    #[test]
    fn rel_is_a_token_list_in_a_link_header() {
        let links = parse_link_header(r#"<https://a.test/1>; REL="me alternate""#);
        assert!(links[0].rel_includes("alternate"));
        assert!(!links[0].rel_includes("alt"));
    }

    #[cfg(feature = "html")]
    mod html {
        use super::super::html_alternate;

        #[test]
        fn finds_the_alternate_link_in_a_page() {
            // A human page whose only pointer to the object is this tag.
            let html = r#"
                <html><head>
                  <link rel="stylesheet" href="/static/style.css" type="text/css" />
                  <link rel="alternate" type="application/rss+xml" href="/feed.xml" />
                  <link rel="alternate"
                        type="application/activity+json"
                        href="https://oeee.cafe/ap/posts/75fbf20d" />
                </head><body>drawing</body></html>"#;
            let base = url::Url::parse("https://oeee.cafe/@pokemon/75fbf20d").unwrap();
            assert_eq!(
                html_alternate(html, &base).as_deref(),
                Some("https://oeee.cafe/ap/posts/75fbf20d")
            );
        }

        #[test]
        fn alternate_link_href_may_be_relative() {
            let html =
                r#"<link rel="alternate" type="application/activity+json" href="/ap/posts/1">"#;
            let base = url::Url::parse("https://oeee.cafe/@pokemon/1").unwrap();
            assert_eq!(
                html_alternate(html, &base).as_deref(),
                Some("https://oeee.cafe/ap/posts/1")
            );
        }

        #[test]
        fn rel_is_a_token_list() {
            let html = r#"<link rel="me alternate" type="application/activity+json" href="https://a.test/1">"#;
            let base = url::Url::parse("https://a.test/page").unwrap();
            assert_eq!(
                html_alternate(html, &base).as_deref(),
                Some("https://a.test/1")
            );
        }

        #[test]
        fn a_page_naming_no_object_resolves_to_nothing() {
            let html = r#"<html><head><title>a page</title></head></html>"#;
            let base = url::Url::parse("https://a.test/page").unwrap();
            assert_eq!(html_alternate(html, &base), None);
        }
    }
}
