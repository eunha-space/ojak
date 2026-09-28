//! Whether a request asks for ActivityPub.

/// Whether `accept` names ActivityStreams, `application/activity+json` or
/// `application/ld+json`, with a quality above zero. A browser's `text/html`,
/// a bare `*/*` and no `Accept` at all are not: the page at the same URL is
/// the application's to serve.
pub(super) fn wants_activity(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    accept.split(',').any(|range| {
        let mut parts = range.split(';').map(str::trim);
        let essence = parts.next().unwrap_or_default().to_ascii_lowercase();
        let quality = parts
            .filter_map(|parameter| parameter.split_once('='))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
            .and_then(|(_, value)| value.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        quality > 0.0
            && matches!(
                essence.as_str(),
                "application/activity+json" | "application/ld+json"
            )
    })
}

#[cfg(test)]
mod tests {
    use super::wants_activity;

    #[test]
    fn activitystreams_is_asked_for_in_either_media_type() {
        for accept in [
            "application/activity+json",
            "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
            "application/ld+json",
            "text/html;q=0.1, application/activity+json",
            "APPLICATION/ACTIVITY+JSON;q=0.5",
        ] {
            assert!(wants_activity(Some(accept)), "{accept}");
        }
        for accept in [
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "*/*",
            "application/json",
            "application/activity+json;q=0",
            "",
        ] {
            assert!(!wants_activity(Some(accept)), "{accept}");
        }
        assert!(!wants_activity(None));
    }
}
