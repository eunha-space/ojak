//! WebFinger and host-meta, which follow from the actor dispatchers.

use super::{ACTIVITY_JSON, ActorRef, Context, Error, Found, Route, authority, empty, response};
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};
use url::Url;

pub(super) const WEBFINGER_PATH: &str = "/.well-known/webfinger";
pub(super) const HOST_META_PATH: &str = "/.well-known/host-meta";

const PROFILE_PAGE: &str = "http://webfinger.net/rel/profile-page";

fn cors(mut response: http::Response<Vec<u8>>) -> http::Response<Vec<u8>> {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

pub(super) async fn webfinger<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    query: Option<&str>,
) -> http::Response<Vec<u8>> {
    let resource = query.and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == "resource")
            .map(|(_, value)| value.into_owned())
    });
    let Some(resource) = resource.filter(|resource| !resource.is_empty()) else {
        return cors(empty(StatusCode::BAD_REQUEST));
    };
    match answer(context, &resource).await {
        Ok(response) => cors(response),
        Err(error) => {
            context.report(&error);
            cors(empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// The actor `resource` names, if it is one of ours.
async fn resolve<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    resource: &str,
) -> Result<Option<ActorRef>, Error> {
    let federation = &context.inner.federation;
    if let Ok(url) = Url::parse(resource)
        && matches!(url.scheme(), "http" | "https")
    {
        if let Some(Route::Actor(actor)) = context.parse_uri(resource) {
            return Ok(Some(actor));
        }
        return match &federation.map_alias {
            Some(map) if context.is_our_host(&authority(&url)) => map(context.clone(), url).await,
            _ => Ok(None),
        };
    }
    let account = resource.strip_prefix("acct:").unwrap_or(resource);
    let account = account.strip_prefix('@').unwrap_or(account);
    let username = match account.rsplit_once('@') {
        Some((username, host)) if context.is_our_host(host) => username,
        Some(_) => return Ok(None),
        // `acct:alice` names a local account, as Mastodon reads it.
        None => account,
    };
    match &federation.handle {
        Some(handle) if !username.is_empty() => handle(context.clone(), username.to_owned()).await,
        _ => Ok(None),
    }
}

async fn answer<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
    resource: &str,
) -> Result<http::Response<Vec<u8>>, Error> {
    let Some(actor_ref) = resolve(context, resource).await? else {
        return Ok(empty(StatusCode::NOT_FOUND));
    };
    let actor = match context.load_actor(&actor_ref).await? {
        Found::Found(actor) => actor,
        Found::Gone(_) => return Ok(empty(StatusCode::GONE)),
        Found::NotFound => return Ok(empty(StatusCode::NOT_FOUND)),
    };
    let id = match actor.get("id").and_then(Value::as_str) {
        Some(id) => id.to_owned(),
        None => context
            .actor_uri(&actor_ref.kind, &actor_ref.identifier)?
            .to_string(),
    };
    let subject = match actor.get("preferredUsername").and_then(Value::as_str) {
        Some(username) => format!("acct:{username}@{}", authority(context.origin())),
        None => id.clone(),
    };
    let pages = urls(actor.get("url"));
    let mut aliases = vec![id.clone()];
    for page in &pages {
        if !aliases.contains(page) {
            aliases.push(page.clone());
        }
    }
    let mut links = vec![json!({"rel": "self", "type": ACTIVITY_JSON, "href": id})];
    if let Some(page) = pages.first() {
        links.push(json!({"rel": PROFILE_PAGE, "type": "text/html", "href": page}));
    }
    if let Some(extra) = &context.inner.federation.webfinger_links {
        links.extend(extra(context, &actor_ref, &actor));
    }
    let document = json!({"subject": subject, "aliases": aliases, "links": links});
    Ok(response(
        StatusCode::OK,
        "application/jrd+json",
        serde_json::to_vec(&document).unwrap_or_default(),
    ))
}

/// The URLs in an actor's `url`: a string, a Link with an `href`, or an array
/// of either.
fn urls(url: Option<&Value>) -> Vec<String> {
    match url {
        Some(Value::String(url)) => vec![url.clone()],
        Some(Value::Object(link)) => link
            .get("href")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .into_iter()
            .collect(),
        Some(Value::Array(values)) => values.iter().flat_map(|value| urls(Some(value))).collect(),
        _ => Vec::new(),
    }
}

/// host-meta, which older software asks for before WebFinger: where
/// WebFinger is.
pub(super) fn host_meta<D: Clone + Send + Sync + 'static>(
    context: &Context<D>,
) -> http::Response<Vec<u8>> {
    let mut template = context.origin().clone();
    template.set_path(WEBFINGER_PATH);
    template.set_query(None);
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <XRD xmlns=\"http://docs.oasis-open.org/ns/xri/xrd-1.0\">\n  \
         <Link rel=\"lrdd\" template=\"{}?resource={{uri}}\"/>\n\
         </XRD>\n",
        template
            .as_str()
            .replace('&', "&amp;")
            .replace('"', "&quot;")
    );
    cors(response(
        StatusCode::OK,
        "application/xrd+xml; charset=utf-8",
        body.into_bytes(),
    ))
}
