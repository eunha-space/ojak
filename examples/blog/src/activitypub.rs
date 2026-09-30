//! The federation: what the blog serves to other servers, and where it
//! receives what they send.
//!
//! Every URI the blog writes comes from the templates registered here,
//! through a [`Context`], so a route and the links to it cannot disagree.

use crate::store::Post;
use crate::{App, Config, inbox, web};
use ojak::federation::{
    ActorRef, BuildError, Collection, Context, Error, Federation, First, Found, NodeInfo, Page,
    PublicKey, Software, with_keys,
};
use ojak::fetch::Fetcher;
use ojak::kv::MemoryKvStore;
use ojak::template::Values;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// The kinds everything is registered under, and their templates.
pub const AUTHOR: &str = "author";
const AUTHOR_PATH: &str = "/users/{username}";
pub const POST: &str = "post";
const POST_PATH: &str = "/posts/{id}";
pub const CREATE: &str = "create";
const CREATE_PATH: &str = "/posts/{id}/create";
pub const OUTBOX: &str = "outbox";
pub const FOLLOWERS: &str = "followers";

const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";
/// How many posts one page of the outbox holds.
const PAGE_SIZE: usize = 10;

// #region federation
/// The federation, registered once and serving every request.
///
/// # Errors
///
/// When a template is wrong.
pub fn federation(config: &Config, fetcher: Arc<Fetcher>) -> Result<Federation<App>, BuildError> {
    Federation::builder()
        .origin(config.origin.clone())
        // The author, found by username, and by `@username@host` through
        // WebFinger.
        .actor(AUTHOR, AUTHOR_PATH, author)
        .key_pairs(|ctx: Context<App>, actor: ActorRef| async move {
            let id = ctx.actor_uri(&actor.kind, &actor.identifier)?;
            Ok::<_, Error>(vec![PublicKey::Rsa {
                id: format!("{id}#main-key"),
                pem: ctx.data().config.public_key_pem.clone(),
            }])
        })
        .handle(|ctx: Context<App>, username: String| async move {
            let ours = username == ctx.data().config.username;
            Ok::<_, Error>(ours.then(|| ActorRef::new(AUTHOR, username)))
        })
        // Posts, and the activity that created each.
        .object(
            POST,
            POST_PATH,
            |ctx: Context<App>, values: Values| async move { found(&ctx, &values, article) },
        )
        .object(
            CREATE,
            CREATE_PATH,
            |ctx: Context<App>, values: Values| async move { found(&ctx, &values, create) },
        )
        .collection(OUTBOX, "/users/{username}/outbox", outbox())
        .collection(FOLLOWERS, "/users/{username}/followers", followers())
        .nodeinfo(|ctx: Context<App>| async move {
            let mut info = NodeInfo::new(Software {
                name: "ojak-example-blog".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                repository: Some("https://github.com/eunha-space/ojak".to_owned()),
                homepage: None,
            });
            info.usage.users_total = Some(1);
            info.usage.local_posts = Some(ctx.data().store().posts().count() as u64);
            Ok::<_, Error>(info)
        })
        // Where activities arrive, and what verifies them: the fetcher
        // fetches senders' keys, the store caches them, and the author's key
        // signs those fetches for servers that require it.
        .inbox(AUTHOR, "/users/{username}/inbox")
        .shared_inbox("/inbox")
        .signed_fetch(
            fetcher,
            MemoryKvStore::new(),
            Duration::from_secs(60 * 60),
            |ctx: Context<App>| async move { Ok::<_, Error>(Some(ctx.data().key.clone())) },
        )
        .on(inbox::follow)
        .on(inbox::undo)
        .on(inbox::create)
        .on(inbox::like)
        .on(inbox::delete)
        .on_error(|error| eprintln!("ActivityPub: {error}"))
        .build()
}
// #endregion federation

/// The author's IRI. The key that signs for the author is named after it
/// before any request comes in, so it is joined here; [`author`] serves the
/// same one, built from its template.
///
/// # Errors
///
/// When the origin cannot take a path.
pub fn author_id(config: &Config) -> Result<Url, url::ParseError> {
    config.origin.join(&format!("users/{}", config.username))
}

// #region author
/// The author, as a `Person`.
async fn author(ctx: Context<App>, username: String) -> Result<Found<Value>, Error> {
    let config = &ctx.data().config;
    if username != config.username {
        return Ok(Found::NotFound);
    }
    let id = ctx.actor_uri(AUTHOR, &username)?;
    let mut actor = json!({
        "id": id.as_str(),
        "type": "Person",
        "preferredUsername": username,
        "name": config.title,
        "url": ctx.origin().as_str(),
        "inbox": ctx.origin().join(&format!("users/{username}/inbox"))?.as_str(),
        "outbox": ctx.collection_uri(OUTBOX, &username)?.as_str(),
        "followers": ctx.collection_uri(FOLLOWERS, &username)?.as_str(),
        "endpoints": {"sharedInbox": ctx.origin().join("inbox")?.as_str()},
        "manuallyApprovesFollowers": false,
        "discoverable": true,
    });
    let keys = ctx.actor_keys(&ActorRef::new(AUTHOR, username)).await?;
    with_keys(&mut actor, &keys);
    Ok(Found::Found(actor))
}
// #endregion author

/// The post `values` names, as `document` writes it.
fn found(
    ctx: &Context<App>,
    values: &Values,
    document: fn(&Context<App>, &Post) -> Result<Value, Error>,
) -> Result<Found<Value>, Error> {
    let Ok(id) = values["id"].parse() else {
        return Ok(Found::NotFound);
    };
    let post = ctx.data().store().post(id).cloned();
    match post {
        Some(post) => Ok(Found::Found(document(ctx, &post)?)),
        None => Ok(Found::NotFound),
    }
}

// #region article
/// A post, as an `Article`: Mastodon shows its title and links to it.
///
/// # Errors
///
/// When a URI cannot be built.
pub fn article(ctx: &Context<App>, post: &Post) -> Result<Value, Error> {
    let username = &ctx.data().config.username;
    let id = ctx.object_uri(POST, &[("id", &post.id.to_string())])?;
    Ok(json!({
        "id": id.as_str(),
        "type": "Article",
        "attributedTo": ctx.actor_uri(AUTHOR, username)?.as_str(),
        "name": post.title,
        "content": web::content(&post.body)?,
        "url": id.as_str(),
        "published": post.published.to_rfc3339(),
        "to": [PUBLIC],
        "cc": [ctx.collection_uri(FOLLOWERS, username)?.as_str()],
    }))
}

/// The `Create` that published a post, with the post in it: what followers
/// are sent.
///
/// # Errors
///
/// When a URI cannot be built.
pub fn create(ctx: &Context<App>, post: &Post) -> Result<Value, Error> {
    let username = &ctx.data().config.username;
    let article = article(ctx, post)?;
    Ok(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": ctx.object_uri(CREATE, &[("id", &post.id.to_string())])?.as_str(),
        "type": "Create",
        "actor": ctx.actor_uri(AUTHOR, username)?.as_str(),
        "published": article["published"],
        "to": article["to"],
        "cc": article["cc"],
        "object": article,
    }))
}
// #endregion article

// #region outbox
/// The author's posts, newest first, as their `Create`s, ten to a page. A
/// page's cursor is the ID of the newest post on it.
fn outbox() -> Collection<App> {
    Collection::new(
        |ctx: Context<App>, username: String, cursor: Option<String>| async move {
            if username != ctx.data().config.username {
                return Ok(None);
            }
            let newest = cursor.and_then(|c| c.parse().ok()).unwrap_or(u64::MAX);
            let posts: Vec<Post> = ctx
                .data()
                .store()
                .posts()
                .filter(|post| post.id <= newest)
                .take(PAGE_SIZE + 1)
                .cloned()
                .collect();
            let next = posts.get(PAGE_SIZE).map(|post| post.id.to_string());
            let items = posts
                .iter()
                .take(PAGE_SIZE)
                .map(|post| create(&ctx, post))
                .collect::<Result<_, _>>()?;
            Ok::<_, Error>(Some(Page {
                items,
                next,
                prev: None,
            }))
        },
    )
    .count(|ctx: Context<App>, _| async move {
        Ok::<_, Error>(Some(ctx.data().store().posts().count() as u64))
    })
    .first_cursor(|ctx: Context<App>, _| async move {
        let newest = ctx.data().store().posts().next().map_or(0, |post| post.id);
        Ok::<_, Error>(Some(First::At(newest.to_string())))
    })
}
// #endregion outbox

// #region followers
/// Who follows the blog: counted, and not listed.
fn followers() -> Collection<App> {
    Collection::new(|ctx: Context<App>, username: String, _| async move {
        let ours = username == ctx.data().config.username;
        Ok::<_, Error>(ours.then(Page::default))
    })
    .count(|ctx: Context<App>, _| async move {
        Ok::<_, Error>(Some(ctx.data().store().follower_count() as u64))
    })
    .first_cursor(|_, _| async { Ok::<_, Error>(Some(First::Hidden)) })
}
// #endregion followers
