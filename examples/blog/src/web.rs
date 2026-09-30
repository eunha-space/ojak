//! What a browser sees, and how the author publishes.
//!
//! A post's page is at the same URL as the post's ActivityPub document:
//! Ojak answers a request that asks for ActivityPub, and passes any other,
//! such as a browser's, on to these routes. Pages are minijinja templates,
//! in *templates/*, which escape what they are given.

use crate::activitypub::{self, AUTHOR};
use crate::{App, Blog};
use axum::Router;
use axum::extract::{Form, Json, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use minijinja::{Environment, Value, context};
use serde::Deserialize;
use serde_json::json;
use std::sync::LazyLock;

/// The templates, compiled into the binary.
static TEMPLATES: LazyLock<Environment<'static>> = LazyLock::new(|| {
    let mut env = Environment::new();
    for (name, source) in [
        ("base.html", include_str!("../templates/base.html")),
        ("home.html", include_str!("../templates/home.html")),
        ("post.html", include_str!("../templates/post.html")),
        ("new.html", include_str!("../templates/new.html")),
        ("content.html", include_str!("../templates/content.html")),
    ] {
        env.add_template(name, source)
            .expect("the templates are well formed");
    }
    env
});

/// Render the template `name` with `ctx` and the blog's title.
fn render(blog: &Blog, name: &str, ctx: Value) -> Result<Html<String>, StatusCode> {
    let ctx = context! { blog_title => blog.config.title, ..ctx };
    TEMPLATES
        .get_template(name)
        .and_then(|template| template.render(ctx))
        .map(Html)
        .map_err(|error| {
            eprintln!("rendering {name}: {error:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

pub fn router() -> Router<App> {
    Router::new()
        .route("/", get(home))
        .route("/posts/{id}", get(post_page))
        .route("/users/{username}", get(|| async { Redirect::to("/") }))
        .route("/new", get(compose).post(publish_form))
        .route("/api/posts", post(publish))
}

async fn home(State(blog): State<App>) -> Result<Html<String>, StatusCode> {
    let posts: Vec<Value> = blog
        .store()
        .posts()
        .map(|post| {
            context! {
                id => post.id,
                title => post.title,
                date => post.published.format("%Y-%m-%d").to_string(),
            }
        })
        .collect();
    let handle = format!(
        "@{}@{}",
        blog.config.username,
        blog.config.origin.host_str().unwrap_or_default()
    );
    render(&blog, "home.html", context! { handle, posts })
}

// #region post-page
async fn post_page(
    State(blog): State<App>,
    Path(id): Path<u64>,
) -> Result<Html<String>, StatusCode> {
    let ctx = {
        let store = blog.store();
        let post = store.post(id).ok_or(StatusCode::NOT_FOUND)?;
        let comments: Vec<Value> = store
            .comments(id)
            .iter()
            .map(|comment| context! { author => comment.author.as_str(), text => comment.text })
            .collect();
        context! {
            title => post.title,
            date => post.published.format("%Y-%m-%d").to_string(),
            paragraphs => paragraphs(&post.body),
            likes => store.like_count(id),
            comments,
        }
    };
    render(&blog, "post.html", ctx)
}
// #endregion post-page

/// The page the author writes a post on.
async fn compose(State(blog): State<App>) -> Result<Html<String>, StatusCode> {
    render(&blog, "new.html", context! {})
}

#[derive(Deserialize)]
struct Compose {
    title: String,
    body: String,
    token: String,
}

/// Publish what the page above sends, and show the post.
async fn publish_form(
    State(blog): State<App>,
    Form(new): Form<Compose>,
) -> Result<Redirect, StatusCode> {
    if new.token != blog.config.token {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let url = publish_and_deliver(&blog, new.title, new.body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Redirect::to(url.path()))
}

#[derive(Deserialize)]
struct NewPost {
    title: String,
    body: String,
}

/// Publish a post from a program, such as `curl`. Takes the configured
/// token as `Authorization: Bearer …`, and answers with the post's URL.
async fn publish(
    State(blog): State<App>,
    headers: HeaderMap,
    Json(new): Json<NewPost>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    let bearer = format!("Bearer {}", blog.config.token);
    if headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()) != Some(bearer.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let url = publish_and_deliver(&blog, new.title, new.body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::CREATED, Json(json!({"url": url.as_str()}))))
}

// #region publish
/// Publish a post, and queue its `Create` for every follower's inbox. The
/// deliverer sends it in the background, retrying each inbox on its own.
/// Returns the post's URL.
async fn publish_and_deliver(
    blog: &std::sync::Arc<Blog>,
    title: String,
    body: String,
) -> Result<url::Url, ojak::federation::Error> {
    let post = blog.store().publish(title, body);
    let ctx = blog.context();
    let create = activitypub::create(&ctx, &post)?;
    let author = ctx.actor_uri(AUTHOR, &blog.config.username)?;
    let inboxes = blog.store().inboxes();
    blog.deliverer
        .send(author.as_str(), &create, inboxes)
        .await?;
    Ok(ctx.object_uri(activitypub::POST, &[("id", &post.id.to_string())])?)
}
// #endregion publish

/// A post's body as HTML, for its ActivityPub document: the paragraphs
/// the page shows, through the same template.
///
/// # Errors
///
/// When the template cannot be rendered.
pub fn content(body: &str) -> Result<String, minijinja::Error> {
    let html = TEMPLATES
        .get_template("content.html")?
        .render(context! { paragraphs => paragraphs(body) })?;
    Ok(html.trim_end().to_owned())
}

/// The paragraphs of a plain-text body: the runs of lines between blank
/// ones.
fn paragraphs(text: &str) -> Vec<&str> {
    text.split("\n\n")
        .map(str::trim)
        .filter(|paragraph| !paragraph.is_empty())
        .collect()
}

/// The text of `html`, its tags removed. A reply's content is HTML from
/// another server, and is never shown as HTML; an application that wants
/// to keep its links and formatting runs it through a sanitiser, such as
/// the `ammonia` crate, instead.
#[must_use]
pub fn strip_tags(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in html.replace("</p>", " </p>").chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => text.push(c),
            _ => {}
        }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
