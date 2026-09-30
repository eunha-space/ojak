//! What the blog does with the activities it receives.
//!
//! Each listener runs only once Ojak has authenticated the sender, and
//! `received.sender` is that sender. Anything else an activity says is a
//! claim: an object it embeds that the sender could not vouch for arrives
//! as a bare reference. What only the blog's data can decide, such as
//! whether an `Undo` names the sender's own follow, is decided here.

use crate::App;
use crate::activitypub::{AUTHOR, POST};
use crate::store::{Comment, Follower};
use ojak::federation::{Context, Error, Received, Route};
use ojak_vocab::{AnyObject, Create, Delete, Follow, Like, Undo};
use serde_json::json;
use url::Url;

// #region follow
/// Someone follows the blog: note where to deliver to them, and accept.
pub async fn follow(ctx: Context<App>, follow: Received<Follow>) -> Result<(), Error> {
    let blog = ctx.data();
    let author = ctx.actor_uri(AUTHOR, &blog.config.username)?;
    if !names(&follow.activity.objects, author.as_str()) {
        return Ok(());
    }
    let Some(id) = follow.activity.id.as_ref().map(ToString::to_string) else {
        return Ok(());
    };

    // The follower's actor document says where their inbox is. The fetch
    // is signed with the author's key, for servers that require it.
    let actor = blog.fetcher.lookup(&follow.sender, Some(&blog.key)).await?;
    let inbox = actor.json["endpoints"]["sharedInbox"]
        .as_str()
        .or_else(|| actor.json["inbox"].as_str())
        .ok_or("the follower has no inbox")?;
    let inbox: Url = inbox.parse()?;
    blog.store().follow(
        follow.sender.clone(),
        Follower {
            follow: id.clone(),
            inbox: inbox.clone(),
        },
    );

    let accept = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{author}#accepts/{}", blog.store().next_id()),
        "type": "Accept",
        "actor": author.as_str(),
        "object": follow.document,
    });
    blog.deliverer
        .send(author.as_str(), &accept, [inbox])
        .await?;
    Ok(())
}
// #endregion follow

// #region undo
/// Someone stops following. Only the sender's own follow is removed: the
/// follower is looked up by the sender, and the follow has to be theirs.
pub async fn undo(ctx: Context<App>, undo: Received<Undo>) -> Result<(), Error> {
    for object in &undo.activity.objects {
        if let Some(follow) = object.id() {
            ctx.data().store().unfollow(&undo.sender, follow.as_str());
        }
    }
    Ok(())
}
// #endregion undo

// #region create
/// A reply to one of the posts becomes a comment under it.
pub async fn create(ctx: Context<App>, create: Received<Create>) -> Result<(), Error> {
    for object in &create.activity.objects {
        // A note the sender could not vouch for arrives as a reference, and
        // is left alone here; fetching it is an exercise in the tutorial.
        let AnyObject::Note(note) = object else {
            continue;
        };
        let (Some(id), Some(text)) = (&note.id, &note.content.value) else {
            continue;
        };
        for target in &note.reply_targets {
            if let Some(post) = target.id().and_then(|iri| our_post(&ctx, iri.as_str())) {
                ctx.data().store().comment(
                    post,
                    Comment {
                        id: id.to_string(),
                        author: create.sender.clone(),
                        text: crate::web::strip_tags(text),
                    },
                );
            }
        }
    }
    Ok(())
}
// #endregion create

// #region like
/// A like of one of the posts is counted, once per actor.
pub async fn like(ctx: Context<App>, like: Received<Like>) -> Result<(), Error> {
    for object in &like.activity.objects {
        if let Some(post) = object.id().and_then(|iri| our_post(&ctx, iri.as_str())) {
            ctx.data().store().like(post, like.sender.clone());
        }
    }
    Ok(())
}
// #endregion like

// #region delete
/// A reply deleted where it was written is removed here too, if its author
/// is the one deleting it.
pub async fn delete(ctx: Context<App>, delete: Received<Delete>) -> Result<(), Error> {
    for object in &delete.activity.objects {
        if let Some(id) = object.id() {
            ctx.data().store().uncomment(id.as_str(), &delete.sender);
        }
    }
    Ok(())
}
// #endregion delete

/// Whether `objects` names the IRI `id`.
fn names(objects: &[AnyObject], id: &str) -> bool {
    objects
        .iter()
        .any(|object| object.id().is_some_and(|iri| iri.as_str() == id))
}

// #region our-post
/// The post `iri` is, if it is one of ours.
fn our_post(ctx: &Context<App>, iri: &str) -> Option<u64> {
    match ctx.parse_uri(iri)? {
        Route::Object { kind, values } if kind == POST => values["id"].parse().ok(),
        _ => None,
    }
}
// #endregion our-post
