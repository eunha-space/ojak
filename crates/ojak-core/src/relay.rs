//! Relays: servers that pass public activities between the servers that
//! subscribe to them, so that a small server sees more than its own users
//! follow.
//!
//! Two conventions are in use, and a relay speaks one of them:
//!
//!  -  *Mastodon's*: the subscriber follows the public collection,
//!     `as:Public`, at the relay's inbox; it sends the relay its public
//!     activities, and the relay sends them on to every other subscriber as
//!     they were, under its own HTTP signature.
//!  -  *LitePub's* (Pleroma, Akkoma, and relays written for them): the
//!     subscriber follows the relay's actor, and the relay `Announce`s what it
//!     passes on.
//!
//! What a relay sends on is signed by the relay, not by the activity's
//! author, so the inbox takes it as forwarded: from its proof, or fetched
//! from its origin. Nothing here is trusted for coming through a relay.
//!
//! These build the activities a subscription needs and recognise the
//! answers; the application keeps which relays it subscribes to, and
//! delivers to their inboxes.

use alloc::boxed::Box;
use alloc::vec;

use ojak_vocab::{ACTIVITYSTREAMS_PUBLIC, Accept, AnyActor, AnyObject, Follow, Iri, Reject, Undo};

/// Which convention a relay speaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// Follow `as:Public`; the relay sends activities on as they were.
    Mastodon,
    /// Follow the relay's actor; the relay `Announce`s.
    LitePub,
}

/// The `Follow` that subscribes `local_actor`, the server's own actor, to the
/// relay whose actor is `relay_actor`. It is delivered to the relay's inbox.
#[must_use]
pub fn subscribe(protocol: Protocol, local_actor: &Iri, relay_actor: &Iri, id: Iri) -> Follow {
    let object = match protocol {
        Protocol::Mastodon => public(),
        Protocol::LitePub => relay_actor.clone(),
    };
    Follow {
        id: Some(id),
        actors: vec![AnyActor::Iri(local_actor.clone())],
        objects: vec![AnyObject::Iri(object)],
        tos: vec![AnyObject::Iri(relay_actor.clone())],
        ..Follow::default()
    }
}

/// The `Undo` that ends the subscription `follow` made.
#[must_use]
pub fn unsubscribe(follow: Follow, id: Iri) -> Undo {
    Undo {
        id: Some(id),
        actors: follow.actors.clone(),
        tos: follow.tos.clone(),
        objects: vec![AnyObject::Follow(Box::new(follow))],
        ..Undo::default()
    }
}

/// What a relay answered a subscription with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Answer {
    Accepted,
    Rejected,
}

/// Whether `accept`, from `sender`, accepts the subscription `follow_id`
/// made to the relay whose actor is `relay_actor`. A relay's `Accept` names
/// the `Follow` by its `id` or embeds it; one from anyone but the relay says
/// nothing.
#[must_use]
pub fn accepted(accept: &Accept, sender: &Iri, relay_actor: &Iri, follow_id: &Iri) -> bool {
    sender == relay_actor && names(&accept.objects, follow_id)
}

/// As [`accepted`], for a `Reject`.
#[must_use]
pub fn rejected(reject: &Reject, sender: &Iri, relay_actor: &Iri, follow_id: &Iri) -> bool {
    sender == relay_actor && names(&reject.objects, follow_id)
}

fn names(objects: &[AnyObject], follow_id: &Iri) -> bool {
    objects.iter().any(|object| object.id() == Some(follow_id))
}

/// Whether an activity of `kind` addressed `to` and `cc` is one to send to
/// the relays: public, and a kind a relay passes on.
#[must_use]
pub fn relayed(kind: &str, to: &[AnyObject], cc: &[AnyObject]) -> bool {
    let public = public();
    matches!(kind, "Create" | "Update" | "Delete" | "Announce" | "Move")
        && to
            .iter()
            .chain(cc)
            .any(|audience| audience.id() == Some(&public))
}

fn public() -> Iri {
    ACTIVITYSTREAMS_PUBLIC
        .parse()
        .expect("the public collection is an IRI")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iri(s: &str) -> Iri {
        s.parse().expect("valid IRI")
    }

    #[test]
    fn each_convention_follows_its_own_object() {
        let me = iri("https://a.test/actor");
        let relay = iri("https://relay.test/actor");
        let id = iri("https://a.test/follows/relay");
        let mastodon = subscribe(Protocol::Mastodon, &me, &relay, id.clone());
        assert_eq!(mastodon.objects, vec![AnyObject::Iri(public())]);
        assert_eq!(mastodon.actors, vec![AnyActor::Iri(me.clone())]);
        let litepub = subscribe(Protocol::LitePub, &me, &relay, id.clone());
        assert_eq!(litepub.objects, vec![AnyObject::Iri(relay.clone())]);

        let undo = unsubscribe(litepub.clone(), iri("https://a.test/undos/1"));
        assert_eq!(undo.objects, vec![AnyObject::Follow(Box::new(litepub))]);
    }

    #[test]
    fn only_the_relay_accepts_its_subscription() {
        let relay = iri("https://relay.test/actor");
        let follow = iri("https://a.test/follows/relay");
        let accept = Accept {
            objects: vec![AnyObject::Iri(follow.clone())],
            ..Accept::default()
        };
        assert!(accepted(&accept, &relay, &relay, &follow));
        assert!(!accepted(
            &accept,
            &iri("https://mallory.test/actor"),
            &relay,
            &follow
        ));
        assert!(!accepted(
            &accept,
            &relay,
            &relay,
            &iri("https://a.test/follows/other")
        ));
    }

    #[test]
    fn what_is_public_is_relayed() {
        let public = vec![AnyObject::Iri(public())];
        let followers = vec![AnyObject::Iri(iri("https://a.test/users/alice/followers"))];
        assert!(relayed("Create", &public, &[]));
        assert!(relayed("Delete", &followers, &public));
        assert!(!relayed("Create", &followers, &[]));
        assert!(!relayed("Like", &public, &[]));
    }
}
