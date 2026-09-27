//! Portable decision logic for inbound activities, expressed as `Input -> Actions`.
//!
//! These functions contain no IO: given the parsed activity plus the small bits
//! of context the host already knows (e.g. whether the target account is
//! locked), they return the [`Action`]s the host should carry out against its
//! own storage and delivery. This keeps the *decision* portable and unit
//! testable, while the host owns persistence and transport.

use alloc::vec;
use alloc::vec::Vec;

use feder_vocab::{Accept, Follow, Iri, Reference};

/// An effect the host should perform in response to an inbound activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Persist an accepted follower relationship.
    RecordFollow,
    /// Persist a pending follow request (the target account is locked).
    RecordFollowRequest,
    /// Deliver this `Accept` activity to the follower's inbox.
    SendAccept(Accept),
}

/// Resolve the IRI an actor reference points at.
fn actor_ref_id<T>(reference: &Reference<T>) -> Option<&Iri>
where
    T: AsActorId,
{
    match reference {
        Reference::Id(id) => Some(id),
        Reference::Object(object) => Some(object.actor_id()),
    }
}

/// Lets the embedded-object branch of a [`Reference`] expose its id.
pub trait AsActorId {
    fn actor_id(&self) -> &Iri;
}

impl AsActorId for feder_vocab::Actor {
    fn actor_id(&self) -> &Iri {
        &self.id
    }
}

/// Decide how to handle an inbound `Follow` addressed to `local_actor`.
///
/// - Returns no actions if the follow targets someone other than `local_actor`.
/// - A locked account yields a single [`Action::RecordFollowRequest`].
/// - Otherwise the follow is accepted: [`Action::RecordFollow`] plus an
///   [`Action::SendAccept`] carrying the `Accept` to deliver (with the embedded
///   `Follow`'s own `@context` cleared, as it is nested).
#[must_use]
pub fn on_follow(follow: Follow, local_actor: &Iri, locked: bool, accept_id: Iri) -> Vec<Action> {
    let Some(object_id) = actor_ref_id(&follow.object) else {
        return Vec::new();
    };
    if object_id != local_actor {
        return Vec::new();
    }

    if locked {
        return vec![Action::RecordFollowRequest];
    }

    let mut embedded = follow;
    embedded.context = None;
    let accept = Accept::new(
        accept_id,
        Reference::id(local_actor.clone()),
        Reference::object(embedded),
    );
    vec![Action::RecordFollow, Action::SendAccept(accept)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iri(s: &str) -> Iri {
        s.parse().expect("valid IRI")
    }

    fn follow_to(target: &str) -> Follow {
        Follow::new(
            iri("https://remote.test/users/bob/follows/1"),
            Reference::id(iri("https://remote.test/users/bob")),
            Reference::id(iri(target)),
        )
    }

    #[test]
    fn unlocked_follow_accepts_and_sends() {
        let me = iri("https://a.test/users/alice");
        let actions = on_follow(
            follow_to("https://a.test/users/alice"),
            &me,
            false,
            iri("https://a.test/accepts/1"),
        );
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], Action::RecordFollow);
        match &actions[1] {
            Action::SendAccept(accept) => {
                // The embedded Follow carries no @context.
                match &accept.object {
                    Reference::Object(f) => assert!(f.context.is_none()),
                    Reference::Id(_) => panic!("expected embedded Follow"),
                }
            }
            other => panic!("expected SendAccept, got {other:?}"),
        }
    }

    #[test]
    fn locked_follow_is_pending() {
        let me = iri("https://a.test/users/alice");
        let actions = on_follow(
            follow_to("https://a.test/users/alice"),
            &me,
            true,
            iri("https://a.test/accepts/1"),
        );
        assert_eq!(actions, vec![Action::RecordFollowRequest]);
    }

    #[test]
    fn follow_for_someone_else_is_ignored() {
        let me = iri("https://a.test/users/alice");
        let actions = on_follow(
            follow_to("https://a.test/users/carol"),
            &me,
            false,
            iri("https://a.test/accepts/1"),
        );
        assert!(actions.is_empty());
    }
}
