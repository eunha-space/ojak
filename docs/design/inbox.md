The inbox
=========

Step 5 of *framework.md*: what Feder does with an activity another server
POSTs. Listeners registered per activity type receive it typed, from a
sender Feder has authenticated, with nothing in it trusted that the sender
could not vouch for. It is last among the steps because a mistake here is a
security problem, and the two applications between them show every kind.


What the two applications do now
--------------------------------

Eunha verifies signatures itself, both schemes, with the policy of step 2,
falls back to an FEP-8b32 proof, answers 202 for an unverified `Delete`,
queues the activity in `eunha.inbox_jobs` and dispatches on the `type`
string. oeee-cafe hands the request to `activitypub_federation`, whose axum
inbox reads a body of any size, checks draft-cavage signatures without
checking the body against its digest, and dispatches through an untagged
serde enum, synchronously, inside the request.

Neither checked, before September 2026, that an activity acts only on what
its sender owns, and each had its own way of not checking:

 -  oeee-cafe deleted any post of its own a remote `Delete` named, and
    undid any reaction or follow a remote `Undo` named, a local user's
    included;
 -  eunha rewrote any account an `Update` named, public key included, which
    is an account takeover; edited any status an `Update(Note)` named; and
    stored an embedded note under whatever URI and author it claimed.

Each was fixed where it was, with a test. This step makes the rule the
framework's, so that no listener has the chance to forget it.


Decisions
---------

### The sender is authenticated, and is the only one trusted

Before a listener sees anything, Feder establishes one fact: which actor sent
the activity. Everything the activity says about anyone else is a claim.

1.  The body is bounded (1 MiB unless configured), and must be a JSON object
    with an `actor`.
2.  A `blocked` hook sees the host the activity claims to come from before any
    key is fetched, so a blocked server costs nothing. A blocked activity is
    answered 202 and dropped, so the server does not retry it.
3.  The HTTP signature is parsed and held to step 2's policy: it covers the
    request target, the host, the date and the digest, the digest matches
    the body, and it was made for this host within the hour.
4.  The key comes from the key-value store or is fetched, and has to be one
    its actor publishes as its own; a key that no longer verifies is fetched
    once more. The *sender* is that actor.
5.  Failing a signature, an FEP-8b32 integrity proof on the activity
    authenticates it instead, with a key the actor lists in its
    `assertionMethod`.
6.  The activity's `actor`, and its `id` when it has one, have to be on the
    sender's origin. A server vouches for its own actors, as Mastodon's rule
    has it, and for nobody else's.
7.  A request signed by a server other than the actor's was forwarded: by a
    gateway (*portable.md*), or by a server passing a reply on to its
    followers. Its signature says nothing of the actor, so a proof by the
    actor is looked for, and failing that the activity is fetched from its
    `id` and processed as the actor's server serves it, if it names the same
    actor. Only a request that verified gets this far, so an unsigned POST
    cannot make the server fetch.

An activity that is not authenticated is answered 401, except a `Delete`,
which is answered 202 and dropped: the usual reason a `Delete` does not
verify is that its actor is gone, key and all, and the server will retry it
until told otherwise. An `on_unverified` hook sees every one, which is where
an application removes an actor whose deletion it could not verify but whose
document is now gone.

### Nothing embedded is trusted that the sender cannot vouch for

An activity may embed its object, and the object may claim an `id` and an
author. Feder keeps an embedded object only when its `id` is on the sender's
origin and every author it names is too. Anything else is reduced to its
`id` before a listener sees it, so the listener fetches it from where the id
says it lives, with the fetcher, which establishes it the same way. An
`Announce` of someone else's post, the ordinary case, arrives as a reference.

Rules that need the application's data stay the listener's: that an `Undo`
names the sender's own `Follow`, that a `Delete` names something the sender
owns. The listener receives the sender to compare against, and Feder never
hands it an activity whose sender is in doubt.

### Listeners are typed

~~~~ rust
.inbox("person", "/ap/users/{user_id}/inbox")
.inbox("group", "/ap/communities/{community_id}/inbox")
.shared_inbox("/ap/inbox")
.on::<Follow>(on_follow)
.on::<Create>(on_create)
.on::<Undo>(on_undo)
~~~~

A listener is an async function of the context and a `Received<T>`:

 -  `activity`, the activity read into `T`, a generated vocabulary type;
 -  `sender`, the authenticated actor;
 -  `recipient`, the actor whose inbox it arrived at, or `None` for the shared
    inbox, where the listener works the recipients out from the addressing;
 -  `document`, the activity as it arrived, for forwarding;
 -  `lost`, what reading it into `T` did not keep.

The listener is chosen by the activity's `type` after normalisation, so
`as:Follow` and `Follow` reach the same one. An activity with no listener is
answered 202 and dropped, as Mastodon does.

### Queued, or not

With a queue, an authenticated activity is queued in the queue named `inbox`
and answered 202; an `InboxWorker` claims it and runs its listener, retrying
a listener that fails with the queue's retry policy. The queue is the
application's, per request: eunha's tenants each have their own database, so
the queue comes from the data, `.inbox_queue(|data| data.queue())`. Without
one, the listener runs inside the request, and a listener that fails is
answered 500, so the sender retries.

An activity processed once is not processed again: its `id` goes into the
key-value store, under the canonical origin it arrived at, for a day.

### Forwarding

A reply to a post of ours reaches the servers its author sent it to, and
not the followers of the post's author, who would see half a conversation.
ActivityPub (§7.1.2) has the server that owns the post pass it on: an
activity seen for the first time, addressed to a collection of ours, that
concerns something of ours in its `object`, `target`, `inReplyTo` or `tag`,
or in those of the object it embeds. Feder decides that, and calls the
application's `forward` with the activity and the collections; the
application sends it to their members, signed by the collection's owner,
as Mastodon does. Whether it was forwarded is kept in the key-value store
under its `id`, so it is forwarded once.

What is forwarded is the activity as it was authenticated here, whose proof,
if it has one, still holds; a server receiving it without one fetches it
from its origin, as above.

### Errors and responses

| Outcome                                   | Status |
| ----------------------------------------- | ------ |
| queued, run, blocked, duplicate, unknown  | 202    |
| unauthenticated `Delete`                  | 202    |
| body too large                            | 413    |
| not a JSON object, no `actor`             | 400    |
| actor or id on another origin than sender | 401    |
| unauthenticated                           | 401    |
| listener failed, no queue                 | 500    |


What moves
----------

**oeee-cafe** first: `activitypub_federation` goes. Its listeners become
`on::<Follow>`, `on::<Create>`, `on::<Undo>`, `on::<Update>`,
`on::<Delete>`, `on::<Like>` and `on::<EmojiReact>`, reading the generated
types, and its actors are fetched with `Fetcher::lookup_as` instead of
`ObjectId::dereference`. The pre-check added in September is Feder's now.

**Eunha**: its handlers become listeners over its existing `inbox_jobs`, or
over `eunha.feder_queue` beside its deliveries; its signature code, the
fallback to a proof and the `Delete` rule are Feder's.


Not in this step
----------------

 -  *Portable objects* (FEP-ef61), which are step 7.
 -  *Relays.*
