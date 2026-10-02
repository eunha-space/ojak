The inbox
=========

What Ojak does with an activity another server POSTs.  Listeners you
register per activity type receive it typed, from a sender Ojak has
authenticated, with nothing in it trusted that the sender could not vouch
for.  The inbox is part of `ojak::federation`, beside [serving](./serving.md),
and also accepts portable activities at gateways ([Portable
objects](./portable.md)).


Why the inbox is strict
-----------------------

An inbox has to verify signatures to a policy strict enough to matter, and
above all has to check that an activity acts only on what its sender owns.
Without that check, a remote `Delete` could delete any local post, an `Undo`
could undo a local user's follow, and an `Update` naming an account could
replace its public key, which is an account takeover.  Ojak makes the check
the framework's, so no listener can forget it.


The sender is authenticated, and is the only one trusted
--------------------------------------------------------

Before a listener sees anything, Ojak establishes one fact: which actor sent
the activity. Everything the activity says about anyone else is a claim.

Authentication needs the signed-fetch settings described in
[Serving](./serving.md#authorized-fetch-is-a-question-the-dispatcher-asks)
(`.signed_fetch`), which hold the fetcher and the key cache. Without them no
HTTP signature can be verified, and every request but a portable actor's is
unauthenticated.

1.  The body is bounded, at 1 MiB (`MAX_INBOX_BODY`), and must be a JSON
    object with an `actor`.
2.  A `blocked` hook sees the host the activity claims to come from, or a
    portable actor's DID, before any key is fetched, so a blocked server costs
    nothing. A blocked activity is answered 202 and dropped, so the server
    does not retry it. A hook that fails is a 500. The hook is asked about
    the host of the signature's key too, before the key is looked for, and
    a request signed with a key on a blocked server does not verify.
3.  The HTTP signature is parsed and checked. A draft-cavage
    signature covers `(request-target)`, `host`, and `date` or `(created)`;
    an RFC 9421 one covers `@method` and `@target-uri`. Either way the digest
    is signed and matches the body, and the signature was made for this host,
    or the canonical one, within the hour, and has not passed an `expires`
    its signer set.
4.  The key comes from the application (`known_key`), the key-value store, or
    is fetched, and has to be one its actor publishes as its own: an RSA
    `publicKey`, or, for RFC 9421, an Ed25519 Multikey it lists in its
    `assertionMethod`. A key ID that is the actor's own `id`, as PeerTube
    signs, names its `#main-key`. A key that no longer verifies is fetched
    once more. The *sender* is that actor. A
    fetched key that verifies and came with its actor's document, handed to
    an application that stores actors (`key_fetched`) and gives their keys
    back (`known_key`), is left to the application rather than cached as
    well. A key that does not verify is cached all the same, so that a run of
    forged requests does not fetch it again.
5.  Failing a signature, an FEP-8b32 integrity proof on the activity
    authenticates it instead, with a key the actor lists in its
    `assertionMethod`, on the actor's origin.
6.  The activity's `actor`, and its `id` when it has one, have to be on the
    sender's origin. A server vouches for its own actors, as Mastodon's rule
    has it, and for nobody else's.
7.  A request signed by a server other than the actor's was forwarded: by a
    gateway ([Portable objects](./portable.md)), or by a server passing a reply
    on to its followers. Its signature says nothing of the actor, so a proof by
    the actor is looked for, and failing that the activity is fetched from its
    `id` and processed as the actor's server serves it, if it is the same
    activity by the same actor. Only a request that verified gets this far, so
    an unsigned POST cannot make the server fetch.

A portable actor, whose identity is a key, is authenticated
by the proof on its activity alone, checked against its DID; an HTTP
signature on the request is ignored.

An activity that is not authenticated is answered 401, except a `Delete`,
which is answered 202 and dropped: the usual reason a `Delete` does not
verify is that its actor is gone, key and all, and the server will retry it
until told otherwise. An `on_unverified` hook sees each one, which is where
an application removes an actor whose deletion it could not verify but whose
document is now gone. A portable activity whose proof fails is stricter, and
is answered 401 even as a `Delete`; the hook sees it.

A forwarded activity that could be established neither by proof nor from its
origin is answered 202 and dropped, whatever its type, and the hook does not
see it. The forwarder's own signature verified, so a retry would change
nothing, and a 401 would only make the forwarder resend it. Mastodon
answers the same way. The reason it was dropped is the response body, for
the application to log.


Nothing embedded is trusted that the sender cannot vouch for
------------------------------------------------------------

An activity may embed its `object`, and the object may claim an `id` and an
author, in `attributedTo` or `actor`. Ojak keeps an embedded object only when
its `id` is on the sender's origin and every author it names is too. Anything
else is reduced to its `id` before a listener sees it, so the listener fetches
it from where the id says it lives, with the fetcher, which establishes it the
same way. One with no `id` that names someone else as its author is dropped.
An `Announce` of someone else's post, the ordinary case, arrives as a
reference.

Rules that need the application's data stay the listener's: that an `Undo`
names the sender's own `Follow`, that a `Delete` names something the sender
owns. The listener receives the sender to compare against, and Ojak never
hands it an activity whose sender is in doubt.


Listeners are typed
-------------------

~~~~ rust
.inbox("person", "/ap/users/{user_id}/inbox")
.inbox("group", "/ap/communities/{community_id}/inbox")
.shared_inbox("/ap/inbox")
.on::<Follow, _, _, _>(on_follow)
.on::<Create, _, _, _>(on_create)
.on(on_undo) // when on_undo's type names Received<Undo>
~~~~

A listener is an async function of the context and a `Received<T>`:

 -  `activity`, the activity read into `T`, a generated vocabulary type;
 -  `sender`, the authenticated actor, as a `Url`: a portable actor's `ap:`
    URI is percent-encoded to be one;
 -  `recipient`, the actor whose inbox it arrived at, or `None` for the shared
    inbox, where the listener works the recipients out from the addressing;
 -  `document`, the activity as it was authenticated, for forwarding;
 -  `vouched`, the activity as the sender spelled it, with what the sender
    cannot vouch for reduced;
 -  `lost`, what reading it into `T` did not keep.

The listener is chosen by the activity's `type` after normalisation, so
`as:Follow` and `Follow` reach the same one, unless the inbox reads
activities as written (`read_inbox_as_written`), when it is chosen by the
`type` the sender wrote. With more than one type, the first with a listener
is used. A type has one listener; a second is a build error. `on_any`
receives, as `Received<AnyObject>`, every activity no typed listener takes,
and an activity no listener takes is answered 202 and dropped, as Mastodon
does. An activity that cannot be read into its listener's type is reported
and answered 202 as well: retrying it would not change it.

An application that already dispatches on the type itself can take every
activity through one `on_any`, reading `vouched`, and keep its own queue.


Queued, or not
--------------

~~~~ rust
.inbox_queue(|state: &AppState| Some(state.inbox_queue.clone()))
~~~~

With a queue, an authenticated activity is queued in the queue named `inbox`
and answered 202; an `InboxWorker` claims it, reads and reduces the stored
document again, and runs its listener. The worker has its own retry policy,
with its batch, lease, concurrency and idle poll, in `InboxWorkerConfig`:

~~~~ rust
InboxWorker::new(federation, data, queue).with_config(config).run_until(stop).await
~~~~

The queue is the application's, per request, so an application whose tenants
each have their own database can keep one queue per tenant; `None` runs the
listener inside the request, where a listener that fails is answered 500, so
the sender retries. A queue that refuses the activity is a 500 too.

An activity processed once is not processed again: its `id` goes into the
key-value store, under the canonical origin it arrived at, for a day, once a
listener is found for it. The mark is taken back when the listener fails
without a queue or the activity could not be queued, so that the retry is
processed.


Forwarding
----------

A reply to a post of ours reaches the servers its author sent it to, and
not the followers of the post's author, who would see half a conversation.
ActivityPub (§7.1.2) has the server that owns the post pass it on: an
activity seen for the first time, addressed in `to`, `cc` or `audience` to a
collection of ours, that concerns something of ours in its `object`,
`target`, `inReplyTo` or `tag`, or in those of the object it embeds. Ojak
decides that, before any listener and whether or not there is one, and calls
the application's hook:

~~~~ rust
.forward(|ctx, Forward { activity, to }| async move {
    match to {
        ForwardTo::Collections(collections) => { /* send to their members */ }
        ForwardTo::Gateways(inbox) => { /* see Portable objects */ }
    }
    Ok(())
})
~~~~

The application sends it to the collections' members, signed by the
collection's owner, as Mastodon does. That it was forwarded is kept in the
key-value store for a week, so it is forwarded once. An activity with no `id`
is not forwarded, and a hook that fails is reported without changing the
answer.

What is forwarded is the activity as it was authenticated here, whose proof,
if it has one, still holds; a server receiving it without one fetches it
from its origin, as above.


Relays
------

A relay passes public activities between the servers subscribed to it,
signed by the relay, so what it sends on is forwarded and is established as
any forwarded activity is: receiving from one needs nothing more. Subscribing
to one is a Follow the application sends and keeps, in whichever convention
the relay speaks, Mastodon's follow of `as:Public` or LitePub's follow of the
relay's actor. Running a relay is not supported yet.


Errors and responses
--------------------

| Outcome                                         | Status |
| ----------------------------------------------- | ------ |
| queued, run, blocked, duplicate, no listener    | 202    |
| not readable as the listener's type             | 202    |
| unauthenticated `Delete`                        | 202    |
| forwarded and not established                   | 202    |
| body too large                                  | 413    |
| not a JSON object, no `actor`, not JSON-LD      | 400    |
| actor or id on another origin than sender       | 401    |
| unauthenticated                                 | 401    |
| portable, proof failed, `Delete` included       | 401    |
| not a POST                                      | 405    |
| `blocked` failed, listener failed with no queue | 500    |
| could not be queued                             | 500    |

A 400 or 401 says why in plain text. Every failure is reported to
`.on_error`.
