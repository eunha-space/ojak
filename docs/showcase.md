Showcase
========

Applications that federate through Ojak, how each uses it, and where each
started.  Both depend on Ojak through Git.


Eunha
-----

[Eunha] is a Rust re-implementation of Mastodon, with drop-in compatibility
with Mastodon's database.  It serves many instances, each a tenant with a
domain and aliases of its own, from one process.

[Eunha]: https://github.com/eunha-space/eunha

### How it uses Ojak

*Serving.*  Eunha serves through `Federation` and `ojak_axum::wrap`, taking
the tenant's state from what its own dispatch put in the request's
extensions, and the canonical origin from its tenancy registry through
`origin_with`.

 -  Mastodon has two URI schemes, `/users/{username}` and `/ap/users/{id}`,
    and eunha serves every account at both: each route is registered twice,
    as `actor` and `actor_by_id`, `followers` and `followers_by_id`, and so
    on.  An account is named by the scheme it uses, which for collections is
    `Collection::uri`.
 -  The instance actor, statuses and their activities, outbox, followers,
    following, featured and featured collections, and feature and quote
    authorisations.
 -  `hide_collections` is `First::Hidden`: the count is shown and the members
    are not.  Pages moved from Mastodon's `?page=true&max_id=` to `?cursor=`
    without a peer noticing.
 -  WebFinger accepts its aliases and both actor URI forms, maps its own
    domain to the instance actor, and adds Mastodon's `subscribe` link
    through `webfinger_links`.  NodeInfo is served in 2.0 and 2.1.

*Receiving.*  Signature checking, the fallback to an integrity proof, the
`Delete` rule and the origin checks are Ojak's.  Eunha configures
`signed_fetch` with an in-memory key cache and its instance key, a fetcher
per tenant through `fetcher_for`, the remote keys it stores through
`known_key` and `key_fetched`, and domain suspension through `blocked`.  Its
inbox reads activities as written, `read_inbox_as_written`, and one `on_any`
hands each activity's `vouched` form to its own `inbox_jobs` queue, which
dispatches on the type.  Replies to its posts are forwarded to the followers
collections they are addressed to, through `forward`.  What to do with a Follow,
accepting it or holding it as a request for a locked account, is eunha's own
policy, as is the mapping between an audience and Mastodon's visibilities.

*Sending.*  Deliveries go through a `Deliverer` over `PostgresQueue`, in the
table `eunha.ojak_queue`, with a priority queue so that sends to few inboxes
go ahead of a fan-out.  Batches such as moving an account's followers use
`send_batch`.
It keeps a guarded fetch of its own for what is not ActivityPub: link
previews and link verification.

*Portable actors.*  Eunha reads portable actors, fetching them from their
gateways with `Fetcher::portable`, and delivers to them at their first
gateway's `https` inbox.  It is not a gateway.

### Where it started

Before Ojak was a framework, eunha had written the middle itself:

 -  It verified signatures with a policy of its own, stricter than
    `verify_request`: the digest required among the signed headers and
    checked, the signature's age bounded, and the key's host matched to the
    actor's.  It fell back to an FEP-8b32 proof and answered 202 for an
    unverified `Delete`.
 -  It parsed every incoming activity as JSON and matched on its `type`; only
    Follow went through `ojak-core`.
 -  It had two Postgres job queues, for incoming activities and deliveries,
    that differed mostly in their table names.
 -  It guarded its fetches against private addresses but delivered through a
    client that was not guarded, and parsed HTTP statuses out of error
    strings to decide whether to retry.
 -  Actor documents, collections, WebFinger and NodeInfo 2.0 were written by
    hand, with helpers for some URIs and `format!` for the rest.  WebFinger
    accepted only its canonical domain and one of the two actor URI forms, and
    an unrouted path fell through to the web app's HTML.

Before September 2026 it rewrote any account an `Update` named, public key
included, which was an account takeover; edited any status an `Update(Note)`
named; and stored an embedded note under whatever URI and author it claimed.
Each was fixed with a test, and Ojak's inbox now makes the rule the
framework's.

### Not yet

 -  Typed listeners, and its inbox on `InboxWorker`.
 -  URIs built through the context rather than `format!`.
 -  Authorized fetch, and an `on_unverified` hook.
 -  Serving as a gateway for portable actors.
 -  Relays.


Oeee Cafe
---------

[Oeee Cafe] is a federated and networked oekaki board: people draw together,
and post to communities.

[Oeee Cafe]: https://github.com/oeee-cafe/web

### How it uses Ojak

*Serving.*  `person` and `group` actors for users and communities, `note`
objects for posts, followers collections for both, with a user's followers
hidden but counted, and the outboxes its actors advertise, always empty.
WebFinger looks a name up as a user and then as a community, and maps the
`/@name` profile pages through `map_alias`.  NodeInfo is served in 2.0 and
2.1, and a deleted user, community or post is a Tombstone with 410, with when
it was deleted.

*Receiving.*  Typed listeners for `Follow`, `Create`, `Undo`, `Update`,
`Delete`, `Like` and `EmojiReact`, run by an `InboxWorker` over
`PostgresQueue`, with a key cache in `PostgresKvStore`.  The listeners check
ownership against the authenticated sender.  Actors are fetched with
`Fetcher::document`, and objects with `Fetcher::lookup_as`.  Replies to its
posts are forwarded to the followers of the person or community whose
followers collection they are addressed to, signed by them, once.

*Sending.*  Deliveries go through a `Deliverer` over `PostgresQueue`.

### Where it started

Oeee Cafe used the `activitypub_federation` crate, whose axum inbox read a
body of any size, checked draft-cavage signatures without checking the body
against its digest, and dispatched through an untagged serde enum,
synchronously, inside the request.  It served its ActivityPub documents at
paths of its own without reading `Accept`; its actors named an outbox, and
its communities a followers collection, that 404ed; it formatted
`https://{domain}/ap/…` at each call site and parsed it back by prefix; its
WebFinger `profile-page` pointed at the actor document rather than the page;
it served no NodeInfo; and a deleted post was a 404.

Before September 2026 it deleted any post of its own a remote `Delete` named,
and undid any reaction or follow a remote `Undo` named, a local user's
included.  Each was fixed with a test.

It moved to Ojak first for serving, having the fewest routes and the most of
the gaps, and then for its inbox, when `activitypub_federation` was removed.

### Not yet

 -  URIs built through the context rather than `format!`, and parsed back
    with `parse_uri` rather than by prefix.
 -  Its own `@context` literal on the activities it sends.
 -  Authorized fetch.
 -  Portable objects.
 -  Relays, and an `on_unverified` hook.
