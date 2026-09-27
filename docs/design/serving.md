Serving
=======

Step 4 of *framework.md*: what Feder answers when another server, or a
person, sends a GET. Actors, objects and collections come from dispatchers the
application registers; WebFinger, host-meta and NodeInfo follow from them.
Nothing here receives an activity; that is step 5.


What the two applications do now
--------------------------------

Both serve their ActivityPub documents at paths of their own (`/ap/…`,
`/users/…`) and their pages elsewhere (`/@alice`), and neither reads `Accept`.
Between them, every problem this step is meant to remove is present:

 -  *Routes advertised and not served.* oeee-cafe's actors name an outbox,
    and its communities a followers collection, that 404. Eunha once did the
    same with featured collections, and an unrouted path there falls through
    to the web app's HTML, which a peer then fails to parse.
 -  *URIs built twice.* oeee-cafe formats `https://{domain}/ap/…` at each
    call site and parses it back by prefix; eunha has helpers for some URIs
    and `format!` for the rest.
 -  *`@context` repeated.* Each handler writes its own literal.
 -  *Nothing gone is gone.* Both answer 404 for a deleted post; neither
    serves a Tombstone or a 410.
 -  *No authorized fetch.* Neither checks a signature on a GET, so neither
    can serve a followers-only post to a follower's server.
 -  *WebFinger by hand.* oeee-cafe's `profile-page` link points at the actor
    document rather than the page. Eunha's accepts only its canonical domain
    and only one of its two actor URI forms.
 -  *NodeInfo.* Eunha serves 2.0 only; oeee-cafe serves none.

Eunha's tenancy is the model for hosts: the request's host is normalised,
an alias is mapped to its canonical domain, and every URI is built from the
canonical one.


Decisions
---------

### Feder answers requests in `http` types, with an axum adapter

The core is framework-neutral:

~~~~ rust
match federation.handle(request, data).await {
    Handled::Response(response) => response,
    // A route matched, but the request did not ask for ActivityPub: the
    // application serves its page at the same URL, or 406.
    Handled::NotAcceptable => app.call(request).await,
    // No route of Feder's matched.
    Handled::NotFound => app.call(request).await,
}
~~~~

`request` is an `http::Request` and `data` is the application's `D`, the value
every callback's context carries. The *feder-axum* adapter is a layer that
does exactly the above, taking `D` from a function over the request's parts,
which is how eunha passes the tenant's state that its dispatch put in the
extensions.

### The origin is the canonical one, from the request

Every URI Feder builds, in a document or a link, uses the origin the
application calls canonical for the request's host:

~~~~ rust
.origin(|host, data: &D| data.canonical_origin(host)) // -> Option<Url>
~~~~

`None` is a 404. The default is one fixed origin, for an application with one
host. A request that arrives on an alias is answered in the canonical origin's
URIs, never the alias's, so a document says the same thing wherever it was
fetched from. The scheme is `https` unless the application sets it
otherwise, for development: behind TLS termination the request no longer
knows.

### Routes and URIs come from the same template

Templates are RFC 6570 level 1: a path with `{name}` expressions, each a
whole segment or a suffix of one. Expansion percent-encodes each value, and
matching decodes it, so an identifier may be anything, a UUID, a login name or
a DID, and survives the round trip. Two templates that could match one path
are refused when the federation is built, not discovered when a request
arrives.

The context builds URIs from them and parses them back:

~~~~ rust
ctx.actor_uri("person", &user_id)            // https://oeee.cafe/ap/users/{user_id}
ctx.object_uri("note", &[("post_id", &id)])  // https://oeee.cafe/ap/posts/{post_id}
ctx.collection_uri("followers", &user_id)
ctx.parse_uri(&iri) // Some(Route::Object { kind: "note", values }) when it is ours
~~~~

`parse_uri` accepts the canonical origin and its aliases, and nothing else.

### Actors, by kind

~~~~ rust
.actor("person", "/ap/users/{user_id}", load_person)
.actor("group", "/ap/communities/{community_id}", load_group)
.actor("instance", "/actor", load_instance_actor)
~~~~

Fedify allows one actor dispatcher and one identifier space. Both
applications have more than one kind of actor at different paths, and eunha
serves one actor at two (`/users/{username}` and `/ap/users/{id}`, Mastodon's
two URI schemes), so an actor here is a *kind* and an identifier. A template
with no expression, such as `/actor`, is an actor with the empty identifier.

A dispatcher returns a `Found<T>`:

~~~~ rust
enum Found<T> {
    Found(T),
    /// Deleted: served as a Tombstone with 410, when it was deleted if known.
    Gone(Option<DateTime>),
    NotFound,
}
~~~~

Key pairs come from their own dispatcher, and the actor dispatcher reads them
through the context, `ctx.actor_keys(kind, id)`, to put `publicKey` and
`assertionMethod` in the document. Feder does not insert them itself: an
actor document the application wrote is the one served.

Feder does not require an actor's `id` to be the URL it was served at. Eunha
serves an account at both of its URIs and names it by the one the account
uses.

### Objects, by kind

~~~~ rust
.object("note", "/ap/posts/{post_id}", load_note)
.object("create", "/users/{username}/statuses/{id}/activity", load_create)
~~~~

An object template may have any number of expressions, and the dispatcher
receives them by name. Kinds are names until *feder-vocab*'s generated types
become the API (step 6), when `object::<Note>` can replace
`object("note", …)` without changing anything else here.

### What a dispatcher returns is a document

Dispatchers return anything that is `IntoDocument`: a `serde_json::Value`, or
a generated vocabulary type. A document without an `@context` gets Feder's
default, ActivityStreams with the security and Multikey contexts; one with its
own keeps it. The content type is always `application/activity+json`, with
`Vary: Accept`.

### Collections, paged by cursor

~~~~ rust
.collection("followers", "/ap/users/{user_id}/followers", Collection::new(followers_page)
    .count(followers_count)
    .first_cursor(|_, _| Some(String::new())))
~~~~

The page function receives the identifier and a cursor and returns the items,
as IRIs or embedded objects, and the next and previous cursors. Feder writes
the documents:

 -  the collection, at the template's URI: an `OrderedCollection` with
    `totalItems` when there is a counter, and `first` and `last` when there
    are cursor functions;
 -  a page, at the same URI with `?cursor=`: an `OrderedCollectionPage` with
    `partOf`, `next` and `prev`.

Without a first cursor the whole collection is one document, the page
function called once with no cursor, which suits a short one such as
featured posts. A collection that hides its members returns no first cursor
and keeps its counter: the count is shown and the members are not, as eunha
does for `hide_collections`.

Followers, following, outbox, liked and featured are collections like any
other; Feder puts none of them in an actor document by itself, and the
application links the ones it serves with `ctx.collection_uri`. A route that
is advertised is then a route that is registered, or the URI cannot be built.

Eunha's pages move from Mastodon's `?page=true&max_id=` to `?cursor=`. Peers
follow the `first` and `next` they are given, so the change is invisible to
them.

### Authorized fetch is a question the dispatcher asks

A GET may be signed. Feder verifies it only when asked, because verifying
may mean fetching the signer's key:

~~~~ rust
async fn load_note(ctx: &Context<D>, values: &Values) -> Result<Found<Value>, Error> {
    let post = ctx.data().post(values["post_id"]).await?;
    if post.followers_only() {
        match ctx.signer().await {
            Some(actor) if post.author_is_followed_by(&actor) => {}
            _ => return Ok(Found::NotFound),
        }
    }
    Ok(Found::Found(note(ctx, &post)))
}
~~~~

`ctx.signer()` runs the checks of *framework.md*'s inbox pipeline that apply
to a GET: the signature's shape, host and age, then the key, from the
key-value store or fetched with the fetcher, and the key owner's origin. It
returns the verified actor's IRI, once per request however often it is asked.
The key cache it fills is the one the inbox will use.

For the common case, a dispatcher takes an `authorize` predicate instead,
`(ctx, identifier, signer) -> bool`, which is how an application runs in
secure mode: refuse every unsigned GET but the instance actor's and
WebFinger's, which a peer needs in order to sign at all. An unauthorised
request is 401.

### WebFinger follows from the actors

~~~~ rust
.handle(|ctx, username| async move { ctx.data().actor_by_handle(username).await })
// -> Option<(kind, identifier)>
.handle_hosts(|host, data| data.is_one_of_our_hosts(host))
.webfinger_links(|ctx, actor| vec![subscribe_template(ctx, actor)])
~~~~

Feder serves `/.well-known/webfinger` for:

 -  `acct:user@host`, where `host` is the canonical origin's or one
    `handle_hosts` accepts, looked up through `handle`;
 -  the URI of any registered actor, looked up through `parse_uri`;
 -  any other `https` URL on our origin, through an optional `map_alias`,
    for profile pages such as `/@alice`.

The answer is built from the actor document the dispatcher returns: `subject`
is `acct:{preferredUsername}@{canonical host}`, `aliases` are its `id` and
`url`, and the links are `self` to the `id`, `profile-page` to the `url` when
it has one, and whatever `webfinger_links` adds, such as Mastodon's
`subscribe` template. It is served as `application/jrd+json` with
`Access-Control-Allow-Origin: *`. host-meta, which older software asks for
before WebFinger, is served from the same route with no further code.

One namespace or two is the application's business: oeee-cafe's `handle`
looks for a user and then a community, as it does now.

### NodeInfo from one dispatcher

~~~~ rust
.nodeinfo(|ctx| async move { Ok(NodeInfo { software, usage, open_registrations, metadata }) })
~~~~

`NodeInfo` is a typed struct of the 2.1 schema. Feder serves
`/.well-known/nodeinfo` linking both 2.0 and 2.1, and each at its own path,
the 2.0 document being the 2.1 one without what 2.0 lacks.

### Content negotiation

A request to a matched route is ActivityPub when its `Accept` names
`application/activity+json`, or `application/ld+json` with the
ActivityStreams profile, with a quality above zero. Anything else, including
a bare `*/*` or a browser's `text/html`, is `NotAcceptable`, and the
application serves the page at that URL or answers 406 itself. This lets an
application keep one URL for a post, if it wants that, and an unrouted path
never answers a peer with HTML: it is Feder's 404 or the application's.

`HEAD` is answered as `GET` without a body. Every other method on a matched
route is 405, except `POST` to an inbox, which is step 5.

### Errors

A dispatcher returns `Result<_, E>` for any `E: Display`. An error is a 500
with no body, and an `on_error` hook sees it for the log. The body never
carries the error, since it is whatever the database said.


What moves
----------

**oeee-cafe** goes first. It has the fewest routes and the most of the gaps,
and moving it fixes them by construction:

 -  `person` and `group` actors, `note` objects, and the followers
    collections, with the outbox it advertises either registered or no longer
    advertised;
 -  WebFinger through `handle`, over its one namespace of users and
    communities, with `profile-page` fixed;
 -  NodeInfo, which it does not serve now;
 -  Tombstones for deleted posts.

Its inbox stays on `activitypub_federation` until step 5, so the crate stays a
dependency until then.

**Eunha** follows:

 -  both actor URI forms, the instance actor, statuses and their activities,
    outbox, followers, following, featured and featured collections;
 -  WebFinger accepting its aliases and both actor URI forms;
 -  NodeInfo 2.1 beside 2.0;
 -  the canonical origin from its tenancy registry;
 -  host-meta, through Feder.


Not in this step
----------------

 -  *The inbox*, which is step 5.
 -  *Typed dispatch*, `object::<Note>`, which waits for step 6.
 -  *Serving portable objects through a gateway*, which is step 7.
 -  *Followers collection synchronisation* (FEP-8fcf), which needs a filter
    on the followers page by host. The page function's arguments leave room
    for it.


Order of work
-------------

1.  Templates: expansion, matching, overlap detection, `parse_uri`.
2.  `Federation`, its builder and `handle`, with content negotiation, for
    actors and objects.
3.  Collections.
4.  WebFinger, host-meta and NodeInfo.
5.  `ctx.signer()` and `authorize`, with the key cache over the key-value
    store.
6.  *feder-axum*.
7.  oeee-cafe onto it, then eunha.
