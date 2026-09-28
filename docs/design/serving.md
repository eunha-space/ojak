Serving
=======

Step 4 of *framework.md*: what Ojak answers when another server, or a
person, sends a GET. Actors, objects and collections come from dispatchers the
application registers; WebFinger, host-meta and NodeInfo follow from them.

*Status: done.* Everything below is implemented in `ojak::federation`, with
*ojak-axum* for axum applications. The same `Federation` also receives
activities (*inbox.md*) and serves portable objects at gateways
(*portable.md*). What was designed and not built is listed at the end; the
[showcase](../showcase.md) says how applications use it.


What this step removes
----------------------

An application that serves ActivityPub by hand, at paths of its own and
without reading `Accept`, tends to collect the same problems:

 -  *Routes advertised and not served.* An actor names an outbox or a
    followers collection that 404s, or an unrouted path falls through to the
    web app's HTML, which a peer then fails to parse.
 -  *URIs built twice.* Each call site formats `https://{domain}/ap/…` and
    parses it back by prefix.
 -  *`@context` repeated.* Each handler writes its own literal.
 -  *Nothing gone is gone.* A deleted post is a 404, not a Tombstone or a 410.
 -  *No authorized fetch.* No signature is checked on a GET.
 -  *WebFinger by hand.* A `profile-page` link that points at the actor
    document rather than the page, or a lookup that accepts only the canonical
    domain and one of several actor URI forms.
 -  *NodeInfo* in one version, or none.

Registering dispatchers removes each of these by construction, except where
an application still builds URIs itself rather than through the context.


Decisions
---------

### Ojak answers requests in `http` types, with an axum adapter

The core is framework-neutral:

~~~~ rust
match federation.handle(&parts, data).await {
    Handled::Response(response) => response,
    // A route matched, but the request did not ask for ActivityPub: the
    // application serves its page at the same URL, or 406.
    Handled::NotAcceptable => app.call(request).await,
    // No route of Ojak's matched, or the host is not one of ours.
    Handled::NotFound => app.call(request).await,
}
~~~~

`parts` is the request's `http::request::Parts`, and a response is an
`http::Response<Vec<u8>>`. A request with a body, a POST to an inbox, goes
through `handle_with_body(&parts, &body, data)` instead. `data` is the
application's `D`, the value every callback's context carries.

The *ojak-axum* adapter puts the federation in front of an application's
router and does exactly the above:

~~~~ rust
ojak_axum::wrap(router, federation, |parts| parts.extensions.get::<AppState>().cloned())
~~~~

It takes `D` from a function over the request's parts, which is how an
application with many tenants passes the tenant's state its own routing put in
the extensions; `None` passes
the request to the application untouched. For an inbox path it reads the body,
up to `MAX_INBOX_BODY`, and answers 413 beyond that.

### The origin is the canonical one, from the request

Every URI Ojak builds, in a document or a link, uses the origin the
application calls canonical for the request's host:

~~~~ rust
.origin(Url::parse("https://example.com")?)            // one host
.origin_with(|host, data: &D| data.canonical_origin(host)) // -> Option<Url>
~~~~

One of the two is required; `build` fails without it. Ojak lower-cases the
host and strips a trailing dot before asking. `None` is a 404. A request that
arrives on an alias is answered in the canonical origin's URIs, never the
alias's, so a document says the same thing wherever it was fetched from. The
scheme is the one the origin's `Url` carries: behind TLS termination the
request no longer knows. `Federation::context(origin, data)` builds a context
outside a request, for URIs in activities an application sends.

### Routes and URIs come from the same template

Templates are RFC 6570 level 1: a path with `{name}` expressions, each a
whole segment or a suffix of one. Expansion percent-encodes each value, and
matching decodes it, so an identifier may be anything, a UUID, a login name or
a DID, and survives the round trip. An expression never matches an empty
value.

`build` refuses, rather than a request discovering, two templates that could
match one path, a template on a path Ojak reserves (WebFinger, host-meta,
NodeInfo), two dispatchers with one kind, an actor or collection template
with more than one expression, and an `authorize` for a kind that is not
registered.

The context builds URIs from templates and parses them back:

~~~~ rust
ctx.actor_uri("person", &user_id)?            // https://example.com/ap/users/{user_id}
ctx.object_uri("note", &[("post_id", &id)])?  // https://example.com/ap/posts/{post_id}
ctx.collection_uri("followers", &user_id)?
ctx.parse_uri(&iri) // Some(Route::Object { kind, values }) when it is ours
~~~~

Each builder returns `Result<Url, UriError>`, an unknown kind or a template
that did not expand. `parse_uri` accepts the canonical origin and its aliases,
with the origin's scheme, and nothing else.

### Actors, by kind

~~~~ rust
.actor("person", "/ap/users/{user_id}", |ctx, id| async move { … })
.actor("group", "/ap/communities/{community_id}", load_group)
.actor("instance", "/actor", load_instance_actor)
~~~~

Fedify allows one actor dispatcher and one identifier space. Both
applications have more than one kind of actor at different paths, so an actor
here is a *kind* and an identifier. A template with no expression, such as
`/actor`, is an actor with the empty identifier. Since a kind is registered
once, an actor served at two URIs is two kinds: an application following
Mastodon's two URI schemes registers `actor` at `/users/{username}` and
`actor_by_id` at `/ap/users/{id}`, and the same for each of its collections.

A dispatcher is `Fn(Context<D>, String) -> Result<Found<Value>, E>`:

~~~~ rust
enum Found<T> {
    Found(T),
    /// Deleted: served as a Tombstone with 410, when it was deleted if known.
    Gone(Option<DateTime<Utc>>),
    NotFound,
}
~~~~

A Tombstone's `id` is the requested URL in the canonical origin. WebFinger for
a gone actor is an empty 410.

Key pairs come from their own dispatcher, `.key_pairs(|ctx, actor| …)`
returning `Vec<PublicKey>`, each an RSA key or a Multikey, and the actor
dispatcher reads them through `ctx.actor_keys(&actor)`. Ojak does not insert
them itself: an actor document the application wrote is the one served.
`with_keys(&mut document, &keys)` puts the first RSA key in `publicKey` and
every Multikey in `assertionMethod`.

Ojak does not require an actor's `id` to be the URL it was served at, so an
account served at two URIs can be named by the one the account uses.

### Objects, by kind

~~~~ rust
.object("note", "/ap/posts/{post_id}", |ctx, values| async move { … })
.object("create", "/users/{username}/statuses/{id}/activity", load_create)
~~~~

An object template may have any number of expressions, and the dispatcher
receives them by name in `Values`. Kinds are names. *ojak-vocab*'s generated
types are its API now (step 6), but typed dispatch, `object::<Note>`, has not
been built.

### What a dispatcher returns is a document

Dispatchers return a `serde_json::Value`. A document without an `@context`
gets Ojak's default, `default_context()`: ActivityStreams with the security
and Multikey contexts; one with its own keeps it. The content type is
`application/activity+json`, with `Vary: Accept`. The gateway serves portable
objects as `application/ld+json` with the ActivityStreams profile instead.

### Collections, paged by cursor

~~~~ rust
.collection("followers", "/ap/users/{user_id}/followers",
    Collection::new(|ctx, id, cursor| async move { … }) // -> Option<Page>
        .count(|ctx, id| async move { … })             // -> Option<u64>
        .first_cursor(|_, _| async { Ok(Some(First::At(String::new()))) }))
~~~~

The page function receives the identifier and a cursor and returns a `Page`:
the items, as IRIs or embedded objects, and the next and previous cursors.
`None` is no such collection, a 404. Ojak writes the documents:

 -  the collection, at the template's URI: an `OrderedCollection` with
    `totalItems`, and `first` and `last` when there are cursor functions;
 -  a page, at the same URI with `?cursor=`: an `OrderedCollectionPage` with
    `partOf`, `next` and `prev`.

Without a first cursor the whole collection is one document, the page
function called once with no cursor, which suits a short one such as featured
posts; its `totalItems` is the counter's, or else the number of items. A
collection that hides its members returns `First::Hidden` and keeps its
counter: the count is shown and the members are not, as Mastodon's
`hide_collections` has it. `Collection::uri` names the collection by a URI
other than the one it was requested at, such as the one of an account's two
URI schemes that the account uses.

Followers, following, outbox, liked and featured are collections like any
other; Ojak puts none of them in an actor document by itself, and the
application links the ones it serves. Linking them with `ctx.collection_uri`
makes a route that is advertised a route that is registered, since otherwise
the URI cannot be built.

Moving from Mastodon's `?page=true&max_id=` to `?cursor=` breaks no peer:
peers follow the `first` and `next` they are given.

### Authorized fetch is a question the dispatcher asks

A GET may be signed. Ojak verifies it only when asked, because verifying
may mean fetching the signer's key:

~~~~ rust
.object("note", "/ap/posts/{post_id}", |ctx, values| async move {
    let post = ctx.data().post(&values["post_id"]).await?;
    if post.followers_only() {
        match ctx.signer().await {
            Some(actor) if post.author_is_followed_by(&actor) => {}
            _ => return Ok(Found::NotFound),
        }
    }
    Ok(Found::Found(note(&ctx, &post)))
})
~~~~

Signed fetches are configured once:

~~~~ rust
.signed_fetch(fetcher, kv, key_ttl, |ctx| async move { … }) // the key Ojak signs with
~~~~

with the fetcher, a key-value store, how long a key is kept, and the key Ojak
signs its own key fetches with, for peers in secure mode. `.fetcher_for`
picks a fetcher per tenant, `.known_key` offers keys the application already
holds before any are fetched, and `.key_fetched` sees each actor document a
key was fetched from.

`ctx.signer()` runs the checks of *inbox.md* that apply to a GET: the
signature's shape, host and age, then the key, from the application, the
key-value store or fetched, and the key owner's origin. It returns the
verified actor's IRI, once per request however often it is asked. The key
cache it fills is the one the inbox uses.

For the common case, a kind takes an `authorize` predicate instead:

~~~~ rust
.authorize("note", |ctx, values, signer| async move { … }) // -> bool
~~~~

which is how an application runs in secure mode: refuse every unsigned GET
but the instance actor's and WebFinger's, which a peer needs in order to sign
at all. There is no global switch; each kind is authorised on its own. An
unauthorised request is 401 with `Vary: Accept, Signature`, and, when it was
unsigned, `WWW-Authenticate: Signature`.

### WebFinger follows from the actors

~~~~ rust
.handle(|ctx, username| async move { … })       // -> Option<ActorRef>
.map_alias(|ctx, url| async move { … })         // -> Option<ActorRef>
.webfinger_links(|ctx, actor, document| vec![subscribe_template(ctx, actor)])
~~~~

Ojak serves `/.well-known/webfinger` for:

 -  `acct:user@host`, where `host` is one of ours, looked up through `handle`.
    An alias is a host the origin function maps to the same canonical origin,
    so no second list of hosts is kept. A leading `@`, and no host at all,
    are read as local;
 -  the URI of any registered actor, looked up through `parse_uri`;
 -  any other `http` or `https` URL on our origin, through `map_alias`, for
    profile pages such as `/@alice`.

A missing `resource` is 400. The answer is built from the actor document the
dispatcher returns: `subject` is `acct:{preferredUsername}@{canonical host}`,
or the actor's `id` when it has no username, `aliases` are its `id` and every
`url`, and the links are `self` to the `id`, `profile-page` to the `url` when
it has one, and whatever `webfinger_links` adds, such as Mastodon's
`subscribe` template. It is served as `application/jrd+json` with
`Access-Control-Allow-Origin: *`. host-meta, which older software asks for
before WebFinger, is served at `/.well-known/host-meta` as XRD with an `lrdd`
template, with no further code. Both are served once any actor is registered.

One namespace or two is the application's business: `handle` may look a name
up as a user and then as a group, or map the server's own domain to the
instance actor.

### NodeInfo from one dispatcher

~~~~ rust
.nodeinfo(|ctx| async move {
    let mut info = NodeInfo::new(Software { name, version, repository, homepage });
    info.usage = usage;
    Ok(info)
})
~~~~

`NodeInfo` is a typed struct of the 2.1 schema, defaulting to `activitypub`
and closed registrations. Ojak serves `/.well-known/nodeinfo` linking both
2.0 and 2.1, and each at its own path with its schema's profile, the 2.0
document being the 2.1 one without the software's repository and homepage.

### Content negotiation

A request to a matched route is ActivityPub when its `Accept` names
`application/activity+json` or `application/ld+json`, with a quality above
zero. Reading is strict about the ActivityStreams profile, since it decides
what is trusted; asking is not, since it decides only which representation
of our own document is sent. Anything else, including a bare `*/*` or a
browser's `text/html`, is `NotAcceptable`, and the application serves the page
at that URL or answers 406 itself. This lets an application keep one URL for a
post, and an unrouted path never answers a peer with HTML: it is Ojak's 404 or
the application's. WebFinger, host-meta and NodeInfo ignore `Accept`.

`HEAD` is answered as `GET` without a body. The method is checked before
`Accept`: any other method on a matched route is 405 with `Allow: GET, HEAD`,
and anything but `POST` on an inbox is 405 with `Allow: POST`.

### Errors

A dispatcher returns `Result<_, E>` for any `E: Into<ojak::federation::Error>`,
a boxed error. An error is a 500 with no body, and `.on_error(|error| …)` sees
it for the log. The body never carries the error, since it is whatever the
database said.


Not built
---------

 -  *Typed dispatch*, `object::<Note>`, and returning a vocabulary type rather
    than a `Value`.
 -  *Followers collection synchronisation* (FEP-8fcf), which needs a filter
    on the followers page by host. The page function's arguments leave room
    for it.
