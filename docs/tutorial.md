Tutorial: a blog that federates
===============================

In this tutorial you'll read through a small blog built with Ojak, run it,
and follow it from Mastodon.  By the end, you'll know how an ActivityPub
service fits together: an actor others can find and follow, posts they can
read in their timelines, and replies and likes that come back.

The blog is a real program in the repository, [*examples/blog/*][example],
and every piece of code on this page is taken from it.  The code you read
here is the code its tests build and run.

[example]: https://github.com/eunha-space/ojak/tree/main/examples/blog


What you'll build
-----------------

The blog has one author.  People can:

 -  find it as `@blog@your.domain` from Mastodon, Misskey, or anywhere in the
    fediverse, and follow it;
 -  see each new post in their home timeline, as an article with its title;
 -  reply to a post, and see the reply appear under it on the blog;
 -  like a post, and see the count go up.

The author writes posts on a page of the blog itself.

To follow along you'll need Rust, and to follow the blog from a real
Mastodon account you'll also need a way to give your computer a public HTTPS
address, such as [Tailscale Funnel], [Cloudflare Tunnel] or [ngrok].

[Tailscale Funnel]: https://tailscale.com/kb/1223/funnel
[Cloudflare Tunnel]: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
[ngrok]: https://ngrok.com/


Run it first
------------

Clone the repository and start the blog, telling it the address it will be
reachable at:

~~~~ sh
git clone https://github.com/eunha-space/ojak.git
cd ojak
BLOG_ORIGIN=https://your.domain cargo run -p ojak-example-blog
~~~~

It prints where it is, and the token you'll publish posts with:

~~~~ text
Serving https://your.domain/ as @blog@your.domain on 127.0.0.1:8080
Write a post at https://your.domain/new
with the token 3f9c…
~~~~

The blog listens on port 8080 on your own machine.  Point your public
address at it; with Tailscale, for instance:

~~~~ sh
tailscale funnel 8080
~~~~

Now search for `@blog@your.domain` on Mastodon and follow it.  Then open
*/new*, write a post with the token, and publish: it arrives in your home
timeline.  Reply to it, like it, and reload the post's page on the blog.

> [!TIP]
> `BLOG_ORIGIN` has to be the exact address other servers reach the blog
> at, `https` included.  Every link the blog writes is built from it, and a
> server that fetches the blog's author from a different address will not
> trust it.

The rest of this page explains how it works.


How it's laid out
-----------------

| File                       | What it does                                      |
| -------------------------- | ------------------------------------------------- |
| *src/store.rs*             | The blog's data: posts, followers, replies, likes |
| *src/activitypub.rs*       | The federation, and the documents it serves       |
| *src/inbox.rs*             | What the blog does with the activities it gets    |
| *src/web.rs*, *templates/* | The pages a browser sees, and publishing a post   |
| *src/lib.rs*               | How the pieces are put together                   |
| *src/main.rs*              | Configuration, and running it                     |
| *tests/federation.rs*      | The blog federating with another server           |

The data lives in memory, in *src/store.rs*, so there's no database to set
up.  That keeps the example short, but it also means the blog forgets
everything when it stops.  Nothing in *store.rs* is about ActivityPub, and
that's the point: Ojak never holds your application's data.  It asks for it
through the functions you register, and you keep it wherever you like.


The shared state
----------------

Every function Ojak calls receives a `Context`, which carries a value of
your choosing.  Here it is an `Arc<Blog>`, called `App`, holding the
configuration, the store, the author's signing key, and the parts of Ojak
that talk to other servers:

<<< @/../examples/blog/src/lib.rs#blog

 -  The `Fetcher` fetches other servers' documents, such as a new follower's
    actor, through a client that refuses to reach private addresses.
 -  The `Deliverer` sends activities to other servers' inboxes through a
    queue, retrying each inbox on its own, and signs them with the author's
    key.  A single `SenderKey` signs for every sender, which suits a blog
    with one author; an application with many actors gives it a map of keys
    by sender instead.
 -  The `Federation` answers requests from other servers.  It is built once,
    at start-up.


The federation
--------------

This is everything the blog tells Ojak, in one place:

<<< @/../examples/blog/src/activitypub.rs#federation

Each line registers something under a *kind*, such as `"author"` or
`"post"`, and a URI template, such as `/users/{username}`.  Ojak uses the
template both ways: to route a request for */users/blog* to the author's
function, and to build the URI of the author when the blog needs it.  The
two can never disagree.

The sections below go through what each line registers.


The author
----------

In ActivityPub, anything that acts, such as a person, a group or a
service, is an *actor*: a JSON document with an inbox to send it
activities, and a public key to check its signatures with.  The blog's
author is a `Person`:

<<< @/../examples/blog/src/activitypub.rs#author

 -  `ctx.actor_uri`, `ctx.inbox_uri`, `ctx.shared_inbox_uri` and
    `ctx.collection_uri` build URIs from the templates registered above.
 -  `with_keys` adds the author's public key, which `.key_pairs(…)` supplied,
    so other servers can check what the blog signs.
 -  `endpoints.sharedInbox` offers one inbox for the whole server.  A server
    delivering the same post to several people here sends it once.

Returning `Found::NotFound` for any other username makes a 404.  An actor
that used to exist would return `Found::Gone`, which Ojak serves as a
`Tombstone` with a 410, so other servers know to forget it.

WebFinger, the lookup that turns `@blog@your.domain` into the author's URI,
needs only `.handle(…)`, which maps a username to an actor.  Ojak answers
*/.well-known/webfinger* and *host-meta* from that, and NodeInfo, which
describes the server, from `.nodeinfo(…)`.


Posts
-----

A post is served as an `Article`.  Mastodon shows an article as its title
with a link to it, which suits a blog.  Posting to followers means sending
them a `Create` activity with the article inside:

<<< @/../examples/blog/src/activitypub.rs#article

 -  `to` holds the public collection, so anyone may see the post, and `cc`
    holds the author's followers, so it shows in their home timelines.
 -  `url` is where a person reads the post.  It's the same URL as the
    article itself: Ojak serves the article to a server that asks for
    ActivityPub, and passes a browser's request on to the blog's own page.
 -  The content is rendered by the same template as the post's page, so
    the text is escaped the same way in both.

The two object dispatchers in the federation serve these for
*/posts/{id}* and */posts/{id}/create*.


Collections
-----------

The author links to two collections.  The *outbox* lists what the author
has published, ten posts to a page:

<<< @/../examples/blog/src/activitypub.rs#outbox

Ojak writes the `OrderedCollection` and its `OrderedCollectionPage`s, with
their `first` and `next` links, from the page function, the counter and the
first cursor.  A cursor is any string you choose; here it's the ID of the
newest post on the page.

The *followers* collection shows how many people follow the blog, without
listing who, as Mastodon does when an account hides its followers:

<<< @/../examples/blog/src/activitypub.rs#followers


Pages for people
----------------

The blog's pages share URLs with its ActivityPub documents.
`ojak_axum::wrap` puts the federation in front of the blog's own axum
router:

<<< @/../examples/blog/src/lib.rs#router

A request that asks for ActivityPub, with `Accept: application/activity+json`,
is answered by Ojak.  Any other request, including a browser's for the same
URL, goes on to the blog's routes.  Here is the post page, rendered with a
[minijinja] template:

<<< @/../examples/blog/src/web.rs#post-page

<<< @/../examples/blog/templates/post.html

minijinja escapes everything it puts into an `.html` template, which
matters here: replies come from other servers, and nothing in them should
be able to run in your readers' browsers.

[minijinja]: https://docs.rs/minijinja


Accepting follows
-----------------

Everything so far answers GET requests.  Activities from other servers
arrive as POSTs to the inbox, and each one reaches a *listener* registered
for its type, such as `.on(inbox::follow)`.

Before any listener runs, Ojak has checked the request's HTTP signature
against the sender's public key, and checked that the activity's actor is
on the same server as that key.  `received.sender` is the actor Ojak
authenticated.  Everything else the activity says is a claim.

When someone follows the blog, it notes where to deliver to them and
accepts:

<<< @/../examples/blog/src/inbox.rs#follow

 -  `follow.activity` is the `Follow`, read into a Rust type from
    *ojak-vocab*.  The listener first checks that it names the blog's author.
 -  The follower's actor document says where their inbox is.
    `fetcher.lookup` fetches it, signed with the author's key, since some
    servers only answer signed requests.
 -  The `Accept` names the `Follow` it accepts.  Until it arrives, Mastodon
    shows the follow as pending.
 -  `deliverer.send` queues the `Accept` and returns.  The delivery loop
    sends it, signed, and retries it if the other server is down.


Publishing
----------

When the author publishes, from */new* or from a program, the blog stores
the post and queues its `Create` for every follower:

<<< @/../examples/blog/src/web.rs#publish

`Blog::context()` builds a context outside of any request, with
`Federation::context`, so publishing can build URIs the same way the
dispatchers do.  `store.inboxes()` gives each follower's shared inbox if
their server has one, once each, so a server with a hundred followers of
the blog gets one delivery.


Replies, likes and taking things back
-------------------------------------

A reply is a `Create` of a `Note` whose `inReplyTo` names one of the blog's
posts:

<<< @/../examples/blog/src/inbox.rs#create

<<< @/../examples/blog/src/inbox.rs#our-post

`ctx.parse_object` is the templates used backwards: it says whether an IRI
is one of the blog's posts, and with which values.  `ctx.parse_actor` does
the same for actors, and the follow listener uses it to check that a
`Follow` is for the author.

A reply's content is HTML from another server.  The blog stores only its
text, with the tags removed.  To keep a reply's links and formatting, run
it through an HTML sanitiser, such as the [ammonia] crate, instead.

The `Note` arrives embedded in the `Create` only when it's on the sender's
own server.  Ojak reduces an embedded object the sender can't vouch for to
a bare reference, so a server can't put words in the mouth of someone
elsewhere.

Likes are counted once per actor:

<<< @/../examples/blog/src/inbox.rs#like

When the author of a reply deletes it, their server sends a `Delete`, and
the blog removes the comment, but only if the sender wrote it:

<<< @/../examples/blog/src/inbox.rs#delete

Unfollowing is an `Undo` of the `Follow`.  Because followers are kept by
actor, only the sender's own follow can be removed:

<<< @/../examples/blog/src/inbox.rs#undo

These checks, that the sender wrote the comment and that the follow is
theirs, are the application's to make, because only the application knows
who wrote what.  Ojak makes sure `sender` is who it says it is.

[ammonia]: https://docs.rs/ammonia


Running it
----------

*src/main.rs* reads the configuration from environment variables, makes the
author's key on the first run, and starts two things:

<<< @/../examples/blog/src/main.rs#run

Ojak never starts a task by itself, so the delivery loop is the blog's to
run.  When you press Ctrl-C, it finishes the deliveries it's sending before
it stops.


Testing it
----------

*tests/federation.rs* runs the blog against a second server, a reader, which
is the part that's hard to test by hand.  Ojak provides that server, with
its `testing` feature:

~~~~ toml
[dev-dependencies]
ojak = { git = "https://github.com/eunha-space/ojak.git", features = ["testing"] }
~~~~

`ojak::testing::Remote` runs on the loopback interface.  Any name is one of
its actors, with a public key, and it keeps whatever is delivered to its
inboxes.  It also signs activities for the blog's inbox, the way a real
server would:

<<< @/../examples/blog/tests/federation.rs#send

The blog's client refuses to reach the loopback interface, as any server's
should, so the test builds the blog with `ojak::testing::client_config()`,
which allows it.  Then the reader follows, receives the `Accept` and the new
post, replies, likes, deletes the reply and unfollows, and the test checks
each step against `remote.received()` and the blog's pages.
`deliverer.run_once()` sends what's queued, so the test doesn't have to wait
for the delivery loop.

Run the tests with:

~~~~ sh
cargo test -p ojak-example-blog
~~~~


Where to go from here
---------------------

Some things to try, each a small change to the blog:

 -  *Keep the data.*  Store posts and followers in a database, and use
    *ojak-postgres*'s `PostgresQueue` for the deliverer, so deliveries
    survive a restart.
 -  *Fetch replies it can't vouch for.*  A reply that arrives as a bare
    reference is ignored now.  Fetch it with `fetcher.lookup`, which checks
    it came from its author's server, and store it.
 -  *Take back likes.*  An `Undo` of a `Like` is ignored now.
 -  *Edit and delete posts.*  Send followers an `Update` or a `Delete`, and
    serve a deleted post as `Found::Gone`.
 -  *Followers-only posts.*  Address a post to the followers collection
    only, and refuse to serve it with `.authorize(…)` unless the request is
    signed by a follower.
 -  *Queue the inbox.*  With `.inbox_queue(…)` and an `InboxWorker`,
    listeners run in the background, and the inbox answers at once.

The [guide](./guide/) explains each part of Ojak in more depth.
