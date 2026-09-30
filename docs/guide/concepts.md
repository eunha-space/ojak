Concepts
========

The ideas the rest of Ojak builds on.  Its rule is that what decides is kept
apart from what does I/O, and that your application, not Ojak, decides what
is true.


Your application owns the data
------------------------------

Ojak never holds a follower, a post or an account of its own.  Where the
protocol needs a fact, Ojak asks your application through a function you
registered.  Where the protocol says something should change, Ojak hands that
to your application to carry out.

What to do with what arrives is yours too.  Whether a `Follow` is accepted,
turned into a follow request because the account is locked, or refused is
policy, and a listener carries it out.  Ojak authenticates the `Follow`,
types it, and sends the `Accept` your application builds.

What Ojak does keep is operational state, in stores your application
provides:

 -  a key-value store, `ojak::kv::KvStore`, for the IDs of activities already
    processed and forwarded, remote public keys, and anything else that is a
    cache;
 -  a queue, `ojak::queue::Queue`, for deliveries and for incoming activities
    waiting to be handled.

Which signature scheme each host accepts is remembered in memory, by the
fetcher and the deliverer.


Stores and queues
-----------------

Both are traits with backends you pick rather than write:

 -  `MemoryKvStore` and `MemoryQueue`, in *ojak*, for tests and small
    deployments.  The store removes expired entries as it is written to, and
    can be bounded to a number of entries, dropping those nearest to expiry
    first.
 -  `PostgresQueue` and `PostgresKvStore`, in *ojak-postgres*, each in a table
    of its own, created by `initialize()` or by a migration you write from
    `schema()`.

Every backend passes one set of conformance checks,
`ojak::testing::check_queue` and `check_kv`, so they agree on the parts that
lose work when they are wrong.  A backend of your own can run them too.

The queue is claimed from, not listened to.  A worker *claims* jobs from a
named queue for a lease, reports each one done, to be retried after a delay,
or failed, and asks when the next one is due.  One backend holds every named
queue, so deliveries and incoming activities can share a table without one
starving the other.  Because jobs are claimed for a lease, any number of
workers in any number of processes can share one store: during a blue/green
deploy both colours run one, and what a stopped worker was holding is handed
out again when its lease lapses.

If your application already has queue tables of its own, it can implement
the trait over them.  One whose inbox already has a queue can keep it and take
activities through `on_any`.


One federation, generic over your data
--------------------------------------

Your application builds one `Federation<D>` at start-up.  `D` is whatever
your callbacks need, typically a database pool, and every callback receives a
`Context<D>` that carries it.  That is what lets callbacks be plain async
functions rather than methods on traits you implement.

~~~~ rust
let federation = Federation::builder()
    .origin(Url::parse("https://example.com")?)
    .actor("person", "/ap/users/{user_id}", load_person)
    .actor("group", "/ap/communities/{community_id}", load_group)
    .key_pairs(load_key_pairs)
    .object("note", "/ap/posts/{post_id}", load_note)
    .collection("followers", "/ap/users/{user_id}/followers", Collection::new(followers_page))
    .signed_fetch(fetcher, PostgresKvStore::new(pool.clone()), key_ttl, instance_key)
    .inbox("person", "/ap/users/{user_id}/inbox")
    .shared_inbox("/ap/inbox")
    .inbox_queue(|state: &AppState| Some(state.inbox_queue.clone()))
    .on::<Follow, _, _, _>(on_follow)
    .on::<Create, _, _, _>(on_create)
    .on::<Like, _, _, _>(on_like)
    .build()?;
~~~~

The key-value store comes with the signed-fetch settings, which the inbox
needs, and the inbox's queue comes from your data.  Sending is separate: a
`Deliverer` owns its own queue (see [Sending and fetching](./sending.md)).

The origin comes from the request.  `.origin_with(|host, data| …)` maps the
host a request was for to its canonical origin, so one process can serve many
hosts, as a multi-tenant application needs, without Ojak knowing what a
tenant is.  `.origin(url)` is the single-host case, and one of the two is
required.  Work outside a request builds a context with
`Federation::context(origin, data)`, and a queued inbox activity keeps the
origin it arrived at.

Ojak does not spawn tasks.  The deliverer's loop and the inbox worker are
futures, `run_until(stop)`, that you spawn however your application spawns
work, for example through a function that carries the tenant along.


Routes and URIs come from the same template
-------------------------------------------

Each dispatcher is registered with a kind and an RFC 6570 level 1 URI
template such as `/ap/users/{user_id}`.  Ojak routes requests with it and
builds URIs with it:

~~~~ rust
ctx.actor_uri("person", &user_id)?
ctx.object_uri("note", &[("post_id", &id)])?
ctx.collection_uri("followers", &user_id)?
ctx.inbox_uri("person", &user_id)?
ctx.shared_inbox_uri()?
ctx.parse_object("note", &iri)  // the values, if it is one of our notes
ctx.parse_actor("person", &iri) // the identifier, if it is one of our people
~~~~

`parse_object` is what an inbox listener uses to recognise a local post in
`inReplyTo`, and `parse_uri` says which dispatcher any IRI of ours belongs
to.  Because the router and every call site read the same template, they
cannot disagree about where something lives.

Some URIs are needed before there is any request, or any of your data: the
ID of an actor's key, for instance, which your application's data holds.
`federation.uris(origin)` builds them from the same templates, with no
context.


An origin is a host or a key
----------------------------

Every same-origin rule in Ojak, in fetching, in the inbox and in ownership,
compares *origins*, `ojak::origin::Origin`, and an origin is one of two
things:

 -  the scheme, host and port of an `http` or `https` URI, as the web defines
    it;
 -  the DID that is the authority of an `ap://` URI.

The rules are written once against this type and never against hostnames
directly, so [portable objects](./portable.md) are the same rules applied to
a second kind of origin rather than a second set of rules.


Documents are read by meaning
-----------------------------

ActivityPub is JSON-LD: a key is an abbreviation for an IRI, and the
`@context` says which.  Two servers can make the same statement with
different keys, and a reader that matches on spelling understands one and
drops the other.

So every document that arrives, whether in an inbox or from a fetch, is
normalised by *ojak-jsonld* before anything reads it: expanded against its
`@context` and compacted into Ojak's own context.  Vocabulary types read the
normalised form, so a type declares each property once, under Ojak's
spelling, and matches every way a peer may have written it.  Recognising
extension vocabulary, such as the consent terms, is an IRI comparison.

Normalisation resolves only the contexts *ojak-jsonld* bundles, fourteen of
them, and fetches nothing: it runs on documents from anyone who can reach an
inbox, and a loader that fetched what those documents name would let them
make your server send requests.  A term from a context Ojak does not ship
keeps the sender's spelling, which no field of Ojak's types matches.
`ojak_vocab::read_reporting` reports the contexts it could not resolve, so
you can log a peer whose documents come back emptier than expected.
Documents that use `@graph`, `@included` or `@reverse` are refused, because
they let one graph be written as trees that say different things.

Processing a context costs about ten times what reading a document with it
does.  A document's top-level `@context`, and Ojak's own, are therefore
processed once and kept in a bounded cache shared by the inbox and the
fetcher: a four-field `Like` normalises in about 25 µs rather than 370 µs.

An application that reads activities as JSON itself, as Mastodon does, can
have its inbox hand listeners each activity as written instead
(`Builder::read_inbox_as_written`).  The activity is still reduced to what
its sender vouches for; it is only not rewritten.

Documents `ojak_vocab::write` writes are compacted into Ojak's context.
Documents the federation serves are your application's `Value`s, which get
`default_context()`, ActivityStreams with the security and Multikey contexts,
when they have none of their own.


The vocabulary
--------------

*ojak-vocab* has a Rust type for every ActivityStreams type and the
extensions the fediverse uses, generated from [Fedify]'s vocabulary schemas
plus Ojak's own additions:

 -  A property's key is its IRI compacted against Ojak's context, which is
    the key `ojak_vocab::read` produces, so the types and the reader cannot
    disagree about spelling.
 -  Inherited properties are copied into each type.  A property whose values
    may be of several types takes an enum of them, with a variant that keeps
    anything else as JSON, since peers send types nobody listed.
 -  What reading a document into a type did not keep is reported as a
    `Loss`.

`ojak_vocab::meaning` says what a post or reaction means where the fediverse
says it several ways, such as a like, an emoji reaction, or a quote.

[Fedify]: https://fedify.dev/


Signatures are checked on what arrived
--------------------------------------

Normalisation rewrites a document, and a signature or proof covers what was
signed, not its meaning.  So verification always runs first: an HTTP
signature's digest against the body as received, and an integrity proof
against the document as received.

Dispatchers return a `Value`, and a forwarded activity is a `Value` too, both
serialised again when sent.  FEP-8b32 proofs survive this, because they are
over the JCS canonical form of the document, which serialising again does
not change.


Testing
-------

Ojak's decisions are plain functions, tested by passing values in and
checking what comes out, and you can test your application the same way.
`MemoryQueue` records what was queued, so a test can run a listener and read
what it would have sent.

To test federating with another server, turn on the `testing` feature in
your dev-dependencies.  `ojak::testing::Remote` is a server on the loopback
interface: any name is one of its actors, with a public key, it keeps what
is delivered to its inboxes, and it signs activities for your inbox the way
a real server would.  `ojak::testing::client_config()` lets your client
reach it.  The [tutorial](../tutorial.md#testing-it) shows a test that
follows, replies, likes and unfollows through it.
