Feder as an application framework
=================================

This is a design record, not a description of what Feder does today. It sets
the direction for turning Feder from a set of protocol primitives into a
framework that ActivityPub applications are built on, in the shape [Fedify]
gives TypeScript applications: the application says where its actors, objects
and collections live and supplies them from its own storage, and Feder does
the protocol around them.

The governing rule is the one *CONTRIBUTING.md* already states, applied to
data as well as to I/O:

> The core decides what should happen. The runtime decides how it happens on a
> specific platform.

The application decides what is true. Feder never holds a follower, a post or
an account of its own; it asks.

Two things are in scope that Fedify does not do: reading JSON-LD by meaning
rather than by spelling, over contexts Feder ships instead of fetches, and
portable objects, whose identity is a key rather than a hostname.

[Fedify]: https://fedify.dev/


The problem
-----------

Feder has four crates today, and every application built on them rebuilds the
same missing middle.

 -  *feder-vocab* has hand-written types for a handful of activities. It
    recognises extension vocabulary by spelling: which consent terms an
    incoming `@context` carries is found by looking for a `QuoteRequest` key in
    it, which works for documents Feder wrote and for nothing else.
 -  *feder-jsonld* resolves keys to the IRIs they stand for over eleven bundled
    contexts, and puts them back into Feder's spelling. Nothing uses it yet.
 -  *feder-core* has two things that pull in opposite directions. The
    `inbound` and `addressing` modules are pure decisions over values the
    caller passes in, which is the right shape. `FederCore` is an in-memory
    state machine for a single local actor that records its own followers,
    objects and activities. No application that exists or is planned has one
    actor or keeps its data in Feder's memory.
 -  *feder-runtime* has the primitives: draft-cavage and RFC 9421 HTTP
    signatures, FEP-8b32 integrity proofs, signed delivery with a retry in the
    other signature scheme, `sign_get` and a WebFinger lookup.

What is missing is everything between a primitive and an application, and the
two applications on Feder today each wrote it themselves:

 -  *Verification policy.* `feder_runtime::signature::verify_request` checks
    the body digest only when a `Digest` header is present, does not require
    the digest to be among the signed headers, and never bounds the
    signature's age. Eunha enforces all three itself, along with the rule that
    the key's host matches the actor's. A second application would have to
    know to do the same.
 -  *Inbox dispatch.* Eunha parses every incoming activity as
    `serde_json::Value` and matches on its `type`; only Follow goes through
    `feder-core`.
 -  *Queues.* Eunha has two Postgres job queues, one for incoming activities
    and one for deliveries, that differ mostly in their table names: claim
    with `SKIP LOCKED`, exponential backoff, cleanup of old rows, wake on
    enqueue.
 -  *Fetching.* Eunha guards its fetches against private addresses but
    delivers through a client that is not guarded. Delivery errors come back
    as strings, and eunha parses the HTTP status out of them to decide whether
    to retry.
 -  *Serving.* Actor documents, collections and their pagination, WebFinger
    and NodeInfo are written by hand, with the `@context` literal repeated in
    each.

oeee-cafe, the other intended consumer, uses the `activitypub_federation`
crate instead, and would face the same list to move.


Decisions
---------

### The application owns the data

`FederCore` and `FederState` are removed. Nothing in Feder stores a domain
fact. Where the protocol needs one, Feder asks the application for it through
a function the application registered, and where the protocol decides
something should change, Feder returns or delivers that decision for the
application to carry out.

What Feder does keep is operational state, and it keeps it in stores the
application provides:

 -  a key-value store, for the IDs of activities already processed, remote
    public keys, which signature scheme each host accepts, and anything else
    that is a cache;
 -  a message queue, for deliveries and for incoming activities waiting to be
    handled.

Both are traits, and as in Fedify their backends are pluggable: an
application picks one rather than writing one. Feder ships an in-memory
backend for tests and small deployments, which removes expired entries as it
is written to and can be bounded to a number of entries, dropping those
nearest to expiry first; *feder-postgres* keeps the queue and
the store each in a table of its own that it creates on first use, and more
backends can follow the same trait. Every backend runs one set of conformance
checks, so they agree on the parts that lose work when they are wrong. An
application with tables for the purpose already implements the trait over them
instead: eunha's queue tables stay exactly as they are, and the loops around
them move into Feder.

The queue is claimed from, not listened to. Where Fedify's message queue hands
a message to a listener, Feder's worker *claims* jobs from a named queue for a
lease, reports each one done, to be retried after a delay, or failed, and asks
when the next one is due. One backend holds every named queue, so deliveries
and incoming activities can share a table without one starving the other.
Claiming for a lease is what lets any number of workers in any number of
processes share one store: the two colours of a blue/green deploy both run one,
and what a colour was holding when it stopped is handed out again when its
lease lapses rather than lost. It is also exactly what eunha's tables already
do with `FOR UPDATE SKIP LOCKED`, so they implement it without changing.

The pure functions in `feder-core` stay, and become the rest of that crate:
given the local actor, the remote actor and a Follow, what should happen,
including the locked-account path that yields a follow request instead of a
follow.

### One federation, generic over the application's data

An application builds one `Federation<D>` at start-up. `D` is whatever the
application needs inside its callbacks, typically a database pool, and every
callback receives a context that carries it. This is what lets callbacks be
plain async functions rather than methods on traits the application implements
for its own types.

~~~~ rust
let federation = Federation::builder()
    .kv(PgKvStore::new(pool.clone()))
    .queue(PgMessageQueue::new(pool.clone()))
    .actor("/ap/users/{user_id}", load_person)
    .key_pairs(load_key_pairs)
    .actor("/ap/communities/{community_id}", load_group)
    .object::<Note>("/ap/posts/{post_id}", load_note)
    .followers("/ap/users/{user_id}/followers", followers_page)
    .inbox("/ap/users/{user_id}/inbox", "/ap/inbox")
        .on::<Follow>(on_follow)
        .on::<Create<Note>>(on_create_note)
        .on::<Like>(on_like)
    .build()?;
~~~~

The origin comes from the context, not from the builder. A context is made for
a request, and the request says which host it was for; a background job is
given its origin when it is enqueued. One process can then serve more than one
host, which eunha's plan for many tenants in one process needs, without Feder
knowing what a tenant is.

The same goes for spawning. Feder does not call `tokio::spawn`; it takes a
spawner from the application. Eunha requires every task to be spawned through
its own function so that work carries the tenant that started it.

### Routes and URIs come from the same template

Each dispatcher is registered with an RFC 6570 URI template such as
`/ap/users/{user_id}`. Feder routes requests with it and builds URIs with it:
`ctx.actor_uri(user_id)`, `ctx.object_uri::<Note>(post_id)`,
`ctx.inbox_uri(Some(user_id))`. The reverse, `ctx.parse_uri(&iri)`, says
whether an IRI is one of ours and which dispatcher it belongs to, which is what
an inbox handler needs to recognise a local post in `inReplyTo`.

An application that builds these strings by hand writes each rule twice, once
in the router and once at every call site, and the two drift. Deriving both
from one template removes the class of bug.

### An origin is a host or a key

Every same-origin rule in Feder, in fetching, in the inbox and in ownership,
compares *origins*, and an origin is one of two things:

 -  the scheme, host and port of an `http` or `https` URI, as the web defines
    it;
 -  the DID that is the authority of an `ap://` URI.

The rules are written once against this type and never against hostnames
directly, so that portable objects, below, are the same rules applied to a
second kind of origin rather than a second set of rules.

### Documents are read by meaning, over contexts Feder ships

ActivityPub is JSON-LD: a key is an abbreviation for an IRI, and the
`@context` says which. Two servers can make the same statement with different
keys, and a reader that matches on spelling understands one and drops the
other.

Every document that arrives, whether in an inbox or from a fetch, is
normalised by *feder-jsonld* before anything reads it: expanded against its
`@context` and compacted into Feder's own context. Typed deserialisation reads
the normalised form, so a type declares each property once, under Feder's
spelling, and matches every way a peer may have written it. Recognising
extension vocabulary, such as the consent terms, is an IRI comparison, not a
look through the `@context` for a familiar key.

Normalisation resolves only the contexts *feder-jsonld* bundles. It fetches
nothing: it runs on documents from anyone who can reach an inbox, before any
signature is checked, and a loader that fetches what those documents name is a
request-forgery primitive. A term from a context Feder does not ship is not
resolved: it keeps the sender's spelling, which no field of Feder's types
matches, and the context is reported, so an application can log a peer whose
documents come back emptier than expected. Documents that use `@graph`,
`@included` or `@reverse` are refused, because they let one graph be written as
trees that say different things.

Processing a context costs about ten times what reading a document with it
does — a four-field `Like` took 370 µs to normalise, nearly all of it spent
processing the ActivityStreams context again — and the fediverse sends a few
dozen distinct contexts. A document's own top-level `@context`, and Feder's
context it is compacted into, are therefore processed once and kept, in a
cache the caller supplies (*feder-jsonld* is `no_std` and keeps no state).
The inbox keeps a bounded one, which starts over when full rather than grow
with contexts a sender invents. A cached context normalises every document
in the corpus exactly as an uncached one does; the same `Like` takes 25 µs.

An application that reads activities as JSON itself, as Mastodon does,
needs none of this, and can have its inbox hand listeners the activity as
written instead (`Builder::read_inbox_as_written`). The activity is still
reduced to what its sender vouches for; it is only not rewritten, and a
context that could not be processed is no longer a reason to refuse it.

Documents Feder writes are compacted into Feder's context, so the `@context`
of every type is declared once, next to the type, and never repeated as a
literal.

### The vocabulary is generated from Fedify's schemas

Fedify describes 81 ActivityStreams and extension types in YAML: for each
type its IRI, what it extends and its default `@context`; for each property
its IRI, the IRIs of the types its values may take, whether it holds one value
or several, and which other vocabularies' properties mean the same thing.
Almost none of that is TypeScript. Hand-writing the same types in Rust would
mean rediscovering, one peer at a time, what those files already record.

So Feder's vocabulary types are generated from them:

 -  The schemas are vendored under *crates/feder-vocab/schemas/*, pinned to a
    released Fedify version and carrying Fedify's MIT notice, with a
    provenance file saying which release and how to update it. Nothing is
    fetched at build time.
 -  A generator, *feder-vocab-gen*, reads them and writes Rust into
    *feder-vocab*. The generated code is committed, so it is reviewed like any
    other code and *feder-vocab* builds with no generator dependencies, and a
    test fails when the committed code is not what the generator would write
    now.
 -  A property's key in Rust is its IRI compacted against Feder's context,
    computed by *feder-jsonld*, not the schema's `compactName`. That is the
    key `feder_vocab::read` produces, so the types and the reader cannot
    disagree about spelling.
 -  Inherited properties are copied into each type. A property whose values
    may be several types takes an enum of those types, with a variant that
    keeps anything else as JSON, since peers send types nobody listed.
 -  Where a schema names a TypeScript function to adjust a value on the way
    in, the generator maps the name to a Rust function written by hand, and
    refuses to generate when it meets a name it has no mapping for.

The schemas' format belongs to Fedify, and a change to it can break the
generator. Once the generator works, the case for Fedify publishing the
schemas separately, with a promise about their format, is one Feder can make
with something to show.

### Signed bytes are kept, not rebuilt

Normalisation rewrites a document, and a proof covers the bytes that were
signed, not their meaning. So an incoming document exists in two forms:

 -  the bytes as received, which are what signatures and proofs are verified
    against and what is forwarded or relayed;
 -  the normalised, typed value, which is what the application reads.

Verification always runs on the bytes as received, before normalisation. An
object the application serves or forwards with a proof on it is handed back to
Feder as those bytes and sent unchanged; re-serialising it from a typed value
would break the proof. Storing the bytes is the application's, like every other
fact; Feder's object dispatchers accept either a value to serialise or bytes to
send as they are.

### Portable objects are part of the model

An `ap://` URI (FEP-ef61) names an object by the DID of the key that controls
it rather than by the host that serves it:
`ap://did:key:z6Mk…/users/alice`. The object carries an integrity proof by
that key, so it authenticates itself wherever it is fetched from, and a host
that serves it is a gateway: a location, not an authority. Moving hosts is
changing gateways, and nothing addressed by the key breaks.

This is in scope because it changes the shape of the framework rather than
adding a feature to it. Once identity can be a key, every rule that says “same
host” has to say “same origin”, every document that is served may have to be
served as signed bytes, and an actor's signing key may not live on the server
at all. Building the framework first and portability after would mean
rewriting the parts that matter most.

What it means in each part of Feder:

 -  *Identifiers.* `ap://` URIs are parsed and compared as first-class IRIs,
    with the DID as their origin. A portable object also has an `https` form
    at a gateway, `https://gateway.example/.well-known/apgateway/did:key:…/…`,
    which is what a peer without FEP-ef61 support sees and fetches. URI
    templates build both forms.
 -  *Verification.* A portable object is accepted only with an integrity proof
    whose verification method belongs to the DID in its ID. Where it was
    fetched from and whose HTTP signature it arrived under do not make it
    authentic; they authenticate the transport. The ownership rules are the
    same ones as for `https` objects, over DID origins.
 -  *Serving.* Feder routes `/.well-known/apgateway/{did}/{+path}` to the
    dispatchers of the actors the application hosts, and serves portable
    objects as the signed bytes the application stored.
 -  *Delivery and fetching.* An actor's `gateways` are tried in order, and a
    gateway that fails is skipped rather than retried to exhaustion.
 -  *The inbox.* A gateway accepts activities addressed to the portable actors
    it hosts, and requires their proofs.
 -  *Keys.* Signing is behind a trait. A key can be held by the server, or
    held elsewhere and reached through a signer the application provides, so
    that an identity key can stay cold, or on the user's device, while a
    server signs what it is allowed to. HTTP signatures on a delivery are the
    gateway's, since they authenticate the connection; the proof on the
    object is the identity's.
 -  *DID methods.* `did:key` is built in, because it needs no resolution.
    Other methods come from a resolver the application provides, which is
    where rotation and recovery live: a method that allows them needs someone
    to ask, and which someone is a choice Feder should not make for its
    applications.

### Dispatchers serve what is fetched

 -  *Actors.* An actor dispatcher returns the actor for an identifier, or
    `None`, or a Tombstone for one that is gone. Key pairs come from a separate
    dispatcher, so that an actor's document and its signing keys can be loaded
    independently. The identifier is the stable key in the URI; the handle is
    the WebFinger name, and a `map_handle` function maps one to the other,
    which is how an identifier can be a UUID or a DID while the handle is a
    login name that can change.
 -  *Objects.* An object dispatcher is registered per type and template, and
    returns the object, its signed bytes, or `None`.
 -  *Collections.* Followers, following, outbox, liked and featured each take a
    page function that receives a cursor and returns items and the next
    cursor, plus optional counter and first-cursor functions. Feder turns these
    into `OrderedCollection` and `OrderedCollectionPage` documents with the
    right links.
 -  *Authorized fetch.* Any dispatcher can take an `authorize` predicate, which
    receives the verified signer of the request and decides whether it may see
    the document.

WebFinger follows from the actor dispatchers without further code; NodeInfo is
served from a dispatcher when one is registered. Content negotiation is
Feder's: a request to a matched route that does not ask for ActivityPub falls
through to the application, so the same path can serve HTML to a browser.

### The inbox verifies before any listener runs

Listeners are registered per activity type. A listener receives the context
and the typed activity; types without a listener are accepted and dropped. The
shared inbox and the personal inboxes share one pipeline, and the listener
learns which one delivered the activity: a personal inbox names its recipient,
the shared inbox does not, and the listener works the recipients out from the
addressing, as eunha already does.

Before a listener sees anything, Feder:

1.  parses the signature and checks its shape: which scheme, which components
    it covers, and that a POST covers the body's digest;
2.  checks that the signature was made for this host and is not older than the
    configured window;
3.  finds the signing key, from the key cache or by fetching it;
4.  checks the claim in both directions: the key's owner must be the actor the
    key ID points at, and that actor must list the key as its own;
5.  verifies the signature against the key and the digest Feder computed from
    the body it received;
6.  verifies any integrity proof on the activity, and requires one when the
    activity or its actor is portable;
7.  checks ownership: the activity's actor is on the origin of the key or
    proof that authenticated it, and an object embedded in it that claims an
    author on another origin is not trusted as that author's without its own
    proof;
8.  normalises the document and deserialises it into the listener's type;
9.  skips an activity whose ID it has processed recently;
10. enqueues the activity, or runs the listener inline when no queue is
    configured.

Parsing and verification are separate steps. The parsed signature is plain data
that can be inspected and tested; verification takes it together with a key and
a digest the caller supplies.

An activity that fails verification never reaches a listener. An
`on_unverified` hook sees it, which is where an application answers a Delete
from an actor whose key is already gone.

### Sending is queued, typed and bounded per host

~~~~ rust
ctx.send_activity(Sender::actor(user_id), Recipients::Followers, create)
    .await?;
ctx.send_activity(Sender::actor(user_id), Recipients::from(actors), update)
    .await?;
~~~~

`Recipients::Followers` walks the followers dispatcher. An explicit list is for
everything else, and it is the path eunha uses: its recipient sets are SQL over
Mastodon's tables and stay the application's.

Delivery:

 -  prefers shared inboxes and removes duplicates;
 -  fans out through the queue, one task per inbox, so that each inbox is
    retried on its own;
 -  retries on network errors, 408, 429 and 5xx, with a retry policy the
    application can replace, and honours `Retry-After`;
 -  treats 404 and 410 as permanent and reports them to a handler, which is
    where an application marks a domain unavailable;
 -  runs at most a configured number of deliveries per remote host at once,
    and stops sending to a host that keeps failing until it recovers;
 -  signs with one scheme and retries once with the other when the first is
    refused, and remembers per host which one worked. The first scheme is
    draft-cavage by default, because it is what most of the network still
    verifies, and is configurable;
 -  attaches integrity proofs once per fan-out rather than once per inbox, and
    always for portable actors;
 -  returns typed errors. Whether a failure is worth retrying is a variant, not
    a substring of a message.

Forwarding an activity re-sends the bytes that were received, so that a proof
on them still verifies.

### Every outgoing request is guarded

All of Feder's outgoing requests, fetches and deliveries alike, go through one
pooled HTTP client that:

 -  refuses loopback, private, link-local, shared-address and similar ranges,
    checked on the addresses DNS returns so that a name cannot be pointed at an
    internal address after it passes the check;
 -  follows redirects itself, checking and re-signing each hop, up to a limit;
 -  bounds response size and time.

Fetching an object returns its bytes together with the URL it was finally
served from. Feder's own lookups then establish it the same way the inbox does:
an `https` object whose `id` is on another origin than the URL it came from is
not trusted as that object without a proof, and a portable object is not
trusted without one at all. A lookup, as Mastodon's does, fetches such an
object once more from its own `id`, and trusts what the owner of the `id`
serves there; a second disagreement is refused. What counts as ActivityPub is
Mastodon's rule too: `application/activity+json`, or `application/ld+json`
with the ActivityStreams profile, and never plain JSON, which a server that
takes uploads would otherwise serve in its own name.

An application can allow specific private addresses for development.

### Crates

 -  *feder-vocab*: vocabulary types, `no_std`, reading and writing Feder's
    normalised form.
 -  *feder-jsonld*: normalisation over bundled contexts, `no_std`.
 -  *feder-core*: pure protocol decisions, `no_std`. Follow, Undo, addressing,
    origins and ownership rules, `ap://` identifiers, and the parse-then-verify
    signature and proof primitives, which take a clock and keys as arguments
    rather than reading them.
 -  *feder*: the framework. The builder, routing, contexts, the inbox pipeline,
    delivery, fetching, gateways, the key-value and queue traits and their
    in-memory implementations, and the axum integration.
 -  Backend crates for stores and queues: *feder-postgres* first.

*feder-runtime* is folded into the other two as its pieces move: what is pure
into *feder-core*, what does I/O into *feder*.

### Tests feed inputs and read outcomes

Core functions are tested as they are now, by passing values and asserting the
outcome. The framework ships a test federation that records what would have
been sent and lets a test hand it an activity as if it had arrived, so that an
application can test its listeners without a network.


Sequence
--------

Each step stands on its own, and both applications can take them one at a time
next to what they have now.

1.  *Read by meaning.* Wire *feder-jsonld* into *feder-vocab*, so that types
    read the normalised form and extension vocabulary is recognised by IRI,
    and into the inbound path after verification. This finishes the work
    *feder-jsonld* was written for, and every later step reads documents
    through it.
2.  *Origins, verification and the guarded client.* The origin type, the
    stricter signature checks, proof verification over both kinds of origin,
    and the guarded client land as primitives, and eunha drops its own copies
    of the policy.
3.  *Sending.* `send_activity` over the queue trait, with eunha's delivery
    table behind it. This is where retry in the other scheme and typed errors
    pay off.
4.  *Serving.* Actor, object and collection dispatchers, WebFinger and
    NodeInfo, which only answer GET requests. *serving.md* has the design.
5.  *The inbox.* Late, because it is where a mistake is a security problem.
    Eunha's handlers become listeners; what they do to the database does not
    change. *inbox.md* has the design.
6.  *Generated vocabulary.* Vendor the schemas, write the generator, and move
    *feder-vocab* onto its output once the generated types read the same
    documents the hand-written ones do. It can run beside the steps above;
    later steps get more types from it, not a different shape. Done: the
    generated types are *feder-vocab*'s API, with Feder's own types and
    properties in `extensions/`, and `tests/corpus` measures what they read.
7.  *Gateways.* Serving and accepting portable objects, and the signer trait
    for keys held off the server. The rules they need are already in place by
    step 2; this step is the routes and the delivery path. Done:
    *portable.md* has the details.

For oeee-cafe the same order applies, with `activitypub_federation` removed at
the end.


Open questions
--------------

 -  *Client-to-server.* Clients that sign activities themselves (FEP-ae97) are
    the natural other half of keys held off the server. Outbox listeners are
    left out until an application needs them.
 -  *Which DID methods beyond `did:key`.* `did:key` cannot rotate. A method
    that can needs a party to resolve it, and the choice between a
    DNS-rooted identifier, a directory, and anything else is left to the
    application's resolver until one of them is clearly right.
 -  *Constrained runtimes.* The split between *feder-core* and *feder* is
    meant to keep that door open. Whether the framework crate itself should
    run anywhere but a standard operating system is not decided.
