Ojak as an application framework
================================

This is the design record for turning Ojak from a set of protocol primitives
into a framework that ActivityPub applications are built on, in the shape
[Fedify] gives TypeScript applications: the application says where its
actors, objects and collections live and supplies them from its own storage,
and Ojak does the protocol around them.

*Status: built.* The seven steps in *Sequence* below are done. Each decision
says where what was built differs from what was designed. *serving.md*,
*inbox.md* and *portable.md* have the details of their steps.

The governing rule is the one *CONTRIBUTING.md* already states, applied to
data as well as to I/O:

> The core decides what should happen. The runtime decides how it happens on a
> specific platform.

The application decides what is true. Ojak never holds a follower, a post or
an account of its own; it asks.

Two things are in scope that Fedify does not do: reading JSON-LD by meaning
rather than by spelling, over contexts Ojak ships instead of fetches, and
portable objects, whose identity is a key rather than a hostname.

[Fedify]: https://fedify.dev/


Where Ojak started
------------------

When this record was written, Ojak had four crates, and every application
built on them rebuilt the same missing middle.

 -  *ojak-vocab* had hand-written types for a handful of activities. It
    recognised extension vocabulary by spelling: which consent terms an
    incoming `@context` carried was found by looking for a `QuoteRequest` key
    in it, which worked for documents Ojak wrote and for nothing else.
 -  *ojak-jsonld* resolved keys to the IRIs they stand for over eleven bundled
    contexts, and put them back into Ojak's spelling. Nothing used it yet.
 -  *ojak-core* had two things that pulled in opposite directions. The
    `inbound` and `addressing` modules were pure decisions over values the
    caller passes in, which is the right shape. `OjakCore` was an in-memory
    state machine for a single local actor that recorded its own followers,
    objects and activities. No application that exists or is planned has one
    actor or keeps its data in Ojak's memory.
 -  *ojak-runtime* had the primitives: draft-cavage and RFC 9421 HTTP
    signatures, FEP-8b32 integrity proofs, signed delivery with a retry in the
    other signature scheme, `sign_get` and a WebFinger lookup.

What was missing was everything between a primitive and an application, and
each application had to write it itself:

 -  *Verification policy.* `ojak_runtime::signature::verify_request` checks
    the body digest only when a `Digest` header is present, does not require
    the digest to be among the signed headers, and never bounds the
    signature's age. An application had to know to enforce all three itself,
    along with the rule that the key's host matches the actor's.
 -  *Inbox dispatch.* An application parsed every incoming activity as
    `serde_json::Value` and matched on its `type`; only Follow went through
    `ojak-core`.
 -  *Queues.* An application kept job queues of its own, one for incoming
    activities and one for deliveries, that differed mostly in their table
    names: claim
    with `SKIP LOCKED`, exponential backoff, cleanup of old rows, wake on
    enqueue.
 -  *Fetching.* Fetches had to be guarded against private addresses, and
    deliveries too. Delivery errors came back as strings, and an application
    parsed the HTTP status out of them to decide whether to retry.
 -  *Serving.* Actor documents, collections and their pagination, WebFinger
    and NodeInfo were written by hand, with the `@context` literal repeated in
    each.

Now Ojak has six crates (*Crates* below), and applications serve, fetch,
deliver and receive through it. `OjakCore` is gone, and the vocabulary is
generated and read through *ojak-jsonld*. `verify_request` is unchanged, but
nothing in Ojak's pipeline uses it: the inbox and signed GETs hold signatures
to the stricter policy in `ojak::sig::verification`.


Decisions
---------

### The application owns the data

`OjakCore` and `OjakState` are removed. Nothing in Ojak stores a domain
fact. Where the protocol needs one, Ojak asks the application for it through
a function the application registered, and where the protocol decides
something should change, Ojak returns or delivers that decision for the
application to carry out.

What Ojak does keep is operational state, in stores the application
provides:

 -  a key-value store, `ojak::kv::KvStore`, for the IDs of activities already
    processed and forwarded, remote public keys, and anything else that is a
    cache;
 -  a queue, `ojak::queue::Queue`, for deliveries and for incoming activities
    waiting to be handled.

Which signature scheme each host accepts is remembered in memory, by the
fetcher and the deliverer, rather than in the store.

Both are traits, and as in Fedify their backends are pluggable: an
application picks one rather than writing one. Ojak ships in-memory backends,
`MemoryKvStore` and `MemoryQueue`, for tests and small deployments; the store
removes expired entries as it is written to and can be bounded to a number of
entries, dropping those nearest to expiry first. *ojak-postgres* keeps the
queue and the store each in a table of its own, `PostgresQueue` and
`PostgresKvStore`, created by `initialize()` or by a migration the
application writes from `schema()`. More backends can follow the same trait.
Every backend runs one set of conformance checks, `ojak::testing::check_queue`
and `check_kv`, so they agree on the parts that lose work when they are wrong.

An application with queue tables of its own can implement the trait over
them, or move its rows into Ojak's table; one whose inbox already has a queue
can keep it and take activities through `on_any`.

The queue is claimed from, not listened to. Where Fedify's message queue hands
a message to a listener, Ojak's worker *claims* jobs from a named queue for a
lease, reports each one done, to be retried after a delay, or failed, and asks
when the next one is due. One backend holds every named queue, so deliveries
and incoming activities can share a table without one starving the other.
Claiming for a lease is what lets any number of workers in any number of
processes share one store: the two colours of a blue/green deploy both run one,
and what a colour was holding when it stopped is handed out again when its
lease lapses rather than lost.

What to do with what arrives is the application's too, as it is in Fedify:
whether a Follow is accepted, turned into a follow request because the account
is locked, or refused, is policy, and a listener carries it out. Ojak
authenticates the Follow, types it, and sends the `Accept` the application
builds. An early `ojak-core` held that decision as a pure function, and it
moved to the application that used it.

### One federation, generic over the application's data

An application builds one `Federation<D>` at start-up. `D` is whatever the
application needs inside its callbacks, typically a database pool, and every
callback receives a context that carries it. This is what lets callbacks be
plain async functions rather than methods on traits the application implements
for its own types.

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
needs, and the inbox's queue from the data. Sending is not part of the
federation: a `Deliverer` owns its queue (*Sending* below).

The origin comes from the request. `.origin_with(|host, data| …)` maps the
host a request was for to its canonical origin, so one process can serve more
than one host, as an application with many tenants needs, without Ojak
knowing what a tenant is; `.origin(url)` is the single-host case, and one of
the two is required. Work outside a request builds a context with
`Federation::context(origin, data)`, and a queued inbox activity keeps the
origin it arrived at.

Ojak does not spawn tasks. The deliverer's loop and the inbox worker are
futures, `run_until(stop)`, that the application spawns however it spawns
work, such as through a function of its own so that work carries the tenant
that started it.

### Routes and URIs come from the same template

Each dispatcher is registered with a kind and an RFC 6570 level 1 URI
template such as `/ap/users/{user_id}`. Ojak routes requests with it and
builds URIs with it: `ctx.actor_uri("person", &user_id)`,
`ctx.object_uri("note", &[("post_id", &id)])`,
`ctx.collection_uri("followers", &user_id)`. The reverse, `ctx.parse_uri(&iri)`,
says whether an IRI is one of ours and which dispatcher it belongs to, which
is what an inbox handler needs to recognise a local post in `inReplyTo`.

An application that builds these strings by hand writes each rule twice, once
in the router and once at every call site, and the two drift. Deriving both
from one template removes the class of bug.

### An origin is a host or a key

Every same-origin rule in Ojak, in fetching, in the inbox and in ownership,
compares *origins*, `ojak::origin::Origin`, and an origin is one of two
things:

 -  the scheme, host and port of an `http` or `https` URI, as the web defines
    it;
 -  the DID that is the authority of an `ap://` URI.

The rules are written once against this type and never against hostnames
directly, so that portable objects, below, are the same rules applied to a
second kind of origin rather than a second set of rules.

### Documents are read by meaning, over contexts Ojak ships

ActivityPub is JSON-LD: a key is an abbreviation for an IRI, and the
`@context` says which. Two servers can make the same statement with different
keys, and a reader that matches on spelling understands one and drops the
other.

Every document that arrives, whether in an inbox or from a fetch, is
normalised by *ojak-jsonld* before anything reads it: expanded against its
`@context` and compacted into Ojak's own context. Typed deserialisation reads
the normalised form, so a type declares each property once, under Ojak's
spelling, and matches every way a peer may have written it. Recognising
extension vocabulary, such as the consent terms, is an IRI comparison, not a
look through the `@context` for a familiar key.

Normalisation resolves only the contexts *ojak-jsonld* bundles, fourteen of
them. It fetches nothing: it runs on documents from anyone who can reach an
inbox, and a loader that fetches what those documents name is a
request-forgery primitive. A term from a context Ojak does not ship is not
resolved: it keeps the sender's spelling, which no field of Ojak's types
matches. `ojak_vocab::read_reporting` reports the contexts it could not
resolve, so an application can log a peer whose documents come back emptier
than expected; the inbox does not pass them on. Documents that use `@graph`,
`@included` or `@reverse` are refused, because they let one graph be written
as trees that say different things.

Processing a context costs about ten times what reading a document with it
does — a four-field `Like` took 370 µs to normalise, nearly all of it spent
processing the ActivityStreams context again — and the fediverse sends a few
dozen distinct contexts. A document's own top-level `@context`, and Ojak's
context it is compacted into, are therefore processed once and kept, in a
cache the caller supplies (*ojak-jsonld* is `no_std` and keeps no state).
The inbox and the fetcher share one bounded cache, which starts over when full
rather than grow with contexts a sender invents. A cached context normalises
every document in the corpus exactly as an uncached one does; the same `Like`
takes 25 µs.

An application that reads activities as JSON itself, as Mastodon does,
needs none of this, and can have its inbox hand listeners the activity as
written instead (`Builder::read_inbox_as_written`). The activity is still
reduced to what its sender vouches for; it is only not rewritten, and a
context that could not be processed is no longer a reason to refuse it.

Documents `ojak_vocab::write` writes are compacted into Ojak's context, so the
`@context` of every type is declared once and never repeated as a literal.
Documents the federation serves are the application's `Value`s, which get
`default_context()`, ActivityStreams with the security and Multikey contexts,
when they have none of their own.

### The vocabulary is generated from Fedify's schemas

Fedify describes 81 ActivityStreams and extension types in YAML: for each
type its IRI, what it extends and its default `@context`; for each property
its IRI, the IRIs of the types its values may take, whether it holds one value
or several, and which other vocabularies' properties mean the same thing.
Almost none of that is TypeScript. Hand-writing the same types in Rust would
mean rediscovering, one peer at a time, what those files already record.

So Ojak's vocabulary types are generated from them:

 -  The schemas are vendored under *crates/ojak-vocab/schemas/*, pinned to a
    released Fedify version and carrying Fedify's MIT notice, with a
    provenance file saying which release and how to update it. Nothing is
    fetched at build time. Ojak's own types and properties are in
    *crates/ojak-vocab/extensions/*.
 -  A generator, *ojak-vocab-gen*, reads them and writes Rust into
    *ojak-vocab*. The generated code is committed, so it is reviewed like any
    other code and *ojak-vocab* builds with no generator dependencies, and a
    test fails when the committed code is not what the generator would write
    now.
 -  A property's key in Rust is its IRI compacted against Ojak's context,
    computed by *ojak-jsonld*, not the schema's `compactName`. That is the
    key `ojak_vocab::read` produces, so the types and the reader cannot
    disagree about spelling.
 -  Inherited properties are copied into each type. A property whose values
    may be several types takes an enum of those types, with a variant that
    keeps anything else as JSON, since peers send types nobody listed.
 -  Where a schema names a TypeScript function to adjust a value on the way
    in, the generator maps the name to a Rust function written by hand, and
    refuses to generate when it meets a name it has no mapping for.

What reading a document into a type did not keep is reported as a `Loss`, and
*crates/ojak-vocab/tests/corpus* measures it over documents real servers
wrote.

The schemas' format belongs to Fedify, and a change to it can break the
generator. Now that the generator works, the case for Fedify publishing the
schemas separately, with a promise about their format, is one Ojak can make
with something to show.

### Signatures are checked on what arrived

Normalisation rewrites a document, and a signature or proof covers what was
signed, not its meaning. So verification always runs before normalisation:
an HTTP signature's digest against the body as received, and an integrity
proof against the document as received.

The design went further, and kept signed bytes to send on unchanged: object
dispatchers that could return bytes, and forwarding that re-sent what was
received. That was not built. Dispatchers return a `Value`, and a forwarded
activity is a `Value` too, both serialised again when sent. It works because
FEP-8b32 proofs are over the JCS canonical form of the document, which
serialising again does not change; a scheme over bytes would need the design
as written.

### Portable objects are part of the model

An `ap://` URI (FEP-ef61) names an object by the DID of the key that controls
it rather than by the host that serves it:
`ap://did:key:z6Mk…/users/alice`. The object carries an integrity proof by
that key, so it authenticates itself wherever it is fetched from, and a host
that serves it is a gateway: a location, not an authority. Moving hosts is
changing gateways, and nothing addressed by the key breaks.

This is in scope because it changes the shape of the framework rather than
adding a feature to it. Once identity can be a key, every rule that says “same
host” has to say “same origin”, and an actor's signing key may not live on
the server at all. Building the framework first and portability after would
have meant rewriting the parts that matter most.

What it means in each part of Ojak, all of it built (*portable.md*):

 -  *Identifiers.* `ApUri` parses and compares `ap://` URIs as first-class
    IRIs, with the DID as their origin. A portable object also has an `https`
    form at a gateway,
    `https://gateway.example/.well-known/apgateway/did:key:…/…`, which is what
    a peer without FEP-ef61 support sees and fetches.
 -  *Verification.* A portable object is accepted only with an integrity proof
    whose verification method belongs to the DID in its ID. Where it was
    fetched from and whose HTTP signature it arrived under do not make it
    authentic; they authenticate the transport. The ownership rules are the
    same ones as for `https` objects, over DID origins.
 -  *Serving.* Ojak routes `/.well-known/apgateway/{did}/{+path}` to the
    application's `gateway` and `gateway_inbox`.
 -  *Delivery and fetching.* An actor's gateways are tried in order, and a
    gateway that fails is skipped rather than retried to exhaustion.
 -  *The inbox.* A gateway accepts activities addressed to the portable actors
    it hosts, and requires their proofs.
 -  *Keys.* Signing is behind a trait, `ProofSigner`. A key can be held by the
    server, or held elsewhere and reached through a signer the application
    provides, so that an identity key can stay cold, or on the user's device,
    while a server signs what it is allowed to. HTTP signatures on a delivery
    are the gateway's, since they authenticate the connection; the proof on
    the object is the identity's.
 -  *DID methods.* `did:key` is built in, because it needs no resolution.
    Other methods come from a `DidResolver` the application provides, which
    is where rotation and recovery live: a method that allows them needs
    someone to ask, and which someone is a choice Ojak should not make for its
    applications.

### Dispatchers serve what is fetched

 -  *Actors.* An actor dispatcher returns the actor for a kind and an
    identifier as a `Found`: found, gone, served as a Tombstone with 410, or
    not found. Key pairs come from a separate dispatcher, so that an actor's
    document and its signing keys can be loaded independently. The identifier
    is the stable key in the URI; the handle is the WebFinger name, and
    `handle` maps one to the other, which is how an identifier can be a UUID
    or a DID while the handle is a login name that can change.
 -  *Objects.* An object dispatcher is registered per kind and template, and
    returns the object.
 -  *Collections.* Followers, following, outbox, liked and featured are each a
    `Collection`: a page function that receives a cursor and returns items and
    the next cursor, plus optional counter and first- and last-cursor
    functions. Ojak turns these into `OrderedCollection` and
    `OrderedCollectionPage` documents with the right links.
 -  *Authorized fetch.* Any kind can take an `authorize` predicate, which
    receives the verified signer of the request and decides whether it may see
    the document.

WebFinger and host-meta follow from the actor dispatchers without further
code; NodeInfo is served from a dispatcher when one is registered. Content
negotiation is Ojak's: a request to a matched route that does not ask for
ActivityPub falls through to the application, so the same path can serve HTML
to a browser.

### The inbox verifies before any listener runs

Listeners are registered per activity type, with `on_any` for the rest;
types without a listener are accepted and dropped. The shared inbox and the
personal inboxes share one pipeline, and the listener learns which one
delivered the activity: a personal inbox names its recipient, the shared
inbox does not, and the listener works the recipients out from the addressing.

Before a listener sees anything, Ojak:

1.  bounds the body, and asks the application whether the sender's host is
    blocked, before any key is fetched;
2.  parses the signature and checks its shape: which scheme, which components
    it covers, and that a POST covers the body's digest;
3.  checks that the signature was made for this host and is not more than an
    hour from now;
4.  finds the signing key, from the application, the key cache, or by fetching
    it;
5.  checks the claim in both directions: the key's owner must be the actor the
    key ID points at, and that actor must list the key as its own;
6.  verifies the signature against the key and the digest Ojak computed from
    the body it received, and failing that, an integrity proof on the
    activity; a portable actor is authenticated by its proof alone;
7.  checks ownership: the activity's actor is on the origin of the key or
    proof that authenticated it, an activity signed by another server is
    established from its origin, and an object embedded in it that claims an
    author on another origin is reduced to a reference;
8.  normalises the document;
9.  decides whether to forward it to a collection's members or a portable
    actor's other gateways;
10. finds the listener, and skips an activity whose ID it has processed
    recently;
11. enqueues the activity, or reads it into the listener's type and runs the
    listener inline when no queue is configured.

Parsing and verification are separate steps, in `ojak::sig::verification`.
The parsed signature is plain data that can be inspected and tested;
verification takes it together with a key and a digest the caller supplies.

An activity that fails verification never reaches a listener. An
`on_unverified` hook sees it, which is where an application answers a Delete
from an actor whose key is already gone.

### Sending is queued, typed and bounded per host

~~~~ rust
let deliverer = Deliverer::new(queue, sender_keys, client, DelivererConfig::default())
    .on_failure(|failure| mark_unavailable(failure));
deliverer.send(&sender_key_id, &create, inboxes).await?;
deliverer.send_batch(&sender_key_id, &move_, inboxes, &Batch { tag, deadline }).await?;
tokio::spawn(async move { deliverer.run_until(stop).await });
~~~~

The design had the federation send, `ctx.send_activity`, with a recipients
walk over the followers dispatcher. What was built is a `Deliverer` of its
own, over a queue and the application's `SenderKeys`, and the application
works out the inboxes, typically as a query over its own tables, shared
inboxes preferred. `send_batch` tags a batch so it can be
followed and gives it a deadline, past which a delivery is given up on
rather than retried; `send_portable` delivers to a portable actor's gateways.

Delivery:

 -  removes duplicate inboxes;
 -  fans out through the queue, one job per inbox, so that each inbox is
    retried on its own, with an optional priority queue so that sends to few
    inboxes go ahead of a fan-out;
 -  retries on network errors, 408, 429 and 5xx, with a retry policy the
    application can replace, and honours `Retry-After`;
 -  treats every other 4xx as permanent and reports it to `on_failure`, with
    its status, which is where an application marks a domain unavailable;
 -  runs at most a configured number of deliveries per remote host at once;
 -  signs with one scheme and retries once with the other when the first is
    refused, and remembers per host which one worked. The first scheme is
    draft-cavage by default, because it is what most of the network still
    verifies, and is configurable;
 -  returns typed errors. Whether a failure is worth retrying is a variant, not
    a substring of a message.

Two things designed here were not built: stopping sending to a host that
keeps failing until it recovers, and attaching integrity proofs as part of
delivery. An application that wants a proof on an activity signs it with its
`ProofSigner` before sending.

### Every outgoing request is guarded

All of Ojak's outgoing requests, fetches and deliveries alike, go through one
pooled HTTP client, `ojak::client::Client`, that:

 -  refuses loopback, private, link-local, shared-address and similar ranges,
    checked on the addresses DNS returns so that a name cannot be pointed at an
    internal address after it passes the check;
 -  follows a GET's redirects itself, checking and re-signing each hop, up to
    three, and never follows a POST's;
 -  bounds response size, at 1 MiB, and time.

Fetching an object returns its document together with the URL it was finally
served from. Ojak's own lookups, `Fetcher::lookup` and `lookup_as`, then
establish it the same way the inbox does: an `https` object whose `id` is on
another origin than the URL it came from is not trusted as that object
without a proof, and a portable object is not trusted without one at all. A
lookup, as Mastodon's does, fetches such an object once more from its own
`id`, and trusts what the owner of the `id` serves there; a second
disagreement is refused. A document that names an author, in `attributedTo`
or `actor`, on another origin than its `id` is refused too: its server can
vouch for its own objects, not for who wrote them elsewhere. What counts as
ActivityPub is Mastodon's rule too: `application/activity+json`, or
`application/ld+json` with the ActivityStreams profile, and never plain JSON,
which a server that takes uploads would otherwise serve in its own name.

An actor is found by its handle through `Fetcher::webfinger`, which reads
`@alice@social.example` as an `Address`, asks the host's WebFinger endpoint
for it with the resource encoded, and returns the actors its `self` links
name, with their type when the link gives one, as Lemmy's does for a name
that is both a user and a community. The host answers only for itself: the
actor is then looked up and established like any other.

An application can allow private addresses for development.

### Crates

 -  *ojak-vocab*: vocabulary types, generated, `no_std`, reading and writing
    Ojak's normalised form, and what a post or reaction means where the
    fediverse says it several ways.
 -  *ojak-jsonld*: normalisation over bundled contexts, `no_std`.
 -  *ojak-sig*: signatures and proofs with their verification policy, doing
    no I/O and given the time and randomness; `ojak::sig` re-exports it.
 -  *ojak*: the framework. The federation, its builder, routing and contexts,
    the inbox pipeline, delivery, fetching, gateways, the guarded client, and
    the key-value and queue traits with their in-memory implementations; and
    beside them, doing no I/O, origins and `ap://` identifiers.
 -  *ojak-axum*: the axum integration, `ojak_axum::wrap`.
 -  *ojak-postgres*: the Postgres queue and key-value store. More backends
    can follow.
 -  *ojak-vocab-gen*: the generator of *ojak-vocab*'s types.

The design had a portable `ojak-core` of protocol decisions beside a
`std` *ojak-runtime* of primitives, with the runtime folded into the other two
over time. What was built made the split not worth its cost: the framework
was the only crate that depended on either, the decisions in `ojak-core`
were the applications' policy rather than the protocol's, and the primitives
were pure but lived in the runtime. So origins and `ap://` identifiers are in
*ojak*, what a reaction means is in *ojak-vocab*, and the Follow and
visibility decisions are the applications' own.

The signature and proof primitives were `ojak::sig` in *ojak* at first, and
are now *ojak-sig*. They were pure, but reaching them meant building the
framework, with its async runtime and HTTP client, which a device that only
signs or verifies has no use for. The crate is given the time and randomness
rather than reading the system's, so that it decides nothing about the
platform it runs on. It is not `no_std`: its structured-field parser and its
JSON canonicaliser need the standard library, and replacing them waits for an
application that runs without one. Fedify keeps its signatures in the
framework package, but they fetch keys and send requests; its vocabulary and
key encodings are the separate packages.

### Tests feed inputs and read outcomes

Core functions are tested as they are now, by passing values and asserting the
outcome, and every queue and store backend runs the same conformance checks.

The design had the framework ship a test federation that records what would
have been sent and lets a test hand it an activity as if it had arrived, so
that an application can test its listeners without a network. That has not
been built; `MemoryQueue` records what was queued, which is the nearest thing.


Sequence
--------

Each step stood on its own, so that an application could take them one at a
time next to what it had.

1.  *Read by meaning.* Wire *ojak-jsonld* into *ojak-vocab*, so that types
    read the normalised form and extension vocabulary is recognised by IRI,
    and into the inbound path after verification. *Done.*
2.  *Origins, verification and the guarded client.* The origin type, the
    stricter signature checks, proof verification over both kinds of origin,
    and the guarded client land as primitives, so that an application drops
    its own copies of the policy. *Done.*
3.  *Sending.* Queued delivery with retry in the other scheme and typed
    errors. *Done,* as a `Deliverer` rather than `send_activity`.
4.  *Serving.* Actor, object and collection dispatchers, WebFinger and
    NodeInfo, which only answer GET requests. *Done.* *serving.md* has the
    design.
5.  *The inbox.* Late, because it is where a mistake is a security problem.
    *Done.* *inbox.md* has the design.
6.  *Generated vocabulary.* Vendor the schemas, write the generator, and move
    *ojak-vocab* onto its output once the generated types read the same
    documents the hand-written ones do. *Done:* the generated types are
    *ojak-vocab*'s API, with Ojak's own types and properties in
    `extensions/`, and `tests/corpus` measures what they read.
7.  *Gateways.* Serving and accepting portable objects, and the signer trait
    for keys held off the server. *Done.* *portable.md* has the details.

What is left, from the decisions above: typed dispatch and returning
vocabulary types from dispatchers, stopping delivery to a failing host,
proofs as part of delivery, and a test federation.


Open questions
--------------

 -  *Client-to-server.* Clients that sign activities themselves (FEP-ae97) are
    the natural other half of keys held off the server. Outbox listeners are
    left out until an application needs them.
 -  *Which DID methods beyond `did:key`.* `did:key` cannot rotate. A method
    that can needs a party to resolve it, and the choice between a
    DNS-rooted identifier, a directory, and anything else is left to the
    application's resolver until one of them is clearly right.
 -  *Constrained runtimes.* The split between the `no_std` crates,
    *ojak-sig*, and *ojak* is meant to keep that door open. *ojak-sig* is
    one step from `no_std`, its structured-field parser and JSON
    canonicaliser. Whether the framework crate itself should run anywhere
    but a standard operating system is not decided.
