Sending and fetching
====================

How Ojak delivers your application's activities to other servers, and how it
fetches their documents.  Both go through one guarded HTTP client.


Delivering activities
---------------------

A `Deliverer` sends activities through a queue, signed with keys your
application supplies through `SenderKeys`:

~~~~ rust
let deliverer = Deliverer::new(queue, sender_keys, client, DelivererConfig::default())
    .on_failure(|failure| mark_unavailable(failure));
deliverer.send(&sender_key_id, &create, inboxes).await?;
deliverer.send_batch(&sender_key_id, &move_, inboxes, &Batch { tag, deadline }).await?;
tokio::spawn(async move { deliverer.run_until(stop).await });
~~~~

Your application works out the inboxes, typically as a query over its own
tables, preferring shared inboxes.  `send_batch` tags a batch so it can be
followed, and gives it a deadline past which a delivery is given up on
rather than retried.  A batch with an `ordering_key` reaches each inbox in
the order it was queued among the batches with that key: give an
activity's object as the key, and its `Delete` waits until its `Create` has
gone through or been given up on, rather than overtaking it while it is
retried.  The queue keeps the order, through `Queue::enqueue_ordered`, so it
holds across processes; *ojak-postgres* keeps the key in an `ordering_key`
column, which `PostgresQueue::schema` adds to a table made before it.
`send_portable` delivers to a portable actor's gateways (see
[Portable objects](./portable.md#delivery)).

Delivery:

 -  removes duplicate inboxes;
 -  fans out through the queue, one job per inbox, so each inbox is retried
    on its own.  An optional priority queue lets sends to a few inboxes, such
    as a reply or a direct message, go ahead of a post to thousands of
    servers;
 -  retries on network errors, 408, 429 and 5xx, and honours `Retry-After`.
    `DelivererConfig::retry` says how many attempts a delivery gets and how
    long to wait after each failure: thirty seconds doubling to an hour, twelve
    attempts, unless given.  `RetryPolicy::exponential` sets other numbers, and
    `RetryPolicy::custom` takes a function of how many attempts have failed,
    for a schedule of your own, such as Mastodon's.  A `Batch` may give its
    deliveries fewer attempts with `max_attempts`, and put them in a
    low-priority lane, claimed only when nothing else is due, with
    `low_priority` and `DelivererConfig::low_priority`.  A retry waits at least
    what `Retry-After` asked, and a delivery the circuit breaker held at least
    until its cool-off ends, unless `DelivererConfig::wait_as_asked` is off;
 -  treats every other 4xx as permanent and reports it to `on_failure` with
    its status, which is where your application marks a domain unavailable.
    Which statuses are permanent is `DelivererConfig::permanent`'s to say:
    Mastodon, for one, retries a 401 and gives up on a 501.  A status
    `DelivererConfig::permanent_if_sender_gone` names is permanent too when
    `SenderKeys::gone` says the sender is gone for good, as Mastodon gives up
    on a 401 to a deleted or suspended account's delivery;
 -  holds back deliveries to a destination that keeps failing.  After ten
    failures in a row, its circuit breaker opens, and deliveries to it are
    retried without being sent until a minute has passed since the last
    failure; then they are let through, and one that succeeds closes it.  A
    held delivery counts as an attempt, as Mastodon counts it.  The breaker
    is kept for each host, or for each inbox, as Mastodon keeps it, in
    memory unless `breaker_store` gives the deliverer a `BreakerStore` of
    your own, such as one in Redis that every process shares, as Mastodon's
    Stoplights are; `DelivererConfig::breaker` sets it, and `None` turns it
    off;
 -  reports every attempt, delivered, failed or held, to `on_attempt`, for an
    application that keeps its own account of which servers answer, as
    Mastodon's delivery failure tracker does;
 -  awaits `on_settled` for each delivery that is done with — delivered,
    refused for good, or skipped — before it leaves the queue, with its
    batch's tag, for what is to follow a delivery having gone through;
 -  drops unsent what `skip_if`, given the inbox and the activity, says no
    longer to send when it comes due, such as a delivery to a server marked
    unavailable since it was queued;
 -  runs at most a configured number of deliveries per remote host at once,
    and optionally shares a limit across deliverers, such as every tenant's
    in one process;
 -  signs with one scheme, and retries once with the other when the first is
    refused, remembering per host which one worked.  The first scheme is
    draft-cavage by default, because it is what most of the network
    verifies;
 -  returns typed errors, so whether a failure is worth retrying is a
    variant, not a substring of a message.

The loop, `run_until(stop)`, finishes what is in flight once `stop`
completes, so a server shutting down does not drop deliveries mid-send.

To attach an integrity proof to an activity, sign it with your
`ProofSigner` before sending.


The guarded client
------------------

All of Ojak's outgoing requests, fetches and deliveries alike, go through one
pooled HTTP client, `ojak::client::Client`, which:

 -  refuses loopback, private, link-local, shared-address and similar ranges,
    checked on the addresses DNS returns, so a name cannot be pointed at an
    internal address after it passes the check;
 -  follows a GET's redirects itself, checking and re-signing each hop, up to
    three, and never follows a POST's;
 -  bounds response size, at 1 MiB, and time.

The ranges it refuses are those Mastodon's `PrivateAddressCheck` refuses,
the NAT64 and 6to4 prefixes included whatever address they carry.  For
development against servers on your own network, or a server reaching the
internet through NAT64, allow that network with `ClientConfig::allow_private`,
as a Mastodon server names it in `ALLOWED_PRIVATE_ADDRESSES`.

What is not a document, such as a link's preview page or a media file, an
application can fetch through the same guard and read itself, as a stream if
it is large: `Client::request` returns a `reqwest::RequestBuilder` whose URL,
addresses and redirects are all checked.  `ojak::client::validate_url` checks a
URL against the same rules without sending anything.


Fetching documents
------------------

A `Fetcher` fetches documents through the client, signing its GETs when
given a key, for servers that require authorized fetch.

`Fetcher::lookup` and `lookup_as`, which reads the document into a
vocabulary type, establish what they fetch the same way the inbox does:

 -  An `https` object whose `id` is on a different origin from the URL it
    came from is not trusted as that object.  Ojak fetches it once more from
    its own `id`, and trusts what the owner of the `id` serves there, as
    Mastodon does.  A second disagreement is refused.
 -  A document that names an author, in `attributedTo` or `actor`, on a
    different origin from its `id` is refused: a server can vouch for its own
    objects, not for who wrote them elsewhere.
 -  A portable object is trusted only with a valid proof (see [Portable
    objects](./portable.md#fetching)).
 -  Only `application/activity+json`, or `application/ld+json` with the
    ActivityStreams profile, counts as ActivityPub.  Plain JSON never does,
    since a server that takes uploads would otherwise serve it in its own
    name.

A fetched document comes back with the URL it was finally served from.

`Fetcher::walk` goes through a collection's items, an outbox or a
followers collection, fetching its pages as their items are wanted:

~~~~ rust
let mut walk = fetcher.walk(&outbox, key, WalkLimits::default());
while let Some(item) = walk.next().await? { … }
~~~~

It follows `first` and then each page's `next`, reading pages embedded in
the one before without a request.  Each page is fetched as `lookup` fetches
a document, and has to be on the collection's origin: a page elsewhere is
another server's say about what the collection holds.  A page seen before
ends the walk, and so do `WalkLimits`, a hundred pages and ten thousand items
unless given.  An item is as the page gives it, an IRI or an embedded object,
and an embedded object on another origin than the collection is that
server's claim, to be fetched from its own `id` before it is trusted.


Finding out what a server runs
------------------------------

`Fetcher::nodeinfo(&origin)` reads the links at `/.well-known/nodeinfo`, and
the NodeInfo document of the newest schema they link, into the `NodeInfo`
a server serves its own as.  It is read leniently, as servers write it:
the software's name lower-cased, what is missing left out.  A link to
another host is not followed, since a server answers only for itself.


Finding an actor by its handle
------------------------------

`Fetcher::webfinger` reads a handle, such as `@alice@social.example`, as an
`Address`, asks the host's WebFinger endpoint for it, and returns the actors
its `self` links name.  Each comes with its type when the link gives one, as
Lemmy's does for a name that is both a user and a community.  The host
answers only for itself, so look the actor up afterwards to establish it like
any other.
