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
rather than retried.  `send_portable` delivers to a portable actor's
gateways (see [Portable objects](./portable.md#delivery)).

Delivery:

 -  removes duplicate inboxes;
 -  fans out through the queue, one job per inbox, so each inbox is retried
    on its own.  An optional priority queue lets sends to a few inboxes, such
    as a reply or a direct message, go ahead of a post to thousands of
    servers;
 -  retries on network errors, 408, 429 and 5xx, with a retry policy you can
    replace, and honours `Retry-After`;
 -  treats every other 4xx as permanent and reports it to `on_failure` with
    its status, which is where your application marks a domain unavailable.
    Which statuses are permanent is `DelivererConfig::permanent`'s to say:
    Mastodon, for one, retries a 401 and gives up on a 501;
 -  holds back deliveries to a destination that keeps failing.  After ten
    failures in a row, its circuit breaker opens, and deliveries to it are
    retried without being sent until a minute has passed since the last
    failure; then they are let through, and one that succeeds closes it.  A
    held delivery counts as an attempt, as Mastodon counts it.  The breaker
    is kept for each host, or for each inbox, as Mastodon keeps it, in
    memory; `DelivererConfig::breaker` sets it, and `None` turns it off;
 -  reports every attempt, delivered, failed or held, to `on_attempt`, for an
    application that keeps its own account of which servers answer, as
    Mastodon's delivery failure tracker does;
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

For development against servers on your own network, allow that network with
`ClientConfig::allow_private`.


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


Finding an actor by its handle
------------------------------

`Fetcher::webfinger` reads a handle, such as `@alice@social.example`, as an
`Address`, asks the host's WebFinger endpoint for it, and returns the actors
its `self` links name.  Each comes with its type when the link gives one, as
Lemmy's does for a name that is both a user and a community.  The host
answers only for itself, so look the actor up afterwards to establish it like
any other.
