Guide
=====

These pages explain how each part of Ojak works and why it works that way.
If you haven't yet, [Getting started](../getting-started.md) shows the parts
together in one small server.

 -  [Concepts](./concepts.md): the ideas the rest builds on, including your
    application's data, the federation, origins, reading documents by
    meaning, and the queue and store.
 -  [Serving](./serving.md): what Ojak answers when another server, or a
    person, sends a GET.
 -  [The inbox](./inbox.md): what Ojak does with an activity another server
    POSTs, before your listener sees it.
 -  [Sending and fetching](./sending.md): delivering activities, fetching
    other servers' documents, and finding an actor by its handle.
 -  [Portable objects](./portable.md): objects whose identity is a key rather
    than a host (FEP-ef61).
 -  [Serving many instances](./multitenancy.md): how one process serves
    many fediverse instances, and the choices in Ojak that come from it.


Not yet supported
-----------------

 -  Typed dispatch: dispatchers take and return JSON (`serde_json::Value`),
    and cannot yet be registered as `object::<Note>` returning vocabulary
    types.
 -  Pausing delivery to a host that keeps failing, and attaching integrity
    proofs as part of delivery.  Your application can sign an activity with
    its `ProofSigner` before sending it.
 -  A test federation that records what a whole federation would have
    sent.  `MemoryQueue` records what was queued, and
    `ojak::testing::Remote` is another server to federate with in tests.
 -  Running a relay.  Receiving from one works (see [The
    inbox](./inbox.md#relays)).
 -  A configurable inbox body limit.  It is 1 MiB.
 -  Followers collection synchronisation (FEP-8fcf).
 -  Client-to-server (FEP-ae97), and forwarding from an outbox, which comes
    with it.
 -  DID methods other than `did:key` without a resolver of your own.
