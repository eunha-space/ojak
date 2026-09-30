What is Ojak?
=============

Ojak is a Rust framework for building ActivityPub applications: the
software that lets your service join the fediverse, alongside Mastodon,
Misskey, Lemmy, PeerTube and the rest.

The name comes from *Ojakgyo* (오작교, 烏鵲橋), the bridge of crows and
magpies that, in the Korean telling of the Weaver and the Herdsman, spans the
Milky Way so that two stars kept apart can meet.  Ojak is the bridge between
your application and the servers it federates with.


How it works
------------

Your application keeps its own data.  It tells Ojak where its actors, objects
and collections live, supplies them from its own storage when asked, and
decides what to do with what arrives.  Ojak does the protocol around them:

 -  *Serving.*  Actors, objects and paged collections at URIs built from the
    same templates requests are routed by, with WebFinger, host-meta and
    NodeInfo following from them.  A browser asking for the same URL gets
    your application's page.
 -  *Receiving.*  Every activity is authenticated before your code sees it,
    by an HTTP signature (draft-cavage or RFC 9421) or an FEP-8b32 integrity
    proof, and anything in it the sender cannot vouch for is reduced to a
    reference.  Your listener receives it typed.
 -  *Sending.*  Deliveries go through a queue, are retried on their own per
    inbox, and are bounded per host.  They are signed in the scheme each
    host accepts.
 -  *Fetching.*  Every outgoing request goes through a client that refuses
    private addresses, and a fetched object is trusted only as far as its
    origin can vouch for it.
 -  *Portable objects.*  Objects whose identity is a key rather than a
    hostname (FEP-ef61), served and accepted at gateways, and signed with a
    key that need not live on the server.

Documents are read by what their keys mean rather than how they are spelled,
so a Mastodon `Follow` and one written with an unusual `@context` reach the
same listener.  The contexts this needs ship with Ojak and are never fetched.

[Getting started](./getting-started.md) builds a small server with all of
this in about a hundred lines.


What it runs on
---------------

The framework itself runs on Tokio, with an adapter for [axum] and
PostgreSQL backends for its queue and cache.  Anything else plugs in behind
the same traits.

What does no I/O is kept apart from what does.  The vocabulary and JSON-LD
crates are `no_std`, and signatures and proofs are a crate of their own that
takes bytes, keys and the time rather than fetching or reading them.  Those
parts can run where a full server cannot, and Ojak aims to let ActivityPub
software be split across machines of very different sizes.
[Crates](./crates.md) lists what is where.

[axum]: https://github.com/tokio-rs/axum


Status
------

Ojak is young, and its APIs may still change.  Applications built on it are
in the [showcase](./showcase.md), and what it does not do yet is listed in the
[guide](./guide/#not-yet-supported).

It is not on crates.io yet.  Depend on it through Git:

~~~~ toml
[dependencies]
ojak = { git = "https://github.com/eunha-space/ojak.git" }
~~~~


License
-------

Ojak is licensed under the [GNU Affero General Public License v3.0][AGPL].

[AGPL]: https://github.com/eunha-space/ojak/blob/main/LICENSE
