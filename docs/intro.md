What is Ojak?
=============

Ojak is an early-stage Rust framework for building ActivityPub applications.

The name comes from *Ojakgyo* (오작교, 烏鵲橋), the bridge of crows and
magpies that, in the Korean telling of the Weaver and the Herdsman, spans the
Milky Way so that two stars kept apart can meet.  Ojak builds bridges between
servers.


Motivation
----------

Ojak grew out of work in the [Fedify] ecosystem and a question about smaller,
cheaper, and more portable fediverse software.  What would it take for a
single-user ActivityPub server to run outside the usual VPS-shaped web
application?

One long-term direction is embedded or device-like federation: not moving a full
Mastodon-style server onto a microcontroller, but decomposing ActivityPub
software so different parts can run on machines with very different resources.

[Fedify]: https://fedify.dev/


Approach
--------

Ojak separates ActivityPub protocol logic from platform execution, as its
main architectural rule has it:

> The core decides what should happen.  The runtime decides how it happens on
> a specific platform.

What does no I/O is kept apart from what does.  The vocabulary and JSON-LD
crates are `no_std`, and signatures and proofs, in a crate of their own, take
bytes, keys and the time rather than fetch or read them, so that the parts that
decide can one day run where a full server cannot.

The application owns its data: it says where its actors, objects and
collections live and supplies them from its own storage, and Ojak does the
protocol around them.  The [design records](./design/) say why it is shaped
this way.


Status
------

Ojak serves actors, objects and collections, answers WebFinger and NodeInfo,
receives and verifies activities, delivers through a queue, and serves and
accepts portable objects.  Applications built on it are in the
[showcase](./showcase.md).  APIs and crate boundaries may still change; the
[design records](./design/) say what is built and what is left.  Depend on it
through Git:

~~~~ toml
[dependencies]
ojak = { git = "https://github.com/eunha-space/ojak.git" }
~~~~


License
-------

Ojak is licensed under the [GNU Affero General Public License v3.0][AGPL].

[AGPL]: https://github.com/eunha-space/ojak/blob/main/LICENSE
