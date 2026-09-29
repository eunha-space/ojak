Ojak
====

A bridge between your application and the fediverse.

Ojak is an early-stage Rust framework for building ActivityPub applications.

The name comes from *Ojakgyo* (오작교, 烏鵲橋), the bridge of crows and
magpies that, in the Korean telling of the Weaver and the Herdsman, spans the
Milky Way so that two stars kept apart can meet.  Ojak builds bridges between
servers.

Documentation is at <https://ojak.dev/>.


Motivation
----------

Ojak grew out of work in the Fedify ecosystem and a question about smaller,
cheaper, and more portable fediverse software. What would it take for a
single-user ActivityPub server to run outside the usual VPS-shaped web
application?

One long-term direction is embedded or device-like federation: not moving a full
Mastodon-style server onto a microcontroller, but decomposing ActivityPub
software so different parts can run on machines with very different resources.


Approach
--------

The application owns its data: it says where its actors, objects and
collections live, supplies them from its own storage, and decides what to do
with what arrives.  Ojak does the protocol around them: serving, verifying,
fetching and delivering.

What does no I/O is kept apart from what does.  The vocabulary and JSON-LD
crates are `no_std`, and signatures and proofs, in a crate of their own, take
bytes, keys and the time rather than fetch or read them, so that the parts that
decide can one day run where a full server cannot.


License
-------

Ojak is licensed under the GNU Affero General Public License v3.0. See
[*LICENSE*](./LICENSE) for details.
