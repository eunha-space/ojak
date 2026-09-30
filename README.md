Ojak
====

A bridge between your application and the fediverse.

Ojak is a Rust framework for building ActivityPub applications.  Your
application keeps its own data: it says where its actors, objects and
collections live, supplies them from its own storage, and decides what to do
with what arrives.  Ojak does the protocol around them: serving, verifying,
fetching and delivering.

The name comes from *Ojakgyo* (오작교, 烏鵲橋), the bridge of crows and
magpies that, in the Korean telling of the Weaver and the Herdsman, spans the
Milky Way so that two stars kept apart can meet.

Documentation, including a [getting started] guide, is at
<https://ojak.dev/>.

[getting started]: https://ojak.dev/getting-started


Using it
--------

Ojak is young, and its APIs may still change.  It is not on crates.io yet, so
depend on it through Git:

~~~~ toml
[dependencies]
ojak = { git = "https://github.com/eunha-space/ojak.git" }
~~~~

What does no I/O is kept apart from what does.  The vocabulary and JSON-LD
crates are `no_std`, and signatures and proofs are a crate of their own that
takes bytes, keys and the time rather than fetching or reading them.  The
[crate list] says what is where.

[crate list]: https://ojak.dev/crates


License
-------

Ojak is licensed under the GNU Affero General Public License v3.0. See
[*LICENSE*](./LICENSE) for details.
