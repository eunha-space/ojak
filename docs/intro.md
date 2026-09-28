What is Ojak?
=============

Ojak is an early-stage Rust project for building ActivityPub applications from
a portable protocol core and platform-specific runtimes.

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

Ojak separates ActivityPub protocol logic from platform execution.  The core
contains federation behavior such as delivery decisions and protocol-level
rules.  Runtimes provide platform-specific pieces such as networking, storage,
clocks, scheduling, and execution.

The main architectural rule is:

> The core decides what should happen.  The runtime decides how it happens on
> a specific platform.

The application owns its data: it says where its actors, objects and
collections live and supplies them from its own storage, and Ojak does the
protocol around them.  See the [design records](./design/) for where this is
going.


Status
------

APIs and crate boundaries may still change.  Ojak is used today by
[Eunha] and [Oeee Cafe], which depend on it through Git.

~~~~ toml
[dependencies]
ojak = { git = "https://github.com/eunha-space/ojak.git" }
~~~~

[Eunha]: https://github.com/eunha-space/eunha
[Oeee Cafe]: https://github.com/oeee-cafe/web


License
-------

Ojak is licensed under the [GNU Affero General Public License v3.0][AGPL].

[AGPL]: https://github.com/eunha-space/ojak/blob/main/LICENSE
