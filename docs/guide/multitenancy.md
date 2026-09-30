Serving many instances
======================

Some of Ojak's shape comes from one requirement: a single process can serve
many fediverse instances, each with its own domain, its own accounts and
often its own database.  [Eunha] works this way.  Each tenant is a
Mastodon-compatible instance with its own PostgreSQL database, domain and
aliases, and one Eunha process serves them all.

This page explains the choices that requirement shapes.  An application that
serves one host pays almost nothing for them: it calls `.origin(url)` instead
of `.origin_with(…)`, and the rest never comes up.

[Eunha]: https://github.com/eunha-space/eunha


Ojak does not know what a tenant is
-----------------------------------

Nothing in Ojak has a tenant ID, a tenant table, or a list of hosts.
Instead, a tenant is whatever your application's `D` is.

A `Federation<D>` is built once, at start-up, and serves every tenant: one
set of routes, templates, dispatchers and listeners.  Each request carries
its own `D`, and every callback receives it through its `Context<D>`.  In
Eunha, `D` is the instance's `AppState`, holding that instance's database
pool, configuration and keys, so a dispatcher that loads an account reads it
from the right database without being told which tenant it is in.

This keeps tenancy entirely the application's business:

 -  Ojak cannot mix tenants up, because it never holds one tenant's data
    where another's request could reach it.
 -  How tenants are stored, isolated, created or unloaded can change without
    Ojak knowing.
 -  A single-host application uses the same API with a `D` that never
    changes.

With axum, the tenant comes from the request.  `ojak_axum::wrap` takes a
function from the request's parts to `D`, and your routing layer, which has
already resolved the host to a tenant, leaves the tenant's state in the
request's extensions:

~~~~ rust
ojak_axum::wrap(routes, federation, |parts| {
    parts.extensions.get::<AppState>().cloned()
})
~~~~

`None` passes the request to your application untouched, so a host that is
not a tenant never reaches Ojak.


The origin comes from the host
------------------------------

Every URI Ojak writes, in documents and in links, uses the canonical origin
for the host a request was for, and `.origin_with` is how your application
says what that is:

~~~~ rust
.origin_with(|host, state: &AppState| {
    let instance = &state.instance;
    let ours = host.eq_ignore_ascii_case(&instance.domain)
        || instance.aliases.iter().any(|alias| host.eq_ignore_ascii_case(alias));
    ours.then(|| Url::parse(&format!("https://{}", instance.domain)).ok()).flatten()
})
~~~~

It receives the host and the request's `D`, so it answers for the tenant the
request is for.  This one function covers several things:

 -  *Aliases.*  A host that maps to the canonical origin is an alias.  A
    document fetched through an alias still names the canonical URIs, so it
    says the same thing wherever it was fetched from.
 -  *Which handles are ours.*  WebFinger answers `acct:alice@host` for a host
    that maps to the tenant's origin, and `parse_uri` recognises IRIs on its
    aliases.  There is no second list of hosts to keep in step.
 -  *Unknown hosts.*  `None` is a 404.
 -  *The scheme.*  The scheme is the one the returned `Url` carries.  Behind
    a TLS-terminating proxy, which is how custom domains are usually served,
    the request itself can no longer tell.

Ojak lower-cases the host and strips a trailing dot before asking, so every
tenant's function sees hosts in one form.


Work outside a request keeps its tenant
---------------------------------------

A listener that sends a reply, or a timed job that delivers a post, runs
outside any request, but still needs the tenant's URIs.
`Federation::context(origin, data)` builds a context for a given tenant.
Code that only needs URIs can keep a `Uris`, from
`federation.uris(origin)`, in the tenant's state: it holds none of your data,
and `uris.with_origin(…)` gives another tenant's from the same templates.

An activity queued by the inbox keeps the origin it arrived at, and the
worker that runs it is built with that tenant's data, so its listener sees
the same context the request would have.


What is per tenant, and what is shared
--------------------------------------

Each part of Ojak that holds state is either handed to it per tenant, or
shared by the whole process on purpose.

### Per tenant

 -  *The inbox queue.*  `.inbox_queue(|data| …)` is asked for each request,
    so a tenant with its own database keeps its own queue in it.  An
    `InboxWorker` is built with one tenant's data and queue:

    ~~~~ rust
    InboxWorker::new(federation.clone(), state.clone(), queue).run_until(stop).await
    ~~~~

 -  *Delivery.*  A `Deliverer` owns a queue and a `SenderKeys`, so each
    tenant has its own, sending from its own table and signing with keys
    read from its own database.  A failed delivery is reported to that
    tenant's `on_failure`, where it marks a domain unavailable in the
    tenant's own records.

 -  *The fetcher.*  `.fetcher_for(|data| …)` picks the fetcher a request's
    signed-fetch checks use, so each tenant fetches with its own client
    settings and keeps its own record of which signature scheme each host
    accepts.

 -  *Every callback.*  `blocked`, `known_key`, `key_fetched` and the rest
    receive the tenant's context, so one tenant can block a server that
    another follows.

A tenant's data never needs a column saying which tenant it belongs to.
That matters to Eunha, whose databases stay compatible with Mastodon's
schema and can be exported or moved one tenant at a time.

### Shared by the process

 -  *The key-value store.*  One store, given to `.signed_fetch`, serves every
    tenant.  What it holds is a cache, so it can be shared, and bounded for
    the whole process with `MemoryKvStore::with_capacity`.  Its entries are
    namespaced so that sharing is safe:
     -  a remote public key is stored by its key ID, since it is the same
        whichever tenant asks;
     -  an activity already processed, and one already forwarded, are stored
        under the canonical origin they arrived at.  The same activity
        delivered to two tenants in one process is processed by both.
 -  *Limits across deliverers.*  `DelivererConfig::shared_limit` is a
    semaphore every tenant's deliverer can hold, so a process sends at most
    so many deliveries at once however many tenants it serves, and its
    sockets and memory stay bounded.  Each deliverer's own per-host limit
    still applies within it.
 -  *Waking.*  A deliverer with nothing due sleeps for up to its
    `idle_poll`, shortened at random by up to a quarter.  Without that,
    hundreds of idle tenants' loops started together would wake together,
    and query the database together.


Ojak does not spawn tasks
-------------------------

The deliverer's loop and the inbox worker are futures, `run_until(stop)`,
that your application spawns.  Ojak never starts a task on its own:

 -  Your application can spawn a tenant's work through its own function, so
    the task carries the tenant's tracing span, its limits, and anything else
    that follows a tenant around.
 -  A tenant can be stopped by itself, when it is unloaded, suspended or
    moved, without stopping the process.  Once `stop` completes, a loop
    claims nothing more and finishes what it has in flight, so no delivery
    is dropped half-sent.
 -  A dormant tenant costs no task at all until your application starts
    one.

Because work is *claimed* from a queue for a lease rather than handed to a
listener, a tenant's queue can be worked by any process, and a tenant moved
from one process to another picks up where it left off: what the old process
held is handed out again when its lease lapses.


Summary
-------

| Choice                                        | Why                                                     |
| --------------------------------------------- | ------------------------------------------------------- |
| The tenant is `D`, per request                | One federation serves every tenant; Ojak holds no data  |
| `origin_with(host, data)`                     | Canonical URIs, aliases and handles from one function   |
| `ojak_axum::wrap` takes `D` from the request  | Your routing, not Ojak's, decides the tenant            |
| `Federation::context(origin, data)`           | Work outside a request keeps its tenant                 |
| Inbox queue, deliverer and fetcher per tenant | Each tenant's state stays in its own database           |
| Seen and forwarded IDs keyed by origin        | A shared store never merges two tenants' activities     |
| `shared_limit` and jittered `idle_poll`       | Many tenants in one process share limits, not stampedes |
| No spawned tasks; `run_until(stop)`           | Tenants start and stop on their own                     |
