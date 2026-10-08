Crates
======

Ojak is a Cargo workspace.  Each crate lives under *crates/* in the
[repository].

[repository]: https://github.com/eunha-space/ojak


API reference
-------------

The API reference is generated from the `main` branch and describes the
unreleased development API.

 -  [ojak]
 -  [ojak-axum]
 -  [ojak-postgres]
 -  [ojak-redis]
 -  [ojak-sig]
 -  [ojak-jsonld]
 -  [ojak-vocab]

To build and preview the guide and API reference together, run
`mise run docs:build`, then `npm --prefix docs run preview`.

[ojak]: https://ojak.dev/api/ojak/index.html
[ojak-axum]: https://ojak.dev/api/ojak_axum/index.html
[ojak-postgres]: https://ojak.dev/api/ojak_postgres/index.html
[ojak-redis]: https://ojak.dev/api/ojak_redis/index.html
[ojak-sig]: https://ojak.dev/api/ojak_sig/index.html
[ojak-jsonld]: https://ojak.dev/api/ojak_jsonld/index.html
[ojak-vocab]: https://ojak.dev/api/ojak_vocab/index.html


The vocabulary
--------------

These do no I/O, and are `no_std`, so that they can run where a standard
library cannot.  `mise run check` builds them for `thumbv7em-none-eabihf`, a
target with no standard library, so that a dependency that pulls `std` back
in fails the check.

 -  *ojak-vocab*: The Activity Vocabulary: every ActivityStreams type and the
    extensions the fediverse uses, generated from Fedify's vocabulary schemas
    and Ojak's own additions, with reading and writing through *ojak-jsonld*.
    `ojak_vocab::meaning` says what a post or reaction means where the
    fediverse says it several ways, and `ojak_vocab::json_ld_helper` reads
    a document as it arrived, as Mastodon's `JsonLdHelper` does: `type` as
    a string or an array, a value or its `id`, a `url`'s `href`.

 -  *ojak-jsonld*: JSON-LD term expansion and compaction over bundled contexts,
    so that a document is read by what its keys stand for rather than how they
    are spelled; and the RDF a document means, in the canonical N-Quads of
    URDNA2015, which is what a Linked Data Signature signs.  It fetches
    nothing; *ojak*'s `contexts` fetches, within bounds, the contexts an
    application asks to have a Linked Data Signature checked over.


Signatures
----------

 -  *ojak-sig*: HTTP Signatures (draft-cavage, and RFC 9421 with RSA or
    Ed25519, on requests and on responses) and the policy the inbox holds
    them to, FEP-8b32 Object
    Integrity Proofs (`eddsa-jcs-2022`, and `mldsa44-jcs-2024` to verify),
    Linked Data Signatures (`RsaSignature2017`, as Mastodon makes them),
    and `did:key`.  It does no I/O and needs no async runtime: the caller
    passes in bytes, headers, keys, the time and, to make a key,
    randomness.  It uses the standard library, which two of its parsers
    need.  *ojak* re-exports it as `ojak::sig`.


The framework
-------------

 -  *ojak*: The application framework.  The application says where its
    actors, objects and collections live and decides what to do with what
    arrives; Ojak does the protocol around them.

     -  `ojak::federation`: serving actors, objects, collections, WebFinger
        and NodeInfo, and the inbox.
     -  `ojak::deliverer`: queued delivery.
     -  `ojak::fetch` and `ojak::client`: fetching other servers' documents
        through the guarded HTTP client.
     -  `ojak::sig`: *ojak-sig*, re-exported.
     -  `ojak::origin` and `ojak::portable`: the same-origin rule, over hosts
        and DIDs, hosts in the form they are compared in (`normalize_host`,
        `host_of`, and `host_within` for a domain and its subdomains), and
        portable objects (FEP-ef61).
     -  `ojak::kv` and `ojak::queue`: the key-value store and the queue, as
        traits with in-memory implementations.


Integrations
------------

 -  *ojak-axum*: Serving an Ojak federation from an [axum] application.

 -  *ojak-postgres*: PostgreSQL backends for the queue and the key-value store.

 -  *ojak-redis*: A Redis backend for the key-value store, its keys under a
    prefix the application gives, so that several instances can share one
    Redis each under an ACL of its own, and for the deliverer's circuit
    breakers, kept as Stoplight keeps Mastodon's (`RedisBreakers`).

[axum]: https://github.com/tokio-rs/axum


Tooling
-------

 -  *ojak-vocab-gen*: Generates *ojak-vocab*'s types from the vendored
    vocabulary schemas.  It runs on a developer's machine, not in a build:

    ~~~~ sh
    cargo run -p ojak-vocab-gen
    ~~~~
