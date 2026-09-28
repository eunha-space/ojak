Crates
======

Ojak is a Cargo workspace.  Each crate lives under *crates/* in the
[repository].

[repository]: https://github.com/eunha-space/ojak


The vocabulary
--------------

These do no I/O, and are `no_std`, so that they can run where a standard
library cannot.

 -  *ojak-vocab*: The Activity Vocabulary: every ActivityStreams type and the
    extensions the fediverse uses, generated from Fedify's vocabulary schemas
    and Ojak's own additions, with reading and writing through *ojak-jsonld*.
    `ojak_vocab::meaning` says what a post or reaction means where the
    fediverse says it several ways.

 -  *ojak-jsonld*: JSON-LD term expansion and compaction over bundled contexts,
    so that a document is read by what its keys stand for rather than how they
    are spelled.


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
     -  `ojak::sig`: HTTP Signatures (draft-cavage, and RFC 9421 with RSA or
        Ed25519) and the policy the inbox holds them to, FEP-8b32 Object
        Integrity Proofs (`eddsa-jcs-2022`, and `mldsa44-jcs-2024` to
        verify), and `did:key`.  These do no I/O.
     -  `ojak::origin` and `ojak::portable`: the same-origin rule, over hosts
        and DIDs, and portable objects (FEP-ef61).
     -  `ojak::kv` and `ojak::queue`: the key-value store and the queue, as
        traits with in-memory implementations.


Integrations
------------

 -  *ojak-axum*: Serving an Ojak federation from an [axum] application.

 -  *ojak-postgres*: PostgreSQL backends for the queue and the key-value store.

[axum]: https://github.com/tokio-rs/axum


Tooling
-------

 -  *ojak-vocab-gen*: Generates *ojak-vocab*'s types from the vendored
    vocabulary schemas.  It runs on a developer's machine, not in a build:

    ~~~~ sh
    cargo run -p ojak-vocab-gen
    ~~~~
