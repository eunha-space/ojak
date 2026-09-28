Crates
======

Ojak is a Cargo workspace.  Each crate lives under *crates/* in the
[repository].

[repository]: https://github.com/eunha-space/ojak


Portable
--------

These make protocol decisions and do no I/O of their own.

 -  *ojak-vocab*: The Activity Vocabulary: every ActivityStreams type and the
    extensions the fediverse uses, generated from Fedify's vocabulary schemas
    and Ojak's own additions, with reading and writing through *ojak-jsonld*.

 -  *ojak-jsonld*: JSON-LD term expansion and compaction over bundled contexts,
    so that a document is read by what its keys stand for rather than how they
    are spelled.

 -  *ojak-core*: Portable ActivityPub decisions: pure functions over the
    vocabulary for addressing and visibility, what to do with a Follow, what a
    post or reaction means, relaying, and portable objects.


Runtime
-------

These do the I/O the portable crates leave out.

 -  *ojak-runtime*: Standard `std` building blocks: HTTP Signatures
    (draft-cavage, and RFC 9421 with RSA or Ed25519), FEP-8b32 Object Integrity
    Proofs, `did:key`, and WebFinger discovery.

 -  *ojak*: The application framework over the protocol crates: the guarded HTTP
    client, queued delivery, serving actors, objects and collections, the
    inbox, and the key-value store.

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
