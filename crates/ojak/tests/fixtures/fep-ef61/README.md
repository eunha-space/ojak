FEP-ef61 documents from other implementations
=============================================

Portable objects as other implementations sign and send them, byte for byte,
for *tests/portable\_interop.rs* to hold Ojak to.  They were captured by the
Fedify project for its 2.4.0 release, from unmodified binaries, and are
copied from its repository, *packages/fedify/test-vectors/fep-ef61/*, at tag
`2.4.0`, under the MIT License, Copyright 2024–2026 Hong Minhee.  The READMEs
there say how each was captured.

 -  *tootik-actor.json*: tootik v0.25.4's portable `Application` actor, whose
    `id` is a compatible identifier and which lists `gateways` without the
    FEP-ef61 context that maps the term.
 -  *tootik-follow.json*: a `Follow` that tootik v0.25.4 delivered from a
    portable `Person`, and *tootik-follow-actor.json*, that `Person`.
 -  *mitra-create.json*: a `Create` of a `Note`, each with its own proof,
    which Mitra v5.10.0 delivered as a gateway for a client that signed them,
    and *mitra-actor.json*, the actor as Mitra served it.
