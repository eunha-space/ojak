<!-- deno-fmt-ignore-file -->

Bundled JSON-LD contexts
========================

Every context `feder-jsonld` can resolve is in this directory.  There is no
document loader: a context IRI that is not listed below does not resolve and
is not fetched.  It is read as the ActivityStreams context instead, which every
context the fediverse serves extends, so that a document naming only its own
server's context, as Mbin's do, still reads; the terms that context would have
added do not expand, and the caller is told which context went unresolved.

That is a security boundary, not an optimisation.  Context resolution happens
on inbound, attacker-controlled documents, and a loader that fetches what those
documents name is a request forgery primitive reachable before any signature
has been verified.  Fedify reached the same conclusion from the other
direction, adding a `preloadedOnlyDocumentLoader` whose comment reads: “the
default fallback must never fetch attacker-supplied context URLs”.  Of the ten
security advisories Fedify has published, five are consequences of a fetching
loader — three SSRF, one unbounded redirect chain, one ReDoS in the HTML
`rel=alternate` scanner.  Feder does not have that code, so it cannot have
those bugs.

The cost is that an unknown extension term is dropped rather than understood.
*feder-vocab*'s `read_reporting` says which ones were.
That is the right trade for a protocol core: a term feder does not know is a
term feder was not going to act on.


Provenance
----------

Fetched verbatim from their canonical URLs on 2026-09-17:

| File                                | Source                                          |
| ----------------------------------- | ----------------------------------------------- |
| `activitystreams.jsonld`            | <https://www.w3.org/ns/activitystreams>         |
| `security-v1.jsonld`                | <https://w3id.org/security/v1>                  |
| `security-data-integrity-v1.jsonld` | <https://w3id.org/security/data-integrity/v1>   |
| `security-data-integrity-v2.jsonld` | <https://w3id.org/security/data-integrity/v2>, fetched 2026-09-27 |
| `security-multikey-v1.jsonld`       | <https://w3id.org/security/multikey/v1>         |
| `did-v1.jsonld`                     | <https://www.w3.org/ns/did/v1>                  |
| `cid-v1.jsonld`                     | <https://www.w3.org/ns/cid/v1>                  |
| `gotosocial.jsonld`                 | <https://gotosocial.org/ns>                     |
| `litepub.jsonld`                    | <https://litepub.social/litepub/context.jsonld> |
| `webfinger.jsonld`                  | <https://purl.archive.org/socialweb/webfinger>  |
| `join-lemmy.jsonld`                 | <https://join-lemmy.org/context.json>           |

Two of those need a word of explanation, because the reason they are bundled
is not “to save a round trip”.

 -  **`join-lemmy.jsonld`** is served as `application/json` with no
    `Link: <...>; rel="http://www.w3.org/ns/json-ld#context"` header.  A
    conforming loader treats that as an ordinary JSON document rather than a
    context, so every Lemmy-originated activity fails to expand before an
    application ever sees it.  Fetching it does not help; bundling it does.
    (Fedify ships a copy for the same reason: their issue #714.)

 -  **`cid-v1.jsonld`** is the W3C Controlled Identifiers context.  Mastodon
    4.7.0 added it to `ContextHelper::NAMED_CONTEXT_MAP`, so it appears in
    Mastodon's emitted `@context` from 4.7 onward.  It supersedes
    `did-v1` + `multikey-v1` for verification-method terms; all three are
    bundled because all three are still in circulation.

`joinmastodon.jsonld` is not fetched, because it cannot be.
<http://joinmastodon.org/ns> has never served a JSON-LD context document and
returns 404 — Mastodon inlines these term definitions into every outgoing
`@context` instead.  Some implementations (Bonfire, for one) nonetheless put
the bare namespace URL in `@context`, where it 404s for everyone.  The copy
here is transcribed from the `toot:` entries of Mastodon 4.7.1's
`app/helpers/context_helper.rb`, which is the only authoritative statement of
what those terms mean.

One difference from Fedify's transcription is deliberate: Mastodon defines
`attributionDomains` as `{"@container": "@set"}`, and Fedify's copy has
`{"@type": "@id"}`.  The values are bare domain names rather than IRIs, so
Mastodon's own definition is the one followed here.

`feder.jsonld` is not a fetched context either, and is not something a document
can refer to.  It is the context feder compacts *to*: the vocabulary
[`normalize`] writes its output in.  Its terms come from two places.  The
first is Mastodon 4.7.1’s `CONTEXT_EXTENSION_MAP`, which is what the rest of
the network already agrees to read — the `toot:`, `ostatus:` and `schema:`
terms, and the FEP-044f/7aa9 consent vocabulary.  The second is the default
contexts of the vocabulary schemas *feder-vocab* generates its types from
(*crates/feder-vocab/schemas*): the bundled data-integrity, Multikey, DID and
GoToSocial contexts they reference, and their inline Misskey, Fedibird,
LitePub, ValueFlows and units-of-measure terms.  Without the data-integrity
context in particular a proof normalises to `sec:proofValue` in a typed value
object rather than the `proofValue` it was written with.  Adding a term here
changes the spelling feder emits, so it belongs with the vocabulary types that
read it.

[`normalize`]: https://docs.rs/feder-jsonld/latest/feder_jsonld/fn.normalize.html


Updating
--------

Re-fetch from the table above and read the diff.  A context is a wire-format
contract: a term whose `@id` or `@type` changes changes what every document
using it means, so a diff here deserves the same attention as a schema change.
