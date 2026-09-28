Portable objects
================

Step 7 of *framework.md*: serving and accepting objects whose identity is a
key rather than a host (FEP-ef61), and signing them with a key that need not
be on the server. *framework.md* says why this belongs in the model; this is
how each part of Ojak does it.

*Status: done.* Everything below is implemented. What was designed and not
built is listed at the end; the [showcase](../showcase.md) says how
applications use it.


Identifiers
-----------

An `ap` URI names an object by a DID: `ap://did:key:z6Mk…/actor`. It is read
in three spellings and written in one:

 -  `ap://did:key:z6Mk…/path`, the canonical form, which is what Ojak writes;
 -  `ap+ef61://…` and a percent-encoded authority, `ap://did%3Akey%3Az6Mk…`,
    which are the same identifier;
 -  the *compatible* form a gateway serves it under,
    `https://gateway.example/.well-known/apgateway/did:key:z6Mk…/path`,
    which a server without FEP-ef61 sees as an ordinary `https` IRI.

`ojak_core::portable::ApUri` parses all three into the DID, the path and the
fragment, and compares by the canonical form, which drops the query. The
query of an `ap` URI carries location hints,
`?@gateway=https%3A%2F%2Fserver1.example`, which are kept apart as
`gateways()`; the compatible form's gateway is one too. A hint is kept only
when it is an `http` or `https` origin with no path. `ApUri` writes itself
back as `canonical()`, `encoded()`, `with_hints(…)` and `at_gateway(…)`, the
compatible form at a gateway; `is_portable`, `same_object` and `did_of` work
on plain strings.

The origin of an `ap` URI is its DID, and so is the origin of a compatible
one: the specification has an implementation that knows `ap` URIs read the
canonical identifier back out of it. Anything that trusted an `https` IRI for
coming from its host therefore does not trust a compatible one. That is the
safe direction to be wrong in, and it is what makes a gateway a location
rather than an authority.

The canonical form is not a valid RFC 3986 URI, because its authority holds
colons, and neither `url` nor `iri-string` accepts it. Where a type needs an
IRI, `Iri` for the vocabulary and `Url` for the inbox's sender, the authority
is percent-encoded, which both accept and which compares equal. The
vocabulary encodes on reading and decodes on writing, so a document read and
written again says what it said.


Verification
------------

A portable object is authentic when it carries an FEP-8b32 integrity proof
whose `verificationMethod` is a DID URL under the DID of the object's `id`,
and the proof verifies with the key that DID URL resolves to. Nothing else
makes it authentic: not the gateway it was fetched from, and not an HTTP
signature, which authenticates the gateway that sent it.

`did:key` needs no resolution; the key is the identifier. A `did:key` DID URL
resolves when its fragment is empty or the key's own multibase, as the
did:key method defines its single verification method, and when the key is
base58btc with no path or query. Other methods come from a `DidResolver`
the application provides, because a method that allows rotation needs
someone to ask and which one is the application's choice:

~~~~ rust
trait DidResolver {
    fn resolve<'a>(&'a self, did_url: &'a str) -> BoxFuture<'a, Result<Option<PublicKey>, Error>>;
}
~~~~

It is given to the fetcher, `Fetcher::did_resolver(resolver)`, and the inbox
uses the one on the signed-fetch fetcher. Without one, other methods do not
resolve and nothing under them is authentic.

`ojak::portable::verify(&document, resolver)` does this for any document: the
`id` is portable, a proof is there, its method is under the `id`'s DID, and it
verifies. It returns the `ApUri`. An actor also has to list at least one
gateway. `verify_by(&document, did, resolver)`, which the inbox uses, checks
the proof under a DID it is given, and does not ask for gateways.


Fetching
--------

`Fetcher::portable(&uri, gateways, key)` dereferences an `ap` URI by asking
each gateway in turn, once each: the hints the URI carries, then the ones the
caller passes. The request is a GET to the compatible form, asking for
`application/ld+json; profile="https://www.w3.org/ns/activitystreams"` and
signed when a key is given. A document is taken from the first gateway that
answers with an ActivityStreams content type and a document whose canonical
`id` is the URI asked for and whose proof verifies; a gateway that fails any
of that is skipped, not retried. When every one fails, the error lists each
gateway and why. `Fetcher::lookup` hands a portable URL to
`Fetcher::portable` rather than refusing it; since it takes a `Url`, that is
the percent-encoded spelling or the compatible one.


The inbox
---------

When the activity's `actor` is portable, the HTTP signature is not asked who
sent it. The proof is: the activity must carry one under the actor's DID,
and the actor is then the sender. The rules after that are the ones every
activity meets, over DID origins: the `id` has to be under the same DID, and
anything embedded that is not is reduced to its `id`. The `blocked` hook is
given the actor's DID. A portable activity whose proof does not verify is
refused with 401, `Delete` included, since unlike a server's actor a DID
cannot have gone away; `on_unverified` sees it.

An activity from an `https` actor may arrive at a portable inbox, and is
authenticated as it would be anywhere else.


Serving
-------

Ojak answers `/.well-known/apgateway/{did}/{+path}` when the application
registers a gateway:

~~~~ rust
.gateway(|ctx, uri: ApUri| async move { … })        // -> Found<Value>
.gateway_inbox(|ctx, inbox: ApUri| async move { … }) // -> Option<GatewayInbox>
~~~~

 -  A GET is answered with what `gateway` found, served as `application/ld+json`
    with the ActivityStreams profile. The application returns the document
    as a `Value` and Ojak serialises it, which may order its keys differently
    from the stored bytes; the proof is over the JCS canonical form, so it
    still holds, and Ojak does not otherwise rewrite a document it did not
    sign. A document that is not public is the application's to refuse; the
    context says who signed the request, as it does for any dispatcher.
    `Found::Gone` is a 410 with a Tombstone, and a path that is not an `ap`
    URI is not found.
 -  A POST is a delivery to a portable inbox, accepted when `gateway_inbox`
    maps the inbox to a `GatewayInbox`: the recipient, an actor the
    application hosts, and every gateway the actor lists, this one included.
    It is received as any inbox's activity is, with that actor as the
    recipient. An inbox it does not host is answered 404, as the
    specification asks; without `gateway_inbox`, a POST is 405.

Media by hashlink, `/.well-known/apgateway/hl:…`, is not served.


Forwarding
----------

An actor's gateways each keep its data, and a delivery reaches only one of
them, so FEP-ef61 asks the one it reaches to forward it to the rest, and
never to forward one activity twice. When an activity arrives at a portable
inbox and is authenticated, Ojak removes this gateway from the ones
`gateway_inbox` returned and calls the application's `forward` hook, the one
*inbox.md* describes, with `ForwardTo::Gateways` and the inbox and its other
gateways. The application sends it with `send_portable`.

That it was forwarded is kept in the key-value store for a week, so a copy
that comes back from another gateway is not sent on again; an activity with
no `id` cannot be kept track of, and is not forwarded, and nor is one when the
store cannot say. Forwarding needs the signed-fetch settings, where the store
is, and does not wait for a listener, or need one.

What another gateway forwards is signed by that gateway, which vouches for
nothing of the actor's. A portable activity carries its proof, and needs
nothing more. An ordinary one, a Mastodon `Follow` of a portable actor, is
accepted on a proof by a key in its actor's `assertionMethod`, and is
otherwise taken from where its `id` says it lives, as *inbox.md* describes for
any forwarded activity; one its server does not serve is refused. What is
forwarded then is the copy its server served. That is the safe way to be
wrong: a gateway may miss an activity, and cannot be handed a forged one.


Delivery
--------

A portable inbox has no host to send to, only gateways:

~~~~ rust
deliverer.send_portable(sender, &activity, [PortableInbox { inbox, gateways }]).await
~~~~

queues each inbox, once by its canonical form, with the gateways to try in
order; an inbox with none is skipped. A delivery tries them in turn within
one attempt: the first that accepts it completes it, and a gateway that fails
is passed over for the next rather than retried to exhaustion. When every
gateway fails, the attempt fails with the last gateway's error, and is retried
by the queue's policy from the first gateway again, or given up when that
error is permanent.

The HTTP signature on the request is the sending server's, as for any
delivery. `send_portable` does not sign the activity: the application proves
it first.


Keys
----

`ProofSigner` is the trait a proof comes from:

~~~~ rust
pub trait ProofSigner: Send + Sync + 'static {
    fn verification_method(&self) -> &str;
    fn prove<'a>(&'a self, document: &'a Value) -> BoxFuture<'a, Result<Value, Error>>;
}
~~~~

`Ed25519Signer` holds a seed in memory, from `new`, `generate` or `from_pem`,
derives its `did:key` and signs with it, `eddsa-jcs-2022`, which is
server-side signing. ML-DSA-44 proofs are verified but not made. A signer that
calls a separate service, or waits on a user's device, implements the same
trait: what is signed is a whole document, and what comes back is that
document with its proof. The application calls `prove` itself; nothing in
Ojak signs a portable object on its own.


Not built
---------

 -  *Forwarding from an outbox*, which comes with FEP-ae97. Forwarding from
    an inbox to collections, ActivityPub's, is built (*inbox.md*).
 -  *Client-to-server* (FEP-ae97): outboxes that accept activities signed by
    the client.
 -  *Collections* served without proofs, which are authentic only from a
    gateway the actor lists; Ojak does not read them yet.
 -  *Hashlink media.*
