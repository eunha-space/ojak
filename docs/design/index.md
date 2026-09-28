Design records
==============

These records say why Ojak is shaped as it is: the framework as a whole, and
the steps that built it. Each opens with its status and says where what was
built differs from what was designed.

 -  [Ojak as an application framework](./framework.md): the governing rule,
    the decisions, and the seven steps. Six are done; the inbox is done in
    Ojak and taken up in full by oeee-cafe.
 -  [Serving](./serving.md): what Ojak answers when another server, or a
    person, sends a GET. Done, and used by both applications.
 -  [The inbox](./inbox.md): what Ojak does with an activity another server
    POSTs. Done; oeee-cafe uses typed listeners, and eunha one `on_any`.
 -  [Portable objects](./portable.md): objects whose identity is a key rather
    than a host (FEP-ef61). Done in Ojak; neither application is a gateway
    yet.


What is left
------------

 -  Typed dispatch, `object::<Note>`, and dispatchers that return vocabulary
    types rather than JSON.
 -  Stopping delivery to a host that keeps failing, and integrity proofs
    attached as part of delivery.
 -  A test federation that records what would have been sent.
 -  Folding *ojak-runtime* into *ojak-core* and *ojak*.
 -  A configurable inbox body limit.
 -  Followers collection synchronisation (FEP-8fcf), client-to-server
    (FEP-ae97), and hashlink media.
