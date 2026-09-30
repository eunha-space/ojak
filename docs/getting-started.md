Getting started
===============

This page builds a small server with one actor, `alice`, served by [axum].
Other servers can find her by her handle and follow her, and she accepts
every follow.  It takes about a hundred lines, and every part of it is
covered in more depth in the [guide](./guide/).

[axum]: https://github.com/tokio-rs/axum


Add the dependencies
--------------------

Ojak is not on crates.io yet, so depend on it through Git:

~~~~ toml
[dependencies]
ojak = { git = "https://github.com/eunha-space/ojak.git" }
ojak-axum = { git = "https://github.com/eunha-space/ojak.git" }
ojak-vocab = { git = "https://github.com/eunha-space/ojak.git" }
axum = "0.8"
serde_json = "1"
tokio = { version = "1", features = ["full"] }
~~~~

Alice signs what she sends with an RSA key.  Make one:

~~~~ sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out alice.pem
openssl pkey -in alice.pem -pubout -out alice.pub.pem
~~~~


Your application's data
-----------------------

Ojak keeps no followers, posts or accounts of its own.  Everything it needs
from your application comes through callbacks, and every callback receives a
`Context` that carries a value of your choosing, typically a database pool.
Here it holds Alice's key and the two things that talk to other servers:

~~~~ rust
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use ojak::client::{Client, ClientConfig};
use ojak::deliverer::{Deliverer, DelivererConfig, SenderKeys};
use ojak::federation::{
    ActorRef, Context, Error, Federation, Found, PublicKey, Received, with_keys,
};
use ojak::fetch::Fetcher;
use ojak::kv::MemoryKvStore;
use ojak::queue::{MemoryQueue, QueueError};
use ojak::sig::{PrivateKey, Scheme, SenderKey};
use ojak_vocab::Follow;
use serde_json::{Value, json};

const ORIGIN: &str = "https://example.com";
const ALICE: &str = "https://example.com/users/alice";

#[derive(Clone)]
struct App {
    public_pem: String,
    key: SenderKey,
    fetcher: Arc<Fetcher>,
    deliverer: Arc<Deliverer<MemoryQueue, Keys>>,
}
~~~~

The deliverer asks which key signs for a sender through `SenderKeys`:

~~~~ rust
#[derive(Clone)]
struct Keys(SenderKey);

impl SenderKeys for Keys {
    async fn key(&self, sender: &str) -> Result<Option<SenderKey>, QueueError> {
        Ok((sender == ALICE).then(|| self.0.clone()))
    }
}
~~~~


Serve the actor
---------------

An actor dispatcher returns the actor's document for an identifier, or says
it was not found or is gone.  Its URI comes from the same template Ojak routes
requests with, so the two cannot drift apart, and `with_keys` adds the public
keys to it:

~~~~ rust
async fn alice(ctx: Context<App>, username: String) -> Result<Found<Value>, Error> {
    if username != "alice" {
        return Ok(Found::NotFound);
    }
    let id = ctx.actor_uri("person", &username)?;
    let mut actor = json!({
        "id": id.as_str(),
        "type": "Person",
        "preferredUsername": "alice",
        "inbox": format!("{id}/inbox"),
    });
    let keys = ctx.actor_keys(&ActorRef::new("person", username)).await?;
    with_keys(&mut actor, &keys);
    Ok(Found::Found(actor))
}
~~~~


Accept follows
--------------

A listener runs for each activity of its type.  By the time it runs, Ojak has
verified the HTTP signature, checked that the sender owns what it claims to,
and read the activity into a vocabulary type.  `follow.sender` is the actor
Ojak authenticated.

This one looks the follower up to find its inbox and queues an `Accept`
there:

~~~~ rust
async fn on_follow(ctx: Context<App>, follow: Received<Follow>) -> Result<(), Error> {
    let app = ctx.data();
    let follower = app.fetcher.lookup(&follow.sender, Some(&app.key)).await?;
    let Some(inbox) = follower.json["inbox"].as_str() else {
        return Ok(());
    };
    let accept = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{ALICE}#accepts/{}", follow.document["id"].as_str().unwrap_or_default()),
        "type": "Accept",
        "actor": ALICE,
        "object": follow.document,
    });
    app.deliverer.send(ALICE, &accept, [inbox.parse()?]).await?;
    Ok(())
}
~~~~

A real application would record the follower here too, in its own database.


Put it together
---------------

The federation is built once, at start-up, from everything above:

~~~~ rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SenderKey {
        key_id: format!("{ALICE}#main-key"),
        private_key: Arc::new(PrivateKey::from_pem(&std::fs::read_to_string("alice.pem")?)?),
    };
    let client = Client::new(ClientConfig::default())?;
    let fetcher = Arc::new(Fetcher::new(client.clone(), Scheme::DraftCavage));
    let deliverer = Arc::new(Deliverer::new(
        MemoryQueue::new(),
        Keys(key.clone()),
        client,
        DelivererConfig::default(),
    ));
    let app = App {
        public_pem: std::fs::read_to_string("alice.pub.pem")?,
        key,
        fetcher: fetcher.clone(),
        deliverer: deliverer.clone(),
    };

    let federation = Federation::builder()
        .origin(ORIGIN.parse()?)
        .actor("person", "/users/{username}", alice)
        .key_pairs(|ctx: Context<App>, actor: ActorRef| async move {
            let id = ctx.actor_uri(&actor.kind, &actor.identifier)?;
            Ok::<_, Error>(vec![PublicKey::Rsa {
                id: format!("{id}#main-key"),
                pem: ctx.data().public_pem.clone(),
            }])
        })
        .handle(|_, username: String| async move {
            Ok::<_, Error>((username == "alice").then(|| ActorRef::new("person", username)))
        })
        .inbox("person", "/users/{username}/inbox")
        .signed_fetch(fetcher, MemoryKvStore::new(), Duration::from_secs(3600), |ctx: Context<App>| async move {
            Ok::<_, Error>(Some(ctx.data().key.clone()))
        })
        .on(on_follow)
        .build()?;

    tokio::spawn(async move { deliverer.run().await });

    let router = ojak_axum::wrap(Router::new(), federation, move |_| Some(app.clone()));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    Ok(())
}
~~~~

What each part does:

 -  `.handle` maps a WebFinger username to an actor, so
    `@alice@example.com` can be found.  WebFinger and host-meta need nothing
    more.
 -  `.signed_fetch` gives the inbox what it needs to verify signatures: a
    fetcher for other servers' keys, a store to cache them in, and the key
    Ojak signs its own key fetches with.
 -  `.on(on_follow)` registers the listener.  Activities of types with no
    listener are accepted and dropped.
 -  Ojak does not spawn tasks of its own, so the deliverer's loop is yours to
    run.
 -  `ojak_axum::wrap` puts the federation in front of your router.  Requests
    for ActivityPub go to Ojak, and everything else, including a browser
    asking for Alice's profile page, goes to your routes.


Try it
------

Run it and ask for Alice as another server would:

~~~~ sh
curl -H 'Host: example.com' -H 'Accept: application/activity+json' \
  localhost:3000/users/alice
curl -H 'Host: example.com' \
  'localhost:3000/.well-known/webfinger?resource=acct:alice@example.com'
~~~~

To be followed from the fediverse, the server has to be reachable over HTTPS
at the origin it claims, here `https://example.com`.


Where to go next
----------------

 -  Replace `MemoryQueue` and `MemoryKvStore` with *ojak-postgres*'s, so that
    deliveries survive a restart.  See [Concepts](./guide/concepts.md).
 -  Serve posts and collections, and decide who may fetch them: [Serving].
 -  Handle more activities, and queue them rather than handling them inside
    the request: [The inbox].
 -  Send to many inboxes, and fetch from other servers: [Sending and fetching].

[Serving]: ./guide/serving.md
[The inbox]: ./guide/inbox.md
[Sending and fetching]: ./guide/sending.md
