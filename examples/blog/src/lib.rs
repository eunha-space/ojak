//! A blog that federates, built with Ojak.
//!
//! One author publishes posts. People on Mastodon and elsewhere find the
//! blog by its handle and follow it; each new post is delivered to them;
//! their replies show up under the post as comments, and their likes are
//! counted. *docs/tutorial.md* walks through it.
//!
//!  -  [`store`]: the blog's own data, which Ojak never holds.
//!  -  [`activitypub`]: the federation, and the documents it serves.
//!  -  [`inbox`]: what the blog does with the activities it receives.
//!  -  [`web`]: the pages a browser sees, and publishing a post.

pub mod activitypub;
pub mod inbox;
pub mod store;
pub mod web;

use ojak::client::{Client, ClientConfig};
use ojak::deliverer::{Deliverer, DelivererConfig};
use ojak::federation::{Context, Federation};
use ojak::fetch::Fetcher;
use ojak::queue::MemoryQueue;
use ojak::sig::{PrivateKey, Scheme, SenderKey};
use std::sync::{Arc, Mutex};
use url::Url;

/// How the blog is set up.
#[derive(Clone, Debug)]
pub struct Config {
    /// Where the blog is served, such as `https://blog.example`. Every URI
    /// the blog writes is on it.
    pub origin: Url,
    /// The author's username: the blog is `@{username}@{host}`.
    pub username: String,
    /// The blog's name, shown as the author's display name.
    pub title: String,
    /// The bearer token that publishing a post takes.
    pub token: String,
    /// The author's RSA key pair, as PKCS#8 and SPKI PEM.
    pub private_key_pem: String,
    pub public_key_pem: String,
    /// The HTTP client's settings; tests allow the loopback network here.
    pub client: ClientConfig,
}

/// Everything a request needs: the federation's `D`.
pub type App = Arc<Blog>;

// #region blog
pub struct Blog {
    pub config: Config,
    pub store: Mutex<store::Store>,
    /// The author's key, which signs deliveries and fetches.
    pub key: SenderKey,
    pub fetcher: Arc<Fetcher>,
    pub deliverer: Deliverer<MemoryQueue, SenderKey>,
    pub federation: Federation<App>,
}
// #endregion blog

impl Blog {
    /// # Errors
    ///
    /// When the private key cannot be read, or the HTTP client or the
    /// federation cannot be built.
    pub fn new(config: Config) -> Result<App, Box<dyn std::error::Error>> {
        let client = Client::new(config.client.clone())?;
        let fetcher = Arc::new(Fetcher::new(client.clone(), Scheme::DraftCavage));
        let federation = activitypub::federation(&config, fetcher.clone())?;
        // The key is named after the author, whose IRI the federation builds
        // from its template before there is any request.
        let author = federation
            .uris(config.origin.clone())
            .actor_uri(activitypub::AUTHOR, &config.username)?;
        let key = SenderKey {
            key_id: format!("{author}#main-key"),
            private_key: Arc::new(PrivateKey::from_pem(&config.private_key_pem)?),
        };
        // The blog has one author, so one key signs everything it sends.
        let deliverer = Deliverer::new(
            MemoryQueue::new(),
            key.clone(),
            client,
            DelivererConfig::default(),
        );
        Ok(Arc::new(Self {
            config,
            store: Mutex::default(),
            key,
            fetcher,
            deliverer,
            federation,
        }))
    }

    /// A context outside any request, for building URIs and activities when
    /// the author publishes.
    #[must_use]
    pub fn context(self: &Arc<Self>) -> Context<App> {
        self.federation
            .context(self.config.origin.clone(), self.clone())
    }

    /// The blog's data, locked.
    ///
    /// # Panics
    ///
    /// When a thread panicked while holding it.
    pub fn store(&self) -> std::sync::MutexGuard<'_, store::Store> {
        self.store.lock().expect("the store is not poisoned")
    }
}

// #region router
/// The whole blog as an axum router: Ojak answers ActivityPub requests,
/// and the web pages answer the rest.
pub fn router(app: App) -> axum::Router {
    let pages = web::router().with_state(app.clone());
    let federation = app.federation.clone();
    ojak_axum::wrap(pages, federation, move |_| Some(app.clone()))
}
// #endregion router
