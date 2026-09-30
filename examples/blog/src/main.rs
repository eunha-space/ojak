//! Run the blog.
//!
//! Configured by environment variables:
//!
//!  -  `BLOG_ORIGIN`: where the blog is reachable, such as
//!     `https://blog.example`. Required.
//!  -  `BLOG_TOKEN`: the token publishing a post takes. Without it, a new
//!     one is made on each run and printed.
//!  -  `BLOG_USERNAME`: the author's username; `blog` by default.
//!  -  `BLOG_TITLE`: the blog's name; `My blog` by default.
//!  -  `BLOG_LISTEN`: the address to listen on; `127.0.0.1:8080` by default.
//!  -  `BLOG_KEY`: where the author's private key is kept; `blog.pem` by
//!     default. A new key is made there on the first run.

use ojak::client::ClientConfig;
use ojak::sig::signature::generate_rsa_keypair;
use ojak_example_blog::{Blog, Config, router};
use std::env;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let var = |name: &str, default: &str| env::var(name).unwrap_or_else(|_| default.to_owned());
    let key_path = var("BLOG_KEY", "blog.pem");
    let (private_key_pem, public_key_pem) = key_pair(Path::new(&key_path))?;
    let config = Config {
        origin: env::var("BLOG_ORIGIN")
            .map_err(|_| "set BLOG_ORIGIN to where the blog is reachable")?
            .parse()?,
        username: var("BLOG_USERNAME", "blog"),
        title: var("BLOG_TITLE", "My blog"),
        token: env::var("BLOG_TOKEN").unwrap_or_else(|_| new_token()),
        private_key_pem,
        public_key_pem,
        client: ClientConfig::default(),
    };
    let listen = var("BLOG_LISTEN", "127.0.0.1:8080");
    let blog = Blog::new(config)?;

    // #region run
    // Ojak does not spawn tasks of its own: the delivery loop is ours to
    // run. It finishes what is in flight before it stops.
    let deliveries = tokio::spawn({
        let blog = blog.clone();
        async move {
            blog.deliverer
                .run_until(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await;
        }
    });

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let config = &blog.config;
    println!(
        "Serving {} as @{}@{} on {listen}",
        config.origin,
        config.username,
        config.origin.host_str().unwrap_or_default()
    );
    println!("Write a post at {}new", config.origin);
    if env::var("BLOG_TOKEN").is_err() {
        println!("with the token {}", config.token);
    }
    axum::serve(listener, router(blog))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    deliveries.await?;
    // #endregion run
    Ok(())
}

/// A token no one could guess: 128 random bits, in hexadecimal.
fn new_token() -> String {
    use rand_core::RngCore as _;
    let mut bytes = [0; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The author's key pair: the private key at `path`, made there if there is
/// none, and the public key beside it.
fn key_pair(path: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    let public = path.with_extension("pub.pem");
    if !path.exists() {
        let (private, public_pem) = generate_rsa_keypair(&mut rand_core::OsRng)?;
        std::fs::write(path, private)?;
        std::fs::write(&public, public_pem)?;
    }
    Ok((
        std::fs::read_to_string(path)?,
        std::fs::read_to_string(public)?,
    ))
}
