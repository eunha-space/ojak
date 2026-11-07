//! Command-line tools for testing ActivityPub applications.

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use url::Url;

mod inbox;
mod tunnel;

use tunnel::Provider;

#[derive(Parser)]
#[command(name = "ojak", version, about = "Tools for testing ActivityPub")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Receive ActivityPub deliveries at a temporary actor.
    Inbox {
        /// Use an existing public HTTPS origin in place of an automatic tunnel.
        #[arg(long, value_parser = public_origin)]
        url: Option<Url>,
        /// Choose the automatic tunnel provider.
        #[arg(long, conflicts_with = "url")]
        tunnel_service: Option<Provider>,
        /// Port the tunnel or reverse proxy forwards to on 127.0.0.1.
        #[arg(long, default_value_t = 3000)]
        port: u16,
    },
    /// Expose a local HTTP port through a public HTTPS tunnel.
    Tunnel {
        /// Local HTTP port on 127.0.0.1.
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// Choose the tunnel provider.
        #[arg(long)]
        tunnel_service: Option<Provider>,
    },
}

fn public_origin(input: &str) -> Result<Url> {
    let url = Url::parse(input).context("expected an HTTPS origin")?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.domain().is_some_and(|name| {
                name.contains('.') && !name.trim_end_matches('.').ends_with(".localhost")
            })
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "use an HTTPS DNS hostname on port 443 without credentials, a path, query or fragment"
    );
    Ok(url)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Inbox {
            url,
            port,
            tunnel_service,
        } => inbox::run(url, port, tunnel_service).await,
        Command::Tunnel {
            port,
            tunnel_service,
        } => {
            let Some(mut tunnel) = tunnel::open(port, tunnel_service).await? else {
                return Ok(());
            };
            println!("{}", tunnel.origin);
            eprintln!("Forwarding to 127.0.0.1:{port}. Press Ctrl-C to stop.");
            tokio::select! {
                biased;
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    tunnel.close().await
                }
                result = tunnel.wait() => result,
            }
        }
    }
}
