//! Reverse SSH tunnels for the CLI, using the same providers as Eunha's trial.

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
};
use url::Url;

// Serveo's port-443 key is pinned to the fingerprint in serveo.net/docs.
// The Pinggy key is from dahlia/localtunnel's provider registry.
const KNOWN_HOSTS: &str = "[serveo.net]:443 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGX8CMtRKSA58fmA3I6oat6+7Z6VUwGbzYUE5FVrA3g1\n[free.pinggy.io]:443 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDF0YJigZJU62vn4rsKGRjIRTtMe/suc3d4YDe0iIvFzLMuaN78oxhWn9Uqefe1gN++dYVssspsgsvTXTTBcxxo3WoFeNr1z/+osJ45+Yxoa0pbaJdAwbr8CqjDa96r9/AhAXHoKncAByEOSiXfdWCXf84YC+Hu48/gZOqSZ3VqPz+nNGFByJcqYJ+jSELSqCNWVLWFxx7vH270Kymw2XkdOW47zzDNO7X4uByxHfaZMgI6phoaNglGizM0VNMQPL5GbspVGejFQE85QJbX3oF8vuCYnM+OMkwopHG+muh6Tro8+fm6G/fcmu34YJNbU3oaTdW1YPqvcKFX1AuIY9CA5lLZR9A1rOJ+fd4JEYaoTxwUN2ZPcrf7JEnvHmcV9hmupTSllJzLk4smDpl5PSknDm68/h/z/ZmaDlunGsHnn397fwCwS7sO9Q1yIuZ+Bri0td7+N2EK1mvM/qsnrSauOymcmqYVy6TLiejHdoVl8+lKqatkTxyFf/3MP8ylCKSoP0SJZratcU1n+0EciG+IjEzdPZ/1tuJZhBWqOUbYfUl+WgovH+J+AQKtoNzPP+fLtLNcmLEhx99N2y5l7A8IOlyy41Minq4N7V5X8Q7QHhEoocatNNn5JRYe/25P9aQelF0ItMD0PEmf8rIHWMqbwnwQ8pVVdDhE6mwhDskBIw==\n";

#[derive(Clone, Copy, ValueEnum)]
pub enum Provider {
    #[value(name = "serveo.net")]
    Serveo,
    #[value(name = "pinggy.io")]
    Pinggy,
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Serveo => "serveo.net",
            Self::Pinggy => "pinggy.io",
        }
    }

    fn url(self, output: &str) -> Option<Url> {
        let suffixes = match self {
            Self::Serveo => [".serveo.net", ".serveousercontent.com"],
            Self::Pinggy => [".free.pinggy.net", ".run.pinggy-free.link"],
        };
        // A final token can still be arriving on the pipe. Wait for its
        // delimiter before trusting a hostname that looks complete.
        let delimiter = |c: char| c.is_whitespace() || c == '\x1b';
        output.split_inclusive(delimiter).find_map(|token| {
            if !token.ends_with(delimiter) {
                return None;
            }
            let url = super::public_origin(token.trim_end_matches(delimiter)).ok()?;
            let host = url.host_str()?;
            suffixes
                .iter()
                .any(|suffix| {
                    host.strip_suffix(suffix).is_some_and(|label| {
                        !label.is_empty()
                            && label
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    })
                })
                .then_some(url)
        })
    }
}

pub struct Tunnel {
    pub origin: Url,
    child: Child,
    _files: tempfile::TempDir,
}

impl Tunnel {
    pub async fn wait(&mut self) -> Result<()> {
        let status = self
            .child
            .wait()
            .await
            .context("waiting for the SSH tunnel")?;
        bail!("public tunnel closed ({status})")
    }

    pub async fn close(mut self) -> Result<()> {
        self.child.kill().await.context("stopping the SSH tunnel")
    }
}

pub async fn open(port: u16, provider: Option<Provider>) -> Result<Option<Tunnel>> {
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            Ok(None)
        }
        result = connect(port, provider) => result.map(Some),
    }
}

async fn connect(port: u16, provider: Option<Provider>) -> Result<Tunnel> {
    let files = tempfile::Builder::new().prefix("ojak-tunnel-").tempdir()?;
    let identity = files.path().join("identity");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "ojak-tunnel", "-f"])
        .arg(&identity)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .context("install OpenSSH with ssh and ssh-keygen, or supply inbox --url")?;
    ensure!(status.success(), "could not generate a disposable SSH key");

    let hosts = files.path().join("known_hosts");
    std::fs::write(&hosts, KNOWN_HOSTS)?;
    let quoted = hosts
        .to_str()
        .context("SSH host key path must be UTF-8")?
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let defaults = [Provider::Serveo, Provider::Pinggy];
    let providers = provider
        .as_ref()
        .map_or(defaults.as_slice(), std::slice::from_ref);
    for &provider in providers {
        eprintln!("Opening a public HTTPS tunnel through {}", provider.name());
        let (host, remote_port) = match provider {
            Provider::Serveo => ("serveo.net", 80),
            Provider::Pinggy => ("free.pinggy.io", 0),
        };
        let mut command = Command::new("ssh");
        command
            .args([
                "-F",
                "/dev/null",
                "-p",
                "443",
                "-T",
                "-l",
                "ojak",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "IdentityAgent=none",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "NumberOfPasswordPrompts=1",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ConnectTimeout=8",
                "-o",
                "ServerAliveInterval=30",
                "-o",
                "ServerAliveCountMax=3",
                "-o",
                "UpdateHostKeys=no",
            ])
            .arg("-i")
            .arg(&identity)
            .arg("-o")
            .arg(format!("UserKnownHostsFile=\"{quoted}\""))
            .arg("-R")
            .arg(format!("{remote_port}:127.0.0.1:{port}"))
            .arg(host);
        if matches!(provider, Provider::Pinggy) {
            command.arg("x:xff");
        }
        // Serveo accepts a keyboard-interactive exchange with zero prompts.
        // Refuse any prompt that would actually require input.
        command
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("SSH_ASKPASS", "/usr/bin/false");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("could not start OpenSSH")?;
        let mut stdout = child.stdout.take().expect("piped SSH stdout");
        let mut stderr = child.stderr.take().expect("piped SSH stderr");
        let startup = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                Some(url) = discover(provider, &mut stdout) => Some(url),
                Some(url) = discover(provider, &mut stderr) => Some(url),
                else => None,
            }
        })
        .await;
        if let Ok(Some(origin)) = startup {
            // Drain the pipes while the tunnel runs so provider output never
            // blocks SSH or reaches the terminal unescaped.
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut stdout, &mut tokio::io::sink()).await;
            });
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
            });
            return Ok(Tunnel {
                origin,
                child,
                _files: files,
            });
        }
        let _ = child.kill().await;
        eprintln!("{} did not announce a public URL", provider.name());
    }
    bail!("no tunnel provider connected. Retry or supply a public URL with inbox --url")
}

async fn discover(provider: Provider, input: &mut (impl AsyncReadExt + Unpin)) -> Option<Url> {
    let mut output = Vec::new();
    let mut bytes = [0; 4096];
    while output.len() < 64 * 1024 {
        let n = input.read(&mut bytes).await.ok()?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&bytes[..n]);
        if let Some(url) = provider.url(&String::from_utf8_lossy(&output)) {
            return Some(url);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_complete_url_only_from_the_selected_provider() {
        assert!(
            Provider::Serveo
                .url("Forwarding https://trial.serveousercontent.com\n")
                .is_some()
        );
        assert!(
            Provider::Pinggy
                .url("https://trial.run.pinggy-free.link\n")
                .is_some()
        );
        assert!(
            Provider::Serveo
                .url("https://trial.serveo.net.evil.example\n")
                .is_none()
        );
        assert!(Provider::Serveo.url("https://trial.serveo.net").is_none());
        assert!(Provider::Pinggy.url("https://trial.serveo.net\n").is_none());
    }
}
