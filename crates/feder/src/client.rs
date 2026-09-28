//! The HTTP client every request Feder sends goes through.
//!
//! An ActivityPub server fetches and posts to URLs other servers name, so
//! anything that reaches its network is reachable by anyone who can name a
//! URL. This client refuses the addresses a public server has no business
//! contacting — loopback, private, link-local, shared and reserved ranges —
//! and it decides on the addresses DNS returns, after resolution, so that a
//! name that passed a check cannot be pointed somewhere else before the
//! connection is made. Literal IP addresses in a URL, and every hop of a
//! redirect, are checked the same way.
//!
//! An application running against a peer on its own network, in development
//! or tests, allows that network explicitly with
//! [`ClientConfig::allow_private`].

use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::HeaderMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// How the client behaves.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Networks the client may reach although they are not public.
    pub allow_private: Vec<IpNet>,
    /// The `User-Agent` sent with every request.
    pub user_agent: String,
    /// How long a connection may take to open.
    pub connect_timeout: Duration,
    /// How long a whole request may take, response included.
    pub timeout: Duration,
    /// The largest response body read; a longer one is an error.
    pub max_response_bytes: usize,
    /// How many redirects a GET follows.
    pub max_redirects: usize,
    /// How long a connection is kept open, unused, for another request to
    /// the same host.
    pub pool_idle_timeout: Duration,
    /// How many unused connections are kept open to one host.
    ///
    /// A fan-out sends to thousands of hosts once each, and every connection
    /// kept for reuse is a socket and its buffers: left unbounded, as the
    /// HTTP client's defaults leave it, a post to 9,258 servers held 3,900
    /// sockets and 370 MiB. Mastodon closes a connection after 30 seconds
    /// idle and keeps 512 at most.
    pub pool_max_idle_per_host: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            allow_private: Vec::new(),
            user_agent: concat!("feder/", env!("CARGO_PKG_VERSION")).to_owned(),
            connect_timeout: Duration::from_secs(10),
            timeout: Duration::from_secs(30),
            max_response_bytes: 1024 * 1024,
            max_redirects: 3,
            pool_idle_timeout: Duration::from_secs(10),
            pool_max_idle_per_host: 2,
        }
    }
}

/// Why a request was not answered.
#[derive(Debug)]
pub enum RequestError {
    /// The URL is not an `http` or `https` URL with a host.
    InvalidUrl(String),
    /// The URL's host is, or resolves only to, an address the client
    /// refuses.
    Refused(String),
    /// The response was larger than [`ClientConfig::max_response_bytes`].
    TooLarge,
    /// The connection failed, timed out, or broke.
    Network(reqwest::Error),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "not a URL Feder will request: {url}"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::TooLarge => f.write_str("response too large"),
            Self::Network(error) => write!(f, "network: {error}"),
        }
    }
}

impl std::error::Error for RequestError {}

/// A response, read in full.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    /// Where the response came from, after any redirects.
    pub url: Url,
    pub body: Vec<u8>,
}

/// The guarded client. Cheap to clone; clones share a connection pool.
#[derive(Clone, Debug)]
pub struct Client {
    get: reqwest::Client,
    /// Follows no redirect.
    direct: reqwest::Client,
    config: Arc<ClientConfig>,
}

impl Client {
    /// Build a client.
    ///
    /// # Errors
    ///
    /// When the TLS backend cannot be initialised.
    pub fn new(config: ClientConfig) -> Result<Self, RequestError> {
        let config = Arc::new(config);
        let resolver = Arc::new(GuardedResolver {
            allow: config.allow_private.clone(),
        });
        let builder = || {
            reqwest::Client::builder()
                .user_agent(config.user_agent.clone())
                .connect_timeout(config.connect_timeout)
                .timeout(config.timeout)
                .pool_idle_timeout(config.pool_idle_timeout)
                .pool_max_idle_per_host(config.pool_max_idle_per_host)
                .dns_resolver(resolver.clone())
        };
        let redirect_config = config.clone();
        let get = builder()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() > redirect_config.max_redirects {
                    return attempt.error("too many redirects");
                }
                match check_url(attempt.url(), &redirect_config.allow_private) {
                    Ok(()) => attempt.follow(),
                    Err(RequestError::Refused(why)) => attempt.error(Refused(why)),
                    Err(error) => attempt.error(error.to_string()),
                }
            }))
            .build()
            .map_err(RequestError::Network)?;
        // A delivery is not redirected: the inbox is where the signature says
        // it is going, and a redirected POST would carry the body elsewhere.
        // A signed GET follows its redirects itself, signing each hop for
        // where it goes.
        let direct = builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(RequestError::Network)?;
        Ok(Self {
            get,
            direct,
            config,
        })
    }

    /// The configuration the client was built with.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// GET `url`, following redirects.
    ///
    /// # Errors
    ///
    /// When the URL or an address is refused, the response is too large, or
    /// the request fails. A response with any status is `Ok`.
    pub async fn get(&self, url: &Url, headers: HeaderMap) -> Result<Response, RequestError> {
        check_url(url, &self.config.allow_private)?;
        let response = self
            .get
            .get(url.clone())
            .headers(headers)
            .send()
            .await
            .map_err(classify)?;
        self.read(response).await
    }

    /// GET `url` without following a redirect: a 3xx is the response.
    ///
    /// # Errors
    ///
    /// As [`Client::get`].
    pub async fn get_direct(
        &self,
        url: &Url,
        headers: HeaderMap,
    ) -> Result<Response, RequestError> {
        check_url(url, &self.config.allow_private)?;
        let response = self
            .direct
            .get(url.clone())
            .headers(headers)
            .send()
            .await
            .map_err(classify)?;
        self.read(response).await
    }

    /// POST `body` to `url`, without following redirects.
    ///
    /// # Errors
    ///
    /// As [`Client::get`].
    pub async fn post(
        &self,
        url: &Url,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<Response, RequestError> {
        check_url(url, &self.config.allow_private)?;
        let response = self
            .direct
            .post(url.clone())
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(classify)?;
        self.read(response).await
    }

    async fn read(&self, mut response: reqwest::Response) -> Result<Response, RequestError> {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let url = response.url().clone();
        let limit = self.config.max_response_bytes;
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(RequestError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(RequestError::Network)? {
            if body.len() + chunk.len() > limit {
                return Err(RequestError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            url,
            body,
        })
    }
}

/// A refusal from the resolver or a redirect surfaces inside reqwest's error;
/// bring it back out as what it is.
fn classify(error: reqwest::Error) -> RequestError {
    let mut source: Option<&dyn std::error::Error> = Some(&error);
    while let Some(current) = source {
        if let Some(refused) = current.downcast_ref::<Refused>() {
            return RequestError::Refused(refused.0.clone());
        }
        source = current.source();
    }
    RequestError::Network(error)
}

/// A refusal, carried through reqwest's error types from the resolver or the
/// redirect policy.
#[derive(Debug)]
struct Refused(String);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refused: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// Check a URL before requesting it: its scheme, and its host when the host
/// is a literal address, which DNS never sees.
fn check_url(url: &Url, allow: &[IpNet]) -> Result<(), RequestError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(RequestError::InvalidUrl(url.to_string()));
    }
    match url.host() {
        None => Err(RequestError::InvalidUrl(url.to_string())),
        Some(url::Host::Ipv4(address)) => check_address(IpAddr::V4(address), allow),
        Some(url::Host::Ipv6(address)) => check_address(IpAddr::V6(address), allow),
        Some(url::Host::Domain(_)) => Ok(()),
    }
}

fn check_address(address: IpAddr, allow: &[IpNet]) -> Result<(), RequestError> {
    if permitted(address, allow) {
        Ok(())
    } else {
        Err(RequestError::Refused(format!(
            "{address} is not a public address"
        )))
    }
}

fn permitted(address: IpAddr, allow: &[IpNet]) -> bool {
    is_public(address) || allow.iter().any(|network| network.contains(&address))
}

/// Resolves names and drops every address the client refuses, so the
/// connection is made only to an address that passed the check.
struct GuardedResolver {
    allow: Vec<IpNet>,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow = self.allow.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|address| permitted(address.ip(), &allow))
                .collect();
            if addresses.is_empty() {
                return Err(
                    Box::new(Refused(format!("{host} resolves to no public address")))
                        as Box<dyn std::error::Error + Send + Sync>,
                );
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

/// Whether `address` is on the public internet.
///
/// Everything the IANA special-purpose registries set aside is refused, and
/// an IPv6 address that carries an IPv4 one — mapped, NAT64, 6to4 — is judged
/// by the IPv4 address inside it, since that is where a packet to it ends up.
#[must_use]
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0                                   // "this network"
        || a == 10                             // private
        || a == 127                            // loopback
        || (a == 100 && (64..128).contains(&b)) // shared address space (CGNAT)
        || (a == 169 && b == 254)              // link-local
        || (a == 172 && (16..32).contains(&b)) // private
        || (a == 192 && b == 0 && c == 0)      // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)      // documentation
        || (a == 192 && b == 88 && c == 99)    // 6to4 relay anycast
        || (a == 192 && b == 168)              // private
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || (a == 198 && b == 51 && c == 100)   // documentation
        || (a == 203 && b == 0 && c == 113)    // documentation
        || a >= 224) // multicast, reserved, broadcast
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    if let Some(v4) = address.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) lead to the IPv4 address they
    // carry.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., hi, lo] = segments;
        return is_public_v4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    if segments[0] == 0x2002 {
        return is_public_v4(Ipv4Addr::from(
            (u32::from(segments[1]) << 16) | u32::from(segments[2]),
        ));
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || segments[0] & 0xfe00 == 0xfc00 // unique local
        || segments[0] & 0xffc0 == 0xfe80 // link-local
        || segments[0] & 0xffc0 == 0xfec0 // site-local, deprecated but routable by some
        || segments[0] & 0xff00 == 0xff00 // multicast
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] == 0x2001 && segments[1] < 0x0200) // Teredo, benchmarking, ORCHID
        || segments[..4] == [0x0100, 0, 0, 0] // discard-only
        || segments[..6] == [0, 0, 0, 0, 0, 0]) // IPv4-compatible, deprecated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(address: &str) -> bool {
        is_public(address.parse().expect("address"))
    }

    #[test]
    fn public_addresses_are_permitted() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700::1111",
            "2a00:1450::1",
        ] {
            assert!(public(address), "{address}");
        }
    }

    #[test]
    fn reserved_addresses_are_refused() {
        for address in [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "100::1",
        ] {
            assert!(!public(address), "{address}");
        }
    }

    /// An IPv6 address that reaches an IPv4 one is judged by that one.
    #[test]
    fn embedded_ipv4_addresses_are_judged_by_what_they_carry() {
        assert!(!public("::ffff:127.0.0.1"));
        assert!(!public("::ffff:10.0.0.1"));
        assert!(public("::ffff:1.1.1.1"));
        assert!(!public("64:ff9b::a9fe:a9fe")); // NAT64 of 169.254.169.254
        assert!(public("64:ff9b::101:101")); // NAT64 of 1.1.1.1
        assert!(!public("2002:7f00:1::1")); // 6to4 of 127.0.0.1
        assert!(!public("::127.0.0.1")); // IPv4-compatible
    }

    #[test]
    fn a_literal_address_in_a_url_is_checked() {
        let allow = [];
        for url in [
            "http://127.0.0.1/inbox",
            "https://[::1]/inbox",
            "http://169.254.169.254/latest/meta-data",
        ] {
            let url = Url::parse(url).expect("url");
            assert!(
                matches!(check_url(&url, &allow), Err(RequestError::Refused(_))),
                "{url}"
            );
        }
        assert!(matches!(
            check_url(&Url::parse("file:///etc/passwd").expect("url"), &allow),
            Err(RequestError::InvalidUrl(_))
        ));
        assert!(check_url(&Url::parse("https://example.com/").expect("url"), &allow).is_ok());
    }

    #[test]
    fn an_allowed_network_is_reachable() {
        let allow: Vec<IpNet> = vec!["127.0.0.0/8".parse().expect("network")];
        let url = Url::parse("http://127.0.0.1:8080/inbox").expect("url");
        assert!(check_url(&url, &allow).is_ok());
        let url = Url::parse("http://10.0.0.1/inbox").expect("url");
        assert!(check_url(&url, &allow).is_err());
    }
}
