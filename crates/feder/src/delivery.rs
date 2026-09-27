//! Delivering one activity to one inbox.
//!
//! One signed POST, retried once in the other signature scheme when the
//! first is refused: a peer that answers 400 or 401 may be one that verifies
//! only the other. Mastodon 4.7 does the same. The result says which scheme
//! the peer accepted, so a caller can start there next time, and a failure
//! says whether trying again later could help.

use crate::client::{Client, RequestError};
use feder_runtime::{rfc9421, signature};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

const ACTIVITY_JSON: &str = "application/activity+json";

/// An HTTP signature scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    /// draft-cavage-http-signatures-12, which most of the network verifies.
    DraftCavage,
    /// RFC 9421 HTTP Message Signatures.
    Rfc9421,
}

impl Scheme {
    /// The scheme a refused request is retried in.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::DraftCavage => Self::Rfc9421,
            Self::Rfc9421 => Self::DraftCavage,
        }
    }
}

/// The key an actor signs deliveries with.
#[derive(Clone, Debug)]
pub struct SenderKey {
    /// The key's IRI, as its actor document publishes it.
    pub key_id: String,
    pub private_key: Arc<signature::PrivateKey>,
}

/// Why a delivery did not go through.
#[derive(Debug)]
pub enum DeliveryError {
    /// The request was not answered, or was refused before it was sent.
    Request(RequestError),
    /// The request could not be signed.
    Signing(String),
    /// Something the delivery needs from the application, such as the
    /// sender's key, could not be read just now.
    Unavailable(String),
    /// The inbox answered with a status other than success.
    Status {
        status: u16,
        /// What the inbox asked for with `Retry-After`, in seconds.
        retry_after: Option<Duration>,
        /// The start of the response body, for the log.
        body: String,
    },
}

impl DeliveryError {
    /// Whether trying again later cannot help.
    ///
    /// A 4xx says the request itself is wrong, except 408 and 429, which say
    /// it came at a bad time. A refused address or URL stays refused. Anything
    /// else — 5xx, a timeout, a broken connection — may pass.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::Status { status, .. } => {
                (400..500).contains(status) && !matches!(status, 408 | 429)
            }
            Self::Request(RequestError::Refused(_) | RequestError::InvalidUrl(_))
            | Self::Signing(_) => true,
            Self::Request(RequestError::TooLarge | RequestError::Network(_))
            | Self::Unavailable(_) => false,
        }
    }

    /// The status the inbox answered with, if it answered.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// How long the inbox asked to be left alone.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Signing(error) => write!(f, "signing: {error}"),
            Self::Unavailable(error) => write!(f, "unavailable: {error}"),
            Self::Status { status, body, .. } => write!(f, "HTTP {status}: {body}"),
        }
    }
}

impl std::error::Error for DeliveryError {}

/// Deliver `body` to `inbox`, signed with `key`, trying `first` and then the
/// other scheme if `first` is refused. Returns the scheme that was accepted.
///
/// # Errors
///
/// When neither scheme is accepted, or the request fails for another reason.
pub async fn deliver(
    client: &Client,
    inbox: &Url,
    body: &[u8],
    key: &SenderKey,
    first: Scheme,
) -> Result<Scheme, DeliveryError> {
    match attempt(client, inbox, body, key, first).await {
        Ok(()) => Ok(first),
        Err(DeliveryError::Status {
            status: 400 | 401, ..
        }) => {
            let second = first.other();
            attempt(client, inbox, body, key, second).await?;
            Ok(second)
        }
        Err(error) => Err(error),
    }
}

async fn attempt(
    client: &Client,
    inbox: &Url,
    body: &[u8],
    key: &SenderKey,
    scheme: Scheme,
) -> Result<(), DeliveryError> {
    let mut headers = HeaderMap::new();
    insert(&mut headers, "content-type", ACTIVITY_JSON)?;
    insert(&mut headers, "accept", ACTIVITY_JSON)?;
    match scheme {
        Scheme::DraftCavage => {
            // Mastodon covers Content-Type on deliveries, so it is covered here.
            let signed = signature::sign_request_with_key(
                "post",
                inbox.as_str(),
                body,
                &key.key_id,
                &key.private_key,
                &[("content-type", ACTIVITY_JSON)],
            )
            .map_err(|error| DeliveryError::Signing(error.to_string()))?;
            insert(&mut headers, "date", &signed.date)?;
            insert(&mut headers, "digest", &signed.digest)?;
            insert(&mut headers, "signature", &signed.signature)?;
        }
        Scheme::Rfc9421 => {
            let signed = rfc9421::sign_request(
                "post",
                inbox.as_str(),
                Some(body),
                &key.key_id,
                &rfc9421::SigningKey::Rsa(&key.private_key),
            )
            .map_err(|error| DeliveryError::Signing(error.to_string()))?;
            insert(&mut headers, "signature-input", &signed.signature_input)?;
            insert(&mut headers, "signature", &signed.signature)?;
            if let Some(digest) = &signed.content_digest {
                // Covered by the signature, so it goes out exactly as signed.
                insert(&mut headers, "content-digest", digest)?;
            }
        }
    }

    let response = client
        .post(inbox, headers, body.to_vec())
        .await
        .map_err(DeliveryError::Request)?;
    if (200..300).contains(&response.status) {
        return Ok(());
    }
    let retry_after = response
        .headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let body: String = String::from_utf8_lossy(&response.body)
        .chars()
        .take(200)
        .collect();
    Err(DeliveryError::Status {
        status: response.status,
        retry_after,
        body,
    })
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), DeliveryError> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| DeliveryError::Signing(format!("{name}: {error}")))?;
    headers.insert(HeaderName::from_static(name), value);
    Ok(())
}
