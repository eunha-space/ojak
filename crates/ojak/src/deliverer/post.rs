//! Delivering one activity to one inbox: one attempt of a [`Deliverer`](super::Deliverer) job.
//!
//! One signed POST, retried once in the other signature scheme when the
//! first is refused: a peer that answers 400 or 401 may be one that verifies
//! only the other. Mastodon 4.7 does the same. The result says which scheme
//! the peer accepted, so a caller can start there next time, and a failure
//! says whether trying again later could help.

use crate::client::{Client, RequestError};
use crate::sig::{Scheme, SenderKey, rfc9421, signature};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;
use std::time::Duration;
use url::Url;

const ACTIVITY_JSON: &str = "application/activity+json";

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
    /// It was not sent: its destination has failed too often in a row, and
    /// the circuit breaker holds deliveries to it until its cool-off ends.
    Held {
        /// How long until a delivery is let through again.
        retry_after: Duration,
    },
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
        self.is_permanent_by(permanent_status)
    }

    /// [`DeliveryError::is_permanent`], with `permanent` saying which
    /// statuses are.
    #[must_use]
    pub fn is_permanent_by(&self, permanent: fn(u16) -> bool) -> bool {
        match self {
            Self::Status { status, .. } => permanent(*status),
            Self::Request(RequestError::Refused(_) | RequestError::InvalidUrl(_))
            | Self::Signing(_) => true,
            Self::Request(RequestError::TooLarge | RequestError::Network(_))
            | Self::Unavailable(_)
            | Self::Held { .. } => false,
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

    /// How long the inbox asked to be left alone, or the circuit breaker
    /// holds it.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            Self::Held { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

/// Whether an inbox answering `status` is answering what will not change: a
/// 4xx, except 408 and 429, which say the request came at a bad time.
#[must_use]
pub fn permanent_status(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 408 | 429)
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Signing(error) => write!(f, "signing: {error}"),
            Self::Unavailable(error) => write!(f, "unavailable: {error}"),
            Self::Held { retry_after } => write!(
                f,
                "held: its destination keeps failing; let through in {}s",
                retry_after.as_secs()
            ),
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
                chrono::Utc::now().timestamp(),
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
                chrono::Utc::now().timestamp(),
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
