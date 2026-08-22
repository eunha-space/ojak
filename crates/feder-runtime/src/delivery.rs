//! Signed delivery of an activity to a remote inbox.

use crate::{rfc9421, signature};

/// POST a serialized activity `body` to `inbox_url`, signed (RSA-SHA256 HTTP
/// Signature) with `key_id` / `private_key_pem`. Returns an error on a non-2xx
/// response. Logging and retries are the caller's concern.
///
/// Signs with draft-cavage first, then "double-knocks": a peer that answers
/// 400 or 401 may be one that has moved on to [RFC 9421] signatures, so the
/// same request is sent once more signed that way before the delivery is
/// called a failure. Mastodon 4.7 does the same, in the same order, since the
/// draft is still what most of the network verifies.
///
/// [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
pub async fn deliver(
    client: &reqwest::Client,
    body: &[u8],
    inbox_url: &str,
    key_id: &str,
    private_key_pem: &str,
) -> anyhow::Result<()> {
    let headers = signature::sign_request("post", inbox_url, body, key_id, private_key_pem)?;

    let resp = client
        .post(inbox_url)
        .header("Content-Type", "application/activity+json")
        .header("Accept", "application/activity+json")
        .header("Date", headers.date)
        .header("Digest", headers.digest)
        .header("Signature", headers.signature)
        .body(body.to_vec())
        .send()
        .await?;

    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    if !matches!(status.as_u16(), 400 | 401) {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("HTTP {} from {}: {}", status.as_u16(), inbox_url, text);
    }

    // The peer rejected the request; it may be one that only verifies RFC 9421.
    let first_error = resp.text().await.unwrap_or_default();
    match deliver_rfc9421(client, body, inbox_url, key_id, private_key_pem).await {
        Ok(()) => Ok(()),
        Err(e) => anyhow::bail!(
            "HTTP {} from {}: {}; retried with RFC 9421: {}",
            status.as_u16(),
            inbox_url,
            first_error,
            e
        ),
    }
}

/// Deliver signed with [RFC 9421] HTTP Message Signatures.
///
/// [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
pub async fn deliver_rfc9421(
    client: &reqwest::Client,
    body: &[u8],
    inbox_url: &str,
    key_id: &str,
    private_key_pem: &str,
) -> anyhow::Result<()> {
    let headers = rfc9421::sign_request("post", inbox_url, Some(body), key_id, private_key_pem)?;

    let mut request = client
        .post(inbox_url)
        .header("Content-Type", "application/activity+json")
        .header("Accept", "application/activity+json")
        .header("Signature-Input", headers.signature_input)
        .header("Signature", headers.signature);
    if let Some(digest) = headers.content_digest {
        // Covered by the signature, so it has to go out exactly as signed.
        request = request.header("Content-Digest", digest);
    }

    let resp = request.body(body.to_vec()).send().await?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("HTTP {} from {}: {}", status.as_u16(), inbox_url, text);
    }
    Ok(())
}
