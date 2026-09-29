//! HTTP Signature (draft-cavage-http-signatures) for ActivityPub federation.
//!
//! Runtime-agnostic: it works with plain byte slices and `(name, value)` header
//! pairs, so it can be used with any HTTP framework.

use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest as _, Sha256};

/// Headers produced by [`sign_request`] that must be attached to the outgoing request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Value for the `Signature` header.
    pub signature: String,
    /// Value for the `Date` header.
    pub date: String,
    /// Value for the `Digest` header.
    pub digest: String,
}

/// The `(request-target)` pseudo-header: the method and the path *including any
/// query string*.
///
/// Mastodon's `HttpSignatureDraft#request_target` appends `?query` when there
/// is one. Signing only the path would produce a signature no correct verifier
/// could reproduce for such a URL, and would accept two different URLs as the
/// same one.
/// The `Host` header a request to `url` carries: the host, and the port when
/// it is not the scheme's default, which is what an HTTP client sends and so
/// what the receiver rebuilds the signing string from.
fn host_header(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

fn request_target(method: &str, url: &url::Url) -> String {
    match url.query() {
        Some(query) => format!("{} {}?{}", method.to_lowercase(), url.path(), query),
        None => format!("{} {}", method.to_lowercase(), url.path()),
    }
}

/// Build a signing string and the `headers` parameter naming its lines.
///
/// The covered set and its order follow Mastodon: the headers the request
/// carries, in the order it carries them, with `(request-target)` appended
/// last. Any verifier reconstructs from the `headers` parameter, so the order
/// is not a correctness matter — but matching what the rest of the network
/// emits keeps eunha out of the way of anything that verifies more strictly
/// than it should.
fn signing_string(covered: &[(&str, String)]) -> (String, String) {
    let string = covered
        .iter()
        .map(|(name, value)| format!("{}: {value}", name.to_lowercase()))
        .collect::<Vec<_>>()
        .join("\n");
    let names = covered
        .iter()
        .map(|(name, _)| name.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    (string, names)
}

/// Sign an outgoing HTTP POST request body using RSA-SHA256.
///
/// Returns [`SignedHeaders`] that the caller must attach to the request.
///
/// Covers `host`, `date`, any `extra_headers` given, `digest`, and
/// `(request-target)` — in that order, as Mastodon does. `extra_headers` are
/// headers the caller will send and wants covered, such as `Content-Type`;
/// Mastodon covers every header on the request except `User-Agent`, `Accept`
/// and `Accept-Encoding`.
///
/// # Arguments
/// * `method`          – HTTP method in any case (will be lowercased)
/// * `url`             – Full URL of the target inbox
/// * `body`            – Serialized activity body (JSON bytes)
/// * `key_id`          – `keyId` URI, typically `https://actor/url#main-key`
/// * `private_key_pem` – PKCS#8 or PKCS#1 PEM-encoded RSA private key
/// * `extra_headers`   – Additional headers to cover, in the order sent
///
/// # Errors
/// Returns an error if the URL cannot be parsed or the key cannot sign.
pub fn sign_request(
    method: &str,
    url: &str,
    body: &[u8],
    key_id: &str,
    private_key_pem: &str,
    extra_headers: &[(&str, &str)],
) -> anyhow::Result<SignedHeaders> {
    let key = PrivateKey::from_pem(private_key_pem)?;
    sign_request_with_key(method, url, body, key_id, &key, extra_headers)
}

/// [`sign_request`] with a key parsed once by [`PrivateKey::from_pem`].
///
/// Parsing an RSA key costs more than signing with it, so a caller that signs
/// often with the same key should parse it once and keep it.
///
/// # Errors
/// Returns an error if the URL cannot be parsed.
pub fn sign_request_with_key(
    method: &str,
    url: &str,
    body: &[u8],
    key_id: &str,
    key: &PrivateKey,
    extra_headers: &[(&str, &str)],
) -> anyhow::Result<SignedHeaders> {
    let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(body)));
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let parsed = url::Url::parse(url).context("invalid URL")?;
    let host = host_header(&parsed);

    let mut covered: Vec<(&str, String)> = vec![("host", host), ("date", date.clone())];
    covered.extend(
        extra_headers
            .iter()
            .map(|(name, value)| (*name, (*value).to_string())),
    );
    covered.push(("digest", digest.clone()));
    covered.push(("(request-target)", request_target(method, &parsed)));

    let (signing_string, headers_param) = signing_string(&covered);
    let sig_b64 = key.sign(signing_string.as_bytes());
    let signature = format!(
        r#"keyId="{key_id}",algorithm="rsa-sha256",headers="{headers_param}",signature="{sig_b64}""#
    );

    Ok(SignedHeaders {
        signature,
        date,
        digest,
    })
}

/// Headers produced by [`sign_get`] for an authorized-fetch GET request.
#[derive(Debug, Clone)]
pub struct SignedGet {
    /// Value for the `Signature` header.
    pub signature: String,
    /// Value for the `Date` header.
    pub date: String,
}

/// Sign an outgoing HTTP GET request using RSA-SHA256, for "authorized fetch"
/// (secure mode) servers that require a signed dereference.
///
/// A GET has no body, so unlike [`sign_request`] it signs only
/// `(request-target) host date` and produces no `Digest`.
///
/// # Arguments
/// * `url`             – Full URL being fetched
/// * `key_id`          – `keyId` URI, typically `https://domain/actor#main-key`
/// * `private_key_pem` – PKCS#8 or PKCS#1 PEM-encoded RSA private key
pub fn sign_get(url: &str, key_id: &str, private_key_pem: &str) -> anyhow::Result<SignedGet> {
    let key = PrivateKey::from_pem(private_key_pem)?;
    sign_get_with_key(url, key_id, &key)
}

/// [`sign_get`] with a key parsed once by [`PrivateKey::from_pem`].
///
/// # Errors
/// Returns an error if the URL cannot be parsed.
pub fn sign_get_with_key(url: &str, key_id: &str, key: &PrivateKey) -> anyhow::Result<SignedGet> {
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let parsed = url::Url::parse(url).context("invalid URL")?;
    let host = host_header(&parsed);

    // Same covered set and order as Mastodon: no body, so no digest.
    let covered = [
        ("host", host),
        ("date", date.clone()),
        ("(request-target)", request_target("get", &parsed)),
    ];
    let (signing_string, headers_param) = signing_string(&covered);

    let sig_b64 = key.sign(signing_string.as_bytes());
    let signature = format!(
        r#"keyId="{key_id}",algorithm="rsa-sha256",headers="{headers_param}",signature="{sig_b64}""#
    );

    Ok(SignedGet { signature, date })
}

/// Verify the HTTP Signature on an incoming POST request.
///
/// This checks the signature and, when there is a `Digest` header, the body
/// against it, and nothing more: not which headers were signed, nor when, nor
/// for which host. [`verification`](super::verification) holds a request to
/// that policy before it calls this.
///
/// # Arguments
/// * `method`         – HTTP method in any case
/// * `path`           – Request path (e.g., `/inbox`)
/// * `headers`        – All request headers as `(lowercase-name, value)` pairs
/// * `body`           – Raw request body bytes
/// * `public_key_pem` – SPKI PEM-encoded RSA public key of the signing actor
pub fn verify_request(
    method: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    public_key_pem: &str,
) -> anyhow::Result<()> {
    let get = |name: &str| -> &str {
        headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or("")
    };

    let sig_header_val = get("signature");
    anyhow::ensure!(!sig_header_val.is_empty(), "missing Signature header");

    let params = parse_params(sig_header_val);
    let headers_list = params.get("headers").map(String::as_str).unwrap_or("date");
    let sig_b64 = params.get("signature").context("missing signature field")?;

    let digest_val = get("digest");
    if !digest_val.is_empty() {
        anyhow::ensure!(
            super::digest::digest_matches(digest_val, body),
            "body digest mismatch"
        );
    }

    let signing_string = headers_list
        .split_whitespace()
        .map(|h| {
            let h = h.to_ascii_lowercase();
            let value = match h.as_str() {
                // The signer covered the path *and* any query string, so the
                // verifier has to reconstruct both or it rebuilds a different
                // request than the one that was signed.
                "(request-target)" => format!("{} {}", method.to_lowercase(), path_and_query),
                "(created)" | "(expires)" => params
                    .get(&h[1..h.len() - 1])
                    .with_context(|| format!("{h} is covered but not given"))?
                    .clone(),
                other => headers
                    .iter()
                    .find(|(name, _)| *name == other)
                    .with_context(|| format!("{other} is covered but was not sent"))?
                    .1
                    .to_owned(),
            };
            Ok(format!("{h}: {value}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .join("\n");

    rsa_verify_pkcs1v15(public_key_pem, signing_string.as_bytes(), sig_b64)
}

/// Extract the `keyId` URI from a raw `Signature` header value.
#[must_use]
pub fn key_id_from_header(sig_header: &str) -> Option<&str> {
    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("keyId=") {
            return Some(rest.trim_matches('"'));
        }
    }
    None
}

// ── RSA helpers ───────────────────────────────────────────────────────────────

/// An RSA private key, parsed and ready to sign with.
///
/// Parsing a PEM decodes the key and precomputes its CRT values, which costs
/// more than a signature does. The `sign_*` functions that take a PEM parse it
/// every call; keep one of these instead to sign many requests with one key.
#[derive(Clone)]
pub struct PrivateKey(rsa::pkcs1v15::SigningKey<Sha256>);

impl PrivateKey {
    /// Parse a PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`)
    /// PEM-encoded RSA private key.
    ///
    /// # Errors
    /// Returns an error if the PEM is neither.
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let key = parse_private_key(pem).context("parse RSA private key")?;
        Ok(Self(rsa::pkcs1v15::SigningKey::<Sha256>::new(key)))
    }

    /// RSASSA-PKCS1-v1_5 over SHA-256, base64-encoded.
    pub(crate) fn sign(&self, message: &[u8]) -> String {
        use rsa::signature::{SignatureEncoding as _, Signer as _};

        let sig: rsa::pkcs1v15::Signature = self.0.sign(message);
        BASE64.encode(sig.to_bytes())
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

/// Sign `message` with RSASSA-PKCS1-v1_5 over SHA-256, base64-encoded.
///
/// Shared with [`crate::sig::rfc9421`], which signs a different string with the same
/// primitive.
pub(crate) fn rsa_sign_pkcs1v15(private_key_pem: &str, message: &[u8]) -> anyhow::Result<String> {
    Ok(PrivateKey::from_pem(private_key_pem)?.sign(message))
}

/// Parse an RSA private key from either PKCS#8 (`BEGIN PRIVATE KEY`) or
/// PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEM format.
fn parse_private_key(pem: &str) -> anyhow::Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey as _;

    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }

    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    rsa::RsaPrivateKey::from_pkcs1_pem(pem).context("not valid PKCS#8 or PKCS#1 PEM")
}

/// Verify an RSASSA-PKCS1-v1_5 SHA-256 signature, base64-encoded.
///
/// Shared with [`crate::sig::rfc9421`], which verifies a different string with the
/// same primitive.
pub(crate) fn rsa_verify_pkcs1v15(
    public_key_pem: &str,
    message: &[u8],
    sig_b64: &str,
) -> anyhow::Result<()> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier as _;

    let sig_bytes = BASE64.decode(sig_b64).context("decode base64 signature")?;
    let public_key = rsa_public_key_from_pem(public_key_pem)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let sig = Signature::try_from(sig_bytes.as_slice()).context("parse signature bytes")?;
    verifying_key
        .verify(message, &sig)
        .context("signature verification failed")
}

/// An RSA public key from a PEM as actors publish them: SubjectPublicKeyInfo
/// (`PUBLIC KEY`) or PKCS#1 (`RSA PUBLIC KEY`), with whatever line length and
/// surrounding whitespace it was written with. The PEM parser holds a key to
/// 64-character lines, which not every implementation writes.
pub(crate) fn rsa_public_key_from_pem(pem: &str) -> anyhow::Result<rsa::RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::pkcs8::DecodePublicKey as _;

    let pem = pem.trim();
    if let Ok(key) = rsa::RsaPublicKey::from_public_key_pem(pem) {
        return Ok(key);
    }
    let (label, der) = pem_body(pem).context("parse RSA public key")?;
    match label {
        "PUBLIC KEY" => rsa::RsaPublicKey::from_public_key_der(&der),
        "RSA PUBLIC KEY" => rsa::RsaPublicKey::from_pkcs1_der(&der).map_err(Into::into),
        _ => anyhow::bail!("not an RSA public key: {label}"),
    }
    .context("parse RSA public key")
}

/// The label and decoded body of a PEM block, read leniently: any line
/// length, and whitespace anywhere in the body.
fn pem_body(pem: &str) -> anyhow::Result<(&str, Vec<u8>)> {
    let rest = pem.strip_prefix("-----BEGIN ").context("no PEM header")?;
    let (label, rest) = rest.split_once("-----").context("no PEM header")?;
    let end = format!("-----END {label}-----");
    let (body, _) = rest.split_once(end.as_str()).context("no PEM footer")?;
    let body: String = body.split_whitespace().collect();
    Ok((label, BASE64.decode(body).context("decode PEM body")?))
}

pub(crate) fn parse_params(header: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some(pos) = part.find('=') {
            let key = part[..pos].trim().to_string();
            let val = part[pos + 1..].trim().trim_matches('"').to_string();
            map.insert(key, val);
        }
    }
    map
}

/// A new RSA key pair for an actor, 2048 bits: the private key as PKCS#8
/// PEM and the public key as SPKI PEM, the forms actor documents publish and
/// [`PrivateKey::from_pem`] reads.
///
/// # Errors
///
/// When the operating system's randomness is unavailable.
pub fn generate_rsa_keypair() -> anyhow::Result<(String, String)> {
    use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

    let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048)?;
    let public = rsa::RsaPublicKey::from(&private);
    Ok((
        private.to_pkcs8_pem(LineEnding::LF)?.to_string(),
        public.to_public_key_pem(LineEnding::LF)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::pkcs8::EncodePublicKey as _;

    #[test]
    fn a_generated_key_pair_signs_and_verifies() {
        let (private, public) = generate_rsa_keypair().unwrap();
        assert!(private.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"));
        let signed = sign_request(
            "post",
            "https://a.example/inbox",
            b"{}",
            "https://b.example/users/b#main-key",
            &private,
            &[],
        )
        .unwrap();
        let headers = [
            ("host", "a.example"),
            ("date", signed.date.as_str()),
            ("digest", signed.digest.as_str()),
            ("signature", signed.signature.as_str()),
        ];
        verify_request("post", "/inbox", &headers, b"{}", &public).unwrap();
    }

    #[test]
    fn a_public_key_is_read_in_the_forms_actors_publish() {
        use rsa::pkcs1::{DecodeRsaPrivateKey as _, EncodeRsaPublicKey as _};

        let private = rsa::RsaPrivateKey::from_pkcs1_pem(include_str!(
            "../../tests/fixtures/rfc9421_test_key_rsa.pem"
        ))
        .unwrap();
        let public = rsa::RsaPublicKey::from(&private);
        let spki = public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let pkcs1 = public.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        assert!(pkcs1.starts_with("-----BEGIN RSA PUBLIC KEY-----"));
        // One long line, and indented, as some servers write them.
        let unwrapped = {
            let body: String = spki
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            format!("\n  -----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----  \n")
        };
        for pem in [spki.as_str(), pkcs1.as_str(), unwrapped.as_str()] {
            assert_eq!(rsa_public_key_from_pem(pem).unwrap(), public, "{pem}");
        }
        assert!(
            rsa_public_key_from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
                .is_err()
        );
    }

    fn keypair() -> (String, String) {
        let mut rng = rand::thread_rng();
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        (
            priv_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
                .to_string(),
            pub_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap(),
        )
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (priv_pem, pub_pem) = keypair();
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            "post",
            "https://remote.example/users/bob/inbox",
            body,
            "https://a.test/users/alice#main-key",
            &priv_pem,
            &[],
        )
        .unwrap();

        assert_eq!(
            key_id_from_header(&signed.signature),
            Some("https://a.test/users/alice#main-key")
        );

        let headers = [
            ("host", "remote.example"),
            ("date", signed.date.as_str()),
            ("digest", signed.digest.as_str()),
            ("signature", signed.signature.as_str()),
        ];
        verify_request("post", "/users/bob/inbox", &headers, body, &pub_pem).unwrap();
    }

    /// A request to a non-default port carries `Host: host:port`, and the
    /// signature has to cover that, not the bare host, or the receiver
    /// rebuilds a different signing string.
    #[test]
    fn a_non_default_port_is_part_of_the_signed_host() {
        let (priv_pem, pub_pem) = keypair();
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            "post",
            "http://127.0.0.1:8080/inbox",
            body,
            "https://a.test/users/alice#main-key",
            &priv_pem,
            &[],
        )
        .unwrap();
        let headers = [
            ("host", "127.0.0.1:8080"),
            ("date", signed.date.as_str()),
            ("digest", signed.digest.as_str()),
            ("signature", signed.signature.as_str()),
        ];
        verify_request("post", "/inbox", &headers, body, &pub_pem).unwrap();

        // The default port is not written, as no client writes it.
        let url = url::Url::parse("https://remote.example:443/inbox").unwrap();
        assert_eq!(host_header(&url), "remote.example");
    }

    #[test]
    fn sign_get_then_verify_roundtrips() {
        let (priv_pem, pub_pem) = keypair();
        let signed = sign_get(
            "https://remote.example/users/bob",
            "https://a.test/actor#main-key",
            &priv_pem,
        )
        .unwrap();

        let headers = [
            ("host", "remote.example"),
            ("date", signed.date.as_str()),
            ("signature", signed.signature.as_str()),
        ];
        // A GET has no body; verification must pass without a Digest header.
        verify_request("get", "/users/bob", &headers, b"", &pub_pem).unwrap();
    }

    /// A key parsed once signs exactly as its PEM does — PKCS#1 v1.5 is
    /// deterministic — and keeps doing so when reused.
    #[test]
    fn a_parsed_key_signs_as_its_pem_does() {
        let (priv_pem, pub_pem) = keypair();
        let key = PrivateKey::from_pem(&priv_pem).unwrap();
        assert_eq!(
            key.sign(b"signing string"),
            rsa_sign_pkcs1v15(&priv_pem, b"signing string").unwrap()
        );

        for target in ["/users/bob", "/users/carol"] {
            let url = format!("https://remote.example{target}");
            let signed = sign_get_with_key(&url, "https://a.test/actor#main-key", &key).unwrap();
            let headers = [
                ("host", "remote.example"),
                ("date", signed.date.as_str()),
                ("signature", signed.signature.as_str()),
            ];
            verify_request("get", target, &headers, b"", &pub_pem).unwrap();
        }

        let body = br#"{"type":"Like"}"#;
        let signed = sign_request_with_key(
            "post",
            "https://remote.example/inbox",
            body,
            "https://a.test/actor#main-key",
            &key,
            &[],
        )
        .unwrap();
        let headers = [
            ("host", "remote.example"),
            ("date", signed.date.as_str()),
            ("digest", signed.digest.as_str()),
            ("signature", signed.signature.as_str()),
        ];
        verify_request("post", "/inbox", &headers, body, &pub_pem).unwrap();
    }

    /// The covered set and its order, as Mastodon's `HttpSignatureDraft`
    /// produces them: the headers the request carries, then `(request-target)`
    /// last. Pinned so this cannot drift back apart without a test saying so.
    #[test]
    fn covers_what_mastodon_covers_in_the_order_mastodon_covers_it() {
        let (priv_pem, _) = keypair();
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            b"{}",
            "https://a.test/users/alice#main-key",
            &priv_pem,
            &[("content-type", "application/activity+json")],
        )
        .unwrap();

        assert!(
            signed
                .signature
                .contains(r#"headers="host date content-type digest (request-target)""#),
            "unexpected covered headers: {}",
            signed.signature
        );
        assert!(signed.signature.contains(r#"algorithm="rsa-sha256""#));
    }

    /// A GET carries no body, so no digest — otherwise the same shape.
    #[test]
    fn a_signed_get_covers_host_date_and_the_request_target() {
        let (priv_pem, _) = keypair();
        let signed = sign_get(
            "https://remote.example/users/bob",
            "https://a.test/actor#main-key",
            &priv_pem,
        )
        .unwrap();

        assert!(
            signed
                .signature
                .contains(r#"headers="host date (request-target)""#),
            "unexpected covered headers: {}",
            signed.signature
        );
    }

    /// A URL with a query signs the query too, and verifies only against the
    /// same query. Mastodon's `request_target` appends `?query`; covering only
    /// the path would make two different URLs indistinguishable to a verifier.
    #[test]
    fn the_request_target_covers_the_query_string() {
        let (priv_pem, pub_pem) = keypair();
        let url = "https://remote.example/inbox?shared=true";
        let body = b"{}";
        let signed = sign_request(
            "post",
            url,
            body,
            "https://a.test/users/alice#main-key",
            &priv_pem,
            &[],
        )
        .unwrap();

        let headers = [
            ("host", "remote.example"),
            ("date", signed.date.as_str()),
            ("digest", signed.digest.as_str()),
            ("signature", signed.signature.as_str()),
        ];

        verify_request("post", "/inbox?shared=true", &headers, body, &pub_pem)
            .expect("the signed path and query must verify");

        assert!(
            verify_request("post", "/inbox", &headers, body, &pub_pem).is_err(),
            "dropping the query must not still verify"
        );
        assert!(
            verify_request("post", "/inbox?shared=false", &headers, body, &pub_pem).is_err(),
            "a different query must not verify"
        );
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (priv_pem, pub_pem) = keypair();
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            b"original",
            "https://a.test/users/alice#main-key",
            &priv_pem,
            &[],
        )
        .unwrap();
        let headers = [
            ("host", "remote.example"),
            ("date", signed.date.as_str()),
            ("digest", signed.digest.as_str()),
            ("signature", signed.signature.as_str()),
        ];
        assert!(verify_request("post", "/inbox", &headers, b"tampered", &pub_pem).is_err());
    }
}
