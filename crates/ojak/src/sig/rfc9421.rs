//! HTTP Message Signatures ([RFC 9421]).
//!
//! The successor to the draft-cavage signatures ActivityPub grew up on. Where
//! the draft signs a list of header names against an ad-hoc string, RFC 9421
//! signs *components* — including derived ones like `@method` and
//! `@target-uri` — against a canonical signature base, and carries the covered
//! list in its own `Signature-Input` header so a verifier reconstructs exactly
//! what was signed.
//!
//! Mastodon 4.7 sends these as a fallback: a request goes out with a cavage
//! signature first, and is retried with an RFC 9421 one if the peer answers
//! 400 or 401. It covers `("@method" "@target-uri" "content-digest")` for a
//! request with a body and `("@method" "@target-uri")` for one without, which
//! is what [`sign_request`] produces.
//!
//! [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html

use anyhow::{Context as _, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest as _, Sha256};

/// Headers produced by [`sign_request`], to attach to the outgoing request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Value for the `Signature-Input` header.
    pub signature_input: String,
    /// Value for the `Signature` header.
    pub signature: String,
    /// Value for the `Content-Digest` header ([RFC 9530]), when the request has
    /// a body. It is a covered component, so it must be sent as given.
    ///
    /// [RFC 9530]: https://www.rfc-editor.org/rfc/rfc9530.html
    pub content_digest: Option<String>,
}

/// A signature algorithm this module can produce and check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 over SHA-256. What Mastodon signs with today, because
    /// it is what its RSA actor keys support.
    RsaV1_5Sha256,
    /// Ed25519, for actors whose keys are Ed25519.
    Ed25519,
}

impl Algorithm {
    /// The `alg` parameter value, as RFC 9421 registers it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RsaV1_5Sha256 => "rsa-v1_5-sha256",
            Self::Ed25519 => "ed25519",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "rsa-v1_5-sha256" => Some(Self::RsaV1_5Sha256),
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// The private key a signature is made with.
pub enum SigningKey<'a> {
    /// PKCS#8 or PKCS#1 PEM-encoded RSA private key, parsed each time.
    RsaPem(&'a str),
    /// An RSA private key parsed once by
    /// [`PrivateKey::from_pem`](crate::sig::signature::PrivateKey::from_pem).
    Rsa(&'a crate::sig::signature::PrivateKey),
    /// A raw 32-byte Ed25519 seed.
    Ed25519(&'a [u8; 32]),
}

impl SigningKey<'_> {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::RsaPem(_) | Self::Rsa(_) => Algorithm::RsaV1_5Sha256,
            Self::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<String> {
        match self {
            Self::RsaPem(pem) => crate::sig::signature::rsa_sign_pkcs1v15(pem, message),
            Self::Rsa(key) => Ok(key.sign(message)),
            Self::Ed25519(seed) => {
                use ed25519_dalek::Signer as _;

                let key = ed25519_dalek::SigningKey::from_bytes(seed);
                Ok(BASE64.encode(key.sign(message).to_bytes()))
            }
        }
    }
}

/// The public key a signature is checked against.
pub enum VerifyingKey<'a> {
    /// PEM-encoded RSA public key.
    RsaPem(&'a str),
    /// A raw 32-byte Ed25519 public key.
    Ed25519(&'a [u8; 32]),
}

impl VerifyingKey<'_> {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::RsaPem(_) => Algorithm::RsaV1_5Sha256,
            Self::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    fn verify(&self, message: &[u8], signature_b64: &str) -> anyhow::Result<()> {
        match self {
            Self::RsaPem(pem) => {
                crate::sig::signature::rsa_verify_pkcs1v15(pem, message, signature_b64)
            }
            Self::Ed25519(key) => {
                use ed25519_dalek::Verifier as _;

                let bytes = BASE64
                    .decode(signature_b64)
                    .context("decode base64 signature")?;
                let signature = ed25519_dalek::Signature::from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("invalid Ed25519 signature: {e}"))?;
                ed25519_dalek::VerifyingKey::from_bytes(key)
                    .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {e}"))?
                    .verify(message, &signature)
                    .context("signature verification failed")
            }
        }
    }
}

/// The label a signature is published under. Any label works; a message can
/// carry several, which is how a proxy adds its own alongside the client's.
const LABEL: &str = "sig1";

/// Sign an outgoing request.
///
/// Covers `@method` and `@target-uri`, plus `content-digest` when there is a
/// body — the components Mastodon covers, so that a Mastodon peer verifies
/// what it expects to. The algorithm follows from the key.
///
/// # Arguments
/// * `method` – HTTP method; canonicalised to uppercase for `@method`
/// * `url`    – full request URL, which becomes `@target-uri`
/// * `body`   – request body, or `None` for a bodyless request
/// * `key_id` – `keyid` parameter, the URI identifying the key
/// * `key`    – the private key to sign with
///
/// # Errors
/// Returns an error if the key cannot be parsed or the signature cannot be made.
pub fn sign_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    key_id: &str,
    key: &SigningKey<'_>,
) -> anyhow::Result<SignedHeaders> {
    let content_digest = body.map(content_digest);

    let mut components = vec![
        ("@method".to_string(), method.to_uppercase()),
        ("@target-uri".to_string(), url.to_string()),
    ];
    if let Some(digest) = &content_digest {
        components.push(("content-digest".to_string(), digest.clone()));
    }

    let created = chrono::Utc::now().timestamp();
    let params = signature_params(
        &components
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        created,
        key_id,
        key.algorithm(),
    );
    let base = signature_base(&components, &params);
    let signature = key
        .sign(base.as_bytes())
        .context("signing the RFC 9421 signature base")?;

    Ok(SignedHeaders {
        signature_input: format!("{LABEL}={params}"),
        signature: format!("{LABEL}=:{signature}:"),
        content_digest,
    })
}

/// The `Content-Digest` field value for a body: a structured-field dictionary
/// whose `sha-256` member holds the digest as a byte sequence (RFC 9530).
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", BASE64.encode(Sha256::digest(body)))
}

/// The `@signature-params` value: the covered component list and its
/// parameters, which is both sent as `Signature-Input` and signed as the last
/// line of the base.
fn signature_params(
    components: &[&str],
    created: i64,
    key_id: &str,
    algorithm: Algorithm,
) -> String {
    let covered = components
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(" ");
    // No `alg`. RFC 9421 makes it optional, and Mastodon's signer (Linzer)
    // emits only `created` and `keyid`; a verifier that knows the key knows the
    // algorithm. It is still honoured on the way in, where a peer that does
    // send it must not have it ignored.
    let _ = algorithm;
    format!("({covered});created={created};keyid=\"{key_id}\"")
}

/// Build the signature base (RFC 9421 §2.5).
///
/// One line per covered component, `"name": value`, then `"@signature-params"`
/// with the parameters. Lines are separated by a newline and the last one — the
/// parameters — carries no trailing newline.
fn signature_base(components: &[(String, String)], params: &str) -> String {
    let mut base = String::new();
    for (name, value) in components {
        base.push_str(&format!("\"{name}\": {value}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {params}"));
    base
}

/// Verify an [RFC 9421] signature on an inbound request.
///
/// The caller supplies the request as it saw it: the method, the URI it was
/// made to, the `Signature-Input` and `Signature` field values, the
/// `Content-Digest` if one was sent, and its header fields. A covered header
/// field is taken from `headers` as RFC 9421 §2.1 reads one — every value it
/// was sent with, trimmed and joined by `, ` — and the derived components a
/// federation request can be rebuilt from are `@method`, `@target-uri`,
/// `@authority`, `@scheme`, `@path`, `@query` and `@request-target`. A
/// signature covering anything else, or a header that was not sent, is
/// rejected rather than verified against a base guessed from what is missing.
///
/// Fedify covers `host` and `date` besides the derived components; a verifier
/// that read no header fields refused every request it signed this way.
///
/// The digest is checked against `body`, so a signature covering
/// `content-digest` binds the body it was sent with.
///
/// [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
#[allow(clippy::too_many_arguments)]
pub fn verify_request(
    method: &str,
    target_uri: &str,
    signature_input: &str,
    signature: &str,
    content_digest: Option<&str>,
    body: &[u8],
    headers: &[(&str, &str)],
    key: &VerifyingKey<'_>,
) -> anyhow::Result<()> {
    let (label, covered, params) = parse_signature_input(signature_input)?;
    let sig_b64 = parse_signature(signature, &label)?;

    // A stated algorithm must be one this module knows *and* the one the key
    // can check: a signature claiming `ed25519` must not be waved through an
    // RSA verification, or vice versa.
    if let Some(alg) = param(&params, "alg") {
        let stated =
            Algorithm::from_str(&alg).ok_or_else(|| anyhow!("unsupported algorithm {alg:?}"))?;
        anyhow::ensure!(
            stated == key.algorithm(),
            "signature claims {} but the key is {}",
            stated.as_str(),
            key.algorithm().as_str()
        );
    }

    let url = url::Url::parse(target_uri).context("invalid target URI")?;
    let mut components = Vec::with_capacity(covered.len());
    for name in &covered {
        let value = match name.as_str() {
            "@method" => method.to_uppercase(),
            "@target-uri" => target_uri.to_string(),
            "@authority" => url
                .host_str()
                .context("target URI has no authority")?
                .to_string(),
            "@path" => url.path().to_string(),
            "@scheme" => url.scheme().to_string(),
            "@query" => format!("?{}", url.query().unwrap_or("")),
            "@request-target" => match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_string(),
            },
            "content-digest" => {
                let sent =
                    content_digest.context("signature covers content-digest, but none was sent")?;
                anyhow::ensure!(
                    sent == crate::sig::rfc9421::content_digest(body),
                    "content-digest does not match the body"
                );
                sent.to_string()
            }
            derived if derived.starts_with('@') => {
                anyhow::bail!("signature covers unsupported component {derived:?}")
            }
            field => {
                let values: Vec<&str> = headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case(field))
                    .map(|(_, value)| value.trim())
                    .collect();
                anyhow::ensure!(
                    !values.is_empty(),
                    "signature covers {field:?}, which was not sent"
                );
                values.join(", ")
            }
        };
        components.push((name.clone(), value));
    }

    let base = signature_base(&components, &params);
    key.verify(base.as_bytes(), &sig_b64)
}

/// The `keyid` parameter of a `Signature-Input`: the URI identifying the key
/// that signed, which the verifier resolves to a public key.
pub fn key_id(signature_input: &str) -> Option<String> {
    let (_, _, params) = parse_signature_input(signature_input).ok()?;
    param(&params, "keyid")
}

/// The components a `Signature-Input` claims to cover, lower-cased.
///
/// Callers check that a signature covers what their protocol requires before
/// spending anything on verifying it.
pub fn covered_components(signature_input: &str) -> Option<Vec<String>> {
    let (_, covered, _) = parse_signature_input(signature_input).ok()?;
    Some(covered)
}

/// The `created` parameter of a `Signature-Input`, as a Unix timestamp.
///
/// Callers bound a signature's age with it; RFC 9421 leaves the policy to the
/// application.
pub fn created_at(signature_input: &str) -> Option<i64> {
    let (_, _, params) = parse_signature_input(signature_input).ok()?;
    param(&params, "created")?.parse().ok()
}

/// Split `label=("a" "b");created=…` into its label, covered components, and
/// the parameter string exactly as received — the signature covers the latter
/// byte for byte, so it must not be re-serialised.
fn parse_signature_input(header: &str) -> anyhow::Result<(String, Vec<String>, String)> {
    let (label, rest) = header
        .split_once('=')
        .context("Signature-Input has no label")?;
    let rest = rest.trim();
    anyhow::ensure!(
        rest.starts_with('('),
        "Signature-Input does not start with a component list"
    );
    let close = rest.find(')').context("unterminated component list")?;

    let covered = rest[1..close]
        .split_whitespace()
        .map(|c| c.trim_matches('"').to_ascii_lowercase())
        .collect();

    Ok((label.trim().to_string(), covered, rest.to_string()))
}

/// The base64 signature published under `label` in a `Signature` field.
fn parse_signature(header: &str, label: &str) -> anyhow::Result<String> {
    for entry in header.split(',') {
        let entry = entry.trim();
        let Some((entry_label, value)) = entry.split_once('=') else {
            continue;
        };
        if entry_label.trim() != label {
            continue;
        }
        let value = value.trim();
        return Ok(value
            .strip_prefix(':')
            .and_then(|v| v.strip_suffix(':'))
            .context("signature is not a byte sequence")?
            .to_string());
    }
    anyhow::bail!("no signature labelled {label:?}")
}

/// Read one parameter out of the `;name=value` tail of a signature input.
fn param(params: &str, name: &str) -> Option<String> {
    let tail = params.split_once(')')?.1;
    for part in tail.split(';') {
        // The tail starts with the separator, so the first piece is empty, and
        // a bare parameter carries no value at all.
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.trim() == name {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `test-key-rsa` private key from RFC 9421 Appendix B.1.1.
    const TEST_KEY_RSA: &str = include_str!("../../tests/fixtures/rfc9421_test_key_rsa.pem");

    /// RFC 9421 Appendix B.4: a signature base covering derived components and
    /// a content digest, built with `rsa-v1_5-sha256`. Reproducing the document
    /// 's own base byte-for-byte is what proves the canonicalisation is right.
    #[test]
    fn builds_the_signature_base_from_the_rfc() {
        let components = vec![
            ("@method".to_string(), "POST".to_string()),
            (
                "@authority".to_string(),
                "origin.host.internal.example".to_string(),
            ),
            ("@path".to_string(), "/foo".to_string()),
            (
                "content-digest".to_string(),
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:".to_string(),
            ),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "18".to_string()),
            (
                "forwarded".to_string(),
                "for=192.0.2.123;host=example.com;proto=https".to_string(),
            ),
        ];
        let params = "(\"@method\" \"@authority\" \"@path\" \"content-digest\" \
             \"content-type\" \"content-length\" \"forwarded\")\
             ;created=1618884480;keyid=\"test-key-rsa\";alg=\"rsa-v1_5-sha256\"\
             ;expires=1618884540";

        let base = signature_base(&components, params);

        let expected = concat!(
            "\"@method\": POST\n",
            "\"@authority\": origin.host.internal.example\n",
            "\"@path\": /foo\n",
            "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n",
            "\"content-type\": application/json\n",
            "\"content-length\": 18\n",
            "\"forwarded\": for=192.0.2.123;host=example.com;proto=https\n",
            "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"content-length\" \"forwarded\");created=1618884480;keyid=\"test-key-rsa\";alg=\"rsa-v1_5-sha256\";expires=1618884540",
        );
        assert_eq!(base, expected);
    }

    /// The same example's signature output. PKCS#1 v1.5 is deterministic, so
    /// the bytes must match the ones the RFC publishes.
    #[test]
    fn reproduces_the_rfc_signature() {
        let base = concat!(
            "\"@method\": POST\n",
            "\"@authority\": origin.host.internal.example\n",
            "\"@path\": /foo\n",
            "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n",
            "\"content-type\": application/json\n",
            "\"content-length\": 18\n",
            "\"forwarded\": for=192.0.2.123;host=example.com;proto=https\n",
            "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"content-length\" \"forwarded\");created=1618884480;keyid=\"test-key-rsa\";alg=\"rsa-v1_5-sha256\";expires=1618884540",
        );

        let signature =
            crate::sig::signature::rsa_sign_pkcs1v15(TEST_KEY_RSA, base.as_bytes()).unwrap();

        let expected = concat!(
            "S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy",
            "+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11s",
            "x3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFn",
            "Im9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0",
            "B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w",
            "5o0LV/g==",
        );
        assert_eq!(signature, expected);
    }

    #[test]
    fn signs_a_post_the_way_mastodon_expects() {
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(body),
            "https://local.example/users/alice#main-key",
            &SigningKey::RsaPem(TEST_KEY_RSA),
        )
        .unwrap();

        assert!(
            signed
                .signature_input
                .starts_with("sig1=(\"@method\" \"@target-uri\" \"content-digest\");created=")
        );
        assert!(
            signed
                .signature_input
                .contains("keyid=\"https://local.example/users/alice#main-key\"")
        );
        assert!(
            signed
                .signature_input
                .ends_with("keyid=\"https://local.example/users/alice#main-key\"")
        );
        assert!(signed.signature.starts_with("sig1=:"));
        assert!(signed.signature.ends_with(':'));
        assert_eq!(signed.content_digest, Some(content_digest(body)));
    }

    #[test]
    fn a_request_without_a_body_covers_no_digest() {
        let signed = sign_request(
            "get",
            "https://remote.example/users/bob",
            None,
            "https://local.example/actor#main-key",
            &SigningKey::RsaPem(TEST_KEY_RSA),
        )
        .unwrap();

        assert!(
            signed
                .signature_input
                .starts_with("sig1=(\"@method\" \"@target-uri\");created=")
        );
        assert_eq!(signed.content_digest, None);
    }

    /// The public half of `test-key-rsa`, from RFC 9421 Appendix B.1.1.
    const TEST_KEY_RSA_PUBLIC: &str =
        include_str!("../../tests/fixtures/rfc9421_test_key_rsa_public.pem");

    #[test]
    fn verifies_what_it_signs() {
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(body),
            "https://local.example/users/alice#main-key",
            &SigningKey::RsaPem(TEST_KEY_RSA),
        )
        .unwrap();

        verify_request(
            "POST",
            "https://remote.example/inbox",
            &signed.signature_input,
            &signed.signature,
            signed.content_digest.as_deref(),
            body,
            &[],
            &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
        )
        .expect("a signature this module produced should verify");
    }

    #[test]
    fn rejects_a_body_the_digest_does_not_cover() {
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(b"original"),
            "https://local.example/users/alice#main-key",
            &SigningKey::RsaPem(TEST_KEY_RSA),
        )
        .unwrap();

        let err = verify_request(
            "POST",
            "https://remote.example/inbox",
            &signed.signature_input,
            &signed.signature,
            signed.content_digest.as_deref(),
            b"swapped",
            &[],
            &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
        )
        .unwrap_err();
        assert!(err.to_string().contains("content-digest"), "{err}");
    }

    #[test]
    fn rejects_a_request_sent_somewhere_else() {
        let body = b"body";
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(body),
            "https://local.example/users/alice#main-key",
            &SigningKey::RsaPem(TEST_KEY_RSA),
        )
        .unwrap();

        assert!(
            verify_request(
                "POST",
                "https://elsewhere.example/inbox",
                &signed.signature_input,
                &signed.signature,
                signed.content_digest.as_deref(),
                body,
                &[],
                &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_components_it_cannot_rebuild() {
        // A signature covering a header this verifier does not have must not be
        // waved through by rebuilding a shorter base.
        let err = verify_request(
            "POST",
            "https://remote.example/inbox",
            "sig1=(\"@method\" \"x-custom\");created=1618884480;keyid=\"k\"",
            "sig1=:AAAA:",
            None,
            b"",
            &[],
            &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
        )
        .unwrap_err();
        assert!(err.to_string().contains("x-custom"), "{err}");
    }

    #[test]
    fn reads_the_created_parameter() {
        assert_eq!(
            created_at("sig1=(\"@method\");created=1618884480;keyid=\"k\""),
            Some(1618884480)
        );
        assert_eq!(created_at("sig1=(\"@method\");keyid=\"k\""), None);
    }

    /// `test-key-ed25519` from RFC 9421 Appendix B.1.4, as raw bytes.
    const TEST_KEY_ED25519_SEED: [u8; 32] = [
        0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c, 0x0e,
        0x84, 0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f, 0x6a, 0x7d,
        0x29, 0xc5,
    ];
    const TEST_KEY_ED25519_PUBLIC: [u8; 32] = [
        0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b,
        0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43,
        0xd1, 0xbb,
    ];

    /// RFC 9421 Appendix B.2.6, signed with `test-key-ed25519`. Ed25519 is
    /// deterministic, so the signature must come out byte-identical to the
    /// one the document publishes.
    #[test]
    fn reproduces_the_rfc_ed25519_signature() {
        let base = concat!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n",
            "\"@method\": POST\n",
            "\"@path\": /foo\n",
            "\"@authority\": example.com\n",
            "\"content-type\": application/json\n",
            "\"content-length\": 18\n",
            "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
        );

        let signature = SigningKey::Ed25519(&TEST_KEY_ED25519_SEED)
            .sign(base.as_bytes())
            .unwrap();

        assert_eq!(
            signature,
            concat!(
                "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1",
                "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
            )
        );

        // And the published signature verifies against the published key.
        VerifyingKey::Ed25519(&TEST_KEY_ED25519_PUBLIC)
            .verify(base.as_bytes(), &signature)
            .expect("the RFC's own signature must verify");
    }

    /// RFC 9421 Appendix B.2.6 end to end: the published signature over
    /// header fields as well as derived components verifies from the request
    /// it was made for.
    #[test]
    fn verifies_the_rfc_signature_over_header_fields() {
        verify_request(
            "POST",
            "https://example.com/foo?param=Value&Pet=dog",
            "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
            "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
            None,
            br#"{"hello": "world"}"#,
            &[
                ("Host", "example.com"),
                ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
                ("Content-Type", "application/json"),
                ("Content-Length", "18"),
            ],
            &VerifyingKey::Ed25519(&TEST_KEY_ED25519_PUBLIC),
        )
        .expect("the RFC's signature over header fields verifies");
    }

    /// A request signed as Fedify signs one — `host` and `date` covered
    /// alongside the derived components — verifies, and does not once a
    /// covered header has changed on the way.
    #[test]
    fn verifies_a_signature_covering_host_and_date_as_fedify_makes_them() {
        let body = br#"{"type":"Create"}"#;
        let digest = content_digest(body);
        let target = "https://seoul.earth/users/alice/inbox";
        let params = "(\"@method\" \"@target-uri\" \"@authority\" \"host\" \"date\" \"content-digest\");created=1759000000;keyid=\"https://hollo.example/@bob#main-key\";alg=\"rsa-v1_5-sha256\"";
        let date = "Sun, 28 Sep 2025 00:00:00 GMT";
        let base = signature_base(
            &[
                ("@method".into(), "POST".into()),
                ("@target-uri".into(), target.into()),
                ("@authority".into(), "seoul.earth".into()),
                ("host".into(), "seoul.earth".into()),
                ("date".into(), date.into()),
                ("content-digest".into(), digest.clone()),
            ],
            params,
        );
        let signature = SigningKey::RsaPem(TEST_KEY_RSA)
            .sign(base.as_bytes())
            .unwrap();
        let input = format!("sig1={params}");
        let signed = format!("sig1=:{signature}:");
        let headers = [("host", "seoul.earth"), ("date", date)];

        verify_request(
            "POST",
            target,
            &input,
            &signed,
            Some(&digest),
            body,
            &headers,
            &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
        )
        .expect("a signature over host and date verifies");

        let changed = [
            ("host", "seoul.earth"),
            ("date", "Mon, 29 Sep 2025 00:00:00 GMT"),
        ];
        assert!(
            verify_request(
                "POST",
                target,
                &input,
                &signed,
                Some(&digest),
                body,
                &changed,
                &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
            )
            .is_err(),
            "a covered header that changed must not verify"
        );
    }

    #[test]
    fn signs_and_verifies_a_request_with_ed25519() {
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(body),
            "https://local.example/users/alice#ed25519-key",
            &SigningKey::Ed25519(&TEST_KEY_ED25519_SEED),
        )
        .unwrap();

        assert!(
            !signed.signature_input.contains("alg="),
            "Mastodon's signer emits no alg parameter"
        );

        verify_request(
            "POST",
            "https://remote.example/inbox",
            &signed.signature_input,
            &signed.signature,
            signed.content_digest.as_deref(),
            body,
            &[],
            &VerifyingKey::Ed25519(&TEST_KEY_ED25519_PUBLIC),
        )
        .expect("an Ed25519 signature this module made should verify");
    }

    /// A peer that does state an algorithm must not have it ignored: a
    /// signature claiming one algorithm is refused against a key of another,
    /// rather than checked anyway.
    #[test]
    fn refuses_a_key_that_does_not_match_a_stated_algorithm() {
        let body = b"body";
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(body),
            "https://local.example/users/alice#ed25519-key",
            &SigningKey::Ed25519(&TEST_KEY_ED25519_SEED),
        )
        .unwrap();

        // Eunha omits `alg`, as Mastodon does; state it the way a peer might.
        let with_alg = format!("{};alg=\"ed25519\"", signed.signature_input);

        let err = verify_request(
            "POST",
            "https://remote.example/inbox",
            &with_alg,
            &signed.signature,
            signed.content_digest.as_deref(),
            body,
            &[],
            &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
        )
        .unwrap_err();
        assert!(err.to_string().contains("claims ed25519"), "{err}");
    }

    /// An algorithm nobody here implements is refused outright, rather than
    /// verified with whatever key happens to be to hand.
    #[test]
    fn refuses_an_unknown_algorithm() {
        let err = verify_request(
            "POST",
            "https://remote.example/inbox",
            "sig1=(\"@method\" \"@target-uri\");created=1;keyid=\"k\";alg=\"rsa-pss-sha512\"",
            "sig1=:AAAA:",
            None,
            b"",
            &[],
            &VerifyingKey::RsaPem(TEST_KEY_RSA_PUBLIC),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported algorithm"), "{err}");
    }

    #[test]
    fn content_digest_is_an_rfc9530_byte_sequence() {
        // The empty SHA-256 digest, wrapped as a structured-field byte sequence.
        assert_eq!(
            content_digest(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }
}
