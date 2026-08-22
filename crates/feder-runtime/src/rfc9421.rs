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

use anyhow::Context as _;
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

/// The label a signature is published under. Any label works; a message can
/// carry several, which is how a proxy adds its own alongside the client's.
const LABEL: &str = "sig1";

/// Sign an outgoing request with `rsa-v1_5-sha256`.
///
/// Covers `@method` and `@target-uri`, plus `content-digest` when there is a
/// body — the components Mastodon covers, so that a Mastodon peer verifies
/// what it expects to.
///
/// # Arguments
/// * `method`          – HTTP method; canonicalised to uppercase for `@method`
/// * `url`             – full request URL, which becomes `@target-uri`
/// * `body`            – request body, or `None` for a bodyless request
/// * `key_id`          – `keyid` parameter, the URI identifying the key
/// * `private_key_pem` – PKCS#8 or PKCS#1 PEM-encoded RSA private key
pub fn sign_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    key_id: &str,
    private_key_pem: &str,
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
    );
    let base = signature_base(&components, &params);
    let signature = crate::signature::rsa_sign_pkcs1v15(private_key_pem, base.as_bytes())
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
fn signature_params(components: &[&str], created: i64, key_id: &str) -> String {
    let covered = components
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!("({covered});created={created};keyid=\"{key_id}\";alg=\"rsa-v1_5-sha256\"")
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
/// made to, the `Signature-Input` and `Signature` field values, and the
/// `Content-Digest` if one was sent. Only the components a federation request
/// can be rebuilt from are supported — `@method`, `@target-uri`, `@authority`,
/// `@path`, and `content-digest` — and a signature covering anything else is
/// rejected rather than verified against a base guessed from what is missing.
///
/// The digest is checked against `body`, so a signature covering
/// `content-digest` binds the body it was sent with.
///
/// [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
pub fn verify_request(
    method: &str,
    target_uri: &str,
    signature_input: &str,
    signature: &str,
    content_digest: Option<&str>,
    body: &[u8],
    public_key_pem: &str,
) -> anyhow::Result<()> {
    let (label, covered, params) = parse_signature_input(signature_input)?;
    let sig_b64 = parse_signature(signature, &label)?;

    if let Some(alg) = param(&params, "alg") {
        anyhow::ensure!(
            alg == "rsa-v1_5-sha256",
            "unsupported signature algorithm {alg:?}"
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
            "content-digest" => {
                let sent =
                    content_digest.context("signature covers content-digest, but none was sent")?;
                anyhow::ensure!(
                    sent == crate::rfc9421::content_digest(body),
                    "content-digest does not match the body"
                );
                sent.to_string()
            }
            other => anyhow::bail!("signature covers unsupported component {other:?}"),
        };
        components.push((name.clone(), value));
    }

    let base = signature_base(&components, &params);
    crate::signature::rsa_verify_pkcs1v15(public_key_pem, base.as_bytes(), &sig_b64)
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
    const TEST_KEY_RSA: &str = include_str!("../tests/fixtures/rfc9421_test_key_rsa.pem");

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

        let signature = crate::signature::rsa_sign_pkcs1v15(TEST_KEY_RSA, base.as_bytes()).unwrap();

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
            TEST_KEY_RSA,
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
        assert!(signed.signature_input.ends_with("alg=\"rsa-v1_5-sha256\""));
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
            TEST_KEY_RSA,
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
        include_str!("../tests/fixtures/rfc9421_test_key_rsa_public.pem");

    #[test]
    fn verifies_what_it_signs() {
        let body = br#"{"type":"Create"}"#;
        let signed = sign_request(
            "post",
            "https://remote.example/inbox",
            Some(body),
            "https://local.example/users/alice#main-key",
            TEST_KEY_RSA,
        )
        .unwrap();

        verify_request(
            "POST",
            "https://remote.example/inbox",
            &signed.signature_input,
            &signed.signature,
            signed.content_digest.as_deref(),
            body,
            TEST_KEY_RSA_PUBLIC,
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
            TEST_KEY_RSA,
        )
        .unwrap();

        let err = verify_request(
            "POST",
            "https://remote.example/inbox",
            &signed.signature_input,
            &signed.signature,
            signed.content_digest.as_deref(),
            b"swapped",
            TEST_KEY_RSA_PUBLIC,
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
            TEST_KEY_RSA,
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
                TEST_KEY_RSA_PUBLIC,
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
            TEST_KEY_RSA_PUBLIC,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported component"), "{err}");
    }

    #[test]
    fn reads_the_created_parameter() {
        assert_eq!(
            created_at("sig1=(\"@method\");created=1618884480;keyid=\"k\""),
            Some(1618884480)
        );
        assert_eq!(created_at("sig1=(\"@method\");keyid=\"k\""), None);
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
