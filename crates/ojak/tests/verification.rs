//! Checking inbound signed requests: every rule, passing and refused.

use ojak::sig::rfc9421;
use ojak::sig::signature::{self, PrivateKey};
use ojak::sig::verification::{
    self, Key, Policy, Rejection, Request, Scheme, key_owner, published_key_pem,
};
use serde_json::json;

const PRIVATE_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa.pem");
const PUBLIC_KEY: &str = include_str!("fixtures/rfc9421_test_key_rsa_public.pem");
const KEY_ID: &str = "https://remote.example/users/bob#main-key";
const HOST: &str = "ojak.example";
const INBOX: &str = "https://ojak.example/users/alice/inbox";
const BODY: &[u8] = br#"{"type":"Create"}"#;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn hosts() -> [&'static str; 1] {
    [HOST]
}

/// Headers of a POST signed with draft-cavage, as a sender would send them.
fn cavage(body: &[u8]) -> Vec<(String, String)> {
    let key = PrivateKey::from_pem(PRIVATE_KEY).unwrap();
    let signed = signature::sign_request_with_key(
        "post",
        INBOX,
        body,
        KEY_ID,
        &key,
        &[("content-type", "application/activity+json")],
    )
    .unwrap();
    vec![
        ("host".into(), HOST.into()),
        ("date".into(), signed.date),
        ("content-type".into(), "application/activity+json".into()),
        ("digest".into(), signed.digest),
        ("signature".into(), signed.signature),
    ]
}

/// Headers of a POST signed with RFC 9421.
fn rfc9421(body: &[u8]) -> Vec<(String, String)> {
    let signed = rfc9421::sign_request(
        "post",
        INBOX,
        Some(body),
        KEY_ID,
        &rfc9421::SigningKey::RsaPem(PRIVATE_KEY),
    )
    .unwrap();
    vec![
        ("host".into(), HOST.into()),
        ("content-digest".into(), signed.content_digest.unwrap()),
        ("signature-input".into(), signed.signature_input),
        ("signature".into(), signed.signature),
    ]
}

fn refs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// Parse, check and verify, as an inbox would.
fn accept(headers: &[(String, String)], body: &[u8], now: i64) -> Result<Scheme, Rejection> {
    let headers = refs(headers);
    let request = Request {
        method: "POST",
        path_and_query: "/users/alice/inbox",
        headers: &headers,
        body,
    };
    let hosts = hosts();
    let parsed = verification::parse(&request)?;
    verification::check(&parsed, &request, &Policy::new(&hosts), now)?;
    verification::verify(&parsed, &request, Key::RsaPem(PUBLIC_KEY))?;
    Ok(parsed.scheme)
}

fn replace(headers: &mut [(String, String)], name: &str, value: &str) {
    for (key, existing) in headers.iter_mut() {
        if key == name {
            *existing = value.to_owned();
        }
    }
}

#[test]
fn a_well_signed_request_is_accepted_in_either_scheme() {
    assert_eq!(accept(&cavage(BODY), BODY, now()), Ok(Scheme::DraftCavage));
    assert_eq!(accept(&rfc9421(BODY), BODY, now()), Ok(Scheme::Rfc9421));
}

#[test]
fn parsing_reads_the_key_and_what_is_covered() {
    let headers = cavage(BODY);
    let headers = refs(&headers);
    let request = Request {
        method: "POST",
        path_and_query: "/users/alice/inbox",
        headers: &headers,
        body: BODY,
    };
    let parsed = verification::parse(&request).unwrap();
    assert_eq!(parsed.key_id, KEY_ID);
    assert_eq!(
        parsed.covered,
        ["host", "date", "content-type", "digest", "(request-target)"]
    );
    assert!(
        parsed
            .created
            .is_some_and(|created| (created - now()).abs() < 5)
    );
}

#[test]
fn a_swapped_body_does_not_match_its_digest() {
    let other = br#"{"type":"Delete"}"#;
    assert_eq!(
        accept(&cavage(BODY), other, now()),
        Err(Rejection::DigestMismatch)
    );
    assert_eq!(
        accept(&rfc9421(BODY), other, now()),
        Err(Rejection::DigestMismatch)
    );
}

#[test]
fn a_digest_the_signature_does_not_cover_is_not_enough() {
    // A signed GET covers no digest; sent as a POST with a digest added, the
    // body could be anything.
    let key = PrivateKey::from_pem(PRIVATE_KEY).unwrap();
    let signed = signature::sign_get_with_key(INBOX, KEY_ID, &key).unwrap();
    let digest = signature::sign_request("post", INBOX, BODY, KEY_ID, PRIVATE_KEY, &[])
        .unwrap()
        .digest;
    let headers = vec![
        ("host".into(), HOST.into()),
        ("date".into(), signed.date),
        ("digest".into(), digest),
        ("signature".into(), signed.signature),
    ];
    assert_eq!(
        accept(&headers, BODY, now()),
        Err(Rejection::NotCovered("digest".into()))
    );
}

#[test]
fn a_missing_digest_is_refused() {
    let mut headers = cavage(BODY);
    headers.retain(|(name, _)| name != "digest");
    assert_eq!(
        accept(&headers, BODY, now()),
        Err(Rejection::MissingHeader("Digest"))
    );
    let mut headers = rfc9421(BODY);
    headers.retain(|(name, _)| name != "content-digest");
    assert_eq!(
        accept(&headers, BODY, now()),
        Err(Rejection::MissingHeader("Content-Digest"))
    );
}

#[test]
fn an_old_or_future_signature_is_refused() {
    for headers in [cavage(BODY), rfc9421(BODY)] {
        assert!(matches!(
            accept(&headers, BODY, now() + 7200),
            Err(Rejection::Stale { .. })
        ));
        assert!(matches!(
            accept(&headers, BODY, now() - 7200),
            Err(Rejection::Stale { .. })
        ));
        assert!(
            accept(&headers, BODY, now() + 600).is_ok(),
            "ten minutes is fine"
        );
    }
}

#[test]
fn an_unsigned_created_does_not_make_an_old_signature_fresh() {
    // A request captured two hours after it was signed over `date`, with a
    // `created` of the moment it is replayed added to its signature. The
    // signature still verifies, since `created` is not what it signed.
    let mut headers = cavage(BODY);
    let later = now() + 7200;
    let signature = headers
        .iter()
        .find(|(name, _)| name == "signature")
        .unwrap()
        .1
        .clone();
    replace(
        &mut headers,
        "signature",
        &format!("{signature},created={later}"),
    );
    assert!(matches!(
        accept(&headers, BODY, later),
        Err(Rejection::Stale { .. })
    ));
}

#[test]
fn a_request_signed_for_another_host_is_refused() {
    for mut headers in [cavage(BODY), rfc9421(BODY)] {
        replace(&mut headers, "host", "other.example");
        assert_eq!(
            accept(&headers, BODY, now()),
            Err(Rejection::WrongHost("other.example".into()))
        );
    }
}

#[test]
fn a_tampered_signature_does_not_verify() {
    let mut headers = cavage(BODY);
    let (_, signature) = headers
        .iter()
        .find(|(n, _)| n == "signature")
        .unwrap()
        .clone();
    let tampered = signature.replacen("signature=\"", "signature=\"AAAA", 1);
    replace(&mut headers, "signature", &tampered);
    assert!(matches!(
        accept(&headers, BODY, now()),
        Err(Rejection::Invalid(_))
    ));
}

#[test]
fn an_unsigned_request_is_refused() {
    let request = Request {
        method: "POST",
        path_and_query: "/inbox",
        headers: &[("host", HOST)],
        body: BODY,
    };
    assert_eq!(verification::parse(&request), Err(Rejection::Unsigned));
}

#[test]
fn a_key_belongs_to_the_actor_it_is_published_by() {
    assert_eq!(
        key_owner("https://a.example/users/bob#main-key"),
        "https://a.example/users/bob"
    );
    assert_eq!(
        key_owner("https://gts.example/users/bob/main-key"),
        "https://gts.example/users/bob"
    );
    assert_eq!(
        key_owner("https://a.example/keys/1"),
        "https://a.example/keys/1"
    );

    let actor = json!({
        "id": "https://remote.example/users/bob",
        "publicKey": {
            "id": KEY_ID,
            "owner": "https://remote.example/users/bob",
            "publicKeyPem": "PEM"
        }
    });
    assert_eq!(published_key_pem(&actor, KEY_ID).as_deref(), Some("PEM"));
    assert_eq!(
        published_key_pem(&actor, "https://remote.example/users/bob#other"),
        None,
        "an actor vouches only for the keys it publishes"
    );

    let disowned = json!({
        "id": "https://remote.example/users/bob",
        "publicKey": {"id": KEY_ID, "owner": "https://remote.example/users/eve", "publicKeyPem": "PEM"}
    });
    assert_eq!(
        published_key_pem(&disowned, KEY_ID),
        None,
        "nor ones someone else owns"
    );

    let several = json!({
        "id": "https://remote.example/users/bob",
        "publicKey": [
            {"id": "https://remote.example/users/bob#old", "publicKeyPem": "OLD"},
            {"id": KEY_ID, "publicKeyPem": "NEW"}
        ]
    });
    assert_eq!(published_key_pem(&several, KEY_ID).as_deref(), Some("NEW"));

    // PeerTube's key ID is its actor's id, for the key it publishes as
    // #main-key; no other key is named by it.
    assert_eq!(
        published_key_pem(&actor, "https://remote.example/users/bob").as_deref(),
        Some("PEM")
    );
    assert_eq!(
        published_key_pem(
            &json!({
                "id": "https://remote.example/users/bob",
                "publicKey": {"id": "https://remote.example/users/bob#other", "publicKeyPem": "PEM"}
            }),
            "https://remote.example/users/bob"
        ),
        None
    );
}

/// The base64 draft-cavage signature over `signing_string`.
fn sign_cavage(signing_string: &str) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
        rsa::RsaPrivateKey::from_pkcs1_pem(PRIVATE_KEY).unwrap(),
    );
    STANDARD.encode(key.sign(signing_string.as_bytes()).to_bytes())
}

/// The body's digest in `algorithm`, base64.
fn digest_of(body: &[u8], algorithm: &str) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use sha2::Digest as _;

    STANDARD.encode(match algorithm {
        "sha-256" => sha2::Sha256::digest(body).to_vec(),
        _ => sha2::Sha512::digest(body).to_vec(),
    })
}

/// Headers of a POST signed with draft-cavage over `(created)` and
/// `(expires)` rather than `date`, as hs2019 signers do.
fn cavage_created(created: i64, expires: i64) -> Vec<(String, String)> {
    let digest = format!("SHA-256={}", digest_of(BODY, "sha-256"));
    let signed = sign_cavage(&format!(
        "(request-target): post /users/alice/inbox\nhost: {HOST}\n(created): {created}\n(expires): {expires}\ndigest: {digest}"
    ));
    vec![
        ("host".into(), HOST.into()),
        ("digest".into(), digest),
        (
            "signature".into(),
            format!(
                r#"keyId="{KEY_ID}",algorithm="hs2019",created={created},expires={expires},headers="(request-target) host (created) (expires) digest",signature="{signed}""#
            ),
        ),
    ]
}

#[test]
fn a_digest_may_list_sha_512_beside_sha_256() {
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let digest = format!(
        "SHA-256={}, SHA-512={}",
        digest_of(BODY, "sha-256"),
        digest_of(BODY, "sha-512")
    );
    let signed = sign_cavage(&format!(
        "(request-target): post /users/alice/inbox\nhost: {HOST}\ndate: {date}\ndigest: {digest}"
    ));
    let headers = vec![
        ("host".into(), HOST.into()),
        ("date".into(), date),
        ("digest".into(), digest),
        (
            "signature".into(),
            format!(
                r#"keyId="{KEY_ID}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="{signed}""#
            ),
        ),
    ];
    assert_eq!(accept(&headers, BODY, now()), Ok(Scheme::DraftCavage));
    assert_eq!(
        accept(&headers, b"swapped", now()),
        Err(Rejection::DigestMismatch)
    );
}

#[test]
fn a_signature_over_created_and_expires_is_verified_until_it_expires() {
    let now = now();
    let headers = cavage_created(now - 10, now + 60);
    assert_eq!(accept(&headers, BODY, now), Ok(Scheme::DraftCavage));
    assert_eq!(
        accept(&headers, BODY, now + 70),
        Err(Rejection::Expired { seconds: 10 }),
        "within the allowed skew, but past when the signer said it ends"
    );
}

#[test]
fn an_rfc9421_signature_past_its_expires_is_refused() {
    let mut headers = rfc9421(BODY);
    let input = headers
        .iter()
        .find(|(name, _)| name == "signature-input")
        .unwrap()
        .1
        .clone();
    let expires = now() - 10;
    replace(
        &mut headers,
        "signature-input",
        &format!("{input};expires={expires}"),
    );
    let headers = refs(&headers);
    let request = Request {
        method: "POST",
        path_and_query: "/users/alice/inbox",
        headers: &headers,
        body: BODY,
    };
    let hosts = hosts();
    let parsed = verification::parse(&request).unwrap();
    assert!(matches!(
        verification::check(&parsed, &request, &Policy::new(&hosts), now()),
        Err(Rejection::Expired { .. })
    ));
}

#[test]
fn a_covered_header_that_was_not_sent_is_refused() {
    let mut headers = cavage(BODY);
    headers.retain(|(name, _)| name != "content-type");
    assert!(matches!(
        accept(&headers, BODY, now()),
        Err(Rejection::Invalid(_))
    ));
}
