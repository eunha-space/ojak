//! Interop test: verify a real FEP-8b32 proof produced by hackers.pub (Fedify),
//! captured from a live inbound activity, against the key from its actor's
//! `assertionMethod`. Guards against serialization mismatches the synthetic W3C
//! vector can't catch (e.g. a trailing RsaSignature2017 `signature` field).

use feder_runtime::integrity::{
    decode_multikey, extract_integrity_proof, verify_object_integrity_proof,
};
use serde_json::Value;

// jihyeok@hackers.pub `#multikey-2` (Ed25519 assertionMethod).
const MULTIKEY_2: &str = "z6MkvSVjX3UcGAFFM1PeKFrxKbLU1JWrMDx1uTo5KXtThVDn";

#[test]
fn verifies_real_hackerspub_proof() {
    let doc: Value =
        serde_json::from_str(include_str!("fixtures/hackerspub_reject.json")).expect("parse");
    let (proof, _, vm) = extract_integrity_proof(&doc).expect("proof present");
    assert!(vm.ends_with("#multikey-2"));
    let key = decode_multikey(MULTIKEY_2).expect("decode key");
    verify_object_integrity_proof(&doc, &proof, &key).expect("real hackers.pub proof must verify");
}
