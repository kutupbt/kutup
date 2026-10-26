//! Recorded security-key answers (docs/plans/security-keys.md, D1), checked
//! again with the server's adapter: each vector under
//! `tests/vectors/webauthn/` holds a registration and a sign-in recorded by
//! `scripts/record-webauthn-vector.mjs`.
//!
//! - `chromium-*.json`: Chromium's virtual authenticator (CTAP2, ES256).
//! - **A real key's slot:** record one with
//!   `node scripts/record-webauthn-vector.mjs device yubikey-5c-nfc` (and once
//!   more with `--uv` for its PIN) and commit the file; this test picks up
//!   every `*.json` there, no code change needed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kutup_crypto::webauthn::{
    finish_authentication, finish_registration, start_authentication, start_registration,
    with_recorded_challenge, AssertionResponse, Ceremony, KeyRef, RelyingParty, StoredKey,
};
use serde_json::Value;

fn bytes16(value: &Value) -> [u8; 16] {
    URL_SAFE_NO_PAD
        .decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn recorded_keys_register_and_sign_in() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/webauthn");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let name = vector["name"].as_str().unwrap().to_owned();
        let rp_id = vector["rpId"].as_str().unwrap();
        let rp =
            RelyingParty::new(rp_id, vec![vector["origin"].as_str().unwrap().to_owned()]).unwrap();
        let account = bytes16(&vector["account"]);

        let registration = &vector["registration"];
        let require_uv = registration["requireUv"].as_bool().unwrap();
        let mut started =
            start_registration(&rp, account, "vector", &[], require_uv, 120_000).unwrap();
        with_recorded_challenge(
            &mut started,
            Ceremony::Registration,
            bytes16(&registration["challenge"]),
        );
        let response = serde_json::to_vec(&registration["response"]).unwrap();
        let key = finish_registration(&rp, &started.state, &response)
            .unwrap_or_else(|error| panic!("{name}: registration: {error}"));

        let authentication = &vector["authentication"];
        let keys = [KeyRef {
            credential_id: &key.credential_id,
            transports: &key.transports,
        }];
        let mut started = start_authentication(
            &rp,
            &keys,
            authentication["requireUv"].as_bool().unwrap(),
            120_000,
        )
        .unwrap();
        with_recorded_challenge(
            &mut started,
            Ceremony::Authentication,
            bytes16(&authentication["challenge"]),
        );
        let response = serde_json::to_vec(&authentication["response"]).unwrap();
        let response = AssertionResponse::parse(&response).unwrap();
        assert_eq!(response.credential_id(), key.credential_id, "{name}");
        let stored = StoredKey {
            credential_id: &key.credential_id,
            account,
            static_state: &key.static_state,
            dynamic_state: &key.dynamic_state,
        };
        let asserted = finish_authentication(&rp, &started.state, &response, stored)
            .unwrap_or_else(|error| panic!("{name}: sign-in: {error:?}"));
        assert!(asserted.sign_count >= key.sign_count, "{name}");

        // A recorded answer under another RP or origin is refused.
        let elsewhere = RelyingParty::new(rp_id, vec![format!("https://other.{rp_id}")]).unwrap();
        let stored = StoredKey {
            credential_id: &key.credential_id,
            account,
            static_state: &key.static_state,
            dynamic_state: &key.dynamic_state,
        };
        assert!(finish_authentication(&elsewhere, &started.state, &response, stored).is_err());
        names.push(name);
    }
    names.sort();
    assert!(
        names.iter().any(|name| name.starts_with("chromium-")),
        "the Chromium recordings are missing: {names:?}"
    );
    eprintln!("WebAuthn vectors checked: {names:?}");
}
