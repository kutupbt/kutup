//! Checked-in vectors for Drive identity (docs/plans/drive-identity-pins.md):
//! an account's Drive key binding, and a sealed identity pin list. Regenerate
//! only for a deliberate format change:
//! `KUTUP_WRITE_IDENTITY_VECTORS=1 cargo test -p kutup-crypto --test identity_pins_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::identity_pins::{self, IdentityPinV1, IdentityPinsV1, PinState};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/identity-pins-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    account: String,
    authority_public_key: String,
    drive_hpke_public_key: String,
    drive_signing_public_key: String,
    drive_key_binding: String,
    pins_key: String,
    revision: u64,
    pins: String,
    nonce: String,
    sealed: String,
}

fn pins() -> IdentityPinsV1 {
    let bob = AccountIdentityKeysV1::derive(&[0x22u8; 32]).unwrap();
    let carol = AccountIdentityKeysV1::derive(&[0x33u8; 32]).unwrap();
    let carol_before = AccountIdentityKeysV1::derive(&[0x34u8; 32]).unwrap();
    IdentityPinsV1 {
        pins: vec![
            IdentityPinV1 {
                account: "bob@kutup.dev".into(),
                authority_public_key: STANDARD.encode(bob.authority_public_key()),
                state: PinState::Seen,
                since: "2026-10-10T12:00:00Z".into(),
                replaced: vec![],
            },
            IdentityPinV1 {
                account: "carol@example.org".into(),
                authority_public_key: STANDARD.encode(carol.authority_public_key()),
                state: PinState::Verified,
                since: "2026-10-11T08:30:00.250Z".into(),
                replaced: vec![carol_before.incarnation_id()],
            },
        ],
    }
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_IDENTITY_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x11u8; 32];
    let account = "alice@kutup.dev";
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let binding = drive_key_binding::sign(&identity, account).unwrap();
    let key = identity_pins::derive_key(&master).unwrap();
    let nonce = [0x44u8; 24];
    let sealed = identity_pins::seal_with_nonce(&key, account, 7, &pins(), &nonce).unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        account: account.into(),
        authority_public_key: STANDARD.encode(identity.authority_public_key()),
        drive_hpke_public_key: STANDARD.encode(identity.drive_hpke_public_key()),
        drive_signing_public_key: STANDARD.encode(identity.drive_signing_public_key()),
        drive_key_binding: STANDARD.encode(binding),
        pins_key: STANDARD.encode(*key),
        revision: 7,
        pins: String::from_utf8(identity_pins::encode(&pins()).unwrap()).unwrap(),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(sealed),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn key32(value: &str) -> [u8; 32] {
    STANDARD.decode(value).unwrap().try_into().unwrap()
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master = key32(&v.master_key);
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    assert_eq!(
        STANDARD.encode(identity.authority_public_key()),
        v.authority_public_key
    );
    assert_eq!(
        STANDARD.encode(identity.drive_hpke_public_key()),
        v.drive_hpke_public_key
    );
    assert_eq!(
        STANDARD.encode(identity.drive_signing_public_key()),
        v.drive_signing_public_key
    );
    assert_eq!(
        STANDARD.encode(drive_key_binding::sign(&identity, &v.account).unwrap()),
        v.drive_key_binding
    );
    drive_key_binding::verify(
        &v.account,
        &key32(&v.authority_public_key),
        &key32(&v.drive_hpke_public_key),
        &key32(&v.drive_signing_public_key),
        &STANDARD.decode(&v.drive_key_binding).unwrap(),
    )
    .unwrap();

    let key = identity_pins::derive_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), v.pins_key);
    assert_eq!(
        String::from_utf8(identity_pins::encode(&pins()).unwrap()).unwrap(),
        v.pins
    );
    let nonce: [u8; 24] = STANDARD.decode(&v.nonce).unwrap().try_into().unwrap();
    let sealed =
        identity_pins::seal_with_nonce(&key, &v.account, v.revision, &pins(), &nonce).unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.sealed);
    assert_eq!(
        identity_pins::open(&key, &v.account, v.revision, &sealed).unwrap(),
        pins()
    );
}
