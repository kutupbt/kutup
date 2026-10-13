//! Checked-in vectors for mail address keys (docs/plans/mail-address-keys.md):
//! a fixed key, its fingerprints, its sealed envelope, and a signed key-list
//! chain. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_MAIL_VECTORS=1 cargo test -p kutup-crypto --test mail_key_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::mail_key::{
    generate_address_key, inspect_address_public_key, open_address_key,
    seal_address_key_with_nonce, MailKeyEntryV1, MailKeyListV1, SignedMailKeyListV1, DEFAULT_FLAGS,
    FLAG_NOT_COMPROMISED,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-address-key-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    address: String,
    login_email: String,
    master_key: String,
    created_at: u32,
    secret_key: String,
    public_key: String,
    fingerprint: String,
    sha256_fingerprint: String,
    envelope_nonce: String,
    envelope: String,
    second_key_fingerprint: String,
    second_key_sha256_fingerprint: String,
    key_lists: Vec<KeyListVector>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyListVector {
    data: String,
    signature: String,
    hash: String,
}

fn b64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("base64")
}

fn arr<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).expect("hex").try_into().expect("length")
}

fn lists(
    identity: &AccountIdentityKeysV1,
    address: &str,
    first: MailKeyEntryV1,
    second: MailKeyEntryV1,
) -> Vec<SignedMailKeyListV1> {
    let base = MailKeyListV1 {
        account: address.into(),
        incarnation_id: arr(&identity.incarnation_id()),
        authority_key_id: arr(&identity.authority_key_id()),
        address: address.into(),
        sequence: 1,
        previous_hash: None,
        issued_at: "2026-10-09T12:00:00Z".into(),
        keys: vec![first.clone()],
    };
    let one = base.sign(identity.authority_signing_key()).unwrap();
    // The first key is kept to decrypt older mail; the second becomes primary.
    let mut keys = vec![
        MailKeyEntryV1 {
            primary: false,
            flags: FLAG_NOT_COMPROMISED,
            ..first
        },
        second,
    ];
    keys.sort_by_key(|key| key.fingerprint);
    let two = MailKeyListV1 {
        sequence: 2,
        previous_hash: Some(one.hash()),
        issued_at: "2026-10-10T12:00:00Z".into(),
        keys,
        ..base
    }
    .sign(identity.authority_signing_key())
    .unwrap();
    vec![one, two]
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let address = "alice@kutup.dev";
    let master = [0x42u8; 32];
    let key = generate_address_key(address, 1_790_000_000).unwrap();
    let second = generate_address_key(address, 1_790_086_400).unwrap();
    let nonce = [0x24u8; 24];
    let envelope = seal_address_key_with_nonce(
        &master,
        "Alice@Example.com",
        address,
        &key.secret_key,
        &nonce,
    )
    .unwrap();
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let chain = lists(
        &identity,
        address,
        MailKeyEntryV1 {
            fingerprint: key.fingerprint,
            sha256_fingerprint: key.sha256_fingerprint,
            primary: true,
            flags: DEFAULT_FLAGS,
        },
        MailKeyEntryV1 {
            fingerprint: second.fingerprint,
            sha256_fingerprint: second.sha256_fingerprint,
            primary: true,
            flags: DEFAULT_FLAGS,
        },
    );
    let vectors = Vectors {
        address: address.into(),
        login_email: "Alice@Example.com".into(),
        master_key: STANDARD.encode(master),
        created_at: 1_790_000_000,
        secret_key: STANDARD.encode(&*key.secret_key),
        public_key: STANDARD.encode(&key.public_key),
        fingerprint: hex::encode(key.fingerprint),
        sha256_fingerprint: hex::encode(key.sha256_fingerprint),
        envelope_nonce: STANDARD.encode(nonce),
        envelope: STANDARD.encode(envelope),
        second_key_fingerprint: hex::encode(second.fingerprint),
        second_key_sha256_fingerprint: hex::encode(second.sha256_fingerprint),
        key_lists: chain
            .iter()
            .map(|list| KeyListVector {
                data: STANDARD.encode(&list.data),
                signature: STANDARD.encode(list.signature),
                hash: hex::encode(list.hash()),
            })
            .collect(),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master = b64(&v.master_key);
    let fingerprint: [u8; 20] = arr(&v.fingerprint);

    // The public key inspects to its recorded fingerprints and creation time.
    let info = inspect_address_public_key(&b64(&v.public_key), &v.address).unwrap();
    assert_eq!(hex::encode(info.fingerprint), v.fingerprint);
    assert_eq!(hex::encode(info.sha256_fingerprint), v.sha256_fingerprint);
    assert_eq!(info.created_at_secs, v.created_at);

    // Sealing the secret key with the fixed nonce gives the same envelope,
    // and it opens only for its own address, fingerprint and account.
    let sealed = seal_address_key_with_nonce(
        &master,
        &v.login_email,
        &v.address,
        &b64(&v.secret_key),
        &b64(&v.envelope_nonce),
    )
    .unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.envelope);
    let opened = open_address_key(
        &b64(&v.envelope),
        &master,
        &v.login_email,
        &v.address,
        &fingerprint,
    )
    .unwrap();
    assert_eq!(STANDARD.encode(&*opened), v.secret_key);
    assert!(open_address_key(
        &b64(&v.envelope),
        &master,
        &v.login_email,
        "bob@kutup.dev",
        &fingerprint
    )
    .is_err());

    // The key lists re-sign to the same bytes (Ed25519 is deterministic),
    // verify against the account authority, and chain.
    let identity = AccountIdentityKeysV1::derive(&master.clone().try_into().unwrap()).unwrap();
    let chain = lists(
        &identity,
        &v.address,
        MailKeyEntryV1 {
            fingerprint,
            sha256_fingerprint: arr(&v.sha256_fingerprint),
            primary: true,
            flags: DEFAULT_FLAGS,
        },
        MailKeyEntryV1 {
            fingerprint: arr(&v.second_key_fingerprint),
            sha256_fingerprint: arr(&v.second_key_sha256_fingerprint),
            primary: true,
            flags: DEFAULT_FLAGS,
        },
    );
    let mut previous: Option<SignedMailKeyListV1> = None;
    for (expected, signed) in v.key_lists.iter().zip(&chain) {
        assert_eq!(STANDARD.encode(&signed.data), expected.data);
        assert_eq!(STANDARD.encode(signed.signature), expected.signature);
        assert_eq!(hex::encode(signed.hash()), expected.hash);
        let verified = SignedMailKeyListV1::verify(
            &b64(&expected.data),
            &b64(&expected.signature),
            &identity.authority_public_key(),
        )
        .unwrap();
        if let Some(previous) = &previous {
            previous.check_successor(&verified).unwrap();
        }
        previous = Some(verified);
    }
}
