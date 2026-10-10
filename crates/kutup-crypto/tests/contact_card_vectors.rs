//! Checked-in vectors for contacts (docs/plans/contacts.md): the contacts key,
//! a signed summary and a sealed card. Regenerate only for a deliberate format
//! change: `KUTUP_WRITE_CONTACT_VECTORS=1 cargo test -p kutup-crypto --test contact_card_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::contact_card::{
    derive_contacts_key, open_card, seal_card_with_nonce, sign_summary, verify_summary,
    ContactEmailV1, ContactSummaryV1, PinnedKeyV1,
};
use kutup_crypto::identity::AccountIdentityKeysV1;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/contact-card-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    account: String,
    contacts_key: String,
    summary: String,
    signature: String,
    uid: String,
    vcard: String,
    nonce: String,
    sealed: String,
}

fn summary() -> ContactSummaryV1 {
    ContactSummaryV1 {
        uid: "urn:uuid:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70".into(),
        name: "Ayşe Yılmaz".into(),
        emails: vec![
            ContactEmailV1 {
                address: "ayse@example.com".into(),
                label: Some("work".into()),
            },
            ContactEmailV1 {
                address: "ayse@kutup.dev".into(),
                label: None,
            },
        ],
        groups: vec!["11111111-1111-4111-8111-111111111111".into()],
        pinned_keys: vec![PinnedKeyV1 {
            address: "ayse@example.com".into(),
            fingerprint: "0123456789abcdef0123456789abcdef01234567".into(),
            encrypt: true,
            sign: false,
        }],
    }
}

const VCARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70\r\nFN:Ayşe Yılmaz\r\nEMAIL;TYPE=work:ayse@example.com\r\nTEL;TYPE=cell:+90 555 000 00 00\r\nNOTE:Met at the conference\r\nEND:VCARD\r\n";

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_CONTACT_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x5au8; 32];
    let account = "alice@kutup.dev";
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let (bytes, signature) =
        sign_summary(&summary(), account, identity.authority_signing_key()).unwrap();
    let key = derive_contacts_key(&master).unwrap();
    let nonce = [0x33u8; 24];
    let sealed =
        seal_card_with_nonce(&key, account, &summary().uid, VCARD.as_bytes(), &nonce).unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        account: account.into(),
        contacts_key: STANDARD.encode(*key),
        summary: String::from_utf8(bytes).unwrap(),
        signature: STANDARD.encode(signature),
        uid: summary().uid,
        vcard: VCARD.into(),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(sealed),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master: [u8; 32] = STANDARD.decode(&v.master_key).unwrap().try_into().unwrap();
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let (bytes, signature) =
        sign_summary(&summary(), &v.account, identity.authority_signing_key()).unwrap();
    assert_eq!(String::from_utf8(bytes).unwrap(), v.summary);
    assert_eq!(STANDARD.encode(signature), v.signature);
    assert_eq!(
        verify_summary(
            v.summary.as_bytes(),
            &STANDARD.decode(&v.signature).unwrap(),
            &v.account,
            &identity.authority_public_key()
        )
        .unwrap(),
        summary()
    );
    let key = derive_contacts_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), v.contacts_key);
    let nonce: [u8; 24] = STANDARD.decode(&v.nonce).unwrap().try_into().unwrap();
    let sealed =
        seal_card_with_nonce(&key, &v.account, &v.uid, v.vcard.as_bytes(), &nonce).unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.sealed);
    assert_eq!(
        &open_card(&key, &v.account, &v.uid, &sealed).unwrap()[..],
        v.vcard.as_bytes()
    );
}
