//! Checked-in vectors for contacts (docs/plans/contacts.md): the contacts key,
//! a signed summary and a sealed card, both bound to the account's key binding
//! (summary domain v2, card suite 2), with the values that must be refused.
//! Regenerate only for a deliberate format change: `KUTUP_WRITE_CONTACT_VECTORS=1 cargo test -p kutup-crypto --test contact_card_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::contact_card::{
    derive_contacts_key, inspect_card, open_card, seal_card_with_nonce, sign_summary,
    verify_summary, ContactEmailV1, ContactSummaryV1, PinnedKeyV1,
};
use kutup_crypto::identity::AccountIdentityKeysV1;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/contact-card-v2.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    /// The account's key binding, which the summary and the card bind.
    binding: String,
    contacts_key: String,
    /// The contact's revision, which the summary's signature and the card
    /// bind.
    revision: u64,
    summary: String,
    signature: String,
    uid: String,
    vcard: String,
    nonce: String,
    sealed: String,
    /// Summary signatures that must not verify, with the binding tried.
    refused_signatures: Vec<RefusedSignature>,
    /// Cards that must not open, with the binding and UID tried.
    refused_cards: Vec<RefusedCard>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefusedSignature {
    case: String,
    binding: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefusedCard {
    case: String,
    binding: String,
    uid: String,
    sealed: String,
}

const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";
const OTHER_BINDING: &str = "9e8d7c6b-5a49-4382-a716-05f4e3d2c1b0";
const ADDRESS: &str = "alice@kutup.dev";
/// 2026-10-10T12:00:00Z in unix milliseconds.
const REVISION: u64 = 1_791_633_600_000;
/// The same summary as version 1 signed it (bound to `alice@kutup.dev`).
const V1_SIGNATURE: &str =
    "T1H0x4wwYXMIn8e9Iz2CATqRanGOp7D7Nh9hXHicOE8YI1Oj8URrUy6De91bJXswRdcKgBoC5q2L/G4+axpqCw==";
/// The same card as suite 1 sealed it (bound to `alice@kutup.dev`).
const V1_SEALED: &str = "S1VUQ0MxAAAAATMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM+72yETk29k8t6HE5YUoFiZGb64f4jyfZI+8nviq2sRQpm6ZIMra/7bOjjyQP5lPwJBAtETEqY5tAaG2CRN/qPKNzqVNNYJk0780W6vI7SJ4zOgfA2e1ue7QUyYNXqrwqLdDTnICgUw7E0Ywuxgy/3/PdAKwAUzXyRHyqCqePezkD3bq4rsNhl4RAquHim5gMqLt0II3nDrFmOXxKm6uvtUqCztoAuHWfPUcx3ZTYSIaJRfU2EEM1455mv/GiXEYeOoEjW85XeZ30JFu7rUWaWA8F7gGuFDSJLw=";

fn refused_signatures(signature: &[u8; 64], newer: &[u8; 64]) -> Vec<RefusedSignature> {
    let case = |case: &str, binding: &str, signature: &[u8]| RefusedSignature {
        case: case.into(),
        binding: binding.into(),
        signature: STANDARD.encode(signature),
    };
    let mut flipped = *signature;
    flipped[0] ^= 1;
    let old = STANDARD.decode(V1_SIGNATURE).unwrap();
    vec![
        case("another account's key binding", OTHER_BINDING, signature),
        case(
            "the account's address instead of its binding",
            ADDRESS,
            signature,
        ),
        case("signature changed", BINDING, &flipped),
        case("signed for another revision", BINDING, newer),
        case("version 1, bound to the address", BINDING, &old),
        case("version 1, checked with the address", ADDRESS, &old),
    ]
}

fn refused_cards(sealed: &[u8], uid: &str) -> Vec<RefusedCard> {
    let case = |case: &str, binding: &str, uid: &str, sealed: &[u8]| RefusedCard {
        case: case.into(),
        binding: binding.into(),
        uid: uid.into(),
        sealed: STANDARD.encode(sealed),
    };
    let mut magic = sealed.to_vec();
    magic[5] = b'1';
    let mut suite = sealed.to_vec();
    suite[9] = 1;
    let mut revision = sealed.to_vec();
    revision[17] ^= 1;
    let mut nonce = sealed.to_vec();
    nonce[18] ^= 1;
    let mut tag = sealed.to_vec();
    *tag.last_mut().unwrap() ^= 1;
    let old = STANDARD.decode(V1_SEALED).unwrap();
    let other_uid = "urn:uuid:00000000-0000-4000-8000-000000000000";
    vec![
        case("another account's key binding", OTHER_BINDING, uid, sealed),
        case(
            "the account's address instead of its binding",
            ADDRESS,
            uid,
            sealed,
        ),
        case("another contact's UID", BINDING, other_uid, sealed),
        case("magic changed", BINDING, uid, &magic),
        case("suite changed", BINDING, uid, &suite),
        case("revision changed", BINDING, uid, &revision),
        case("nonce changed", BINDING, uid, &nonce),
        case("ciphertext changed", BINDING, uid, &tag),
        case("suite 1, bound to the address", BINDING, uid, &old),
        case("suite 1, opened with the address", ADDRESS, uid, &old),
    ]
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
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let (bytes, signature) = sign_summary(
        &summary(),
        BINDING,
        REVISION,
        identity.authority_signing_key(),
    )
    .unwrap();
    let (_, newer) = sign_summary(
        &summary(),
        BINDING,
        REVISION + 1,
        identity.authority_signing_key(),
    )
    .unwrap();
    let key = derive_contacts_key(&master).unwrap();
    let nonce = [0x33u8; 24];
    let sealed = seal_card_with_nonce(
        &key,
        BINDING,
        &summary().uid,
        REVISION,
        VCARD.as_bytes(),
        &nonce,
    )
    .unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        binding: BINDING.into(),
        contacts_key: STANDARD.encode(*key),
        revision: REVISION,
        summary: String::from_utf8(bytes).unwrap(),
        signature: STANDARD.encode(signature),
        uid: summary().uid,
        vcard: VCARD.into(),
        nonce: STANDARD.encode(nonce),
        refused_signatures: refused_signatures(&signature, &newer),
        refused_cards: refused_cards(&sealed, &summary().uid),
        sealed: STANDARD.encode(sealed),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master: [u8; 32] = STANDARD.decode(&v.master_key).unwrap().try_into().unwrap();
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let (bytes, signature) = sign_summary(
        &summary(),
        &v.binding,
        v.revision,
        identity.authority_signing_key(),
    )
    .unwrap();
    let (_, newer) = sign_summary(
        &summary(),
        &v.binding,
        v.revision + 1,
        identity.authority_signing_key(),
    )
    .unwrap();
    assert_eq!(String::from_utf8(bytes).unwrap(), v.summary);
    assert_eq!(STANDARD.encode(signature), v.signature);
    assert_eq!(
        verify_summary(
            v.summary.as_bytes(),
            &STANDARD.decode(&v.signature).unwrap(),
            &v.binding,
            v.revision,
            &identity.authority_public_key()
        )
        .unwrap(),
        summary()
    );
    let key = derive_contacts_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), v.contacts_key);
    let nonce: [u8; 24] = STANDARD.decode(&v.nonce).unwrap().try_into().unwrap();
    let sealed = seal_card_with_nonce(
        &key,
        &v.binding,
        &v.uid,
        v.revision,
        v.vcard.as_bytes(),
        &nonce,
    )
    .unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.sealed);
    assert_eq!(inspect_card(&sealed).unwrap(), v.revision);
    let (vcard, revision) = open_card(&key, &v.binding, &v.uid, &sealed).unwrap();
    assert_eq!((&vcard[..], revision), (v.vcard.as_bytes(), v.revision));

    let expected = refused_signatures(&signature, &newer);
    assert_eq!(v.refused_signatures.len(), expected.len());
    for (case, want) in v.refused_signatures.iter().zip(&expected) {
        assert_eq!(
            (&case.case, &case.binding, &case.signature),
            (&want.case, &want.binding, &want.signature)
        );
        assert!(
            verify_summary(
                v.summary.as_bytes(),
                &STANDARD.decode(&case.signature).unwrap(),
                &case.binding,
                v.revision,
                &identity.authority_public_key()
            )
            .is_err(),
            "{} verified",
            case.case
        );
    }
    let expected = refused_cards(&sealed, &v.uid);
    assert_eq!(v.refused_cards.len(), expected.len());
    for (case, want) in v.refused_cards.iter().zip(&expected) {
        assert_eq!(
            (&case.case, &case.binding, &case.uid, &case.sealed),
            (&want.case, &want.binding, &want.uid, &want.sealed)
        );
        assert!(
            open_card(
                &key,
                &case.binding,
                &case.uid,
                &STANDARD.decode(&case.sealed).unwrap()
            )
            .is_err(),
            "{} opened",
            case.case
        );
    }
    // The address is not a key binding: nothing signs or seals to it.
    assert!(sign_summary(
        &summary(),
        ADDRESS,
        v.revision,
        identity.authority_signing_key()
    )
    .is_err());
    assert!(seal_card_with_nonce(
        &key,
        ADDRESS,
        &v.uid,
        v.revision,
        v.vcard.as_bytes(),
        &nonce
    )
    .is_err());
}
