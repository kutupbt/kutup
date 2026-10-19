//! Checked-in vectors for the formats that name a person by their account
//! (docs/plans/account-ids.md): `AccountRef` itself, the Drive key binding,
//! folder and file share envelopes and the profile key envelope. Each binds
//! the server and the account id, never an address. The envelopes are
//! sealed once (HPKE draws a fresh key) and checked in; every client must
//! open them with the same parties and refuse them for any other.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_ACCOUNT_REF_VECTORS=1 cargo test -p kutup-crypto --test account_ref_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::named_share::{FileShareEnvelopeV1, NamedShareEnvelopeV1};
use kutup_crypto::profile_key_share::{ProfileKeyEnvelopeV1, ProfileKeyParties};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/account-refs-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    /// Sender and recipient: master keys and accounts (`aci:` form).
    sender_master_key: String,
    sender: String,
    recipient_master_key: String,
    recipient: String,
    /// `AccountRef::bytes` of the sender (hex).
    sender_bytes: String,
    /// The sender's Drive key binding: the signed bytes (hex) and signature.
    binding_bytes: String,
    binding: String,
    collection_id: String,
    epoch: u32,
    collection_key: String,
    named_share: String,
    file_id: String,
    generation: u32,
    file_key: String,
    file_share: String,
    profile_key: String,
    profile_key_envelope: String,
}

fn b64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn key32(value: &str) -> [u8; 32] {
    b64(value).try_into().unwrap()
}

fn identity(master_key: &str) -> AccountIdentityKeysV1 {
    AccountIdentityKeysV1::derive(&key32(master_key)).unwrap()
}

/// The same server, another account id: never the same person.
fn someone_else(person: &AccountRef) -> AccountRef {
    AccountRef::new(&person.server, "00000000-0000-4000-8000-000000000000").unwrap()
}

#[test]
#[ignore]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_ACCOUNT_REF_VECTORS").is_err() {
        return;
    }
    let sender_master_key = STANDARD.encode([0x11u8; 32]);
    let recipient_master_key = STANDARD.encode([0x22u8; 32]);
    let sender: AccountRef = "aci:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70@a.kutup.test"
        .parse()
        .unwrap();
    let recipient: AccountRef = "aci:8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b@b.kutup.test"
        .parse()
        .unwrap();
    let (from, to) = (
        identity(&sender_master_key),
        identity(&recipient_master_key),
    );
    let binding_bytes = drive_key_binding::binding_bytes(
        &sender,
        &from.authority_public_key(),
        1,
        &from.drive_hpke_public_key(),
        &from.drive_signing_public_key(),
    )
    .unwrap();
    let binding = drive_key_binding::sign(&from, &sender, 1).unwrap();
    let collection_id = "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b";
    let collection_key = [0x33u8; 32];
    let named_share = NamedShareEnvelopeV1::seal(
        &collection_key,
        collection_id,
        3,
        &sender,
        &from.incarnation_id(),
        from.drive_signing_key(),
        &recipient,
        &to.incarnation_id(),
        &to.drive_hpke_public_key(),
    )
    .unwrap();
    let file_id = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
    let file_key = [0x44u8; 32];
    let file_share = FileShareEnvelopeV1::seal(
        &file_key,
        file_id,
        2,
        &sender,
        &from.incarnation_id(),
        from.drive_signing_key(),
        &recipient,
        &to.incarnation_id(),
        &to.drive_hpke_public_key(),
    )
    .unwrap();
    let profile_key = [0x55u8; 32];
    let profile_key_envelope = ProfileKeyEnvelopeV1::seal(
        &profile_key,
        &ProfileKeyParties {
            sender: &sender,
            sender_incarnation_id: &from.incarnation_id(),
            recipient: &recipient,
            recipient_incarnation_id: &to.incarnation_id(),
        },
        from.drive_signing_key(),
        &to.drive_hpke_public_key(),
    )
    .unwrap();
    let vectors = Vectors {
        sender_master_key,
        sender: sender.to_string(),
        recipient_master_key,
        recipient: recipient.to_string(),
        sender_bytes: hex::encode(sender.bytes()),
        binding_bytes: hex::encode(binding_bytes),
        binding: STANDARD.encode(binding),
        collection_id: collection_id.into(),
        epoch: 3,
        collection_key: STANDARD.encode(collection_key),
        named_share: named_share.encode_b64().unwrap(),
        file_id: file_id.into(),
        generation: 2,
        file_key: STANDARD.encode(file_key),
        file_share: file_share.encode_b64().unwrap(),
        profile_key: STANDARD.encode(profile_key),
        profile_key_envelope: profile_key_envelope.encode_b64().unwrap(),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn load() -> Vectors {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

#[test]
fn an_account_is_its_server_and_id_in_bytes() {
    let v = load();
    let sender: AccountRef = v.sender.parse().unwrap();
    assert_eq!(hex::encode(sender.bytes()), v.sender_bytes);
    assert_eq!(sender.to_string(), v.sender);
}

#[test]
fn the_drive_key_binding_names_the_account() {
    let v = load();
    let sender: AccountRef = v.sender.parse().unwrap();
    let from = identity(&v.sender_master_key);
    let (authority, hpke, signing) = (
        from.authority_public_key(),
        from.drive_hpke_public_key(),
        from.drive_signing_public_key(),
    );
    assert_eq!(
        hex::encode(
            drive_key_binding::binding_bytes(&sender, &authority, 1, &hpke, &signing).unwrap()
        ),
        v.binding_bytes
    );
    // Ed25519 is deterministic: the same signature, byte for byte.
    assert_eq!(
        STANDARD.encode(drive_key_binding::sign(&from, &sender, 1).unwrap()),
        v.binding
    );
    let binding = b64(&v.binding);
    drive_key_binding::verify(&sender, &authority, 1, &hpke, &signing, &binding).unwrap();
    assert!(drive_key_binding::verify(
        &someone_else(&sender),
        &authority,
        1,
        &hpke,
        &signing,
        &binding
    )
    .is_err());
}

#[test]
fn shares_open_only_between_their_accounts() {
    let v = load();
    let sender: AccountRef = v.sender.parse().unwrap();
    let recipient: AccountRef = v.recipient.parse().unwrap();
    let (from, to) = (
        identity(&v.sender_master_key),
        identity(&v.recipient_master_key),
    );

    let named = NamedShareEnvelopeV1::decode_b64(&v.named_share).unwrap();
    assert_eq!((&named.sender, &named.recipient), (&sender, &recipient));
    let open_named = |who: &AccountRef, to_whom: &AccountRef| {
        named.open(
            &v.collection_id,
            v.epoch,
            who,
            &from.incarnation_id(),
            &from.drive_signing_public_key(),
            to_whom,
            &to.incarnation_id(),
            to.drive_hpke_private_key(),
        )
    };
    assert_eq!(
        open_named(&sender, &recipient).unwrap().as_slice(),
        b64(&v.collection_key)
    );
    assert!(open_named(&someone_else(&sender), &recipient).is_err());
    assert!(open_named(&sender, &someone_else(&recipient)).is_err());

    let file = FileShareEnvelopeV1::decode_b64(&v.file_share).unwrap();
    assert_eq!((&file.sender, &file.recipient), (&sender, &recipient));
    let open_file = |who: &AccountRef, to_whom: &AccountRef| {
        file.open(
            &v.file_id,
            v.generation,
            who,
            &from.incarnation_id(),
            &from.drive_signing_public_key(),
            to_whom,
            &to.incarnation_id(),
            to.drive_hpke_private_key(),
        )
    };
    assert_eq!(
        open_file(&sender, &recipient).unwrap().as_slice(),
        b64(&v.file_key)
    );
    assert!(open_file(&sender, &someone_else(&recipient)).is_err());

    let profile = ProfileKeyEnvelopeV1::decode_b64(&v.profile_key_envelope).unwrap();
    let open_profile = |who: &AccountRef, to_whom: &AccountRef| -> [u8; 32] {
        let (sender_incarnation, recipient_incarnation) =
            (from.incarnation_id(), to.incarnation_id());
        let parties = ProfileKeyParties {
            sender: who,
            sender_incarnation_id: &sender_incarnation,
            recipient: to_whom,
            recipient_incarnation_id: &recipient_incarnation,
        };
        profile
            .open(
                &parties,
                &from.drive_signing_public_key(),
                to.drive_hpke_private_key(),
            )
            .map(|key| key.as_slice().try_into().unwrap())
            .unwrap_or([0; 32])
    };
    assert_eq!(
        open_profile(&sender, &recipient).as_slice(),
        b64(&v.profile_key)
    );
    assert_eq!(open_profile(&someone_else(&sender), &recipient), [0; 32]);
}
