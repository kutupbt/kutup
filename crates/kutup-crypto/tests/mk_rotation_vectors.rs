//! Checked-in vectors for a master-key rotation
//! (docs/plans/mk-rotation-exercise.md): an account at generation 1, its
//! records, and the rotation to generation 2 from fixed keys. Records carry
//! random nonces, so they are sealed once and checked in; every client must
//! open and refuse them as below. Regenerate only for a deliberate format
//! change:
//! `KUTUP_WRITE_MK_ROTATION_VECTORS=1 cargo test -p kutup-crypto --test mk_rotation_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_head::{self, HeadKeys, HeadStatus};
use kutup_crypto::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use kutup_crypto::account_roots::AccountRoots;
use kutup_crypto::chat_store::StoreCipher;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::master_keys::{MasterKeys, MASTER_KEY_STALE};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mk-rotation-v1.json"
);
const BINDING: &str = "4c2e8a1f-6b3d-4e9a-8c7f-1d2e3f4a5b6c";
const STORE: &str = "kutup-chat-v2:vectors";
const UID: &str = "contact-uid-1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    binding: String,
    /// The master keys of generation 1 and 2, the recovery entropy of the
    /// rotation, and the roots' common bytes (base64).
    old_master_key: String,
    new_master_key: String,
    recovery_entropy: String,
    roots_bytes: String,
    /// What the rotation sends: the keyring record, the five roots under the
    /// new key, the recovery wrap, and the head that follows `firstHead`.
    keyring: String,
    roots: Vec<String>,
    recovery_envelope: String,
    first_head: String,
    rotation_head: String,
    /// Records sealed before the rotation: a contact card and a Chat store
    /// key, both still opened (through the keyring) after it.
    old_contact_card: String,
    old_store_key: String,
    /// A record of generation 3: newer than the rotated account's keys.
    future_record: String,
}

fn b64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn key32(value: &str) -> [u8; 32] {
    b64(value).try_into().unwrap()
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MK_ROTATION_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let (old, new, entropy, bytes) = ([0x51u8; 32], [0x52u8; 32], [0x53u8; 32], [0x54u8; 32]);
    let roots = AccountRoots::same_for_tests(bytes);
    let before = MasterKeys::first(&old);
    let incarnation = AccountIdentityKeysV1::derive(&roots.identity)
        .unwrap()
        .incarnation_id();
    let keys = HeadKeys::derive(&before, &roots.object_id).unwrap();
    let writer = keys.writer("vectors").unwrap();
    let (first_head, verified) = account_head::first(
        &keys,
        BINDING,
        &incarnation,
        roots.head_generations(),
        &writer,
        vec![],
    )
    .unwrap();
    let rotation = kutup_crypto::mk_rotation::prepare_with(
        &before, BINDING, &roots, &verified, &writer, &new, &entropy,
    )
    .unwrap();
    let old_contact_card = kutup_crypto::contact_card::seal_card(
        &old,
        MasterKeyGeneration::FIRST,
        BINDING,
        UID,
        1,
        b"BEGIN:VCARD\r\nEND:VCARD\r\n",
    )
    .unwrap();
    let (_, old_store_key) =
        StoreCipher::create(&before, BINDING, STORE, &mut rand_core::OsRng).unwrap();
    let future_record = account_record::seal(
        &[9; 32],
        &[0x55; 32],
        AccountRecordPurpose::ChatBackupRoot,
        MasterKeyGeneration::new(3).unwrap(),
        BINDING,
    )
    .unwrap();
    let encode = |bytes: &[u8]| STANDARD.encode(bytes);
    let vectors = Vectors {
        binding: BINDING.into(),
        old_master_key: encode(&old),
        new_master_key: encode(&new),
        recovery_entropy: encode(&entropy),
        roots_bytes: encode(&bytes),
        keyring: encode(&rotation.keyring),
        roots: rotation.roots.iter().map(|r| encode(r)).collect(),
        recovery_envelope: encode(&rotation.recovery_envelope),
        first_head: encode(&first_head),
        rotation_head: encode(&rotation.head),
        old_contact_card: encode(&old_contact_card),
        old_store_key: encode(&old_store_key),
        future_record: encode(&future_record),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let (old, new) = (key32(&v.old_master_key), key32(&v.new_master_key));
    let roots = AccountRoots::same_for_tests(key32(&v.roots_bytes));

    // The keyring reaches the old key from the new one at generation 2.
    let keyring = b64(&v.keyring);
    assert_eq!(
        account_record::inspect(&keyring).unwrap().generation.get(),
        2
    );
    let keys = MasterKeys::open(
        &new,
        MasterKeyGeneration::new(2).unwrap(),
        &v.binding,
        std::slice::from_ref(&keyring),
    )
    .unwrap();
    assert_eq!(keys.at(MasterKeyGeneration::FIRST).unwrap(), &old);
    // The old key alone can't take a keyring past its own generation.
    let stale =
        MasterKeys::open(&old, MasterKeyGeneration::FIRST, &v.binding, &[keyring]).unwrap_err();
    assert!(stale.to_string().contains(MASTER_KEY_STALE), "{stale}");

    // The roots, re-wrapped at generation 2, are the same roots.
    let records: Vec<Vec<u8>> = v.roots.iter().map(|r| b64(r)).collect();
    for record in &records {
        assert_eq!(account_record::inspect(record).unwrap().generation.get(), 2);
    }
    let authority = AccountIdentityKeysV1::derive(&roots.identity)
        .unwrap()
        .authority_public_key();
    let opened = AccountRoots::open(&records, &keys, &v.binding, &authority).unwrap();
    assert!(opened.same_for_tests_as(&roots));

    // The new phrase opens the new key.
    let recovered = account_record::open(
        &b64(&v.recovery_envelope),
        &key32(&v.recovery_entropy),
        AccountRecordPurpose::RecoveryMasterKey,
        &v.binding,
    )
    .unwrap();
    assert_eq!(recovered.as_slice(), &new);

    // A device anchored on the first head follows the chain across the
    // rotation; a client with the old key alone is told it is stale.
    let incarnation = AccountIdentityKeysV1::derive(&roots.identity)
        .unwrap()
        .incarnation_id();
    let (first, rotated) = (b64(&v.first_head), b64(&v.rotation_head));
    let old_keys = HeadKeys::derive(&MasterKeys::first(&old), &roots.object_id).unwrap();
    let anchor = account_head::check(
        &old_keys,
        &v.binding,
        &incarnation,
        roots.head_generations(),
        None,
        &first,
        None,
    )
    .unwrap()
    .verified
    .unwrap()
    .anchor()
    .clone();
    let new_keys = HeadKeys::derive(&keys, &roots.object_id).unwrap();
    let checked = account_head::check(
        &new_keys,
        &v.binding,
        &incarnation,
        roots.head_generations(),
        Some(&anchor),
        &rotated,
        Some(&[first.clone(), rotated.clone()]),
    )
    .unwrap();
    assert_eq!(checked.status, HeadStatus::Extends);
    let error = account_head::check(
        &old_keys,
        &v.binding,
        &incarnation,
        roots.head_generations(),
        Some(&anchor),
        &rotated,
        None,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains(MASTER_KEY_STALE), "{error}");

    // Records sealed before the rotation still open, under the key their
    // header names; the store key moves to the new one.
    let card = b64(&v.old_contact_card);
    let (vcard, _) =
        kutup_crypto::contact_card::open_card(keys.key_for(&card).unwrap(), &v.binding, UID, &card)
            .unwrap();
    assert_eq!(&vcard[..], b"BEGIN:VCARD\r\nEND:VCARD\r\n");
    let store_key = b64(&v.old_store_key);
    StoreCipher::unwrap(&keys, &v.binding, STORE, &store_key).unwrap();
    let moved = StoreCipher::rewrapped(&keys, &v.binding, STORE, &store_key)
        .unwrap()
        .unwrap();
    assert_eq!(account_record::inspect(&moved).unwrap().generation.get(), 2);

    // A record of a newer generation than the account's keys: stale.
    let future = keys.key_for(&b64(&v.future_record)).unwrap_err();
    assert!(future.to_string().contains(MASTER_KEY_STALE), "{future}");
}
