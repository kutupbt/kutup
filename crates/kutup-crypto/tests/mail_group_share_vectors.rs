//! Checked-in vector for a shared mailbox's key share (docs/plans/mail-groups.md,
//! docs/plans/account-ids.md): the group key (here the key of
//! `mail-address-key-v1.json`) sealed to a member's account key, bound to the
//! group, the group key, the member's account and its incarnation. Sealed once
//! (HPKE draws a fresh key) and checked in; every client must open it for that
//! member only. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_SHARE_VECTORS=1 cargo test -p kutup-crypto --features mail --test mail_group_share_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::mail_key::{
    group_key_share_incarnation, open_group_key_share, seal_group_key_share, GroupShareMember,
};

const KEYS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-address-key-v1.json"
);
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-group-share-v1.json"
);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    secret_key: String,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    group_id: String,
    /// The member: their account (`aci:` form) and the master key whose
    /// account keys the share is sealed to.
    member: String,
    member_master_key: String,
    member_incarnation_id: String,
    share: String,
}

fn group_key() -> (Vec<u8>, [u8; 20]) {
    let keys: Keys = serde_json::from_str(&std::fs::read_to_string(KEYS).unwrap()).unwrap();
    (
        STANDARD.decode(keys.secret_key).unwrap(),
        hex::decode(keys.fingerprint).unwrap().try_into().unwrap(),
    )
}

fn member_keys(master: &str) -> AccountIdentityKeysV1 {
    AccountIdentityKeysV1::derive(&STANDARD.decode(master).unwrap().try_into().unwrap()).unwrap()
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_SHARE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let (secret, _) = group_key();
    let member: AccountRef = "aci:8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b@kutup.dev"
        .parse()
        .unwrap();
    let master = STANDARD.encode([0x22u8; 32]);
    let keys = member_keys(&master);
    let group_id = "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b";
    let incarnation = keys.incarnation_id();
    let share = seal_group_key_share(
        &secret,
        group_id,
        &GroupShareMember {
            account: &member,
            incarnation_id: &incarnation,
        },
        &keys.drive_hpke_public_key(),
    )
    .unwrap();
    let vectors = Vectors {
        group_id: group_id.into(),
        member: member.to_string(),
        member_master_key: master,
        member_incarnation_id: incarnation,
        share: STANDARD.encode(share),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn the_checked_in_share_opens_for_its_member_only() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let (secret, fingerprint) = group_key();
    let member: AccountRef = v.member.parse().unwrap();
    let keys = member_keys(&v.member_master_key);
    let share = STANDARD.decode(&v.share).unwrap();
    // The layout: version 1, the member's incarnation, then the HPKE parts.
    assert_eq!(share[0], 1);
    assert_eq!(
        group_key_share_incarnation(&share).unwrap(),
        v.member_incarnation_id
    );
    assert_eq!(v.member_incarnation_id, keys.incarnation_id());
    let opened = open_group_key_share(
        &share,
        &v.group_id,
        &fingerprint,
        &member,
        keys.drive_hpke_private_key(),
    )
    .unwrap();
    assert_eq!(&*opened, secret.as_slice());
    let someone_else =
        AccountRef::new(&member.server, "00000000-0000-4000-8000-000000000000").unwrap();
    assert!(open_group_key_share(
        &share,
        &v.group_id,
        &fingerprint,
        &someone_else,
        keys.drive_hpke_private_key(),
    )
    .is_err());
}
