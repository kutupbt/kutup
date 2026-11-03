//! Checked-in vectors for an organization's key formats
//! (docs/plans/organizations.md §3): a key certificate, a key share to a
//! second admin, an access request and a member's escrow, made from fixed
//! master keys. HPKE draws a fresh key, so they are sealed once and checked
//! in; every client must verify and open them as below. Regenerate only for a
//! deliberate format change:
//! `KUTUP_WRITE_ORGANIZATION_VECTORS=1 cargo test -p kutup-crypto --test organization_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_envelope::MasterKeyGeneration;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::organization::{
    key_id, public_key, AccessRequestV1, EscrowV1, KeyCertificateV1, KeyShareV1, Party,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/organization-v1.json"
);

const ORG: &str = "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b";
const ADMIN: &str = "aci:8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b@kutup.dev";
const SECOND_ADMIN: &str = "aci:9e3f5c72-1d4b-4f0a-8c6e-7b2a3f4d5e6c@kutup.dev";
const MEMBER: &str = "aci:0f4a6d83-2e5c-4a1b-9d7f-8c3b4a5e6f7d@kutup.dev";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    organization_id: String,
    /// The organization key's seed and id (hex).
    organization_seed: String,
    key_id: String,
    /// Master keys (base64) of the admin who made the key, the admin it is
    /// shared with, and the member who escrowed theirs.
    admin_master_key: String,
    second_admin_master_key: String,
    member_master_key: String,
    member_generation: u32,
    issued_at: u64,
    certificate: String,
    share: String,
    request: String,
    escrow: String,
}

fn person(master: &str, account: &str) -> (AccountIdentityKeysV1, Party) {
    let keys = AccountIdentityKeysV1::derive(&STANDARD.decode(master).unwrap().try_into().unwrap())
        .unwrap();
    let account: AccountRef = account.parse().unwrap();
    let party = Party::new(&account, &keys.incarnation_id()).unwrap();
    (keys, party)
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_ORGANIZATION_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let seed = [0x5au8; 32];
    let public = public_key(&seed);
    let (admin_master, second_master, member_master) = (
        STANDARD.encode([0x11u8; 32]),
        STANDARD.encode([0x22u8; 32]),
        STANDARD.encode([0x33u8; 32]),
    );
    let (admin_keys, admin) = person(&admin_master, ADMIN);
    let (second_keys, second) = person(&second_master, SECOND_ADMIN);
    let (_, member) = person(&member_master, MEMBER);
    let issued_at = 1_793_000_000;
    let certificate = KeyCertificateV1::sign(ORG, &public, issued_at, &admin, &admin_keys).unwrap();
    let share = KeyShareV1::seal(
        &seed,
        ORG,
        &second,
        &second_keys.drive_hpke_public_key(),
        &admin,
        &admin_keys,
    )
    .unwrap();
    let request = AccessRequestV1 {
        organization_id: *uuid::Uuid::parse_str(ORG).unwrap().as_bytes(),
        key_id: key_id(&public),
        member: member.clone(),
        admin: admin.clone(),
        issued_at,
    }
    .sign(&admin_keys);
    let escrow = EscrowV1::seal(
        &[0x33; 32],
        MasterKeyGeneration::FIRST,
        ORG,
        &public,
        &member,
    )
    .unwrap();
    let vectors = Vectors {
        organization_id: ORG.into(),
        organization_seed: hex::encode(seed),
        key_id: hex::encode(key_id(&public)),
        admin_master_key: admin_master,
        second_admin_master_key: second_master,
        member_master_key: member_master,
        member_generation: 1,
        issued_at,
        certificate: STANDARD.encode(certificate),
        share: STANDARD.encode(share),
        request: STANDARD.encode(request),
        escrow: STANDARD.encode(escrow),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let seed: [u8; 32] = hex::decode(&v.organization_seed)
        .unwrap()
        .try_into()
        .unwrap();
    let id: [u8; 32] = hex::decode(&v.key_id).unwrap().try_into().unwrap();
    assert_eq!(key_id(&public_key(&seed)), id);
    let (admin_keys, admin) = person(&v.admin_master_key, ADMIN);
    let (second_keys, second) = person(&v.second_admin_master_key, SECOND_ADMIN);
    let (member_keys, member) = person(&v.member_master_key, MEMBER);

    let certificate = KeyCertificateV1::verify(
        &STANDARD.decode(&v.certificate).unwrap(),
        &admin_keys.authority_public_key(),
    )
    .unwrap();
    assert_eq!(
        (certificate.key_id, certificate.issued_at, certificate.admin),
        (id, v.issued_at, admin.clone())
    );

    let (opened, granter) = KeyShareV1::open(
        &STANDARD.decode(&v.share).unwrap(),
        &v.organization_id,
        &id,
        &second,
        second_keys.drive_hpke_private_key(),
        &admin_keys.authority_public_key(),
    )
    .unwrap();
    assert_eq!((*opened, granter), (seed, admin.clone()));

    let request = AccessRequestV1::verify(
        &STANDARD.decode(&v.request).unwrap(),
        &admin_keys.authority_public_key(),
    )
    .unwrap();
    assert_eq!(
        (request.member, request.admin, request.key_id),
        (member.clone(), admin, id)
    );

    let escrowed = EscrowV1::open(
        &STANDARD.decode(&v.escrow).unwrap(),
        &v.organization_id,
        &seed,
        &member,
        &member_keys.authority_public_key(),
    )
    .unwrap();
    assert_eq!(
        (escrowed.master_key.as_slice(), escrowed.generation.get()),
        (
            STANDARD.decode(&v.member_master_key).unwrap().as_slice(),
            v.member_generation
        )
    );
}
