use super::*;

const ORG: &str = "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b";
const OTHER_ORG: &str = "6c1f8a4b-2e3d-4c9f-8a7b-8d4e3f2a1b0c";

fn person(master: u8, account: &str) -> (AccountIdentityKeysV1, Party) {
    let keys = AccountIdentityKeysV1::derive(&crate::account_roots::IdentityRoot::from_bytes(
        [master; 32],
    ))
    .unwrap();
    let account: AccountRef = account.parse().unwrap();
    let party = Party::new(&account, &keys.incarnation_id()).unwrap();
    (keys, party)
}

fn admin() -> (AccountIdentityKeysV1, Party) {
    person(0x11, "aci:8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b@kutup.dev")
}

fn second_admin() -> (AccountIdentityKeysV1, Party) {
    person(0x22, "aci:9e3f5c72-1d4b-4f0a-8c6e-7b2a3f4d5e6c@kutup.dev")
}

fn member() -> (AccountIdentityKeysV1, Party) {
    person(0x33, "aci:0f4a6d83-2e5c-4a1b-9d7f-8c3b4a5e6f7d@kutup.dev")
}

fn drive_key(keys: &AccountIdentityKeysV1, party: &Party) -> VerifiedDriveKey {
    let signature = crate::drive_key_binding::sign(keys, &party.account, 1).unwrap();
    VerifiedDriveKey::verify(
        &party.account,
        &keys.authority_public_key(),
        1,
        &keys.drive_hpke_public_key(),
        &keys.drive_signing_public_key(),
        &signature,
    )
    .unwrap()
}

fn certificate(public: &[u8]) -> VerifiedKeyCertificate {
    let (keys, admin) = admin();
    let bytes = KeyCertificateV1::sign(ORG, public, 1_700_000_000, &admin, &keys).unwrap();
    KeyCertificateV1::verify(&bytes, &keys.authority_public_key()).unwrap()
}

#[test]
fn a_key_id_is_its_public_keys_hash_under_its_label() {
    let (seed, public, id) = generate();
    assert_eq!(public, public_key(&seed));
    assert_eq!(id, key_id(&public));
    let (_, other, _) = generate();
    assert_ne!(key_id(&other), id);
}

#[test]
fn a_certificate_verifies_only_under_its_admins_authority() {
    let (keys, party) = admin();
    let (_, public, id) = generate();
    let certificate = KeyCertificateV1::sign(ORG, &public, 1_700_000_000, &party, &keys).unwrap();
    let read = KeyCertificateV1::verify(&certificate, &keys.authority_public_key()).unwrap();
    assert_eq!(
        (read.key_id, read.public_key.as_slice(), read.admin.clone()),
        (id, public.as_slice(), party)
    );
    let (other, _) = second_admin();
    assert!(KeyCertificateV1::verify(&certificate, &other.authority_public_key()).is_err());
    // Any changed byte, the public key's among them, fails.
    for at in [10, 60, certificate.len() / 2, certificate.len() - 1] {
        let mut tampered = certificate.clone();
        tampered[at] ^= 1;
        assert!(
            KeyCertificateV1::verify(&tampered, &keys.authority_public_key()).is_err(),
            "byte {at}"
        );
    }
}

#[test]
fn a_share_opens_for_its_recipient_only_and_names_its_granter() {
    let (granter_keys, granter) = admin();
    let (recipient_keys, recipient) = second_admin();
    let (seed, _, id) = generate();
    let share = KeyShareV1::seal(
        &seed,
        ORG,
        &recipient,
        &drive_key(&recipient_keys, &recipient),
        &granter,
        &granter_keys,
    )
    .unwrap();
    let (opened, named) = KeyShareV1::open(
        &share,
        ORG,
        &id,
        &recipient,
        recipient_keys.drive_hpke_private_key(),
        &granter_keys.authority_public_key(),
    )
    .unwrap();
    assert_eq!(*opened, *seed);
    assert_eq!(named, granter);

    // Another recipient's keys, another organization, another key: refused.
    let (member_keys, member) = member();
    assert!(KeyShareV1::open(
        &share,
        ORG,
        &id,
        &member,
        member_keys.drive_hpke_private_key(),
        &granter_keys.authority_public_key()
    )
    .is_err());
    assert!(KeyShareV1::open(
        &share,
        OTHER_ORG,
        &id,
        &recipient,
        recipient_keys.drive_hpke_private_key(),
        &granter_keys.authority_public_key()
    )
    .is_err());
    assert!(KeyShareV1::open(
        &share,
        ORG,
        &[9; 32],
        &recipient,
        recipient_keys.drive_hpke_private_key(),
        &granter_keys.authority_public_key()
    )
    .is_err());

    // Sealing in the admin's name with someone else's keys is refused, and
    // a share a non-admin signed as themselves fails under the admin's
    // authority.
    assert!(KeyShareV1::seal(
        &seed,
        ORG,
        &recipient,
        &drive_key(&recipient_keys, &recipient),
        &granter,
        &member_keys,
    )
    .is_err());
    let forged = KeyShareV1::seal(
        &seed,
        ORG,
        &recipient,
        &drive_key(&recipient_keys, &recipient),
        &member,
        &member_keys,
    )
    .unwrap();
    assert!(KeyShareV1::open(
        &forged,
        ORG,
        &id,
        &recipient,
        recipient_keys.drive_hpke_private_key(),
        &granter_keys.authority_public_key()
    )
    .is_err());

    // A changed header byte (the AAD) fails, whatever re-signs it.
    let mut tampered = share.clone();
    tampered[30] ^= 1;
    assert!(KeyShareV1::open(
        &tampered,
        ORG,
        &id,
        &recipient,
        recipient_keys.drive_hpke_private_key(),
        &granter_keys.authority_public_key()
    )
    .is_err());
}

#[test]
fn a_request_verifies_under_its_admins_authority() {
    let (keys, admin) = admin();
    let (_, member) = member();
    let request = AccessRequestV1 {
        organization_id: uuid_bytes(ORG).unwrap(),
        key_id: [7; 32],
        member,
        admin,
        issued_at: 1_700_000_000,
    };
    let signed = request.sign(&keys).unwrap();
    assert_eq!(
        AccessRequestV1::verify(&signed, &keys.authority_public_key()).unwrap(),
        request
    );
    let (other, _) = second_admin();
    assert!(AccessRequestV1::verify(&signed, &other.authority_public_key()).is_err());
    let mut tampered = signed.clone();
    tampered[20] ^= 1;
    assert!(AccessRequestV1::verify(&tampered, &keys.authority_public_key()).is_err());
}

#[test]
fn an_escrow_opens_only_as_the_members_own_master_key() {
    let (seed, public, _) = generate();
    let (member_keys, member) = member();
    let master = [0x33u8; 32];
    let generation = MasterKeyGeneration::new(2).unwrap();
    let escrow = EscrowV1::seal(
        &master,
        &crate::account_roots::IdentityRoot::from_bytes(master),
        generation,
        &certificate(&public),
        &member,
    )
    .unwrap();
    let opened = EscrowV1::open(
        &escrow,
        ORG,
        &seed,
        &member,
        &member_keys.authority_public_key(),
    )
    .unwrap();
    assert_eq!(*opened.master_key, master);
    assert_eq!(opened.generation, generation);

    // Another key's seed, another organization: refused.
    let (other_seed, _, _) = generate();
    assert!(EscrowV1::open(
        &escrow,
        ORG,
        &other_seed,
        &member,
        &member_keys.authority_public_key()
    )
    .is_err());
    assert!(EscrowV1::open(
        &escrow,
        OTHER_ORG,
        &seed,
        &member,
        &member_keys.authority_public_key()
    )
    .is_err());

    // Planted: anyone can seal to the organization key, but not with the
    // member's identity root; with another one, it never passes as theirs.
    let planted = EscrowV1::seal(
        &master,
        &crate::account_roots::IdentityRoot::from_bytes([0x44; 32]),
        generation,
        &certificate(&public),
        &member,
    )
    .unwrap();
    assert!(EscrowV1::open(
        &planted,
        ORG,
        &seed,
        &member,
        &member_keys.authority_public_key()
    )
    .is_err());

    // The generation is bound: changed in the header, the escrow fails.
    let mut tampered = escrow.clone();
    let generation_at = escrow.len() - ENCAPSULATED_LEN - 2 - ESCROW_SECRET_LEN - 4;
    tampered[generation_at + 3] ^= 1;
    assert!(EscrowV1::open(
        &tampered,
        ORG,
        &seed,
        &member,
        &member_keys.authority_public_key()
    )
    .is_err());
}

#[test]
fn magics_and_truncations_are_refused() {
    let (keys, party) = admin();
    let (_, public, _) = generate();
    let certificate = KeyCertificateV1::sign(ORG, &public, 1, &party, &keys).unwrap();
    for len in [0, 7, 9, 40, certificate.len() - 1] {
        assert!(
            KeyCertificateV1::verify(&certificate[..len], &keys.authority_public_key()).is_err()
        );
    }
    // A certificate is no request.
    assert!(AccessRequestV1::verify(&certificate, &keys.authority_public_key()).is_err());
}

#[test]
fn an_escrow_names_its_member_and_incarnation() {
    let (seed, public, _) = generate();
    let (member_keys, member) = member();
    let (other_keys, other) = second_admin();
    let escrow = EscrowV1::seal(
        &[0x33; 32],
        &crate::account_roots::IdentityRoot::from_bytes([0x33; 32]),
        MasterKeyGeneration::FIRST,
        &certificate(&public),
        &member,
    )
    .unwrap();
    // Opened as another member's: refused, under their party or their authority.
    assert!(EscrowV1::open(
        &escrow,
        ORG,
        &seed,
        &other,
        &other_keys.authority_public_key()
    )
    .is_err());
    assert!(EscrowV1::open(
        &escrow,
        ORG,
        &seed,
        &member,
        &other_keys.authority_public_key()
    )
    .is_err());
    // A member's party with another incarnation: refused.
    let stale = Party {
        incarnation_id: [0x99; 32],
        ..member.clone()
    };
    assert!(EscrowV1::open(
        &escrow,
        ORG,
        &seed,
        &stale,
        &member_keys.authority_public_key()
    )
    .is_err());
}

#[test]
fn a_document_naming_a_wrong_incarnation_is_refused() {
    let (keys, admin) = admin();
    let (_, public, _) = generate();
    // Signing for a party whose incarnation isn't the signer's is refused.
    let stale = Party {
        incarnation_id: [0x99; 32],
        ..admin.clone()
    };
    assert!(KeyCertificateV1::sign(ORG, &public, 1, &stale, &keys).is_err());
    let (_, someone) = member();
    let request = AccessRequestV1 {
        organization_id: uuid_bytes(ORG).unwrap(),
        key_id: key_id(&public),
        member: someone,
        admin: stale,
        issued_at: 1,
    };
    assert!(request.sign(&keys).is_err());
    // A recipient key bound to another account is refused for the share.
    let (seed, _, _) = generate();
    let (other_keys, other) = second_admin();
    let (_, someone) = member();
    assert!(KeyShareV1::seal(
        &seed,
        ORG,
        &someone,
        &drive_key(&other_keys, &other),
        &admin,
        &keys
    )
    .is_err());
    // A certificate refuses a short public key.
    assert!(KeyCertificateV1::sign(ORG, &public[..100], 1, &admin, &keys).is_err());
}
