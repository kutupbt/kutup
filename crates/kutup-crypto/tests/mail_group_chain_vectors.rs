//! Checked-in vectors for a shared mailbox's key-list chain (docs/plans/mail-groups.md,
//! docs/plans/account-ids.md): lists signed by the group's signing key, a
//! handover to the next signer, and the chains every client must refuse —
//! a link the server signs, the outgoing signer forking after its handover,
//! a missing handover — and an administrator's new chain, which verifies on
//! its own but under another first signer (senders who pinned the first one
//! see a change). Ed25519 is deterministic: regenerating gives the same
//! bytes. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_GROUP_CHAIN_VECTORS=1 cargo test -p kutup-crypto --features mail --test mail_group_chain_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::identity::{authority_key_id_from_public, incarnation_id_from_authority_public};
use kutup_crypto::mail_group::{verify_group_key_chain, GroupSignerHandoverV1, GroupSigningKey};
use kutup_crypto::mail_key::{MailKeyEntryV1, MailKeyListV1, SignedMailKeyListV1, DEFAULT_FLAGS};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-group-chain-v1.json"
);
const GROUP: &str = "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b";

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct List {
    data: String,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Chain {
    first_signer: String,
    lists: Vec<List>,
    handovers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    group_id: String,
    /// Signed by A, handed over to B at sequence 3.
    valid: Chain,
    /// Its signers in order and each list's digest (hex).
    valid_signers: Vec<String>,
    valid_digests: Vec<String>,
    /// List 3 signed by a key of the server's own: refused.
    server_forged: Chain,
    /// After handing over at 3, A signs a list 3 of its own: refused.
    old_signer_fork: Chain,
    /// B's list 3 without the handover: refused.
    missing_handover: Chain,
    /// An administrator's new chain from sequence 1 under signer C: valid on
    /// its own; a sender who pinned A sees a change.
    admin_restart: Chain,
}

fn key(byte: u8) -> GroupSigningKey {
    GroupSigningKey::from_seed(&[byte; 32])
}

fn list(
    signer: &GroupSigningKey,
    sequence: u64,
    previous: Option<&SignedMailKeyListV1>,
    fingerprint: u8,
) -> SignedMailKeyListV1 {
    let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
    MailKeyListV1 {
        incarnation_id: hex32(incarnation_id_from_authority_public(&signer.public_key)),
        authority_key_id: hex32(authority_key_id_from_public(&signer.public_key)),
        address: "hr@kutup.dev".into(),
        sequence,
        previous_hash: previous.map(SignedMailKeyListV1::hash),
        issued_at: "2026-10-16T12:00:00Z".into(),
        keys: vec![MailKeyEntryV1 {
            fingerprint: [fingerprint; 20],
            sha256_fingerprint: [fingerprint; 32],
            primary: true,
            flags: DEFAULT_FLAGS,
        }],
    }
    .sign(&signer.signing_key())
    .unwrap()
}

fn chain(
    first: &GroupSigningKey,
    lists: &[&SignedMailKeyListV1],
    handovers: &[&GroupSignerHandoverV1],
) -> Chain {
    Chain {
        first_signer: STANDARD.encode(first.public_key),
        lists: lists
            .iter()
            .map(|list| List {
                data: STANDARD.encode(&list.data),
                signature: STANDARD.encode(list.signature),
            })
            .collect(),
        handovers: handovers
            .iter()
            .map(|handover| STANDARD.encode(handover.encode()))
            .collect(),
    }
}

fn verify(chain: &Chain) -> kutup_crypto::Result<kutup_crypto::mail_group::GroupKeyChainView> {
    let first: [u8; 32] = STANDARD
        .decode(&chain.first_signer)
        .unwrap()
        .try_into()
        .unwrap();
    let lists: Vec<(Vec<u8>, Vec<u8>)> = chain
        .lists
        .iter()
        .map(|list| {
            (
                STANDARD.decode(&list.data).unwrap(),
                STANDARD.decode(&list.signature).unwrap(),
            )
        })
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = lists
        .iter()
        .map(|(data, signature)| (data.as_slice(), signature.as_slice()))
        .collect();
    let handovers: Vec<GroupSignerHandoverV1> = chain
        .handovers
        .iter()
        .map(|handover| GroupSignerHandoverV1::decode(&STANDARD.decode(handover).unwrap()).unwrap())
        .collect();
    verify_group_key_chain(GROUP, &first, &pairs, &handovers)
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_GROUP_CHAIN_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let (a, b, c, server) = (key(1), key(2), key(3), key(9));
    let one = list(&a, 1, None, 1);
    let two = list(&a, 2, Some(&one), 2);
    let handover = GroupSignerHandoverV1::sign(&a, GROUP, 3, &two.hash(), &b.public_key).unwrap();
    let three = list(&b, 3, Some(&two), 3);
    let forged = list(&server, 3, Some(&two), 3);
    let fork = list(&a, 3, Some(&two), 4);
    let restart = list(&c, 1, None, 5);
    let vectors = Vectors {
        group_id: GROUP.into(),
        valid: chain(&a, &[&one, &two, &three], &[&handover]),
        valid_signers: vec![hex::encode(a.public_key), hex::encode(b.public_key)],
        valid_digests: [&one, &two, &three]
            .iter()
            .map(|list| hex::encode(list.hash()))
            .collect(),
        server_forged: chain(&a, &[&one, &two, &forged], &[]),
        old_signer_fork: chain(&a, &[&one, &two, &fork], &[&handover]),
        missing_handover: chain(&a, &[&one, &two, &three], &[]),
        admin_restart: chain(&c, &[&restart], &[]),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn the_checked_in_chains_verify_or_are_refused() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let view = verify(&v.valid).unwrap();
    assert_eq!(
        view.signers.iter().map(hex::encode).collect::<Vec<_>>(),
        v.valid_signers
    );
    assert_eq!(
        view.digests.iter().map(hex::encode).collect::<Vec<_>>(),
        v.valid_digests
    );
    assert_eq!(view.sequence, 3);
    assert!(verify(&v.server_forged).is_err());
    assert!(verify(&v.old_signer_fork).is_err());
    assert!(verify(&v.missing_handover).is_err());
    // The administrator's chain is a chain of its own, under another signer.
    let restart = verify(&v.admin_restart).unwrap();
    assert!(!restart
        .signers
        .iter()
        .any(|signer| hex::encode(signer) == v.valid_signers[0]));
}
