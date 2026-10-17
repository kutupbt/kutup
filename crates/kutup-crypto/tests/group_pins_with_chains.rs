//! A shared mailbox's chain (mail_group::verify_group_key_chain, the
//! checked-in mail-group-chain-v1 vectors) through the pin list's rules
//! (identity_pins::lookup_group/record_group): what a sender's app does on
//! every lookup. The valid chain is pinned on first use; an administrator's
//! restarted chain verifies on its own and is "changed" for a sender who
//! pinned the first; the chains a server forges, an old signer's fork after
//! its handover, a missing handover never verify at all, so a pinned sender
//! never takes them.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use kutup_crypto::identity_pins::{self, GroupChain, GroupMatch, GroupUpdate, IdentityPinsV2};
use kutup_crypto::mail_group::{verify_group_key_chain, GroupKeyChainView, GroupSignerHandoverV1};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct List {
    data: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Chain {
    first_signer: String,
    lists: Vec<List>,
    handovers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    group_id: String,
    valid: Chain,
    server_forged: Chain,
    old_signer_fork: Chain,
    missing_handover: Chain,
    admin_restart: Chain,
}

const SINCE: &str = "2026-10-16T12:00:00Z";

fn verified(group_id: &str, chain: &Chain) -> kutup_crypto::error::Result<GroupKeyChainView> {
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
    let lists: Vec<(&[u8], &[u8])> = lists
        .iter()
        .map(|(d, s)| (d.as_slice(), s.as_slice()))
        .collect();
    let handovers: Vec<GroupSignerHandoverV1> = chain
        .handovers
        .iter()
        .map(|h| GroupSignerHandoverV1::decode(&STANDARD.decode(h).unwrap()).unwrap())
        .collect();
    verify_group_key_chain(group_id, &first, &lists, &handovers)
}

fn found(list: &IdentityPinsV2, group_id: &str, view: &GroupKeyChainView) -> &'static str {
    let chain = GroupChain {
        signers: &view.signers,
        digests: &view.digests,
    };
    match identity_pins::lookup_group(list, "kutup.dev", group_id, &chain).unwrap() {
        GroupMatch::New => "new",
        GroupMatch::Same { .. } => "same",
        GroupMatch::Changed { .. } => "changed",
    }
}

#[test]
fn a_sender_pins_the_group_signer_and_sees_a_restart_as_a_change() {
    let v: Vectors =
        serde_json::from_str(include_str!("vectors/mail-group-chain-v1.json")).unwrap();
    let group = v.group_id.as_str();
    let mut pins = IdentityPinsV2::default();

    // The valid chain (A, handed over to B at 3): pinned on first use, then the same.
    let valid = verified(group, &v.valid).unwrap();
    assert_eq!(found(&pins, group, &valid), "new");
    let chain = GroupChain {
        signers: &valid.signers,
        digests: &valid.digests,
    };
    assert!(identity_pins::record_group(
        &mut pins,
        "kutup.dev",
        group,
        &chain,
        GroupUpdate::FirstSeen,
        SINCE
    )
    .unwrap());
    assert_eq!(found(&pins, group, &valid), "same");
    let pin = pins.group("kutup.dev", group).unwrap();
    assert_eq!(pin.signer_public_key, STANDARD.encode(valid.signer));
    assert_eq!(pin.anchor.sequence, valid.sequence);

    // An administrator's new chain: valid on its own, a change for this sender.
    let restart = verified(group, &v.admin_restart).unwrap();
    assert_eq!(found(&pins, group, &restart), "changed");

    // What a server forges, an old signer's fork after its handover, a
    // missing handover: refused before any pin is asked.
    for (chain, why) in [
        (&v.server_forged, "server forged"),
        (&v.old_signer_fork, "old signer's fork"),
        (&v.missing_handover, "missing handover"),
    ] {
        assert!(verified(group, chain).is_err(), "{why}");
    }
}
