use super::*;
use crate::{AccountManifestDeviceV3, DeviceKind};
use base64::Engine as _;
use kutup_crypto::envelope::{kind, CollabFrameContextV3};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::primitives::{SigningKey, Suite};

const FILE: &str = "6f1f3e5d-7c9b-4b8e-9c2d-0b6b5e0c4c1e";

fn account() -> AccountRef {
    AccountRef::new("example.test", "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b").unwrap()
}

/// An editor entry whose frame key is the one `seed` makes.
fn editor(device_id: u32, seed: u8) -> AccountManifestDeviceV3 {
    let key = SigningKey::from_seed(Suite::V1, &[seed; 32])
        .verifying_key()
        .to_array::<32>();
    AccountManifestDeviceV3 {
        device_id,
        kind: DeviceKind::Editor,
        chat: None,
        frame_key: Some(base64::engine::general_purpose::STANDARD.encode(key)),
        session: "ab".repeat(32),
    }
}

/// A frame of `device_id` under `manifest_sequence`, signed with `seed`'s key.
fn frame(device_id: u32, manifest_sequence: u64, seed: u8) -> Vec<u8> {
    let context = CollabFrameContextV3::new(
        kind::YJS_UPDATE,
        1,
        1,
        FILE,
        device_id,
        manifest_sequence,
        7,
    )
    .unwrap();
    let packed = envelope::seal_unsigned(b"an edit", &[3; 32], context).unwrap();
    envelope::sign(&Frame::unpack(&packed).unwrap(), &account(), &[seed; 32]).unwrap()
}

/// The account's chain: each manifest lists `devices[i]`.
fn chain(
    keys: &AccountIdentityKeysV1,
    devices: &[Vec<AccountManifestDeviceV3>],
) -> Vec<AccountManifestV3> {
    let mut out: Vec<AccountManifestV3> = Vec::new();
    for listed in devices {
        let mut next = match out.last() {
            None => {
                AccountManifestV3::first(account(), keys, listed.clone(), "2026-10-27T00:00:00Z")
            }
            Some(head) => head
                .successor(listed.clone(), "2026-10-27T00:01:00Z")
                .unwrap(),
        };
        next.sign(keys.authority_signing_key()).unwrap();
        out.push(next);
    }
    out
}

fn keys() -> AccountIdentityKeysV1 {
    AccountIdentityKeysV1::derive(&[5; 32]).unwrap()
}

#[test]
fn a_live_frame_counts_while_the_head_lists_its_device_and_key() {
    let keys = keys();
    // 1: device 1; 2: devices 1 and 2; 3: device 2 removed.
    let manifests = chain(
        &keys,
        &[
            vec![editor(1, 1)],
            vec![editor(1, 1), editor(2, 2)],
            vec![editor(1, 1)],
        ],
    );
    let mut sender = SenderManifests::new(account(), None);
    assert_eq!(sender.check(&frame(1, 1, 1), true), SenderVerdict::NeedHead);
    sender.take_head(manifests[1].clone(), &[], false).unwrap();
    assert_eq!(sender.check(&frame(1, 1, 1), true), SenderVerdict::Take);
    assert_eq!(sender.check(&frame(2, 2, 2), true), SenderVerdict::Take);
    // Another key under a listed id, or an id the head doesn't list.
    assert!(matches!(
        sender.check(&frame(2, 2, 9), true),
        SenderVerdict::Refuse { .. }
    ));
    assert!(matches!(
        sender.check(&frame(4, 2, 4), true),
        SenderVerdict::Refuse { .. }
    ));
    // A frame naming a later manifest: read the head first.
    assert_eq!(sender.check(&frame(1, 3, 1), true), SenderVerdict::NeedHead);
    // Device 2 removed: its live frames stop.
    sender.take_head(manifests[2].clone(), &[], false).unwrap();
    assert!(matches!(
        sender.check(&frame(2, 2, 2), true),
        SenderVerdict::Refuse { .. }
    ));
    assert_eq!(sender.check(&frame(1, 3, 1), true), SenderVerdict::Take);
}

#[test]
fn a_logged_frame_counts_under_the_manifest_it_names() {
    let keys = keys();
    // Device 2 is removed at 3 and its id reused by another key at 4.
    let manifests = chain(
        &keys,
        &[
            vec![editor(1, 1)],
            vec![editor(1, 1), editor(2, 2)],
            vec![editor(1, 1)],
            vec![editor(1, 1), editor(2, 22)],
        ],
    );
    let mut sender = SenderManifests::new(account(), None);
    sender.take_head(manifests[3].clone(), &[], false).unwrap();
    // A logged frame of a device the head lists with that key: no fetch.
    assert_eq!(sender.check(&frame(1, 2, 1), false), SenderVerdict::Take);
    // The removed holder's past edit: fetch 2 through 3 (up to the head),
    // then it counts.
    let old = frame(2, 2, 2);
    assert_eq!(
        sender.check(&old, false),
        SenderVerdict::NeedManifest {
            sequence: 2,
            through: 3
        }
    );
    // Not linked up to the head: refused.
    assert!(sender.take_history(&[manifests[1].clone()]).is_err());
    sender
        .take_history(&[manifests[2].clone(), manifests[1].clone()])
        .unwrap();
    assert_eq!(sender.check(&old, false), SenderVerdict::Take);
    // Live, the id is the new holder's: the old key no longer counts.
    assert!(matches!(
        sender.check(&old, true),
        SenderVerdict::Refuse { .. }
    ));
    assert_eq!(sender.check(&frame(2, 4, 22), true), SenderVerdict::Take);
    // Held, and not listing it so: refused without a fetch.
    assert!(matches!(
        sender.check(&frame(3, 2, 3), false),
        SenderVerdict::Refuse { .. }
    ));
    // History must be the chain's: not altered, not another authority's.
    let mut fresh = SenderManifests::new(account(), None);
    fresh.take_head(manifests[3].clone(), &[], false).unwrap();
    let mut altered = manifests[2].clone();
    altered.devices.push(editor(5, 5));
    assert!(fresh.take_history(&[altered]).is_err());
    let other = AccountIdentityKeysV1::derive(&[6; 32]).unwrap();
    let theirs = chain(
        &other,
        &[vec![editor(1, 1)], vec![editor(1, 1)], vec![editor(1, 1)]],
    );
    assert!(fresh.take_history(&[theirs[2].clone()]).is_err());
}

/// A manifest the account's authority signed at a sequence but the chain
/// never held (a concurrent publish the server didn't take) is no history.
#[test]
fn a_signed_manifest_off_the_chain_is_no_history() {
    let keys = keys();
    let manifests = chain(
        &keys,
        &[
            vec![editor(1, 1)],
            vec![editor(1, 1), editor(2, 2)],
            vec![editor(1, 1)],
        ],
    );
    // Signed at 2 too, listing a device the chain never had.
    let mut fork = manifests[0]
        .successor(vec![editor(1, 1), editor(7, 7)], "2026-10-27T00:05:00Z")
        .unwrap();
    fork.sign(keys.authority_signing_key()).unwrap();
    let mut sender = SenderManifests::new(account(), None);
    sender.take_head(manifests[2].clone(), &[], false).unwrap();
    assert_eq!(
        sender.check(&frame(7, 2, 7), false),
        SenderVerdict::NeedManifest {
            sequence: 2,
            through: 2
        }
    );
    assert!(sender.take_history(&[fork]).is_err());
    sender.take_history(&[manifests[1].clone()]).unwrap();
    assert!(matches!(
        sender.check(&frame(7, 2, 7), false),
        SenderVerdict::Refuse { .. }
    ));
}

#[test]
fn the_head_only_moves_forward_along_a_verified_chain() {
    let keys = keys();
    let manifests = chain(
        &keys,
        &[
            vec![editor(1, 1)],
            vec![editor(1, 1), editor(2, 2)],
            vec![editor(1, 1)],
            vec![editor(1, 1), editor(3, 3)],
        ],
    );
    let mut sender = SenderManifests::new(account(), None);
    sender.take_head(manifests[1].clone(), &[], false).unwrap();
    // Older: refused, the head stays.
    assert!(sender.take_head(manifests[0].clone(), &[], false).is_err());
    assert_eq!(sender.head.as_ref().unwrap().sequence, 2);
    // Later without the link between: refused; with it: taken.
    assert!(sender.take_head(manifests[3].clone(), &[], false).is_err());
    sender
        .take_head(manifests[3].clone(), &[manifests[2].clone()], false)
        .unwrap();
    assert_eq!(sender.pin.as_ref().unwrap().sequence, 4);
    // The links on the way are kept for logged frames.
    assert!(sender.entries.iter().any(|m| m.sequence == 3));
    // A fork at the pinned sequence: refused.
    let mut fork = manifests[2]
        .successor(vec![editor(1, 1), editor(4, 4)], "2026-10-27T00:09:00Z")
        .unwrap();
    fork.sign(keys.authority_signing_key()).unwrap();
    assert!(sender.take_head(fork, &[], false).is_err());
    // A pin kept from before: a new record holds the chain to it.
    let mut again = SenderManifests::new(account(), sender.pin.clone());
    assert!(again.take_head(manifests[2].clone(), &[], false).is_err());
    again.take_head(manifests[3].clone(), &[], false).unwrap();
}

#[test]
fn another_incarnation_needs_the_identity_pins_to_vouch() {
    let keys = keys();
    let manifests = chain(&keys, &[vec![editor(1, 1)]]);
    let reset = AccountIdentityKeysV1::derive(&[7; 32]).unwrap();
    let fresh = chain(&reset, &[vec![editor(1, 1)]]);
    let mut sender = SenderManifests::new(account(), None);
    sender.take_head(manifests[0].clone(), &[], false).unwrap();
    // The account reset (or a server's own keys): refused until accepted.
    assert!(sender.take_head(fresh[0].clone(), &[], false).is_err());
    assert_eq!(sender.check(&frame(1, 1, 1), true), SenderVerdict::Take);
    // Accepted (the identity pins vouch for the new authority).
    sender.take_head(fresh[0].clone(), &[], true).unwrap();
    assert_eq!(
        sender.pin.as_ref().unwrap().incarnation_id,
        reset.incarnation_id()
    );
}
