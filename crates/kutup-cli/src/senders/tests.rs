use std::cell::{Cell, RefCell};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{AccountManifestDeviceV3, AccountManifestPinV1, DeviceKind};
use kutup_crypto::envelope::{self, kind, CollabFrameContextV3, Frame};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::primitives::{SigningKey, Suite};

use super::*;

const SENDER: &str = "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.test";

fn account() -> AccountRef {
    SENDER.parse().unwrap()
}

fn editor(device_id: u32, seed: u8) -> AccountManifestDeviceV3 {
    let key = SigningKey::from_seed(Suite::V1, &[seed; 32])
        .verifying_key()
        .to_array::<32>();
    AccountManifestDeviceV3 {
        device_id,
        kind: DeviceKind::Editor,
        chat: None,
        frame_key: Some(STANDARD.encode(key)),
        session: "ab".repeat(32),
    }
}

fn chain(
    keys: &AccountIdentityKeysV1,
    devices: &[Vec<AccountManifestDeviceV3>],
) -> Vec<AccountManifestV3> {
    let mut out: Vec<AccountManifestV3> = Vec::new();
    for listed in devices {
        let mut next = match out.last() {
            None => {
                AccountManifestV3::first(account(), keys, listed.clone(), "2026-10-29T00:00:00Z")
            }
            Some(head) => head
                .successor(listed.clone(), "2026-10-29T00:01:00Z")
                .unwrap(),
        };
        next.sign(keys.authority_signing_key()).unwrap();
        out.push(next);
    }
    out
}

fn frame(device_id: u32, manifest_sequence: u64, seed: u8) -> Vec<u8> {
    let context = CollabFrameContextV3::new(
        kind::YJS_UPDATE,
        1,
        1,
        "6f1f3e5d-7c9b-4b8e-9c2d-0b6b5e0c4c1e",
        device_id,
        manifest_sequence,
        9,
    )
    .unwrap();
    let packed = envelope::seal_unsigned(b"an edit", &[3; 32], context).unwrap();
    envelope::sign(&Frame::unpack(&packed).unwrap(), &account(), &[seed; 32]).unwrap()
}

/// The sender's server, as this one relays it; `down` makes every read fail.
struct Source {
    chain: Vec<AccountManifestV3>,
    down: Cell<bool>,
}

impl ManifestSource for Source {
    fn head(&self, _: &AccountRef) -> Result<Option<AccountManifestV3>> {
        if self.down.get() {
            bail!("the server can't be reached");
        }
        Ok(self.chain.last().cloned())
    }

    fn history(&self, _: &AccountRef, from: u64, to: u64) -> Result<Vec<AccountManifestV3>> {
        if self.down.get() {
            bail!("the server can't be reached");
        }
        Ok(self
            .chain
            .iter()
            .filter(|m| m.sequence >= from && m.sequence <= to)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct Pins(RefCell<Option<AccountManifestPinV1>>);

impl PinStore for Pins {
    fn sender_pin(&self, _: &AccountRef) -> Result<Option<AccountManifestPinV1>> {
        Ok(self.0.borrow().clone())
    }

    fn put_sender_pin(&self, pin: &AccountManifestPinV1) -> Result<()> {
        *self.0.borrow_mut() = Some(pin.clone());
        Ok(())
    }
}

fn unknown<'a>() -> AuthorityCheck<'a> {
    Box::new(|_, _| Ok(AuthorityVerdict::Unknown))
}

/// A home relaying frames the sender's devices didn't sign: an unlisted
/// device, or a listed device under another key. Skipped and counted; the
/// sender's real frames still count.
#[test]
fn forged_frames_are_skipped_and_counted() {
    let keys = AccountIdentityKeysV1::derive(&[5; 32]).unwrap();
    let source = Source {
        chain: chain(
            &keys,
            &[vec![editor(1, 1)], vec![editor(1, 1), editor(2, 2)]],
        ),
        down: Cell::new(false),
    };
    let pins = Pins::default();
    let mut senders = Senders::new(&source, &pins, unknown());
    assert!(senders.verify(SENDER, &frame(1, 1, 1)).unwrap());
    assert!(!senders.verify(SENDER, &frame(3, 2, 3)).unwrap());
    assert!(!senders.verify(SENDER, &frame(2, 2, 1)).unwrap());
    assert!(senders.verify(SENDER, &frame(2, 2, 2)).unwrap());
    assert_eq!(senders.refused_frames, 2);
    assert!(pins.0.borrow().is_some(), "the head was pinned");
}

/// The sender's server unreachable: the frame can't be checked now. That
/// fails the file (an error), refuses nothing for good, and the next read
/// checks it.
#[test]
fn an_unreadable_server_fails_the_file_not_the_sender() {
    let keys = AccountIdentityKeysV1::derive(&[5; 32]).unwrap();
    let source = Source {
        chain: chain(&keys, &[vec![editor(1, 1)]]),
        down: Cell::new(true),
    };
    let pins = Pins::default();
    let mut senders = Senders::new(&source, &pins, unknown());
    assert!(senders.verify(SENDER, &frame(1, 1, 1)).is_err());
    assert_eq!(senders.refused_frames, 0);
    source.down.set(false);
    assert!(senders.verify(SENDER, &frame(1, 1, 1)).unwrap());
}

/// A reset account: refused (an error naming the way out), both when the
/// identity pins hold another authority and when they don't know the account
/// but its pin is of another incarnation.
#[test]
fn a_reset_account_is_refused_with_its_way_out() {
    let old = AccountIdentityKeysV1::derive(&[5; 32]).unwrap();
    let new = AccountIdentityKeysV1::derive(&[6; 32]).unwrap();
    let first = chain(&old, &[vec![editor(1, 1)]]);
    let pins = Pins::default();
    pins.put_sender_pin(&AccountManifestPinV1::of(&first[0]).unwrap())
        .unwrap();
    let source = Source {
        chain: chain(&new, &[vec![editor(1, 1)]]),
        down: Cell::new(false),
    };
    let mut senders = Senders::new(&source, &pins, unknown());
    let error = senders
        .verify(SENDER, &frame(1, 1, 1))
        .unwrap_err()
        .to_string();
    assert!(error.contains("forget-pin --sender"), "{error}");
    let mut changed = Senders::new(
        &source,
        &pins,
        Box::new(|_, _| Ok(AuthorityVerdict::Changed)),
    );
    let error = changed
        .verify(SENDER, &frame(1, 1, 1))
        .unwrap_err()
        .to_string();
    assert!(error.contains("identity trust"), "{error}");
    assert_eq!(senders.refused_frames + changed.refused_frames, 0);
}
