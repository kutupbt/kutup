//! The CLI's device of its account (docs/plans/one-device-list.md): a `cli`
//! entry of the account's manifest, with the Ed25519 frame key its edits to
//! notes, code files and place lists are signed with, and the credential its
//! requests carry (`X-Kutup-Device`), as an editor tab's.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use kutup_chat_proto::{
    AccountManifestDeviceV3, AccountManifestV3, DeviceKind, OwnManifestPinV1,
    RegisterDeviceRequestV1,
};
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::primitives::{SigningKey, Suite};
use zeroize::Zeroizing;

use crate::api::{ApiError, Client};
use crate::session::{CollabDevice, Session, Store};

/// A device of the account its manifest lists, ready to sign frames.
pub struct Device {
    pub id: u32,
    seed: Zeroizing<[u8; 32]>,
    credential: Zeroizing<[u8; 32]>,
    /// The account its frames name.
    pub account: AccountRef,
    /// The account's manifest sequence that lists it.
    pub manifest_sequence: u64,
}

impl Device {
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The `X-Kutup-Device` value.
    pub fn header(&self) -> String {
        format!(
            "{}.{}",
            self.id,
            URL_SAFE_NO_PAD.encode(self.credential.as_ref())
        )
    }
}

/// Whether `error` is the server saying this device is not (or no longer)
/// one of the account's: register again.
pub fn not_authorized(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|e| e.downcast_ref::<ApiError>())
        .any(|e| {
            (e.status == 403 && e.code.as_deref() == Some("deviceNotAuthorized"))
                || (e.status == 401 && e.code.as_deref() == Some("deviceCredential"))
        })
}

fn frame_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(Suite::V1, seed)
        .verifying_key()
        .to_array::<32>()
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// What signs the account's manifest: its authority, from the master key.
pub struct Signer<'a> {
    client: &'a Client,
    store: &'a Store,
    sess: &'a Session,
    server: String,
    account: AccountRef,
    identity: AccountIdentityKeysV1,
}

/// `head`, the account's head as its server gave it, checked against `pin`
/// for the account `identity` holds the keys of
/// ([`OwnManifestPinV1::check`]): the pin to keep. A head that doesn't
/// verify (one the server changed: another Drive key, identity or device),
/// one under another authority, an older one, or none once one was seen, is
/// refused, and nothing is listed from it or signed after it.
fn checked_head(
    pin: Option<&OwnManifestPinV1>,
    head: Option<&AccountManifestV3>,
    account: &AccountRef,
    identity: &AccountIdentityKeysV1,
) -> Result<Option<OwnManifestPinV1>> {
    OwnManifestPinV1::check(pin, head, account, &identity.incarnation_id())
        .map_err(|error| anyhow!("the account's manifest can't be trusted: {error}"))
}

impl<'a> Signer<'a> {
    pub fn new(client: &'a Client, store: &'a Store, sess: &'a Session) -> Result<Self> {
        if sess.master_key.is_empty() {
            return Err(anyhow!(
                "this session holds no account keys; sign in again to edit notes and lists"
            ));
        }
        let master_key: [u8; 32] = sess
            .master_key_bytes()?
            .as_slice()
            .try_into()
            .context("master key must be 32 bytes")?;
        let server = client.settings()?.chat.server_name;
        Ok(Signer {
            client,
            store,
            sess,
            account: AccountRef::new(&server, &sess.user_id)
                .map_err(|_| anyhow!("this session's account is malformed"))?,
            server,
            identity: AccountIdentityKeysV1::derive(&master_key)?,
        })
    }

    /// The account's head as its server gives it, checked: it verifies under
    /// this account's authority and incarnation and is no older than the
    /// newest one this profile saw (none at all is refused once one was
    /// seen). Only such a head is listed from or signed a successor of.
    fn head(&self) -> Result<Option<AccountManifestV3>> {
        let head = self.client.account_manifest(&self.account)?;
        self.pin(head.as_ref())?;
        Ok(head)
    }

    /// Checks `head` against this profile's pin and keeps the pin it gives.
    fn pin(&self, head: Option<&AccountManifestV3>) -> Result<()> {
        let pin = self.store.manifest_pin()?;
        let next = checked_head(pin.as_ref(), head, &self.account, &self.identity)?;
        if let Some(next) = next.filter(|next| Some(next) != pin.as_ref()) {
            self.store.put_manifest_pin(&next)?;
        }
        Ok(())
    }

    /// This profile's device: the one kept, while the account's manifest
    /// lists it with its key; else a new one registered and listed now.
    pub fn device(&self) -> Result<Device> {
        if let Some(kept) = self.store.collab_device()? {
            if kept.server == self.server && kept.user_id == self.sess.user_id {
                if let Some(device) = self.listed(&kept)? {
                    return Ok(device);
                }
            }
        }
        self.register()
    }

    /// The server no longer takes this profile's device: a new one.
    pub fn recover(&self) -> Result<Device> {
        self.register()
    }

    /// `kept` as the account's head lists it, if it does.
    fn listed(&self, kept: &CollabDevice) -> Result<Option<Device>> {
        let seed: [u8; 32] = STANDARD
            .decode(&kept.seed)?
            .try_into()
            .map_err(|_| anyhow!("stored device key has the wrong length"))?;
        let credential: [u8; 32] = STANDARD
            .decode(&kept.credential)?
            .try_into()
            .map_err(|_| anyhow!("stored device credential has the wrong length"))?;
        let Some(head) = self.head()? else {
            return Ok(None);
        };
        let key = STANDARD.encode(frame_key(&seed));
        let listed = head
            .device(kept.device_id)
            .is_some_and(|entry| entry.frame_key.as_deref() == Some(key.as_str()));
        Ok(listed.then(|| Device {
            id: kept.device_id,
            seed: Zeroizing::new(seed),
            credential: Zeroizing::new(credential),
            account: self.account.clone(),
            manifest_sequence: head.sequence,
        }))
    }

    /// Registers a new device, lists it in the account's manifest, and keeps
    /// it.
    pub fn register(&self) -> Result<Device> {
        let mut seed = Zeroizing::new([0u8; 32]);
        kutup_crypto::primitives::random(seed.as_mut());
        let mut credential = Zeroizing::new([0u8; 32]);
        kutup_crypto::primitives::random(credential.as_mut());
        let key = STANDARD.encode(frame_key(&seed));
        let registered = self
            .client
            .register_device(&RegisterDeviceRequestV1 {
                kind: DeviceKind::Cli,
                name: "Kutup CLI".into(),
                frame_key: key.clone(),
                credential: URL_SAFE_NO_PAD.encode(credential.as_ref()),
            })
            .context("register this CLI as a device of the account")?;
        let mut device = Device {
            id: registered.device_id,
            seed,
            credential,
            account: self.account.clone(),
            manifest_sequence: 0,
        };
        let entry = AccountManifestDeviceV3 {
            device_id: device.id,
            kind: DeviceKind::Cli,
            chat: None,
            frame_key: Some(key),
            session: registered.session,
        };
        let id = device.id;
        device.manifest_sequence = self
            .publish(&device.header(), |devices| {
                devices.retain(|listed| listed.device_id != id);
                devices.push(entry.clone());
                Ok(())
            })
            .context("list this CLI in the account's manifest")?;
        self.store.put_collab_device(Some(&CollabDevice {
            server: self.server.clone(),
            user_id: self.sess.user_id.clone(),
            device_id: device.id,
            seed: STANDARD.encode(device.seed.as_ref()),
            credential: STANDARD.encode(device.credential.as_ref()),
        }))?;
        Ok(device)
    }

    /// The account's next manifest, with `change` made to its devices,
    /// signed and published as the device `by` names; its sequence. A head
    /// that moved meanwhile is read again, once.
    pub fn publish(
        &self,
        by: &str,
        change: impl Fn(&mut Vec<AccountManifestDeviceV3>) -> Result<()>,
    ) -> Result<u64> {
        let mut attempt = 0;
        loop {
            let head = self.head()?;
            let mut next = match &head {
                Some(head) => {
                    let mut devices = head.devices.clone();
                    change(&mut devices)?;
                    head.successor(devices, now_rfc3339())
                        .map_err(|error| anyhow!(error))?
                }
                None => {
                    let mut devices = Vec::new();
                    change(&mut devices)?;
                    AccountManifestV3::first(
                        self.account.clone(),
                        &self.identity,
                        devices,
                        now_rfc3339(),
                    )
                }
            };
            next.sign(self.identity.authority_signing_key())
                .map_err(|error| anyhow!(error))?;
            next.verify_successor(head.as_ref())
                .map_err(|error| anyhow!(error))?;
            match self.client.publish_manifest(&next, by) {
                Ok(()) => {
                    self.pin(Some(&next))?;
                    return Ok(next.sequence);
                }
                Err(error)
                    if attempt == 0
                        && error
                            .chain()
                            .filter_map(|e| e.downcast_ref::<ApiError>())
                            .any(|e| e.status == 409) =>
                {
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor(device_id: u32, byte: u8) -> AccountManifestDeviceV3 {
        AccountManifestDeviceV3 {
            device_id,
            kind: DeviceKind::Cli,
            chat: None,
            frame_key: Some(STANDARD.encode(frame_key(&[byte; 32]))),
            session: "ab".repeat(32),
        }
    }

    /// The heads a server could serve the CLI to have it sign their
    /// successor: each is refused before anything is signed.
    #[test]
    fn a_forged_or_stale_head_is_refused() {
        let keys = AccountIdentityKeysV1::derive(&[3; 32]).unwrap();
        let account =
            AccountRef::new("example.test", "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b").unwrap();
        let mut first = AccountManifestV3::first(
            account.clone(),
            &keys,
            vec![editor(1, 1)],
            "2026-10-27T00:00:00Z",
        );
        first.sign(keys.authority_signing_key()).unwrap();
        let pin = checked_head(None, Some(&first), &account, &keys)
            .unwrap()
            .unwrap();
        let mut second = first
            .successor(vec![editor(1, 1), editor(2, 2)], "2026-10-27T00:01:00Z")
            .unwrap();
        second.sign(keys.authority_signing_key()).unwrap();
        let pin = checked_head(Some(&pin), Some(&second), &account, &keys)
            .unwrap()
            .unwrap();

        // The server's own Drive key and an extra entry under the account's
        // authority, which it can't sign: before this check the CLI signed
        // a successor of it.
        let mut forged = second.clone();
        forged.drive.share_signing_public_key = STANDARD.encode(frame_key(&[9; 32]));
        forged.devices.push(editor(3, 3));
        assert!(checked_head(Some(&pin), Some(&forged), &account, &keys).is_err());
        assert!(checked_head(None, Some(&forged), &account, &keys).is_err());
        // The same, signed under an authority of the server's.
        let other = AccountIdentityKeysV1::derive(&[4; 32]).unwrap();
        let mut theirs = AccountManifestV3::first(
            account.clone(),
            &other,
            vec![editor(1, 1), editor(3, 3)],
            "2026-10-27T00:02:00Z",
        );
        theirs.sign(other.authority_signing_key()).unwrap();
        assert!(checked_head(None, Some(&theirs), &account, &keys).is_err());
        // The head before the last one seen (device 2 gone again), and no
        // head at all (a new chain).
        assert!(checked_head(Some(&pin), Some(&first), &account, &keys).is_err());
        assert!(checked_head(Some(&pin), None, &account, &keys).is_err());
        // The current head passes.
        assert_eq!(
            checked_head(Some(&pin), Some(&second), &account, &keys).unwrap(),
            Some(pin)
        );
    }
}
