//! One libsignal identity per account, as Signal's ACI
//! (docs/plans/account-identity-key.md): how a device comes to hold it.
//!
//! - An account's first device, and a device whose account has lost every
//!   other one, **re-registers**: a new identity, and the account's next
//!   manifest listing this device alone, in the registration call.
//! - Every other device is **linked** by one that has the identity (Signal's
//!   provisioning): the new device shows a `kutup://link` code, the linking
//!   device sends it the identity in a provisioning envelope, and the new
//!   device registers with the link token it carried, then publishes the
//!   manifest that lists it.
//!
//! A store from before the account identity has no device credential; it
//! counts as no device, and installing one discards its transport state
//! (never its history).

use std::rc::Rc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use libsignal_protocol::{GenericSignedPreKey as _, IdentityKey, IdentityKeyPair, PrivateKey};
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use kutup_chat_proto::{
    AccountManifestDeviceV2, AccountManifestV2, ChatProvisionV1, DirectChatSuiteId,
    ProvisionEnvelopeV1, ProvisioningLinkCodeV1, ProvisioningRelayRequest, PROVISIONING_VERSION,
    REREGISTRATION_DEVICE_ID,
};
use kutup_crypto::provisioning::ProvisioningKeyPair;

use crate::db::ChatDb;
use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::keys::NewDevice;
use crate::manifest::AccountAuthority;
use crate::session::Session;
use crate::transport::ChatTransport;

/// Where a store stands with its account's Chat identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Installation {
    /// A device of the account: open it.
    Registered { device_id: u32 },
    /// A registration was written down and not yet confirmed: finish it with
    /// the same request ([`Engine::resume_registration`]).
    Registering,
    /// No device here. With `account_has_identity`, another device of the
    /// account holds the identity and links this one; without, this device
    /// re-registers (the account's first Chat device).
    Unregistered { account_has_identity: bool },
}

/// What the account settings a provisioning message carries, for the
/// application to apply on the new device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionedSettings {
    pub read_receipts: bool,
    pub typing_indicators: bool,
}

/// A provisioning message the new device opened and checked: its account,
/// an identity the account's verified manifest lists, and the link token.
pub struct VerifiedProvision {
    identity: IdentityKeyPair,
    link_token: Zeroizing<String>,
    pub settings: ProvisionedSettings,
}

/// The new device's side of linking: one ephemeral key for one provisioning
/// socket.
pub struct LinkingDevice {
    key_pair: ProvisioningKeyPair,
}

impl Default for LinkingDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkingDevice {
    pub fn new() -> Self {
        Self {
            key_pair: ProvisioningKeyPair::generate(),
        }
    }

    /// The code to show, as a QR code and as text, once the socket has given
    /// its address (canonical unpadded base64url of 16 bytes).
    pub fn link_code(&self, address: &str) -> Result<String> {
        let address = kutup_chat_proto::decode_provisioning_address(address)
            .map_err(ChatError::Protocol)?;
        Ok(ProvisioningLinkCodeV1 {
            address,
            public_key: self.key_pair.public_key(),
        }
        .to_uri())
    }

    /// Open the envelope the socket delivered and check it before anything
    /// is taken from it: the account is this one, the private key is the
    /// public key's, and the account's manifest, verified under the authority
    /// this device derives from the master key, lists exactly that identity
    /// (docs/plans/account-identity-key.md, "What the new device checks").
    pub async fn verify(
        &self,
        transport: &dyn ChatTransport,
        user: &str,
        authority: &AccountAuthority,
        envelope: &ProvisionEnvelopeV1,
    ) -> Result<VerifiedProvision> {
        envelope.validate().map_err(ChatError::Protocol)?;
        let sender = STANDARD
            .decode(&envelope.public_key)
            .map_err(|_| ChatError::Protocol("provisioning key is not base64".into()))?;
        let body = STANDARD
            .decode(&envelope.body)
            .map_err(|_| ChatError::Protocol("provisioning body is not base64".into()))?;
        let plaintext = self
            .key_pair
            .open(&sender, &body)
            .map_err(|_| ChatError::Trust("the provisioning message does not open".into()))?;
        let message: ChatProvisionV1 = serde_json::from_slice(&plaintext)
            .map_err(|error| ChatError::Protocol(format!("provisioning message: {error}")))?;
        message.validate().map_err(ChatError::Protocol)?;
        if message.provisioning_version != PROVISIONING_VERSION {
            return Err(ChatError::Protocol("unsupported provisioning version".into()));
        }
        let account = crate::address::parse_account(user)?;
        if message.account != account {
            return Err(ChatError::Trust(
                "the provisioning message is for another account".into(),
            ));
        }
        let identity = identity_from_parts(&message.identity_key_public, &message.identity_key_private)?;

        let head = transport
            .fetch_manifest(user)
            .await?
            .ok_or_else(|| ChatError::Trust("the account has no manifest to link to".into()))?;
        verify_own_manifest(&head, &account, authority)?;
        if head.identity_key != message.identity_key_public {
            return Err(ChatError::Trust(
                "the account's manifest lists another identity".into(),
            ));
        }
        match head.sequence.cmp(&message.manifest_sequence) {
            std::cmp::Ordering::Less => {
                return Err(ChatError::Trust(
                    "the account's manifest is older than the provisioning message's".into(),
                ))
            }
            std::cmp::Ordering::Equal => {
                if head.manifest_hash().map_err(ChatError::Trust)? != message.manifest_hash {
                    return Err(ChatError::Trust(
                        "the provisioning message names another manifest".into(),
                    ));
                }
            }
            // A later manifest (another device linked or removed meanwhile)
            // still listing this identity is as good.
            std::cmp::Ordering::Greater => {}
        }
        Ok(VerifiedProvision {
            identity,
            link_token: Zeroizing::new(message.link_token.clone()),
            settings: ProvisionedSettings {
                read_receipts: message.read_receipts,
                typing_indicators: message.typing_indicators,
            },
        })
    }
}

/// The libsignal identity key pair from a provisioning message's or a sync's
/// halves, refused unless the private key is the public key's.
pub(crate) fn identity_from_parts(public: &str, private: &str) -> Result<IdentityKeyPair> {
    let public = STANDARD
        .decode(public)
        .map_err(|_| ChatError::Protocol("identity key is not base64".into()))?;
    let private = Zeroizing::new(
        STANDARD
            .decode(private)
            .map_err(|_| ChatError::Protocol("identity private key is not base64".into()))?,
    );
    let public = IdentityKey::decode(&public)
        .map_err(|error| ChatError::Protocol(format!("identity key: {error}")))?;
    let private = PrivateKey::deserialize(&private)
        .map_err(|error| ChatError::Protocol(format!("identity private key: {error}")))?;
    let derived = private
        .public_key()
        .map_err(|error| ChatError::Protocol(format!("identity private key: {error}")))?;
    if derived != *public.public_key() {
        return Err(ChatError::Trust(
            "the identity private key is not the public key's".into(),
        ));
    }
    Ok(IdentityKeyPair::new(public, private))
}

/// The account's own manifest, as the server serves it: valid, this
/// account's, and signed by this account's authority.
pub(crate) fn verify_own_manifest(
    manifest: &AccountManifestV2,
    account: &kutup_chat_proto::AccountRef,
    authority: &AccountAuthority,
) -> Result<()> {
    manifest.verify().map_err(ChatError::Trust)?;
    if manifest.account != *account {
        return Err(ChatError::Trust(
            "the account manifest belongs to another account".into(),
        ));
    }
    if manifest.authority_key_id != authority.key_id()
        || manifest.self_authority_key != authority.public_key_base64()
    {
        return Err(ChatError::Trust(
            "the account manifest belongs to a different authority".into(),
        ));
    }
    Ok(())
}

impl Engine {
    /// Where `db` stands: a registered device, a registration to finish, or
    /// none (link or re-register, by whether the account has an identity).
    pub async fn installation(
        db: &dyn ChatDb,
        transport: &dyn ChatTransport,
        user: &str,
    ) -> Result<Installation> {
        match db.load_local_identity().await? {
            // A store from before the account identity is no device.
            Some(local) if local.credential.is_some() => {
                return Ok(match local.device_id {
                    Some(device_id) => Installation::Registered { device_id },
                    None => Installation::Registering,
                })
            }
            _ => {}
        }
        let account_has_identity = transport.fetch_manifest(user).await?.is_some();
        Ok(Installation::Unregistered {
            account_has_identity,
        })
    }

    /// Re-register: a new account identity, and the account's next manifest
    /// listing this device alone as device 1, sent in the registration call.
    /// The server drops every other device of the account in the same
    /// transaction (Signal's `reclaimAccount`); peers see the safety number
    /// change once. Also how an account's first Chat device registers.
    pub async fn reregister<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
        authority: &AccountAuthority,
        issued_at: impl Into<String>,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let user = user.into();
        crate::timeline::ensure_built(db.as_ref()).await?;
        let account = crate::address::parse_account(&user)?;
        let head = transport.fetch_manifest(&user).await?;
        if let Some(head) = &head {
            verify_own_manifest(head, &account, authority)?;
        }
        let (sequence, previous_hash) = match &head {
            None => (1, None),
            Some(head) => (
                head.sequence
                    .checked_add(1)
                    .ok_or_else(|| ChatError::Trust("manifest sequence is exhausted".into()))?,
                Some(head.manifest_hash().map_err(ChatError::Trust)?),
            ),
        };
        let issued_at = issued_at.into();
        let sign = |identity_key: &str, registration_id: u32| -> Result<AccountManifestV2> {
            let manifest = authority.sign_manifest(
                account.clone(),
                sequence,
                previous_hash.clone(),
                identity_key.to_string(),
                vec![AccountManifestDeviceV2 {
                    device_id: REREGISTRATION_DEVICE_ID,
                    direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                    registration_id,
                    mls: None,
                }],
                issued_at.clone(),
            )?;
            manifest
                .verify_successor(head.as_ref())
                .map_err(ChatError::Trust)?;
            Ok(manifest)
        };
        let session = Session::generate(
            db,
            user,
            REREGISTRATION_DEVICE_ID,
            num_one_time,
            NewDevice::Reregistration { manifest: &sign },
            rng,
        )
        .await?;
        Self::finish_registration(session, transport).await
    }

    /// Register a linked device with the identity and link token its
    /// provisioning message carried. The device then publishes the manifest
    /// that lists it ([`Engine::sync_own_manifest`]).
    pub async fn register_linked<R: Rng + CryptoRng>(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
        provision: VerifiedProvision,
        num_one_time: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let user = user.into();
        crate::timeline::ensure_built(db.as_ref()).await?;
        // The provisional id is never used for a crypto operation before the
        // server's answer binds the real one.
        let session = Session::generate(
            db,
            user,
            1,
            num_one_time,
            NewDevice::Linked {
                identity: provision.identity,
                link_token: provision.link_token.to_string(),
            },
            rng,
        )
        .await?;
        Self::finish_registration(session, transport).await
    }

    /// Finish a registration written down and not confirmed (the app closed,
    /// or the answer was lost), with the same request: the server answers the
    /// row the same credential made.
    pub async fn resume_registration(
        db: Rc<dyn ChatDb>,
        transport: Rc<dyn ChatTransport>,
        user: impl Into<String>,
    ) -> Result<Self> {
        let user = user.into();
        crate::timeline::ensure_built(db.as_ref()).await?;
        let local = db
            .load_local_identity()
            .await?
            .ok_or_else(|| ChatError::Invalid("no chat registration to resume".into()))?;
        let session = Session::resume_registration(db, user, local).await?;
        Self::finish_registration(session, transport).await
    }

    async fn finish_registration(
        mut session: Session,
        transport: Rc<dyn ChatTransport>,
    ) -> Result<Self> {
        let request = session
            .registration()
            .ok_or_else(|| ChatError::Invalid("the session carries no registration".into()))?
            .clone();
        let device_id = transport.register_device(&request).await?;
        if let kutup_chat_proto::DeviceRegistrationV1::Reregistration { .. } = &request.registration
        {
            if device_id != REREGISTRATION_DEVICE_ID {
                return Err(ChatError::Protocol(
                    "a re-registration is answered with device 1".into(),
                ));
            }
        }
        session.complete_registration(device_id).await?;
        let mut engine = Engine::new(session, transport);
        engine.authenticate_device()?;
        // The re-registration's manifest is the account's head now: pin it as
        // this account's own.
        if let kutup_chat_proto::DeviceRegistrationV1::Reregistration { manifest } =
            &request.registration
        {
            let account = engine.session.user().to_string();
            engine
                .accept_current_manifest_evidence(&account, manifest)
                .await?;
        }
        Ok(engine)
    }

    /// Hand the transport this device's credential.
    pub(crate) fn authenticate_device(&self) -> Result<()> {
        let credential = self.session.credential().ok_or_else(|| {
            ChatError::Invalid("this device has no credential: it must register again".into())
        })?;
        self.transport
            .set_device_auth(self.session.device_id(), credential);
        Ok(())
    }

    /// Link a new device of this account from this one (Settings → Linked
    /// devices): parse the code it shows, get a one-time link token, and send
    /// it the account identity, sealed to its ephemeral key, through its
    /// provisioning socket. `Ok(false)`: the code's socket is gone (expired
    /// or closed); the new device shows a new code. The new device registers
    /// and publishes the manifest that lists it.
    pub async fn link_device(
        &mut self,
        code: &str,
        settings: ProvisionedSettings,
        authority: &AccountAuthority,
    ) -> Result<bool> {
        let code = ProvisioningLinkCodeV1::parse(code).map_err(ChatError::Invalid)?;
        let account = self.self_account()?;
        let transport = Rc::clone(&self.transport);
        let head = transport
            .fetch_manifest(self.session.user())
            .await?
            .ok_or_else(|| ChatError::Trust("the account has no manifest".into()))?;
        verify_own_manifest(&head, &account, authority)?;
        let identity_key = self.session.account_identity_key();
        if head.identity_key != identity_key {
            return Err(ChatError::Trust(
                "the account's identity is not this device's".into(),
            ));
        }
        let profile = self
            .session
            .db()
            .load_local_profile()
            .await?
            .ok_or_else(|| ChatError::Invalid("this device has no profile key yet".into()))?;
        let token = transport.create_link_token().await?;
        let identity = self.session.local_identity_key_pair();
        let message = ChatProvisionV1 {
            provisioning_version: PROVISIONING_VERSION,
            account,
            identity_key_public: identity_key,
            identity_key_private: STANDARD.encode(identity.private_key().serialize()),
            link_token: token.token.clone(),
            manifest_sequence: head.sequence,
            manifest_hash: head.manifest_hash().map_err(ChatError::Trust)?,
            profile_key: STANDARD.encode(&profile.key),
            profile_suite: kutup_chat_proto::ProfileSuiteId::XChaCha20Poly1305V1,
            read_receipts: settings.read_receipts,
            typing_indicators: settings.typing_indicators,
        };
        message.validate().map_err(ChatError::Invalid)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&message)
                .map_err(|error| ChatError::Content(format!("provisioning message: {error}")))?,
        );
        let sealed = kutup_crypto::provisioning::seal(&code.public_key, &plaintext)
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        let request = ProvisioningRelayRequest {
            envelope: ProvisionEnvelopeV1 {
                public_key: STANDARD.encode(sealed.sender_public),
                body: STANDARD.encode(&sealed.body),
            },
        };
        transport
            .relay_provisioning(&URL_SAFE_NO_PAD.encode(code.address), &request)
            .await
    }
}

impl Engine {
    /// Reset the account's identity and keep its devices (Signal's PNI
    /// identity-key distribution, for the account identity): a new identity,
    /// a new registration id and signed and last-resort keys for every device
    /// kept, one `accountIdentity` sync sealed to each other kept device, and
    /// the account's next manifest listing exactly them, in one request. The
    /// devices in `remove` (a lost or stolen one) are left out and dropped by
    /// the server in the same transaction. Peers see the safety number change
    /// once. Returns the devices kept. Needs the account's keys
    /// (`enable_group_list`).
    pub async fn reset_identity<R: Rng + CryptoRng>(
        &mut self,
        remove: &[u32],
        issued_at: impl Into<String>,
        rng: &mut R,
    ) -> Result<Vec<u32>> {
        if remove.contains(&self.session.device_id()) {
            return Err(ChatError::Invalid(
                "a device cannot reset the identity and remove itself".into(),
            ));
        }
        let issued_at = issued_at.into();
        let user = self.session.user().to_string();
        let account = self.self_account()?;
        let transport = Rc::clone(&self.transport);
        for _ in 0..crate::engine::MAX_SEND_ATTEMPTS {
            let head = transport
                .fetch_manifest(&user)
                .await?
                .ok_or_else(|| ChatError::Trust("the account has no manifest".into()))?;
            verify_own_manifest(&head, &account, &self.group_keys()?.authority)?;
            if head.identity_key != self.session.account_identity_key() {
                return Err(ChatError::Trust(
                    "the account's identity is not this device's".into(),
                ));
            }
            if head.device(self.session.device_id()).is_none() {
                return Err(ChatError::Trust(
                    "this device is not in the account's manifest".into(),
                ));
            }
            let kept: Vec<&AccountManifestDeviceV2> = head
                .devices
                .iter()
                .filter(|device| !remove.contains(&device.device_id))
                .collect();

            let identity = IdentityKeyPair::generate(rng);
            let identity_key = STANDARD.encode(identity.identity_key().serialize());
            let mut devices = Vec::with_capacity(kept.len());
            let mut listed = Vec::with_capacity(kept.len());
            let mut private = Vec::with_capacity(kept.len());
            for device in &kept {
                let registration_id = crate::keys::random_registration_id(rng);
                let rotation = crate::keys::generate_rotation(&identity, 1, 1, rng)?;
                devices.push(kutup_chat_proto::DistributedDeviceKeysV1 {
                    device_id: device.device_id,
                    registration_id,
                    signed_pre_key: rotation.signed_pre_key.clone(),
                    last_resort_kyber_pre_key: rotation.last_resort_kyber_pre_key.clone(),
                });
                listed.push(AccountManifestDeviceV2 {
                    device_id: device.device_id,
                    direct_chat_suite: device.direct_chat_suite,
                    registration_id,
                    mls: device.mls.clone(),
                });
                private.push((device.device_id, registration_id, rotation));
            }
            let manifest = self.group_keys()?.authority.sign_manifest(
                account.clone(),
                head.sequence
                    .checked_add(1)
                    .ok_or_else(|| ChatError::Trust("manifest sequence is exhausted".into()))?,
                Some(head.manifest_hash().map_err(ChatError::Trust)?),
                identity_key.clone(),
                listed,
                issued_at.clone(),
            )?;
            manifest
                .verify_successor(Some(&head))
                .map_err(ChatError::Trust)?;
            let manifest_hash = manifest.manifest_hash().map_err(ChatError::Trust)?;

            // One sync to each other kept device, under this identity's
            // session with it.
            let others: Vec<u32> = kept
                .iter()
                .map(|device| device.device_id)
                .filter(|id| *id != self.session.device_id())
                .collect();
            let bundles = if others.is_empty() {
                Vec::new()
            } else {
                self.fetch_verified_bundles(&user).await?
            };
            let mut messages = Vec::with_capacity(others.len());
            for (device_id, registration_id, rotation) in &private {
                if *device_id == self.session.device_id() {
                    continue;
                }
                let bundle = bundles
                    .iter()
                    .find(|bundle| bundle.device_id == *device_id)
                    .ok_or(ChatError::MissingBundle(*device_id))?;
                let body = kutup_chat_proto::AccountIdentityBody {
                    identity_key_public: identity_key.clone(),
                    identity_key_private: STANDARD.encode(identity.private_key().serialize()),
                    registration_id: *registration_id,
                    signed_pre_key: STANDARD.encode(&rotation.signed_record),
                    last_resort_kyber_pre_key: STANDARD.encode(&rotation.last_resort_record),
                    manifest_sequence: manifest.sequence,
                    manifest_hash: manifest_hash.clone(),
                };
                let content = kutup_chat_proto::ChatContent::account_identity_with_id(
                    uuid::Uuid::new_v4().to_string(),
                    crate::clock::rfc3339(crate::clock::unix_millis()),
                    0,
                    &body,
                );
                let plaintext = serde_json::to_vec(&content)
                    .map_err(|error| ChatError::Content(error.to_string()))?;
                messages.push((bundle, plaintext));
            }
            let mut device_messages = self
                .session
                .seal_to_own_devices(&messages, rng)
                .await?;
            device_messages.sort_by_key(|envelope| envelope.device_id);
            devices.sort_by_key(|keys| keys.device_id);
            let request = kutup_chat_proto::AccountIdentityDistributionRequest {
                identity_key: identity_key.clone(),
                devices,
                device_messages,
                manifest: manifest.clone(),
            };
            request
                .validate(self.session.device_id())
                .map_err(|error| ChatError::Invalid(format!("{error:?}")))?;
            match transport.distribute_identity(&request).await? {
                crate::transport::DistributionOutcome::Mismatch(_) => {
                    // The devices moved meanwhile: build it again from the
                    // account's manifest and devices as they are now.
                    self.known_devices.remove(&user);
                    continue;
                }
                crate::transport::DistributionOutcome::Accepted => {}
            }
            let (_, registration_id, rotation) = private
                .into_iter()
                .find(|(device_id, ..)| *device_id == self.session.device_id())
                .expect("the sending device keeps itself");
            self.session
                .install_identity(
                    &identity,
                    registration_id,
                    (1, rotation.signed_record),
                    (1, rotation.last_resort_record),
                )
                .await?;
            self.reopen_after_identity_change(&manifest).await?;
            return Ok(kept.iter().map(|device| device.device_id).collect());
        }
        Err(ChatError::SendNotConverged(crate::engine::MAX_SEND_ATTEMPTS))
    }

    /// Apply an `accountIdentity` sync another device of this account sent
    /// (kept by the receive pass): check it as a provisioning message — the
    /// account's manifest, verified under its authority, lists exactly this
    /// identity and this device with this registration id — then install the
    /// identity, its keys and the registration id. A sync the account has
    /// moved past (a later distribution) is dropped: this device is then no
    /// longer the account's and is linked again.
    pub(crate) async fn apply_account_identity(&mut self) -> Result<()> {
        let Some(encoded) = self.session.db().load_pending_account_identity().await? else {
            return Ok(());
        };
        let encoded = Zeroizing::new(encoded);
        let body: kutup_chat_proto::AccountIdentityBody = serde_json::from_slice(&encoded)
            .map_err(|error| ChatError::Db(format!("kept identity sync: {error}")))?;
        body.validate().map_err(ChatError::Protocol)?;
        let account = self.self_account()?;
        let user = self.session.user().to_string();
        let head = Rc::clone(&self.transport)
            .fetch_manifest(&user)
            .await?
            .ok_or_else(|| ChatError::Trust("the account has no manifest".into()))?;
        verify_own_manifest(&head, &account, &self.group_keys()?.authority)?;
        let current = head.identity_key == body.identity_key_public
            && head
                .device(self.session.device_id())
                .is_some_and(|device| device.registration_id == body.registration_id)
            && match head.sequence.cmp(&body.manifest_sequence) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => {
                    head.manifest_hash().map_err(ChatError::Trust)? == body.manifest_hash
                }
                std::cmp::Ordering::Greater => true,
            };
        if !current {
            self.session.drop_pending_account_identity().await?;
            return Err(ChatError::Trust(
                "the account's identity moved past this device's distribution".into(),
            ));
        }
        let identity = identity_from_parts(&body.identity_key_public, &body.identity_key_private)?;
        let signed = decode_record(&body.signed_pre_key)?;
        let signed_record = libsignal_protocol::SignedPreKeyRecord::deserialize(&signed)
            .map_err(|error| ChatError::Protocol(format!("signed prekey: {error}")))?;
        let last_resort = decode_record(&body.last_resort_kyber_pre_key)?;
        let last_resort_record = libsignal_protocol::KyberPreKeyRecord::deserialize(&last_resort)
            .map_err(|error| ChatError::Protocol(format!("last-resort Kyber key: {error}")))?;
        // Both keys are the new identity's, as the server checked too.
        let signed_ok = identity
            .public_key()
            .verify_signature(
                &signed_record.public_key().map_err(protocol)?.serialize(),
                &signed_record.signature().map_err(protocol)?,
            );
        let last_resort_ok = identity.public_key().verify_signature(
            &last_resort_record.public_key().map_err(protocol)?.serialize(),
            &last_resort_record.signature().map_err(protocol)?,
        );
        if !signed_ok || !last_resort_ok {
            return Err(ChatError::Trust(
                "the distributed keys are not signed by the identity".into(),
            ));
        }
        let signed_id = u32::from(signed_record.id().map_err(protocol)?);
        let last_resort_id = u32::from(last_resort_record.id().map_err(protocol)?);
        self.session
            .install_identity(
                &identity,
                body.registration_id,
                (signed_id, signed),
                (last_resort_id, last_resort),
            )
            .await?;
        self.reopen_after_identity_change(&head).await
    }

    /// After this device's identity changed: open the session again on the
    /// new identity and pin the account's manifest that lists it. The server
    /// cleared the one-time keys; the next prekey maintenance refills them.
    async fn reopen_after_identity_change(&mut self, manifest: &AccountManifestV2) -> Result<()> {
        let db = Rc::clone(self.session.db());
        let user = self.session.user().to_string();
        let device_id = self.session.device_id();
        self.session = Session::open(db, user.clone(), device_id).await?;
        self.authenticate_device()?;
        self.known_devices.clear();
        self.known_devices_at.clear();
        self.accept_current_manifest_evidence(&user, manifest)
            .await?;
        Ok(())
    }
}

fn decode_record(value: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| ChatError::Protocol("a distributed key record is not base64".into()))
}

fn protocol(error: libsignal_protocol::SignalProtocolError) -> ChatError {
    ChatError::Protocol(error.to_string())
}
