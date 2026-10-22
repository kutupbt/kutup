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
        let address =
            kutup_chat_proto::decode_provisioning_address(address).map_err(ChatError::Protocol)?;
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
            return Err(ChatError::Protocol(
                "unsupported provisioning version".into(),
            ));
        }
        let account = crate::address::parse_account(user)?;
        if message.account != account {
            return Err(ChatError::Trust(
                "the provisioning message is for another account".into(),
            ));
        }
        let identity =
            identity_from_parts(&message.identity_key_public, &message.identity_key_private)?;

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
    crate::manifest::verify_identity_binding(manifest)?;
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

/// Manifests [`Engine::catch_up_identity`] follows before it gives up for
/// now (each a distribution made while it caught up).
const IDENTITY_CATCH_UP_ROUNDS: usize = 4;

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
        let sign =
            |identity: &IdentityKeyPair, registration_id: u32| -> Result<AccountManifestV2> {
                let manifest = authority.sign_manifest(
                    account.clone(),
                    sequence,
                    previous_hash.clone(),
                    identity,
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
        let session = Session::generate_device(
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
        let session = Session::generate_device(
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
        // A new device's sender keys are new: the groups' books start over.
        engine.forget_sender_books().await?;
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
                &identity,
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
            let mut device_messages = self.session.seal_to_own_devices(&messages, rng).await?;
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
        Err(ChatError::SendNotConverged(
            crate::engine::MAX_SEND_ATTEMPTS,
        ))
    }

    /// Apply an `accountIdentity` sync another device of this account sent
    /// (kept by the receive pass): check it as a provisioning message — the
    /// account's manifest, verified under its authority, lists exactly this
    /// identity and this device with this registration id — then install the
    /// identity, its keys and the registration id. A sync the account has
    /// moved past (a later distribution) is dropped, and `false` says so:
    /// [`Engine::catch_up_identity`] then finds whether a later one is on its
    /// way or this device missed it.
    pub(crate) async fn apply_account_identity(&mut self) -> Result<bool> {
        let Some(encoded) = self.session.db().load_pending_account_identity().await? else {
            return Ok(true);
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
            return Ok(false);
        }
        let identity = identity_from_parts(&body.identity_key_public, &body.identity_key_private)?;
        let signed = decode_record(&body.signed_pre_key)?;
        let signed_record = libsignal_protocol::SignedPreKeyRecord::deserialize(&signed)
            .map_err(|error| ChatError::Protocol(format!("signed prekey: {error}")))?;
        let last_resort = decode_record(&body.last_resort_kyber_pre_key)?;
        let last_resort_record =
            libsignal_protocol::KyberPreKeyRecord::deserialize(&last_resort)
                .map_err(|error| ChatError::Protocol(format!("last-resort Kyber key: {error}")))?;
        // Both keys are the new identity's, as the server checked too.
        let signed_ok = identity.public_key().verify_signature(
            &signed_record.public_key().map_err(protocol)?.serialize(),
            &signed_record.signature().map_err(protocol)?,
        );
        let last_resort_ok = identity.public_key().verify_signature(
            &last_resort_record
                .public_key()
                .map_err(protocol)?
                .serialize(),
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
        self.reopen_after_identity_change(&head).await?;
        Ok(true)
    }

    /// Bring this device to the account's identity, or find that it missed
    /// it. A device that was offline through a distribution finds its
    /// `accountIdentity` sync in its mailbox: the account's manifest is read
    /// first and the mailbox drained after, so a sync for that manifest is
    /// in the drain. If the same manifest still names another identity
    /// afterwards, this device wasn't kept (or lost the sync): it forgets
    /// its registration, keeping its history, and is linked again
    /// ([`ChatError::LinkRequired`]).
    pub async fn catch_up_identity<R: Rng + CryptoRng>(&mut self, rng: &mut R) -> Result<()> {
        let account = self.self_account()?;
        let user = self.session.user().to_string();
        let mut drained_after: Option<String> = None;
        for _ in 0..IDENTITY_CATCH_UP_ROUNDS {
            self.apply_account_identity().await?;
            let head = Rc::clone(&self.transport)
                .fetch_manifest(&user)
                .await?
                .ok_or_else(|| ChatError::Trust("the account has no manifest".into()))?;
            verify_own_manifest(&head, &account, &self.group_keys()?.authority)?;
            if head.identity_key == self.session.account_identity_key() {
                return Ok(());
            }
            let hash = head.manifest_hash().map_err(ChatError::Trust)?;
            if drained_after.as_deref() == Some(hash.as_str()) {
                self.session.forget_registration().await?;
                return Err(ChatError::LinkRequired);
            }
            self.receive_pass(rng).await?;
            drained_after = Some(hash);
        }
        Err(ChatError::Trust(
            "the account's identity kept changing while this device caught up".into(),
        ))
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
        self.forget_sender_books().await?;
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

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use futures_executor::block_on;

    use super::*;
    use crate::group_harness_tests::{rng, World, ISSUED_AT};
    use crate::SqliteChatDb;

    fn authority(person: &crate::group_harness_tests::Person) -> AccountAuthority {
        AccountAuthority::derive(&[person.authority_seed; 32]).unwrap()
    }

    fn head(world: &Rc<World>, account: &str) -> AccountManifestV2 {
        block_on(world.client(account).fetch_manifest(account))
            .unwrap()
            .unwrap()
    }

    fn settings() -> ProvisionedSettings {
        ProvisionedSettings {
            read_receipts: false,
            typing_indicators: true,
        }
    }

    /// An account's first device re-registers: device 1 alone, the chain's
    /// first manifest; a later re-registration continues the chain and
    /// drops every other device.
    #[test]
    fn re_registration_lists_device_one_alone_and_continues_the_chain() {
        let world = World::new();
        let mut alice = world.person(1);
        let first = head(&world, &alice.account);
        assert_eq!(first.devices.len(), 1);
        assert_eq!(first.devices[0].device_id, REREGISTRATION_DEVICE_ID);
        assert_eq!(
            first.identity_key,
            alice.engine.session().account_identity_key()
        );
        let _alice2 = world.link_device(&mut alice);
        let linked = head(&world, &alice.account);
        assert_eq!(linked.devices.len(), 2);

        // Every device lost: a new browser re-registers.
        let client = world.client(&alice.account);
        let fresh = block_on(Engine::reregister(
            Rc::new(SqliteChatDb::open_in_memory().unwrap()),
            client,
            alice.account.clone(),
            &authority(&alice),
            ISSUED_AT,
            8,
            &mut rng(),
        ))
        .unwrap();
        let reregistered = head(&world, &alice.account);
        reregistered.verify_successor(Some(&linked)).unwrap();
        assert_eq!(reregistered.devices.len(), 1);
        assert_eq!(reregistered.devices[0].device_id, REREGISTRATION_DEVICE_ID);
        assert_ne!(reregistered.identity_key, linked.identity_key);
        assert_eq!(
            fresh.session().account_identity_key(),
            reregistered.identity_key
        );
    }

    /// Linking end to end: the code, the envelope, the checks, and a new
    /// device with the account's identity.
    #[test]
    fn a_linked_device_shares_the_account_identity() {
        let world = World::new();
        let mut alice = world.person(1);
        let alice2 = world.link_device(&mut alice);
        assert_eq!(
            alice2.engine.session().account_identity_key(),
            alice.engine.session().account_identity_key()
        );
        assert_ne!(alice2.device(), alice.device());
        let manifest = head(&world, &alice.account);
        assert!(manifest.device(alice2.device()).is_some());
        assert_eq!(
            manifest.identity_key,
            alice.engine.session().account_identity_key()
        );
        // The new device holds a credential of its own.
        let local = block_on(alice2.engine.session().db().load_local_identity())
            .unwrap()
            .unwrap();
        assert!(local.credential.is_some());
    }

    #[test]
    fn a_provisioning_message_is_refused_unless_it_checks_out() {
        let world = World::new();
        let mut alice = world.person(1);
        let bob = world.person(2);
        let linking = LinkingDevice::new();
        let envelope = world.provisioning_envelope(&mut alice, &linking, settings());

        // Another account's new device: refused.
        let bob_client = world.client(&bob.account);
        assert!(matches!(
            block_on(linking.verify(
                bob_client.as_ref(),
                &bob.account,
                &authority(&bob),
                &envelope
            )),
            Err(ChatError::Trust(_))
        ));
        // Tampered with on the way: refused before anything is read.
        let mut tampered = envelope.clone();
        let mut body = STANDARD.decode(&tampered.body).unwrap();
        let last = body.len() - 1;
        body[last] ^= 1;
        tampered.body = STANDARD.encode(&body);
        let client = world.client(&alice.account);
        assert!(block_on(linking.verify(
            client.as_ref(),
            &alice.account,
            &authority(&alice),
            &tampered
        ))
        .is_err());
        // Another ephemeral key than the code's: it doesn't open.
        assert!(block_on(LinkingDevice::new().verify(
            client.as_ref(),
            &alice.account,
            &authority(&alice),
            &envelope
        ))
        .is_err());
        // The account's identity moved on (a reset) after it was sent: the
        // manifest lists another identity now.
        block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        assert!(matches!(
            block_on(linking.verify(
                client.as_ref(),
                &alice.account,
                &authority(&alice),
                &envelope
            )),
            Err(ChatError::Trust(_))
        ));
    }

    #[test]
    fn a_fresh_envelope_verifies() {
        let world = World::new();
        let mut alice = world.person(1);
        let linking = LinkingDevice::new();
        let envelope = world.provisioning_envelope(&mut alice, &linking, settings());
        let client = world.client(&alice.account);
        let provision = block_on(linking.verify(
            client.as_ref(),
            &alice.account,
            &authority(&alice),
            &envelope,
        ))
        .unwrap();
        assert_eq!(provision.settings, settings());
    }

    /// "Reset identity, keep my devices": the sender installs the new
    /// identity at once, keeping its device id and credential, its one-time
    /// keys gone; the other device takes it from its sync.
    #[test]
    fn a_distribution_moves_every_kept_device_to_the_new_identity() {
        let world = World::new();
        let mut alice = world.person(1);
        let mut alice2 = world.link_device(&mut alice);
        let before = block_on(alice.engine.session().db().load_local_identity())
            .unwrap()
            .unwrap();
        let old_identity = alice.engine.session().account_identity_key();
        assert!(block_on(alice.engine.session().db().load_pre_key(100))
            .unwrap()
            .is_some());

        let kept = block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        assert_eq!(kept, vec![alice.device(), alice2.device()]);
        let manifest = head(&world, &alice.account);
        let new_identity = alice.engine.session().account_identity_key();
        assert_ne!(new_identity, old_identity);
        assert_eq!(manifest.identity_key, new_identity);
        let after = block_on(alice.engine.session().db().load_local_identity())
            .unwrap()
            .unwrap();
        assert_eq!(after.device_id, before.device_id);
        assert_eq!(after.credential, before.credential);
        assert_eq!(
            Some(after.registration_id),
            manifest
                .device(alice.device())
                .map(|device| device.registration_id)
        );
        assert!(block_on(alice.engine.session().db().load_pre_key(100))
            .unwrap()
            .is_none());

        // The other device applies its sync when it next reads its mail.
        alice2.receive();
        assert_eq!(alice2.engine.session().account_identity_key(), new_identity);
        let local2 = block_on(alice2.engine.session().db().load_local_identity())
            .unwrap()
            .unwrap();
        assert_eq!(
            Some(local2.registration_id),
            manifest
                .device(alice2.device())
                .map(|device| device.registration_id)
        );
        assert!(
            block_on(alice2.engine.session().db().load_pending_account_identity())
                .unwrap()
                .is_none()
        );
    }

    /// A kept device that was closed through the distribution opens on the
    /// old identity: catching up drains its mailbox and takes the sync
    /// waiting there.
    #[test]
    fn a_kept_device_closed_through_a_distribution_catches_up() {
        let world = World::new();
        let mut alice = world.person(1);
        let mut alice2 = world.link_device(&mut alice);
        block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        let new_identity = alice.engine.session().account_identity_key();
        assert_ne!(alice2.engine.session().account_identity_key(), new_identity);
        block_on(alice2.engine.catch_up_identity(&mut rng())).unwrap();
        assert_eq!(alice2.engine.session().account_identity_key(), new_identity);
        assert!(block_on(alice2.engine.session().db().load_local_identity())
            .unwrap()
            .unwrap()
            .credential
            .is_some());
    }

    /// A device that missed the distribution (its sync never came) isn't
    /// left on an identity nobody uses: it forgets its registration, keeps
    /// its history, and opens as a device to link.
    #[test]
    fn a_device_that_missed_a_distribution_is_linked_again() {
        use crate::group_harness_tests::befriend;
        let world = World::new();
        let mut alice = world.person(1);
        let mut alice2 = world.link_device(&mut alice);
        let mut bob = world.person(2);
        befriend(&mut alice2, &mut bob);
        let history = block_on(alice2.engine.session().sent_history())
            .unwrap()
            .len();
        assert!(history > 0);
        block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        world.retain_mailbox(&alice2.account, alice2.device(), |_| false);

        assert!(matches!(
            block_on(alice2.engine.catch_up_identity(&mut rng())),
            Err(ChatError::LinkRequired)
        ));
        let local = block_on(alice2.engine.session().db().load_local_identity())
            .unwrap()
            .unwrap();
        assert_eq!(local.credential, None);
        assert_eq!(local.device_id, None);
        assert_eq!(
            block_on(Engine::installation(
                alice2.engine.session().db().as_ref(),
                alice2.client.as_ref(),
                &alice2.account,
            ))
            .unwrap(),
            Installation::Unregistered {
                account_has_identity: true
            }
        );
        assert_eq!(
            block_on(alice2.engine.session().sent_history())
                .unwrap()
                .len(),
            history,
            "its history stays"
        );
    }

    /// A contact reads a message sent under the account's new identity
    /// (sealed, before they saw the manifest that lists it): they fetch the
    /// account's signed manifest, take the new identity, see one "safety
    /// number changed" line, and are no longer verified for it.
    #[test]
    fn a_contact_reads_the_new_identity_and_sees_it_changed_once() {
        use crate::group_harness_tests::befriend;
        let world = World::new();
        let mut alice = world.person(1);
        let mut bob = world.person(2);
        befriend(&mut alice, &mut bob);
        let identity = block_on(bob.engine.safety_number(&alice.account))
            .unwrap()
            .identity_key;
        block_on(
            bob.engine
                .set_identity_verified(&alice.account, &identity, true),
        )
        .unwrap();

        block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        let send_id = uuid::Uuid::new_v4().to_string();
        let seq = block_on(alice.engine.session().next_sent_seq()).unwrap();
        let content =
            kutup_chat_proto::ChatContent::text_with_id(&send_id, ISSUED_AT, seq, "new identity");
        block_on(
            alice
                .engine
                .send(&send_id, &bob.account, &content, &mut rng()),
        )
        .unwrap();
        let report = bob.receive();
        assert!(
            report
                .messages
                .iter()
                .any(|message| message.content.message_id == send_id),
            "{report:?}"
        );
        let changed: Vec<_> = bob.engine.take_events().into_iter().filter(|event| {
            matches!(event, crate::ChatEvent::SafetyNumberChanged { peer } if *peer == alice.account)
        }).collect();
        assert_eq!(changed.len(), 1);
        let lines = block_on(bob.engine.session().sent_history())
            .unwrap()
            .into_iter()
            .filter(|message| {
                serde_json::from_slice::<kutup_chat_proto::ChatContent>(&message.content)
                    .is_ok_and(|content| content.is_safety_number_changed())
            })
            .count();
        assert_eq!(lines, 1);
        let safety = block_on(bob.engine.safety_number(&alice.account)).unwrap();
        assert_ne!(safety.identity_key, identity);
        assert_eq!(safety.trust, crate::AuthorityTrust::Tofu);

        // And Bob's answer reaches Alice under her new identity.
        let answer = uuid::Uuid::new_v4().to_string();
        let seq = block_on(bob.engine.session().next_sent_seq()).unwrap();
        let content = kutup_chat_proto::ChatContent::text_with_id(&answer, ISSUED_AT, seq, "ok");
        block_on(
            bob.engine
                .send(&answer, &alice.account, &content, &mut rng()),
        )
        .unwrap();
        let report = alice.receive();
        assert!(report
            .messages
            .iter()
            .any(|message| message.content.message_id == answer));
    }

    /// As spec 169: Alice has a linked device, both write to Bob, then her
    /// first device removes the second (lost) and resets the identity; Bob's
    /// reply reaches her.
    #[test]
    fn after_removing_a_lost_device_with_a_reset_both_sides_read_each_other() {
        use crate::group_harness_tests::befriend;
        let world = World::new();
        let mut alice = world.person(1);
        let mut bob = world.person(2);
        befriend(&mut alice, &mut bob);
        let mut alice2 = world.link_device(&mut alice);
        alice2.receive();
        let text = |from: &mut crate::group_harness_tests::Person, to: &str, body: &str| {
            let send_id = uuid::Uuid::new_v4().to_string();
            let seq = block_on(from.engine.session().next_sent_seq()).unwrap();
            let content =
                kutup_chat_proto::ChatContent::text_with_id(&send_id, ISSUED_AT, seq, body);
            block_on(from.engine.send(&send_id, to, &content, &mut rng())).unwrap();
            send_id
        };
        let bob_account = bob.account.clone();
        let alice_account = alice.account.clone();
        text(&mut alice, &bob_account, "from first");
        text(&mut alice2, &bob_account, "from second");
        bob.receive();
        let answer = text(&mut bob, &alice_account, "answer");
        let got = alice.receive();
        assert!(got.messages.iter().any(|m| m.content.message_id == answer));
        alice2.receive();

        let removed = alice2.device();
        block_on(
            alice
                .engine
                .reset_identity(&[removed], ISSUED_AT, &mut rng()),
        )
        .unwrap();
        let after = text(&mut alice, &bob_account, "after reset");
        let got = bob.receive();
        assert!(
            got.messages.iter().any(|m| m.content.message_id == after),
            "{got:?}"
        );
        let reply = text(&mut bob, &alice_account, "reply after reset");
        let got = alice.receive();
        assert!(
            got.messages.iter().any(|m| m.content.message_id == reply),
            "{got:?}"
        );
    }

    /// A sync the account moved past (a second reset before the device read
    /// the first) is dropped; with nothing newer in its mailbox the device is
    /// no longer the account's and is linked again.
    #[test]
    fn a_distribution_the_account_moved_past_is_dropped() {
        let world = World::new();
        let mut alice = world.person(1);
        let mut alice2 = world.link_device(&mut alice);
        block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        block_on(alice.engine.reset_identity(&[], ISSUED_AT, &mut rng())).unwrap();
        let result = block_on(alice2.engine.receive(&mut rng()));
        assert!(matches!(result, Err(ChatError::LinkRequired)), "{result:?}");
        assert_eq!(
            block_on(alice2.engine.session().db().load_local_identity())
                .unwrap()
                .unwrap()
                .credential,
            None
        );
        assert!(
            block_on(alice2.engine.session().db().load_pending_account_identity())
                .unwrap()
                .is_none()
        );
        assert_ne!(
            alice2.engine.session().account_identity_key(),
            head(&world, &alice.account).identity_key
        );
    }

    /// A store from before the account identity (a local identity with no
    /// credential) is no device: it links or re-registers.
    #[test]
    fn a_store_from_before_the_account_identity_is_no_device() {
        let world = World::new();
        let alice = world.person(1);
        let db = SqliteChatDb::open_in_memory().unwrap();
        block_on(
            db.apply(&crate::Pending {
                local_identity: Some(crate::LocalIdentity {
                    identity_key_pair: alice
                        .engine
                        .session()
                        .local_identity_key_pair()
                        .serialize()
                        .to_vec(),
                    registration_id: 5,
                    device_id: Some(4),
                    credential: None,
                }),
                ..crate::Pending::default()
            }),
        )
        .unwrap();
        let client = world.client(&alice.account);
        assert_eq!(
            block_on(Engine::installation(&db, client.as_ref(), &alice.account)).unwrap(),
            Installation::Unregistered {
                account_has_identity: true
            }
        );
        let stranger = format!(
            "aci:00000000-0000-4000-8000-0000000000ee@{}",
            crate::group_harness_tests::SERVER
        );
        let client = world.client(&stranger);
        assert_eq!(
            block_on(Engine::installation(&db, client.as_ref(), &stranger)).unwrap(),
            Installation::Unregistered {
                account_has_identity: false
            }
        );
    }
}
