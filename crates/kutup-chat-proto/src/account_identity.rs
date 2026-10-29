//! One libsignal identity per account, as Signal's ACI
//! (docs/plans/account-identity-key.md), and one device list per account
//! (docs/plans/one-device-list.md): the V3 account manifest, linking a
//! device (Signal's provisioning), the identity distribution (Signal's PNI
//! distribution, for the account identity), re-registration, per-device
//! credentials, and the `accountIdentity` sync a distribution sends.
//!
//! These types replaced the V1 and V2 manifests, the V1 bundles and the V1
//! registration request, which nothing accepts any more: there is no legacy
//! path.
//!
//! Limits (envelope sizes, token lifetimes, rates) are site settings and live
//! in the server; the bounds here are the formats' own.
//!
//! Unknown fields: what a client sends and the server parses is strict
//! (`deny_unknown_fields`), as is what one client sends another (the
//! provisioning message, the `accountIdentity` sync) and the signed manifest.
//! What the server answers and clients read (bundles, link tokens, the
//! provisioning socket's messages) takes unknown fields, so a field a newer
//! server adds doesn't break an older client. The key types shared by
//! requests and answers (`EcPreKey`, `KemPreKey`, `OutgoingEnvelope`) stay as
//! they are for that reason.

use serde::{Deserialize, Serialize};

#[cfg(feature = "openapi")]
use crate::AccountRefSchema;
use crate::{
    decode_canonical_base64_exact, decode_lower_hex_32, push_optional, push_string,
    AccountManifestDriveKeysV1, AccountRef, DeviceListMismatch, DirectChatSuiteId, EcPreKey,
    KemPreKey, OutgoingEnvelope, ProfileSuiteId, MAX_ACCOUNT_MANIFEST_HISTORY_PAGE,
};

pub const ACCOUNT_MANIFEST_V3_VERSION: u16 = 3;

/// The most entries one manifest lists (the device id space). How many an
/// account may have is the server's site setting, below this.
pub const MAX_ACCOUNT_MANIFEST_DEVICES: usize = MAX_DEVICE_ID as usize;

/// An XEdDSA signature by the account identity key (`identityBinding`).
pub const IDENTITY_BINDING_LEN: usize = 64;

/// The bytes an account identity key signs to bind itself to its authority
/// ([`AccountManifestV3::identity_binding`]), for a manifest not built yet.
pub fn identity_binding_bytes(
    authority_key_id: &str,
    incarnation_id: &str,
    account: &AccountRef,
    identity_key: &str,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(kutup_crypto::labels::ACCOUNT_IDENTITY_BINDING_V1);
    out.extend_from_slice(&decode_lower_hex_32("authorityKeyId", authority_key_id)?);
    out.extend_from_slice(&decode_lower_hex_32("incarnationId", incarnation_id)?);
    out.extend_from_slice(&account.bytes());
    out.extend_from_slice(&decode_identity_key("identityKey", identity_key)?);
    Ok(out)
}

/// libsignal's serialized identity public key: the Curve25519 type byte and
/// 32 bytes.
pub const IDENTITY_PUBLIC_KEY_LEN: usize = 33;
/// libsignal's `DjbECPublicKey` type byte.
pub const DJB_KEY_TYPE: u8 = 0x05;
pub const IDENTITY_PRIVATE_KEY_LEN: usize = 32;
/// The highest libsignal registration id (14 bits, as Signal's
/// `isValidRegistrationId`); Kutup never hands out 0.
pub const MAX_REGISTRATION_ID: u32 = 0x3fff;
/// Device ids are 1..=127, as libsignal's `DeviceId`.
pub const MAX_DEVICE_ID: u32 = 127;
/// A device's credential (Signal's per-device password): 32 random bytes the
/// device draws at registration; the server keeps only a salted hash.
pub const DEVICE_CREDENTIAL_LEN: usize = 32;
/// The header carrying `<deviceId>.<credential>` beside the JWT on every
/// device-bound Chat call (Signal's `AccountAuthenticator`).
pub const DEVICE_HEADER: &str = "X-Kutup-Device";
/// A provisioning socket's address: random bytes for the socket's life.
pub const PROVISIONING_ADDRESS_LEN: usize = 16;
/// A one-time link token (Signal's provisioning code).
pub const LINK_TOKEN_LEN: usize = 32;
pub const PROVISIONING_VERSION: u16 = 1;
/// The device a re-registration takes: every other row is dropped in the same
/// transaction, so it is the lowest free id (Signal's primary device id).
pub const REREGISTRATION_DEVICE_ID: u32 = 1;

/// The id a re-registering Chat device takes: the lowest the account's other
/// (non-Chat) devices leave free, [`REREGISTRATION_DEVICE_ID`] while it has
/// none.
pub fn reregistration_device_id(others: &[u32]) -> u32 {
    (REREGISTRATION_DEVICE_ID..)
        .find(|id| !others.contains(id))
        .expect("an unbounded range")
}
/// A serialized libsignal `SignedPreKeyRecord` or `KyberPreKeyRecord` inside a
/// sync (a Kyber1024 record is about 4.8 KiB).
pub const MAX_PREKEY_RECORD_BYTES: usize = 16 * 1024;
/// The largest provisioning cipher body the format allows; the site setting
/// that caps the relay request stays at or below it. A provisioning message
/// is under 1 KiB.
pub const MAX_PROVISION_BODY_BYTES: usize = 64 * 1024;

/// The `kutup://link` code a new device shows (QR code and copyable text):
/// its provisioning socket's address and its ephemeral X25519 key, as
/// Signal's `sgnl://linkdevice?uuid=…&pub_key=…`.
pub const LINK_URI_PREFIX: &str = "kutup://link?";

fn b64url_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical unpadded base64url of exactly `expected` bytes.
fn decode_b64url_exact(name: &str, value: &str, expected: usize) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical unpadded base64url"))?;
    if bytes.len() != expected || b64url_encode(&bytes) != value {
        return Err(format!(
            "{name} must be canonical unpadded base64url for {expected} bytes"
        ));
    }
    Ok(bytes)
}

/// Canonical padded base64 of 1..=`max` bytes.
fn decode_canonical_base64_bounded(name: &str, value: &str, max: usize) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if bytes.is_empty()
        || bytes.len() > max
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != value
    {
        return Err(format!("{name} must be canonical base64 for 1-{max} bytes"));
    }
    Ok(bytes)
}

/// The account identity public key: canonical base64 of libsignal's 33-byte
/// serialized form. Whether it is a valid point is libsignal's check (server
/// and clients); this is the format.
pub fn decode_identity_key(
    name: &str,
    value: &str,
) -> Result<[u8; IDENTITY_PUBLIC_KEY_LEN], String> {
    let bytes = decode_canonical_base64_exact(name, value, IDENTITY_PUBLIC_KEY_LEN)?;
    if bytes[0] != DJB_KEY_TYPE {
        return Err(format!("{name} must be a Curve25519 key"));
    }
    Ok(bytes.try_into().expect("length checked"))
}

fn check_device_id(device_id: u32) -> Result<(), String> {
    if device_id == 0 || device_id > MAX_DEVICE_ID {
        return Err("device id must be 1-127".into());
    }
    Ok(())
}

fn check_registration_id(registration_id: u32) -> Result<(), String> {
    if registration_id == 0 || registration_id > MAX_REGISTRATION_ID {
        return Err("registration id must be 1-16383".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The V3 manifest
// ---------------------------------------------------------------------------

/// What a device of the account is: a Chat app instance, an editing app
/// instance (Drive, Office, Maps, Pass), or the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum DeviceKind {
    Chat,
    Editor,
    Cli,
}

impl DeviceKind {
    /// The byte the manifest signs.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Chat => 1,
            Self::Editor => 2,
            Self::Cli => 3,
        }
    }

    /// The name the server's `devices.kind` column holds.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Editor => "editor",
            Self::Cli => "cli",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "chat" => Ok(Self::Chat),
            "editor" => Ok(Self::Editor),
            "cli" => Ok(Self::Cli),
            _ => Err(format!("unknown device kind {value:?}")),
        }
    }
}

/// What a device that takes Chat messages carries in the manifest: its
/// suite and the registration id the authority vouches for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatDeviceKeysV3 {
    pub direct_chat_suite: DirectChatSuiteId,
    /// Bundles, `409`s and `410`s that disagree with it are refused.
    pub registration_id: u32,
}

/// One device in an [`AccountManifestV3`]: no identity of its own (the
/// account has one), its Chat keys if it takes Chat, its frame key if it
/// edits, and the sign-in it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestDeviceV3 {
    pub device_id: u32,
    pub kind: DeviceKind,
    /// Required on a `chat` device, optional on `cli`, never on `editor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat: Option<ChatDeviceKeysV3>,
    /// The device's Ed25519 key for collab frames (and later any other
    /// per-device signature), canonical base64 of 32 bytes. Required on
    /// `editor` and `cli`, optional on `chat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_key: Option<String>,
    /// [`device_session_hash`] of the device's sign-in, lowercase hex: the
    /// account's devices group by sign-in without naming it.
    pub session: String,
}

impl AccountManifestDeviceV3 {
    /// A Chat device of `suite` and `registration_id`.
    pub fn chat(
        device_id: u32,
        suite: DirectChatSuiteId,
        registration_id: u32,
        session: String,
    ) -> Self {
        Self {
            device_id,
            kind: DeviceKind::Chat,
            chat: Some(ChatDeviceKeysV3 {
                direct_chat_suite: suite,
                registration_id,
            }),
            frame_key: None,
            session,
        }
    }

    /// The id, the kind's required and allowed keys, and their encodings.
    pub fn validate(&self) -> Result<(), String> {
        check_device_id(self.device_id)?;
        match (self.kind, &self.chat, &self.frame_key) {
            (DeviceKind::Chat, None, _) => return Err("a chat device carries chat keys".into()),
            (DeviceKind::Editor | DeviceKind::Cli, _, None) => {
                return Err("an editor or CLI device carries a frame key".into())
            }
            (DeviceKind::Editor, Some(_), _) => {
                return Err("an editor device carries no chat keys".into())
            }
            _ => {}
        }
        if let Some(chat) = &self.chat {
            check_registration_id(chat.registration_id)?;
        }
        if let Some(frame_key) = &self.frame_key {
            decode_frame_key(frame_key)?;
        }
        decode_lower_hex_32("session", &self.session)?;
        Ok(())
    }
}

/// `POST /api/devices`: an editor or CLI device of the account registers
/// (a Chat device registers by `POST /api/chat/device`). The server issues
/// its id; the device then lists itself in the account's manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterDeviceRequestV1 {
    pub kind: DeviceKind,
    /// Shown in device management ("Office · Firefox on Linux").
    #[serde(default)]
    pub name: String,
    /// The device's Ed25519 frame key, as its manifest entry lists it.
    pub frame_key: String,
    /// The device's credential, as a Chat device's: canonical unpadded
    /// base64url of 32 random bytes, sent in [`DEVICE_HEADER`].
    pub credential: String,
}

/// The longest device name, in characters.
pub const MAX_DEVICE_NAME_CHARS: usize = 120;

impl RegisterDeviceRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.kind == DeviceKind::Chat {
            return Err("a Chat device registers through /api/chat/device".into());
        }
        if self.name.chars().count() > MAX_DEVICE_NAME_CHARS {
            return Err("a device name is at most 120 characters".into());
        }
        decode_frame_key(&self.frame_key)?;
        decode_device_credential(&self.credential)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponseV1 {
    pub device_id: u32,
    /// What its manifest entry lists as `session`.
    pub session: String,
}

/// One device of the account, as `GET /api/devices` lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountDeviceV1 {
    pub device_id: u32,
    pub kind: DeviceKind,
    pub name: String,
    /// The hash of its sign-in, as its manifest entry carries it.
    pub session: String,
    /// It belongs to the caller's sign-in.
    pub this_sign_in: bool,
    /// The account's manifest lists it (a device between registering and
    /// listing itself isn't yet).
    pub listed: bool,
    /// Idle too long: the next manifest drops it.
    pub expired: bool,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
}

/// A device's frame key: canonical base64 of a valid Ed25519 public key.
pub fn decode_frame_key(value: &str) -> Result<[u8; 32], String> {
    let bytes: [u8; 32] = decode_canonical_base64_exact("frameKey", value, 32)?
        .try_into()
        .map_err(|_| "frameKey must be 32 bytes".to_string())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "frameKey must be a valid Ed25519 public key".to_string())?;
    if key.is_weak() {
        return Err("frameKey must not be a small-order Ed25519 point".into());
    }
    Ok(bytes)
}

/// A device entry's `session`: SHA-256 over its domain and the id of the
/// device's root sign-in (an app's session's parent, or the session itself
/// for the CLI and native apps), lowercase hex. The server works it out at
/// registration; contacts see only the hash.
pub fn device_session_hash(root_session_id: &[u8; 16]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(kutup_crypto::labels::ACCOUNT_DEVICE_SESSION_V1);
    hasher.update(root_session_id);
    hex::encode(hasher.finalize())
}

/// The account manifest: the account's one libsignal identity and its one
/// device list (Chat, editing and CLI devices), signed by the account
/// authority. The wipe that brought V3 cleared every V2 manifest, so its
/// chain starts at sequence 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountManifestV3 {
    pub manifest_version: u16,
    #[cfg_attr(feature = "openapi", schema(value_type = AccountRefSchema))]
    pub account: AccountRef,
    pub incarnation_id: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    /// The account's libsignal identity key itself (canonical base64 of 33
    /// bytes). It changes only with an identity distribution or a
    /// re-registration (the identity rule). None while the account has no
    /// Chat identity (no Chat device ever registered): its manifest then
    /// lists only devices that don't take Chat, and the first Chat device
    /// sets it by re-registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    /// The identity key's signature (XEdDSA, as libsignal signs prekeys) over
    /// [`AccountManifestV3::identity_binding_bytes`]: the identity vouches for
    /// this authority, incarnation and account, as the authority vouches for
    /// the identity. Without it a server could list someone's real identity
    /// under an authority of its own, and comparing safety numbers (which
    /// cover the identity) would wrongly vouch for that authority. Canonical
    /// base64 of 64 bytes; libsignal checks it (clients and server), since
    /// this crate has no XEdDSA. Present exactly when `identityKey` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<String>,
    pub drive: AccountManifestDriveKeysV1,
    /// Strictly ordered by `deviceId`.
    pub devices: Vec<AccountManifestDeviceV3>,
    pub issued_at: String,
    pub authority_key_id: String,
    pub self_authority_key: String,
    pub signature: String,
}

impl AccountManifestV3 {
    /// Deterministic, domain-separated encoding the authority signs. Devices
    /// MUST be strictly ordered by `deviceId`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        const DOMAIN: &[u8] = kutup_crypto::labels::ACCOUNT_MANIFEST_V3;
        let mut out = Vec::with_capacity(320 + self.devices.len() * 80);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.manifest_version.to_be_bytes());
        out.extend_from_slice(&self.account.bytes());
        out.extend_from_slice(&decode_lower_hex_32("incarnationId", &self.incarnation_id)?);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        push_optional(&mut out, self.previous_hash.as_deref())?;
        push_string(&mut out, &self.issued_at)?;
        out.extend_from_slice(&decode_lower_hex_32(
            "authorityKeyId",
            &self.authority_key_id,
        )?);
        out.extend_from_slice(&decode_canonical_base64_exact(
            "selfAuthorityKey",
            &self.self_authority_key,
            32,
        )?);
        match (&self.identity_key, &self.identity_binding) {
            (Some(identity_key), Some(identity_binding)) => {
                out.push(1);
                out.extend_from_slice(&decode_identity_key("identityKey", identity_key)?);
                out.extend_from_slice(&decode_canonical_base64_exact(
                    "identityBinding",
                    identity_binding,
                    IDENTITY_BINDING_LEN,
                )?);
            }
            (None, None) => out.push(0),
            _ => return Err("identityKey and identityBinding come together".into()),
        }
        out.extend_from_slice(&u16::from(self.drive.suite).to_be_bytes());
        out.extend_from_slice(&decode_canonical_base64_exact(
            "drive.hpkePublicKey",
            &self.drive.hpke_public_key,
            self.drive.suite.hpke_public_key_len(),
        )?);
        out.extend_from_slice(&decode_canonical_base64_exact(
            "drive.shareSigningPublicKey",
            &self.drive.share_signing_public_key,
            32,
        )?);
        let count = u32::try_from(self.devices.len()).map_err(|_| "too many devices")?;
        out.extend_from_slice(&count.to_be_bytes());
        let mut prior = None;
        for device in &self.devices {
            if prior.is_some_and(|id| device.device_id <= id) {
                return Err("manifest devices must be strictly ordered by deviceId".into());
            }
            prior = Some(device.device_id);
            device.validate()?;
            out.extend_from_slice(&device.device_id.to_be_bytes());
            out.push(device.kind.as_u8());
            match &device.chat {
                Some(chat) => {
                    out.push(1);
                    out.extend_from_slice(&u16::from(chat.direct_chat_suite).to_be_bytes());
                    out.extend_from_slice(&chat.registration_id.to_be_bytes());
                }
                None => out.push(0),
            }
            match &device.frame_key {
                Some(frame_key) => {
                    out.push(1);
                    out.extend_from_slice(&decode_frame_key(frame_key)?);
                }
                None => out.push(0),
            }
            out.extend_from_slice(&decode_lower_hex_32("session", &device.session)?);
        }
        Ok(out)
    }

    /// What the account identity key signs for [`Self::identity_binding`]:
    /// its own domain, the authority's key id, the incarnation, the account
    /// and the identity key itself. Nothing that changes with the devices, so
    /// one binding serves every manifest of the same identity and authority.
    pub fn identity_binding_bytes(&self) -> Result<Vec<u8>, String> {
        identity_binding_bytes(
            &self.authority_key_id,
            &self.incarnation_id,
            &self.account,
            self.chat_identity_key()?,
        )
    }

    /// The account's Chat identity key: an error naming its absence when the
    /// account has none.
    pub fn chat_identity_key(&self) -> Result<&str, String> {
        self.identity_key
            .as_deref()
            .ok_or_else(|| "the account has no Chat identity".to_string())
    }

    /// What the next manifest's `previousHash`, and a provisioning message's
    /// or sync's `manifestHash`, name: the signed bytes and the signature.
    pub fn manifest_hash(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes()?);
        hasher.update(self.signature.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// The listed device, if any.
    pub fn device(&self, device_id: u32) -> Option<&AccountManifestDeviceV3> {
        self.devices
            .binary_search_by_key(&device_id, |device| device.device_id)
            .ok()
            .map(|index| &self.devices[index])
    }

    /// The account's first manifest, unsigned, when it has none: its
    /// authority, incarnation and Drive keys (from `keys`), no Chat identity
    /// (a Chat device's re-registration sets one), listing `devices`. Sign it
    /// with [`Self::sign`].
    pub fn first(
        account: AccountRef,
        keys: &kutup_crypto::identity::AccountIdentityKeysV1,
        mut devices: Vec<AccountManifestDeviceV3>,
        issued_at: impl Into<String>,
    ) -> Self {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let public = keys.authority_public_key();
        devices.sort_by_key(|device| device.device_id);
        Self {
            manifest_version: ACCOUNT_MANIFEST_V3_VERSION,
            account,
            incarnation_id: keys.incarnation_id(),
            sequence: 1,
            previous_hash: None,
            identity_key: None,
            identity_binding: None,
            drive: AccountManifestDriveKeysV1 {
                suite: crate::AccountIdentitySuiteId::XWingEd25519V2,
                hpke_public_key: b64(&keys.drive_hpke_public_key()),
                share_signing_public_key: b64(&keys.drive_signing_public_key()),
            },
            devices,
            issued_at: issued_at.into(),
            authority_key_id: hex::encode(Sha256::digest(public)),
            self_authority_key: b64(&public),
            signature: String::new(),
        }
    }

    /// The head's successor, unsigned: the same account, authority, identity
    /// and Drive keys, the next sequence linked by hash, listing `devices`
    /// (ordered here). Sign it with [`Self::sign`].
    pub fn successor(
        &self,
        mut devices: Vec<AccountManifestDeviceV3>,
        issued_at: impl Into<String>,
    ) -> Result<Self, String> {
        devices.sort_by_key(|device| device.device_id);
        Ok(Self {
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or("manifest sequence is exhausted")?,
            previous_hash: Some(self.manifest_hash()?),
            devices,
            issued_at: issued_at.into(),
            signature: String::new(),
            ..self.clone()
        })
    }

    /// Signs the manifest with the account authority's key, which must be
    /// the one it names; the result verifies.
    pub fn sign(&mut self, authority: &kutup_crypto::primitives::SigningKey) -> Result<(), String> {
        use base64::Engine as _;
        let public = base64::engine::general_purpose::STANDARD
            .encode(authority.verifying_key().to_array::<32>());
        if public != self.self_authority_key {
            return Err("the manifest names another authority".into());
        }
        let signature = authority.sign(&self.signing_bytes()?);
        self.signature = base64::engine::general_purpose::STANDARD.encode(signature);
        self.verify()
    }

    /// The listed device's Chat keys, if it takes Chat.
    pub fn chat_device(&self, device_id: u32) -> Option<&ChatDeviceKeysV3> {
        self.device(device_id)?.chat.as_ref()
    }

    /// The devices that take Chat, by id, with their Chat keys.
    pub fn chat_devices(&self) -> impl Iterator<Item = (u32, &ChatDeviceKeysV3)> {
        self.devices
            .iter()
            .filter_map(|device| Some((device.device_id, device.chat.as_ref()?)))
    }

    /// Verify the authority binding, the chain shape, the device bounds and
    /// order, and the Ed25519 signature. Continuity against a manifest seen
    /// before is the caller's (client pins, server head).
    pub fn verify(&self) -> Result<(), String> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use sha2::{Digest, Sha256};

        if self.manifest_version != ACCOUNT_MANIFEST_V3_VERSION {
            return Err("unsupported account manifest version".into());
        }
        if self.sequence == 0 {
            return Err("manifest sequence must be positive".into());
        }
        if (self.sequence == 1) != self.previous_hash.is_none() {
            return Err("only manifest sequence 1 has no previousHash".into());
        }
        if let Some(previous_hash) = &self.previous_hash {
            decode_lower_hex_32("previousHash", previous_hash)?;
        }
        if self.issued_at.is_empty() || self.issued_at.len() > 64 {
            return Err("manifest issuedAt must be 1-64 bytes".into());
        }
        if self.devices.is_empty() || self.devices.len() > MAX_ACCOUNT_MANIFEST_DEVICES {
            return Err("account manifest requires 1-127 devices".into());
        }
        // A device that takes Chat holds the account's Chat identity.
        if self.identity_key.is_none() && self.devices.iter().any(|device| device.chat.is_some()) {
            return Err("a manifest listing a Chat device names the account's identity".into());
        }

        let public =
            decode_canonical_base64_exact("selfAuthorityKey", &self.self_authority_key, 32)?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| "selfAuthorityKey must be 32 bytes".to_string())?;
        if self.authority_key_id != hex::encode(Sha256::digest(public)) {
            return Err("authorityKeyId does not match selfAuthorityKey".into());
        }
        let mut incarnation = Sha256::new();
        incarnation.update(kutup_crypto::labels::ACCOUNT_INCARNATION_V1);
        incarnation.update(public);
        if self.incarnation_id != hex::encode(incarnation.finalize()) {
            return Err("incarnationId does not match selfAuthorityKey".into());
        }
        let drive_signing = decode_canonical_base64_exact(
            "drive.shareSigningPublicKey",
            &self.drive.share_signing_public_key,
            32,
        )?;
        VerifyingKey::from_bytes(
            &drive_signing
                .try_into()
                .map_err(|_| "Drive signing public key must be 32 bytes")?,
        )
        .map_err(|_| "Drive signing public key is not valid Ed25519")?;

        let signature = decode_canonical_base64_exact("signature", &self.signature, 64)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| "manifest signature must be 64 bytes".to_string())?;
        let verifying = VerifyingKey::from_bytes(&public)
            .map_err(|_| "selfAuthorityKey is not a valid Ed25519 key".to_string())?;
        // signing_bytes checks the identity key, the Drive keys, and each
        // device and their order.
        verifying
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| "manifest signature is invalid".to_string())
    }

    /// Whether this manifest may follow `head`, the account's current one
    /// (`None`: the account has none). The one continuity check the server,
    /// the web client and the native clients all use: it verifies, and either
    /// starts the chain (sequence 1, no `previousHash`) or continues `head`
    /// (the same account, incarnation and authority, sequence + 1, and
    /// `previousHash` the head's [`Self::manifest_hash`]).
    pub fn verify_successor(&self, head: Option<&AccountManifestV3>) -> Result<(), String> {
        self.verify()?;
        let Some(head) = head else {
            if self.sequence != 1 {
                return Err("the account has no manifest: the chain starts at sequence 1".into());
            }
            return Ok(());
        };
        if self.account != head.account
            || self.incarnation_id != head.incarnation_id
            || self.authority_key_id != head.authority_key_id
            || self.self_authority_key != head.self_authority_key
        {
            return Err("a successor names another account, incarnation or authority".into());
        }
        if Some(self.sequence) != head.sequence.checked_add(1) {
            return Err("a successor's sequence is the head's + 1".into());
        }
        if self.previous_hash.as_deref() != Some(head.manifest_hash()?.as_str()) {
            return Err("a successor's previousHash is the head's manifest hash".into());
        }
        Ok(())
    }
}

/// The newest manifest of its own account a client has seen: its rollback
/// pin (docs/plans/one-device-list.md §8, slice 2). A client keeps one per
/// account and signs a successor only of a head [`Self::check`] accepted, so
/// a server can't have it sign a stale head (bringing back a removed device,
/// or dropping the Chat identity) or start a new chain over an existing one.
/// The pin names its incarnation: a reset account's new keys start a chain
/// of their own, and the old pin no longer applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnManifestPinV1 {
    pub account: AccountRef,
    pub incarnation_id: String,
    pub sequence: u64,
    /// The manifest's [`AccountManifestV3::manifest_hash`].
    pub hash: String,
}

impl OwnManifestPinV1 {
    /// The pin `manifest` sets.
    pub fn of(manifest: &AccountManifestV3) -> Result<Self, String> {
        Ok(Self {
            account: manifest.account.clone(),
            incarnation_id: manifest.incarnation_id.clone(),
            sequence: manifest.sequence,
            hash: manifest.manifest_hash()?,
        })
    }

    /// Checks `head`, the account's head as its server gave it (`None`: it
    /// has none), against `pin` for the account and incarnation the client
    /// holds the keys of, and gives the pin to keep. The head must verify
    /// and name that account and incarnation, and be no older than the pin:
    /// the same sequence with the same hash, or a later one (which verifies
    /// under the account's own authority, so the server can't have made it).
    /// With a pin, no head at all is refused. A pin of another account or
    /// incarnation is ignored.
    pub fn check(
        pin: Option<&Self>,
        head: Option<&AccountManifestV3>,
        account: &AccountRef,
        incarnation_id: &str,
    ) -> Result<Option<Self>, String> {
        let pin = pin.filter(|pin| &pin.account == account && pin.incarnation_id == incarnation_id);
        let Some(head) = head else {
            if pin.is_some() {
                return Err(
                    "the server has no manifest for an account this client saw one of".into(),
                );
            }
            return Ok(None);
        };
        head.verify()?;
        if &head.account != account || head.incarnation_id != incarnation_id {
            return Err("the head names another account or incarnation".into());
        }
        let seen = Self::of(head)?;
        if let Some(pin) = pin {
            if seen.sequence < pin.sequence {
                return Err("the head is older than one this client saw".into());
            }
            if seen.sequence == pin.sequence && seen.hash != pin.hash {
                return Err("the head differs from the one this client saw at its sequence".into());
            }
        }
        Ok(Some(seen))
    }
}

/// Successful publication of one signed V3 manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountManifestPublicationV3 {
    pub manifest: AccountManifestV3,
}

/// A bounded run of the V3 chain, by exact sequence cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountManifestHistoryPageV3 {
    #[cfg_attr(feature = "openapi", schema(value_type = AccountRefSchema))]
    pub account: AccountRef,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub manifests: Vec<AccountManifestV3>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_sequence: Option<u64>,
}

impl AccountManifestHistoryPageV3 {
    /// Each manifest verifies, names the account and follows the one before
    /// it by sequence and hash.
    pub fn validate(&self) -> Result<(), String> {
        if self.from_sequence == 0
            || self.to_sequence < self.from_sequence
            || self.manifests.is_empty()
            || self.manifests.len() > MAX_ACCOUNT_MANIFEST_HISTORY_PAGE
        {
            return Err("account manifest history page has an invalid shape".into());
        }
        let mut expected = self.from_sequence;
        let mut previous: Option<String> = None;
        for manifest in &self.manifests {
            manifest.verify()?;
            if manifest.account != self.account || manifest.sequence != expected {
                return Err("account manifest history page is missing or reordered".into());
            }
            if previous.is_some() && manifest.previous_hash != previous {
                return Err("account manifest history page breaks the hash chain".into());
            }
            let first = &self.manifests[0];
            if manifest.incarnation_id != first.incarnation_id
                || manifest.authority_key_id != first.authority_key_id
            {
                return Err("account manifest history page changes authority".into());
            }
            previous = Some(manifest.manifest_hash()?);
            expected = expected
                .checked_add(1)
                .ok_or_else(|| "account manifest sequence is exhausted".to_string())?;
        }
        let last = expected - 1;
        match self.next_sequence {
            Some(next) if last < self.to_sequence && next == expected => Ok(()),
            None if last == self.to_sequence => Ok(()),
            _ => Err("account manifest history pagination is inconsistent".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Bundles under the account identity
// ---------------------------------------------------------------------------

/// One device's prekeys, without an identity (the response carries the
/// account's once).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeyBundleV2 {
    pub device_id: u32,
    pub registration_id: u32,
    pub suite: DirectChatSuiteId,
    pub signed_pre_key: EcPreKey,
    pub kyber_pre_key: KemPreKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_pre_key: Option<EcPreKey>,
}

/// `GET /api/chat/accounts/{accountId}/keys` once the account identity is
/// in: the identity once (Signal's `/v2/keys`), each listed device's prekeys,
/// and the manifest they are checked against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountPreKeyBundlesResponse {
    #[cfg_attr(feature = "openapi", schema(value_type = AccountRefSchema))]
    pub account: AccountRef,
    pub identity_key: String,
    pub devices: Vec<DevicePreKeyBundleV2>,
    pub manifest: AccountManifestV3,
}

impl AccountPreKeyBundlesResponse {
    /// The manifest verifies and is this account's; the identity is the
    /// manifest's; every bundle is a listed device with its listed
    /// registration id and suite, at most once. The prekey signatures are
    /// libsignal's to check against `identityKey`.
    pub fn check_against_manifest(&self) -> Result<(), String> {
        self.manifest.verify()?;
        if self.manifest.account != self.account {
            return Err("bundles name another account than their manifest".into());
        }
        if self.manifest.identity_key.as_deref() != Some(self.identity_key.as_str()) {
            return Err("bundles carry another identity than their manifest".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for bundle in &self.devices {
            let listed = self
                .manifest
                .chat_device(bundle.device_id)
                .ok_or("a bundle names a device the manifest does not list for Chat")?;
            if listed.registration_id != bundle.registration_id
                || listed.direct_chat_suite != bundle.suite
            {
                return Err("a bundle disagrees with the manifest".into());
            }
            if !seen.insert(bundle.device_id) {
                return Err("a device has two bundles".into());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Device credentials
// ---------------------------------------------------------------------------

/// The `X-Kutup-Device` value: `<deviceId>.<credential>`, the credential
/// as canonical unpadded base64url.
pub fn format_device_header(device_id: u32, credential: &[u8; DEVICE_CREDENTIAL_LEN]) -> String {
    format!("{device_id}.{}", b64url_encode(credential))
}

/// Parse an `X-Kutup-Device` value. The server then compares the
/// credential, in constant time, with the salted hash on that device's row of
/// the JWT's account.
pub fn parse_device_header(value: &str) -> Result<(u32, [u8; DEVICE_CREDENTIAL_LEN]), String> {
    let (id, credential) = value
        .split_once('.')
        .ok_or("device header must be <deviceId>.<credential>")?;
    if id.is_empty()
        || id.len() > 3
        || !id.bytes().all(|b| b.is_ascii_digit())
        || id.starts_with('0')
    {
        return Err("device header has an invalid device id".into());
    }
    let device_id: u32 = id
        .parse()
        .map_err(|_| "device header has an invalid device id")?;
    check_device_id(device_id)?;
    let credential = decode_b64url_exact("credential", credential, DEVICE_CREDENTIAL_LEN)?;
    Ok((device_id, credential.try_into().expect("length checked")))
}

/// The registration's credential field: canonical unpadded base64url, as in
/// the header (one encoding for the credential everywhere).
pub fn decode_device_credential(value: &str) -> Result<[u8; DEVICE_CREDENTIAL_LEN], String> {
    let bytes = decode_b64url_exact("credential", value, DEVICE_CREDENTIAL_LEN)?;
    Ok(bytes.try_into().expect("length checked"))
}

// ---------------------------------------------------------------------------
// Linking: link tokens, the provisioning socket, the link code
// ---------------------------------------------------------------------------

/// `POST /api/chat/link-tokens` (device-authenticated): one single-use token
/// for one new device, as Signal's provisioning code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChatLinkTokenResponse {
    /// Canonical unpadded base64url of 32 random bytes; the server stores
    /// only its hash.
    pub token: String,
    pub expires_at: String,
}

pub fn decode_link_token(value: &str) -> Result<[u8; LINK_TOKEN_LEN], String> {
    let bytes = decode_b64url_exact("linkToken", value, LINK_TOKEN_LEN)?;
    Ok(bytes.try_into().expect("length checked"))
}

pub fn decode_provisioning_address(value: &str) -> Result<[u8; PROVISIONING_ADDRESS_LEN], String> {
    let bytes = decode_b64url_exact("address", value, PROVISIONING_ADDRESS_LEN)?;
    Ok(bytes.try_into().expect("length checked"))
}

/// Signal's `ProvisionEnvelope`: the sender's ephemeral public key, and the
/// `ProvisioningCipher` body `0x01 ‖ IV(16) ‖ AES-256-CBC/PKCS7 ‖
/// HMAC-SHA256(32)` (kutup-crypto `provisioning`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ProvisionEnvelopeV1 {
    /// Canonical base64 of the sender's 33-byte serialized X25519 key.
    pub public_key: String,
    /// Canonical base64 of the cipher body.
    pub body: String,
}

impl ProvisionEnvelopeV1 {
    /// Version, IV, at least one cipher block, MAC.
    pub const MIN_BODY_LEN: usize = 1 + 16 + 16 + 32;

    /// The shape only: the key's type, and a body of at most
    /// [`MAX_PROVISION_BODY_BYTES`] whose ciphertext is whole AES blocks. The
    /// MAC is the recipient's.
    pub fn validate(&self) -> Result<(), String> {
        decode_identity_key("publicKey", &self.public_key)?;
        let body = decode_canonical_base64_bounded("body", &self.body, MAX_PROVISION_BODY_BYTES)?;
        if body.len() < Self::MIN_BODY_LEN || (body.len() - 1 - 16 - 32) % 16 != 0 {
            return Err("provisioning body has an invalid length".into());
        }
        if body[0] != 1 {
            return Err("unsupported provisioning cipher version".into());
        }
        Ok(())
    }
}

/// `PUT /api/chat/provisioning/{address}` (device-authenticated): relay one
/// envelope to a provisioning socket of the same account. "No such socket"
/// and "another account's socket" are the same `404`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvisioningRelayRequest {
    pub envelope: ProvisionEnvelopeV1,
}

/// What `GET /api/chat/provisioning` (a WebSocket, JWT-authenticated) sends
/// the new device: its address once, then exactly one envelope; the server
/// closes the socket after the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ProvisioningSocketMessage {
    Address { address: String },
    Envelope { envelope: ProvisionEnvelopeV1 },
}

/// The code the new device shows, as a QR code and as text to copy:
/// `kutup://link?address=<base64url>&key=<base64url>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningLinkCodeV1 {
    pub address: [u8; PROVISIONING_ADDRESS_LEN],
    /// The new device's ephemeral X25519 public key, libsignal-serialized.
    pub public_key: [u8; IDENTITY_PUBLIC_KEY_LEN],
}

impl ProvisioningLinkCodeV1 {
    pub fn to_uri(&self) -> String {
        format!(
            "{LINK_URI_PREFIX}address={}&key={}",
            b64url_encode(&self.address),
            b64url_encode(&self.public_key)
        )
    }

    /// Exactly the form [`Self::to_uri`] writes (a pasted code may carry
    /// surrounding whitespace, which is trimmed); anything else is refused.
    pub fn parse(value: &str) -> Result<Self, String> {
        let query = value
            .trim()
            .strip_prefix(LINK_URI_PREFIX)
            .ok_or("not a Kutup link code")?;
        let (address, key) = query
            .strip_prefix("address=")
            .and_then(|rest| rest.split_once("&key="))
            .ok_or("link code must be address=…&key=…")?;
        let address = decode_provisioning_address(address)?;
        let public_key = decode_b64url_exact("key", key, IDENTITY_PUBLIC_KEY_LEN)?;
        if public_key[0] != DJB_KEY_TYPE {
            return Err("link code key must be a Curve25519 key".into());
        }
        Ok(Self {
            address,
            public_key: public_key.try_into().expect("length checked"),
        })
    }
}

/// The provisioning message (Signal's `ProvisionMessage`, the fields Kutup
/// needs), canonical JSON inside a [`ProvisionEnvelopeV1`]. No master key:
/// the new device has it from signing in.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatProvisionV1 {
    pub provisioning_version: u16,
    /// The new device checks it is its own account.
    pub account: AccountRef,
    pub identity_key_public: String,
    pub identity_key_private: String,
    /// From `POST /api/chat/link-tokens`; the new device registers with it.
    pub link_token: String,
    /// The manifest the identity is listed in: the new device fetches it,
    /// verifies it under the authority it derives from the master key, and
    /// takes the identity only if the manifest lists exactly this key.
    pub manifest_sequence: u64,
    pub manifest_hash: String,
    pub profile_key: String,
    pub profile_suite: ProfileSuiteId,
    pub read_receipts: bool,
    pub typing_indicators: bool,
}

impl ChatProvisionV1 {
    /// The format only; the key pair's agreement and the manifest are checked
    /// by the receiving client.
    pub fn validate(&self) -> Result<(), String> {
        if self.provisioning_version != PROVISIONING_VERSION {
            return Err("unsupported provisioning version".into());
        }
        decode_identity_key("identityKeyPublic", &self.identity_key_public)?;
        decode_canonical_base64_exact(
            "identityKeyPrivate",
            &self.identity_key_private,
            IDENTITY_PRIVATE_KEY_LEN,
        )?;
        decode_link_token(&self.link_token)?;
        if self.manifest_sequence == 0 {
            return Err("manifestSequence must be positive".into());
        }
        decode_lower_hex_32("manifestHash", &self.manifest_hash)?;
        decode_canonical_base64_exact("profileKey", &self.profile_key, 32)?;
        Ok(())
    }
}

/// Never prints the identity private key or the profile key.
impl std::fmt::Debug for ChatProvisionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatProvisionV1")
            .field("account", &self.account)
            .field("manifest_sequence", &self.manifest_sequence)
            .finish_non_exhaustive()
    }
}

impl Drop for ChatProvisionV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.identity_key_private);
        zeroize::Zeroize::zeroize(&mut self.profile_key);
        zeroize::Zeroize::zeroize(&mut self.link_token);
    }
}

// ---------------------------------------------------------------------------
// The identity distribution and re-registration
// ---------------------------------------------------------------------------

/// One kept device's new keys in a distribution, signed by the new identity.
/// [`AccountIdentityDistributionRequest::validate`] checks only that the
/// signed prekey carries a signature; the server verifies both the signed
/// prekey's and the last-resort Kyber key's signatures against `identityKey`
/// with libsignal (`400 badSignature`), and the receiving devices do too.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DistributedDeviceKeysV1 {
    pub device_id: u32,
    /// The device's new registration id, as the manifest lists it.
    pub registration_id: u32,
    pub signed_pre_key: EcPreKey,
    pub last_resort_kyber_pre_key: KemPreKey,
}

/// `PUT /api/chat/account-identity` (device-authenticated): Signal's
/// `PhoneNumberIdentityKeyDistributionRequest`, for the account identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountIdentityDistributionRequest {
    pub identity_key: String,
    /// Every Chat device the manifest lists, the sender included, strictly
    /// ordered by `deviceId`.
    pub devices: Vec<DistributedDeviceKeysV1>,
    /// One `accountIdentity` sync per other listed Chat device, sealed on its
    /// current session; `registrationId` is the device's **current** one (a
    /// mismatch is `410`). Strictly ordered by `deviceId`.
    pub device_messages: Vec<OutgoingEnvelope>,
    /// The account's next V3 manifest (sequence + 1, `previousHash` the
    /// head's hash: [`AccountManifestV3::verify_successor`]): this identity,
    /// exactly these Chat devices with these registration ids.
    pub manifest: AccountManifestV3,
}

/// Why a distribution (or a re-registration) is refused before the server
/// looks at its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionError {
    /// `400`: the request contradicts itself or its manifest.
    Invalid(String),
    /// `409`: the device maps and the messages don't name exactly the
    /// manifest's devices.
    Mismatched(DeviceListMismatch),
}

impl From<String> for DistributionError {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}

impl From<&str> for DistributionError {
    fn from(value: &str) -> Self {
        Self::Invalid(value.into())
    }
}

fn strictly_ordered<T>(items: &[T], id: impl Fn(&T) -> u32, what: &str) -> Result<(), String> {
    if items.windows(2).any(|pair| id(&pair[0]) >= id(&pair[1])) {
        return Err(format!("{what} must be strictly ordered by deviceId"));
    }
    Ok(())
}

/// The ids in `have` against `want`: missing = wanted and absent, extra =
/// present and not wanted.
fn compare_sets(want: &[u32], have: &[u32]) -> DeviceListMismatch {
    DeviceListMismatch {
        missing_devices: want
            .iter()
            .copied()
            .filter(|id| !have.contains(id))
            .collect(),
        stale_devices: Vec::new(),
        extra_devices: have
            .iter()
            .copied()
            .filter(|id| !want.contains(id))
            .collect(),
    }
}

impl AccountIdentityDistributionRequest {
    /// Everything that needs no rows and no libsignal: the manifest verifies
    /// and names this identity; `devices` names exactly the manifest's Chat
    /// devices with its registration ids; `deviceMessages` names exactly the
    /// other listed Chat devices. The server then checks the rows (`409` for a
    /// device not the account's, `410` for a stale registration id), the
    /// prekey signatures (`400 badSignature`), and that the manifest is the
    /// next sequence.
    pub fn validate(&self, sender_device_id: u32) -> Result<(), DistributionError> {
        self.manifest.verify()?;
        decode_identity_key("identityKey", &self.identity_key)?;
        if self.manifest.identity_key.as_deref() != Some(self.identity_key.as_str()) {
            return Err("the manifest lists another identity".into());
        }
        if self.manifest.chat_device(sender_device_id).is_none() {
            return Err("the sending device must keep itself".into());
        }
        strictly_ordered(&self.devices, |d| d.device_id, "devices")?;
        strictly_ordered(&self.device_messages, |m| m.device_id, "deviceMessages")?;

        let listed: Vec<u32> = self.manifest.chat_devices().map(|(id, _)| id).collect();
        let keyed: Vec<u32> = self.devices.iter().map(|d| d.device_id).collect();
        let mismatch = compare_sets(&listed, &keyed);
        if !mismatch.missing_devices.is_empty() || !mismatch.extra_devices.is_empty() {
            return Err(DistributionError::Mismatched(mismatch));
        }
        let others: Vec<u32> = listed
            .iter()
            .copied()
            .filter(|id| *id != sender_device_id)
            .collect();
        let messaged: Vec<u32> = self.device_messages.iter().map(|m| m.device_id).collect();
        let mismatch = compare_sets(&others, &messaged);
        if !mismatch.missing_devices.is_empty() || !mismatch.extra_devices.is_empty() {
            return Err(DistributionError::Mismatched(mismatch));
        }

        for keys in &self.devices {
            let listed = self
                .manifest
                .chat_device(keys.device_id)
                .expect("sets compared");
            if listed.registration_id != keys.registration_id {
                return Err("a device's registration id disagrees with the manifest".into());
            }
            if keys.signed_pre_key.signature.is_none() {
                return Err("a signed prekey must carry its signature".into());
            }
        }
        Ok(())
    }
}

/// How a device registers: linked by a device of the account, or a
/// re-registration. Exactly one, by type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "type", deny_unknown_fields)]
pub enum DeviceRegistrationV1 {
    /// Linked: the one-time token the linking device obtained and sent in
    /// the provisioning message, consumed in the insert's transaction. A
    /// device of the account publishes the manifest that lists it afterwards.
    #[serde(rename_all = "camelCase")]
    Link { link_token: String },
    /// A re-registration: this device takes a new identity and every other
    /// Chat device of the account is dropped (Signal's `reclaimAccount`); the
    /// account's first Chat device registers this way too. The gate is the
    /// account authority. `manifest` is the account's next V3 manifest,
    /// listing this device as its one Chat device, as
    /// [`reregistration_device_id`] of the others, with the request's
    /// identity and registration id, and the head's other (non-Chat) entries
    /// unchanged; it continues the chain
    /// ([`AccountManifestV3::verify_successor`]): sequence 1 with no
    /// `previousHash` when the account has no manifest, otherwise the head's
    /// sequence + 1 with `previousHash` the head's hash. The server inserts
    /// the device in the transaction that drops the other Chat devices and
    /// publishes the manifest.
    Reregistration { manifest: Box<AccountManifestV3> },
}

/// The link token is single-use, but wiped all the same once the request is
/// dropped.
impl Drop for DeviceRegistrationV1 {
    fn drop(&mut self) {
        if let Self::Link { link_token } = self {
            zeroize::Zeroize::zeroize(link_token);
        }
    }
}

/// `POST /api/chat/device` from the cutover on: the V1 request with the
/// account's identity key, the device's credential, and how it registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterChatDeviceRequestV2 {
    pub suite: DirectChatSuiteId,
    /// libsignal registration id, 1..=16383.
    pub registration_id: u32,
    /// The account's identity key (canonical base64 of the 33-byte key).
    pub identity_key: String,
    /// Signed by the account identity key, as are the Kyber keys.
    pub signed_pre_key: EcPreKey,
    pub last_resort_kyber_pre_key: KemPreKey,
    #[serde(default)]
    pub one_time_pre_keys: Vec<EcPreKey>,
    #[serde(default)]
    pub one_time_kyber_pre_keys: Vec<KemPreKey>,
    /// Human label shown in device management ("Firefox on laptop").
    #[serde(default)]
    pub name: String,
    /// The device's credential (Signal's per-device password): canonical
    /// unpadded base64url of 32 random bytes; the server stores a salted hash
    /// and the device sends it in [`DEVICE_HEADER`].
    pub credential: String,
    pub registration: DeviceRegistrationV1,
}

impl RegisterChatDeviceRequestV2 {
    /// Everything that needs no rows and no libsignal: the identity's and
    /// the credential's encodings, the registration id, the link token's
    /// encoding, and a re-registration manifest that verifies and lists this
    /// device as its one Chat device, with this identity, registration id
    /// and suite. The
    /// server then checks the prekey signatures (`400 badSignature`), the
    /// token, and the manifest's place in the chain.
    pub fn validate(&self) -> Result<(), String> {
        decode_identity_key("identityKey", &self.identity_key)?;
        decode_device_credential(&self.credential)?;
        check_registration_id(self.registration_id)?;
        if self.signed_pre_key.signature.is_none() {
            return Err("a signed prekey must carry its signature".into());
        }
        match &self.registration {
            DeviceRegistrationV1::Link { link_token } => {
                decode_link_token(link_token)?;
                Ok(())
            }
            DeviceRegistrationV1::Reregistration { manifest } => {
                manifest.verify()?;
                if manifest.identity_key.as_deref() != Some(self.identity_key.as_str()) {
                    return Err("the manifest lists another identity".into());
                }
                let chat: Vec<&AccountManifestDeviceV3> = manifest
                    .devices
                    .iter()
                    .filter(|device| device.chat.is_some())
                    .collect();
                let others: Vec<u32> = manifest
                    .devices
                    .iter()
                    .filter(|device| device.chat.is_none())
                    .map(|device| device.device_id)
                    .collect();
                match chat.as_slice() {
                    [device]
                        if device.kind == DeviceKind::Chat
                            && device.device_id == reregistration_device_id(&others)
                            && device.chat
                                == Some(ChatDeviceKeysV3 {
                                    direct_chat_suite: self.suite,
                                    registration_id: self.registration_id,
                                }) =>
                    {
                        Ok(())
                    }
                    _ => Err(
                        "a re-registration manifest lists this device as its one Chat device"
                            .into(),
                    ),
                }
            }
        }
    }
}

/// `POST /api/chat/keys/check` (Signal's `/v2/keys/check`): the device's
/// digest of what it believes the server holds for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatKeysCheckRequest {
    /// Lowercase hex of [`repeated_use_keys_digest`].
    pub digest: String,
}

/// SHA-256 over the identity key and the device's repeated-use keys, as
/// Signal's `KeysController.checkKeys` (with Kutup's domain). Inputs are the
/// libsignal-serialized public keys.
pub fn repeated_use_keys_digest(
    identity_key: &[u8],
    signed_pre_key_id: u32,
    signed_pre_key: &[u8],
    last_resort_key_id: u32,
    last_resort_key: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(kutup_crypto::labels::CHAT_KEYS_CHECK_V1);
    for (id, key) in [
        (None, identity_key),
        (Some(signed_pre_key_id), signed_pre_key),
        (Some(last_resort_key_id), last_resort_key),
    ] {
        if let Some(id) = id {
            hasher.update(u64::from(id).to_be_bytes());
        }
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// The accountIdentity sync
// ---------------------------------------------------------------------------

/// The body of a `kind::ACCOUNT_IDENTITY` sync (Signal's `PniChangeNumber`):
/// a distribution's message to one kept device. Hidden; never history.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountIdentityBody {
    pub identity_key_public: String,
    pub identity_key_private: String,
    /// The device's new registration id.
    pub registration_id: u32,
    /// libsignal `SignedPreKeyRecord`, serialized, private part included.
    pub signed_pre_key: String,
    /// libsignal `KyberPreKeyRecord`, serialized, private part included.
    pub last_resort_kyber_pre_key: String,
    /// The manifest that lists the identity and this registration id; the
    /// device checks it as it checks a provisioning message.
    pub manifest_sequence: u64,
    pub manifest_hash: String,
}

impl AccountIdentityBody {
    pub fn validate(&self) -> Result<(), String> {
        decode_identity_key("identityKeyPublic", &self.identity_key_public)?;
        decode_canonical_base64_exact(
            "identityKeyPrivate",
            &self.identity_key_private,
            IDENTITY_PRIVATE_KEY_LEN,
        )?;
        check_registration_id(self.registration_id)?;
        decode_canonical_base64_bounded(
            "signedPreKey",
            &self.signed_pre_key,
            MAX_PREKEY_RECORD_BYTES,
        )?;
        decode_canonical_base64_bounded(
            "lastResortKyberPreKey",
            &self.last_resort_kyber_pre_key,
            MAX_PREKEY_RECORD_BYTES,
        )?;
        if self.manifest_sequence == 0 {
            return Err("manifestSequence must be positive".into());
        }
        decode_lower_hex_32("manifestHash", &self.manifest_hash)?;
        Ok(())
    }
}

/// Never prints a private key.
impl std::fmt::Debug for AccountIdentityBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountIdentityBody")
            .field("registration_id", &self.registration_id)
            .field("manifest_sequence", &self.manifest_sequence)
            .finish_non_exhaustive()
    }
}

impl Drop for AccountIdentityBody {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.identity_key_private);
        zeroize::Zeroize::zeroize(&mut self.signed_pre_key);
        zeroize::Zeroize::zeroize(&mut self.last_resort_kyber_pre_key);
    }
}

#[cfg(test)]
mod tests;
