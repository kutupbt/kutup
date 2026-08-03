//! Signal-style encrypted profile primitives.
//!
//! Kutup keeps Signal's random 32-byte profile key and fixed display-name
//! padding buckets, while its purpose-specific suite uses XChaCha20-Poly1305,
//! canonical account/revision binding and HKDF-separated field keys.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::db::{LocalProfile, PeerProfile};
use crate::error::{ChatError, Result};
use kutup_chat_proto::{
    capability_hash, decode_profile_envelope, derive_delivery_capability,
    encode_profile_envelope_header, ChatProfileResponse, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, ProfileSuiteId, PutChatProfileRequest, MAX_PROFILE_AVATAR_BYTES,
    PROFILE_NAME_PADDED_LENGTHS,
};

pub const PROFILE_KEY_BYTES: usize = 32;
pub const PROFILE_ACCESS_KEY_BYTES: usize = 16;
pub const MAX_AVATAR_BYTES: usize = MAX_PROFILE_AVATAR_BYTES;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const NAME_PADDED_LENGTHS: [usize; 2] = PROFILE_NAME_PADDED_LENGTHS;
const VERSION_INFO: &[u8] = b"kutup-chat-profile-version-v1";
const ACCESS_INFO: &[u8] = b"kutup-chat-profile-access-v1";
const WRAP_INFO: &[u8] = b"kutup-chat-profile-wrap-v1";
const ENVELOPE_KEY_SALT: &[u8] = b"kutup/profile-envelope/key/v1\0";

pub fn derive_wrapping_key(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    hkdf_expand(master_key, WRAP_INFO)
}

pub fn profile_version(key: &[u8]) -> Result<String> {
    let key = profile_key(key)?;
    Ok(hex::encode(hkdf_expand::<32>(&key, VERSION_INFO)?))
}

pub fn profile_access_key(key: &[u8]) -> Result<[u8; PROFILE_ACCESS_KEY_BYTES]> {
    let key = profile_key(key)?;
    hkdf_expand(&key, ACCESS_INFO)
}

pub fn access_key_verifier(access_key: &[u8]) -> String {
    hex::encode(Sha256::digest(access_key))
}

pub fn validate_display_name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ChatError::Invalid(
            "profile display name is required".into(),
        ));
    }
    if value.chars().count() > 80
        || value.len() > NAME_PADDED_LENGTHS[1]
        || value.chars().any(char::is_control)
    {
        return Err(ChatError::Invalid(
            "profile display name must be at most 80 non-control characters".into(),
        ));
    }
    Ok(value.to_string())
}

pub fn validate_avatar(avatar: Option<&[u8]>, content_type: Option<&str>) -> Result<()> {
    match (avatar, content_type) {
        (None, None) => Ok(()),
        (Some(bytes), Some(kind))
            if !bytes.is_empty()
                && bytes.len() <= MAX_AVATAR_BYTES
                && avatar_type_code(kind).is_some() =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => Err(ChatError::Invalid(
            "profile avatar must be a non-empty PNG, JPEG, or WebP under 512 KiB".into(),
        )),
        _ => Err(ChatError::Invalid(
            "profile avatar bytes and content type must be provided together".into(),
        )),
    }
}

pub fn create_local_profile<R: Rng + CryptoRng>(
    display_name: &str,
    avatar: Option<Vec<u8>>,
    avatar_content_type: Option<String>,
    source_device_id: u32,
    wrapping_key: &[u8; 32],
    canonical_recipient: &str,
    rng: &mut R,
) -> Result<LocalProfile> {
    let mut key = vec![0u8; PROFILE_KEY_BYTES];
    rng.fill(key.as_mut_slice());
    prepare_local_profile(
        LocalProfileDraft {
            key,
            display_name,
            avatar,
            avatar_content_type,
            revision: 1,
            source_device_id,
        },
        wrapping_key,
        canonical_recipient,
        rng,
    )
}

pub(crate) struct LocalProfileUpdate<'a> {
    pub display_name: &'a str,
    pub avatar: Option<Vec<u8>>,
    pub avatar_content_type: Option<String>,
    pub source_device_id: u32,
    pub wrapping_key: &'a [u8; 32],
    pub canonical_recipient: &'a str,
}

pub(crate) fn update_local_profile<R: Rng + CryptoRng>(
    current: &LocalProfile,
    update: LocalProfileUpdate<'_>,
    rng: &mut R,
) -> Result<LocalProfile> {
    let LocalProfileUpdate {
        display_name,
        avatar,
        avatar_content_type,
        source_device_id,
        wrapping_key,
        canonical_recipient,
    } = update;
    let revision = current
        .revision
        .checked_add(1)
        .ok_or_else(|| ChatError::Invalid("profile revision is exhausted".into()))?;
    prepare_local_profile(
        LocalProfileDraft {
            key: current.key.clone(),
            display_name,
            avatar,
            avatar_content_type,
            revision,
            source_device_id,
        },
        wrapping_key,
        canonical_recipient,
        rng,
    )
}

pub fn rotate_local_profile<R: Rng + CryptoRng>(
    current: &LocalProfile,
    source_device_id: u32,
    wrapping_key: &[u8; 32],
    canonical_recipient: &str,
    rng: &mut R,
) -> Result<LocalProfile> {
    let mut key = vec![0u8; PROFILE_KEY_BYTES];
    rng.fill(key.as_mut_slice());
    let revision = current
        .revision
        .checked_add(1)
        .ok_or_else(|| ChatError::Invalid("profile revision is exhausted".into()))?;
    prepare_local_profile(
        LocalProfileDraft {
            key,
            display_name: &current.display_name,
            avatar: current.avatar.clone(),
            avatar_content_type: current.avatar_content_type.clone(),
            revision,
            source_device_id,
        },
        wrapping_key,
        canonical_recipient,
        rng,
    )
}

/// Reapply a locally intended profile over a newer linked-device revision.
/// If the two devices disagree on the random profile key, generate another
/// fresh key so a stale device can never accidentally undo a block rotation.
pub(crate) fn rebase_local_profile<R: Rng + CryptoRng>(
    desired: &LocalProfile,
    remote: &LocalProfile,
    source_device_id: u32,
    wrapping_key: &[u8; 32],
    canonical_recipient: &str,
    rng: &mut R,
) -> Result<LocalProfile> {
    let rebased = update_local_profile(
        remote,
        LocalProfileUpdate {
            display_name: &desired.display_name,
            avatar: desired.avatar.clone(),
            avatar_content_type: desired.avatar_content_type.clone(),
            source_device_id,
            wrapping_key,
            canonical_recipient,
        },
        rng,
    )?;
    if desired.key == remote.key {
        Ok(rebased)
    } else {
        rotate_local_profile(
            &rebased,
            source_device_id,
            wrapping_key,
            canonical_recipient,
            rng,
        )
    }
}

pub fn open_own_profile(
    encrypted: &PutChatProfileRequest,
    wrapping_key: &[u8; 32],
    canonical_recipient: &str,
) -> Result<LocalProfile> {
    validate_profile_request_context(encrypted, canonical_recipient)?;
    let wrapped_context = profile_context(ProfileEnvelopePurpose::WrappedProfileKey, encrypted)?;
    let key = decrypt_b64(&encrypted.wrapped_key, wrapping_key, &wrapped_context)?;
    profile_key(&key)?;
    if profile_version(&key)? != encrypted.version {
        return Err(ChatError::Content(
            "wrapped profile key does not match profile version".into(),
        ));
    }
    let access = profile_access_key(&key)?;
    if access_key_verifier(&access) != encrypted.access_key_verifier {
        return Err(ChatError::Content(
            "wrapped profile key does not match access verifier".into(),
        ));
    }
    let delivery = derive_delivery_capability(
        key.as_slice()
            .try_into()
            .map_err(|_| ChatError::Content("wrapped profile key has an invalid length".into()))?,
        canonical_recipient,
    )
    .map_err(ChatError::Content)?;
    if hex::encode(capability_hash(&delivery)) != encrypted.delivery_capability_verifier {
        return Err(ChatError::Content(
            "wrapped profile key does not match delivery capability verifier".into(),
        ));
    }
    let (display_name, avatar, avatar_content_type) = decrypt_profile_items(
        &encrypted.name,
        encrypted.avatar.as_deref(),
        &key,
        &encrypted.account,
        &encrypted.version,
        encrypted.revision,
        encrypted.source_device_id,
    )?;
    Ok(LocalProfile {
        key,
        display_name,
        avatar,
        avatar_content_type,
        revision: encrypted.revision,
        source_device_id: encrypted.source_device_id,
        pending_upload: None,
        broadcast_pending: false,
    })
}

pub fn open_peer_profile(
    peer: impl Into<String>,
    encrypted: &ChatProfileResponse,
    key: &[u8],
) -> Result<PeerProfile> {
    let peer = peer.into();
    if encrypted.suite != ProfileSuiteId::XChaCha20Poly1305V1 || encrypted.account != peer {
        return Err(ChatError::Content(
            "encrypted peer profile context does not match the requested account".into(),
        ));
    }
    if profile_version(key)? != encrypted.version {
        return Err(ChatError::Content(
            "peer profile key does not match profile version".into(),
        ));
    }
    let (display_name, avatar, avatar_content_type) = decrypt_profile_items(
        &encrypted.name,
        encrypted.avatar.as_deref(),
        key,
        &encrypted.account,
        &encrypted.version,
        encrypted.revision,
        encrypted.source_device_id,
    )?;
    Ok(PeerProfile {
        peer,
        key: key.to_vec(),
        display_name: Some(display_name),
        avatar,
        avatar_content_type,
        revision: encrypted.revision,
        source_device_id: encrypted.source_device_id,
    })
}

pub fn profile_key_base64(profile: &LocalProfile) -> Result<String> {
    profile_key(&profile.key)?;
    Ok(STANDARD.encode(&profile.key))
}

pub fn decode_shared_profile_key(encoded: &str) -> Result<Vec<u8>> {
    let key = STANDARD
        .decode(encoded)
        .map_err(|_| ChatError::Content("profileKey must be standard base64".into()))?;
    profile_key(&key)?;
    Ok(key)
}

struct LocalProfileDraft<'a> {
    key: Vec<u8>,
    display_name: &'a str,
    avatar: Option<Vec<u8>>,
    avatar_content_type: Option<String>,
    revision: u64,
    source_device_id: u32,
}

fn prepare_local_profile<R: Rng + CryptoRng>(
    draft: LocalProfileDraft<'_>,
    wrapping_key: &[u8; 32],
    canonical_recipient: &str,
    rng: &mut R,
) -> Result<LocalProfile> {
    let LocalProfileDraft {
        key,
        display_name,
        avatar,
        avatar_content_type,
        revision,
        source_device_id,
    } = draft;
    profile_key(&key)?;
    let display_name = validate_display_name(display_name)?;
    validate_avatar(avatar.as_deref(), avatar_content_type.as_deref())?;
    let version = profile_version(&key)?;
    let name = encrypt_name(
        &display_name,
        &key,
        canonical_recipient,
        &version,
        revision,
        source_device_id,
        rng,
    )?;
    let avatar_ciphertext = encrypt_avatar(
        avatar.as_deref(),
        avatar_content_type.as_deref(),
        &key,
        canonical_recipient,
        &version,
        revision,
        source_device_id,
        rng,
    )?;
    let wrapped_context = ProfileEnvelopeContextV1::new(
        ProfileEnvelopePurpose::WrappedProfileKey,
        canonical_recipient,
        &version,
        revision,
        source_device_id,
    )
    .map_err(ChatError::Invalid)?;
    let wrapped_key = encrypt_b64(&key, wrapping_key, &wrapped_context, rng)?;
    let access_key = profile_access_key(&key)?;
    let delivery_capability = derive_delivery_capability(
        key.as_slice()
            .try_into()
            .map_err(|_| ChatError::Invalid("profile key has an invalid length".into()))?,
        canonical_recipient,
    )
    .map_err(ChatError::Invalid)?;
    let pending_upload = PutChatProfileRequest {
        suite: ProfileSuiteId::XChaCha20Poly1305V1,
        account: canonical_recipient.to_string(),
        version,
        revision,
        source_device_id,
        name,
        avatar: avatar_ciphertext,
        wrapped_key,
        access_key_verifier: access_key_verifier(&access_key),
        delivery_capability_verifier: hex::encode(capability_hash(&delivery_capability)),
    };
    Ok(LocalProfile {
        key,
        display_name,
        avatar,
        avatar_content_type,
        revision,
        source_device_id,
        pending_upload: Some(pending_upload),
        broadcast_pending: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn encrypt_name<R: Rng + CryptoRng>(
    value: &str,
    key: &[u8],
    account: &str,
    version: &str,
    revision: u64,
    source_device_id: u32,
    rng: &mut R,
) -> Result<String> {
    let bytes = value.as_bytes();
    let padded_len = NAME_PADDED_LENGTHS
        .into_iter()
        .find(|length| bytes.len() <= *length)
        .ok_or_else(|| ChatError::Invalid("profile display name is too large".into()))?;
    let mut padded = vec![0u8; padded_len];
    padded[..bytes.len()].copy_from_slice(bytes);
    let context = ProfileEnvelopeContextV1::new(
        ProfileEnvelopePurpose::DisplayName,
        account,
        version,
        revision,
        source_device_id,
    )
    .map_err(ChatError::Invalid)?;
    encrypt_b64(&padded, &profile_key(key)?, &context, rng)
}

#[allow(clippy::too_many_arguments)]
fn encrypt_avatar<R: Rng + CryptoRng>(
    avatar: Option<&[u8]>,
    content_type: Option<&str>,
    key: &[u8],
    account: &str,
    version: &str,
    revision: u64,
    source_device_id: u32,
    rng: &mut R,
) -> Result<Option<String>> {
    let (Some(avatar), Some(content_type)) = (avatar, content_type) else {
        return Ok(None);
    };
    validate_avatar(Some(avatar), Some(content_type))?;
    let mut plaintext = Vec::with_capacity(avatar.len() + 1);
    plaintext.push(avatar_type_code(content_type).expect("validated avatar type"));
    plaintext.extend_from_slice(avatar);
    let context = ProfileEnvelopeContextV1::new(
        ProfileEnvelopePurpose::Avatar,
        account,
        version,
        revision,
        source_device_id,
    )
    .map_err(ChatError::Invalid)?;
    encrypt_b64(&plaintext, &profile_key(key)?, &context, rng).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn decrypt_profile_items(
    encrypted_name: &str,
    encrypted_avatar: Option<&str>,
    key: &[u8],
    account: &str,
    version: &str,
    revision: u64,
    source_device_id: u32,
) -> Result<(String, Option<Vec<u8>>, Option<String>)> {
    let key = profile_key(key)?;
    let name_context = ProfileEnvelopeContextV1::new(
        ProfileEnvelopePurpose::DisplayName,
        account,
        version,
        revision,
        source_device_id,
    )
    .map_err(ChatError::Content)?;
    let padded = decrypt_b64(encrypted_name, &key, &name_context)?;
    if !NAME_PADDED_LENGTHS.contains(&padded.len()) {
        return Err(ChatError::Content(
            "encrypted profile name has an invalid padded length".into(),
        ));
    }
    let end = padded
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(padded.len());
    if padded[end..].iter().any(|byte| *byte != 0) {
        return Err(ChatError::Content("profile name padding is invalid".into()));
    }
    let display_name = std::str::from_utf8(&padded[..end])
        .map_err(|_| ChatError::Content("profile display name is not UTF-8".into()))?;
    let display_name = validate_display_name(display_name)?;

    let (avatar, avatar_content_type) = match encrypted_avatar {
        None => (None, None),
        Some(value) => {
            let avatar_context = ProfileEnvelopeContextV1::new(
                ProfileEnvelopePurpose::Avatar,
                account,
                version,
                revision,
                source_device_id,
            )
            .map_err(ChatError::Content)?;
            let plaintext = decrypt_b64(value, &key, &avatar_context)?;
            let (&kind, bytes) = plaintext
                .split_first()
                .ok_or_else(|| ChatError::Content("encrypted profile avatar is empty".into()))?;
            if bytes.is_empty() || bytes.len() > MAX_AVATAR_BYTES {
                return Err(ChatError::Content(
                    "encrypted profile avatar has an invalid size".into(),
                ));
            }
            let content_type = avatar_type_name(kind)
                .ok_or_else(|| ChatError::Content("profile avatar type is invalid".into()))?;
            (Some(bytes.to_vec()), Some(content_type.to_string()))
        }
    };
    Ok((display_name, avatar, avatar_content_type))
}

fn encrypt_b64<R: Rng + CryptoRng>(
    plaintext: &[u8],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
    rng: &mut R,
) -> Result<String> {
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill(&mut nonce);
    encrypt_b64_with_nonce(plaintext, root_key, context, &nonce)
}

fn encrypt_b64_with_nonce(
    plaintext: &[u8],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String> {
    let ciphertext_len = u32::try_from(plaintext.len() + TAG_BYTES)
        .map_err(|_| ChatError::Invalid("encrypted profile item is too large".into()))?;
    let header = encode_profile_envelope_header(context, nonce, ciphertext_len)
        .map_err(ChatError::Invalid)?;
    let key = profile_envelope_key(root_key, context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| ChatError::Protocol("invalid profile envelope key".into()))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| ChatError::Protocol("profile encryption failed".into()))?;
    let mut encoded = header;
    encoded.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(encoded))
}

fn decrypt_b64(
    encoded: &str,
    root_key: &[u8; 32],
    expected: &ProfileEnvelopeContextV1,
) -> Result<Vec<u8>> {
    let parsed = decode_profile_envelope(encoded).map_err(ChatError::Content)?;
    if parsed.context != *expected {
        return Err(ChatError::Content(
            "encrypted profile envelope context does not match".into(),
        ));
    }
    let key = profile_envelope_key(root_key, expected)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| ChatError::Protocol("invalid profile envelope key".into()))?;
    cipher
        .decrypt(
            XNonce::from_slice(&parsed.nonce),
            Payload {
                msg: &parsed.ciphertext,
                aad: &parsed.aad,
            },
        )
        .map_err(|_| ChatError::Protocol("profile decryption failed".into()))
}

fn profile_envelope_key(
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(ENVELOPE_KEY_SALT), root_key);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&context.key_derivation_info(), output.as_mut_slice())
        .map_err(|_| ChatError::Protocol("profile envelope key derivation failed".into()))?;
    Ok(output)
}

fn profile_context(
    purpose: ProfileEnvelopePurpose,
    profile: &PutChatProfileRequest,
) -> Result<ProfileEnvelopeContextV1> {
    ProfileEnvelopeContextV1::new(
        purpose,
        &profile.account,
        &profile.version,
        profile.revision,
        profile.source_device_id,
    )
    .map_err(ChatError::Content)
}

fn validate_profile_request_context(
    profile: &PutChatProfileRequest,
    canonical_recipient: &str,
) -> Result<()> {
    if profile.suite != ProfileSuiteId::XChaCha20Poly1305V1
        || profile.account != canonical_recipient
    {
        return Err(ChatError::Content(
            "encrypted profile suite or account does not match".into(),
        ));
    }
    Ok(())
}

fn profile_key(key: &[u8]) -> Result<[u8; PROFILE_KEY_BYTES]> {
    key.try_into()
        .map_err(|_| ChatError::Invalid("profile key must be exactly 32 bytes".into()))
}

fn hkdf_expand<const N: usize>(key: &[u8], info: &[u8]) -> Result<[u8; N]> {
    let hkdf = Hkdf::<Sha256>::new(None, key);
    let mut output = [0u8; N];
    hkdf.expand(info, &mut output)
        .map_err(|_| ChatError::Protocol("profile key derivation failed".into()))?;
    Ok(output)
}

fn avatar_type_code(value: &str) -> Option<u8> {
    match value {
        "image/png" => Some(1),
        "image/jpeg" => Some(2),
        "image/webp" => Some(3),
        _ => None,
    }
}

fn avatar_type_name(value: u8) -> Option<&'static str> {
    match value {
        1 => Some("image/png"),
        2 => Some("image/jpeg"),
        3 => Some("image/webp"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const RECIPIENT: &str = "alice@example.com";

    #[test]
    fn signal_style_name_padding_and_profile_round_trip() {
        let mut rng = StdRng::seed_from_u64(7);
        let wrapping = derive_wrapping_key(&[9; 32]).unwrap();
        let profile = create_local_profile(
            "Alice Example",
            Some(vec![1, 2, 3, 4]),
            Some("image/png".into()),
            3,
            &wrapping,
            RECIPIENT,
            &mut rng,
        )
        .unwrap();
        let upload = profile.pending_upload.as_ref().unwrap();
        let encrypted_name = decode_profile_envelope(&upload.name).unwrap();
        assert_eq!(
            encrypted_name.context.purpose,
            ProfileEnvelopePurpose::DisplayName
        );
        assert_eq!(encrypted_name.ciphertext.len(), 53 + TAG_BYTES);

        let restored = open_own_profile(upload, &wrapping, RECIPIENT).unwrap();
        assert_eq!(restored.display_name, "Alice Example");
        assert_eq!(restored.avatar, Some(vec![1, 2, 3, 4]));
        assert_eq!(restored.avatar_content_type.as_deref(), Some("image/png"));
        assert_eq!(restored.key, profile.key);
    }

    #[test]
    fn rotation_revokes_the_old_version_and_access_capability() {
        let mut rng = StdRng::seed_from_u64(8);
        let wrapping = derive_wrapping_key(&[4; 32]).unwrap();
        let before =
            create_local_profile("Alice", None, None, 1, &wrapping, RECIPIENT, &mut rng).unwrap();
        let after = rotate_local_profile(&before, 1, &wrapping, RECIPIENT, &mut rng).unwrap();
        assert_ne!(
            profile_version(&before.key).unwrap(),
            profile_version(&after.key).unwrap()
        );
        assert_ne!(
            profile_access_key(&before.key).unwrap(),
            profile_access_key(&after.key).unwrap()
        );
        assert_eq!(after.revision, before.revision + 1);
    }

    #[test]
    fn decryption_rejects_the_wrong_profile_key() {
        let mut rng = StdRng::seed_from_u64(9);
        let wrapping = derive_wrapping_key(&[5; 32]).unwrap();
        let profile =
            create_local_profile("Alice", None, None, 1, &wrapping, RECIPIENT, &mut rng).unwrap();
        let response = ChatProfileResponse::from(profile.pending_upload.as_ref().unwrap());
        assert!(open_peer_profile(RECIPIENT, &response, &[7; 32]).is_err());
    }

    #[test]
    fn profile_envelope_has_a_stable_canonical_vector() {
        let context = ProfileEnvelopeContextV1::new(
            ProfileEnvelopePurpose::DisplayName,
            RECIPIENT,
            &"11".repeat(32),
            7,
            3,
        )
        .unwrap();
        let encoded =
            encrypt_b64_with_nonce(&[0x41; 53], &[0x22; 32], &context, &[0x44; 24]).unwrap();
        assert_eq!(
            encoded,
            "S1VUUFBFMQAAAQEAAAAAAAAAAAcAAAADEREREREREREREREREREREREREREREREREREREREREREAEWFsaWNlQGV4YW1wbGUuY29tREREREREREREREREREREREREREREREREAAAARYaNMOVilU0bL2+uvJN52+hDVIssTxhNsQ+9b/uJOu6FinFZXzXyfG6+1hwjfUPeLGEIQxueS79XT22WSsTGaDITowT0Tg=="
        );
    }

    #[test]
    fn stale_linked_device_rebase_preserves_edit_without_undoing_rotation() {
        let mut rng = StdRng::seed_from_u64(10);
        let wrapping = derive_wrapping_key(&[6; 32]).unwrap();
        let original =
            create_local_profile("Alice", None, None, 1, &wrapping, RECIPIENT, &mut rng).unwrap();
        let desired = update_local_profile(
            &original,
            LocalProfileUpdate {
                display_name: "Alice Local Edit",
                avatar: None,
                avatar_content_type: None,
                source_device_id: 1,
                wrapping_key: &wrapping,
                canonical_recipient: RECIPIENT,
            },
            &mut rng,
        )
        .unwrap();
        let remote = rotate_local_profile(&original, 2, &wrapping, RECIPIENT, &mut rng).unwrap();

        let rebased =
            rebase_local_profile(&desired, &remote, 1, &wrapping, RECIPIENT, &mut rng).unwrap();
        assert_eq!(rebased.display_name, "Alice Local Edit");
        assert!(rebased.revision > remote.revision);
        assert_ne!(rebased.key, original.key);
        assert_ne!(rebased.key, remote.key);
    }
}
