//! Signal-style encrypted profiles: chat-core's side.
//!
//! Kutup keeps Signal's random 32-byte profile key and fixed display-name
//! padding buckets, while its purpose-specific suite uses XChaCha20-Poly1305,
//! canonical account/revision binding and HKDF-separated field keys. The
//! format and its crypto are kutup-crypto's (`kutup_crypto::chat_profile`,
//! docs/plans/chat-crypto-move.md); this module keeps the local and peer
//! profiles the Chat store holds, and their flows.
//!
//! The profile is a statement to peers about an account, so its envelopes
//! name the account. The account's own copy of the profile key (the wrapped
//! key) is an account record (purpose `ChatProfileKeyWrap`,
//! docs/plans/w1-account-record.md) under the master key, bound to the
//! account's key binding, the profile version and the revision.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_record::MasterKeyGeneration;
pub use kutup_crypto::chat_profile::ProfileOwnerKey;
use kutup_crypto::chat_profile::{self as crypto, ProfileContents, SealedProfile};
use kutup_crypto::error::CryptoError;
use rand::{CryptoRng, Rng};

use crate::db::{LocalProfile, PeerProfile};
use crate::error::{ChatError, Result};
#[cfg(test)]
use kutup_chat_proto::{
    capability_hash, decode_profile_envelope, derive_delivery_capability, ProfileEnvelopeContextV1,
    ProfileEnvelopePurpose, PROFILE_ABOUT_PADDED_LENGTHS, PROFILE_NAME_PADDED_LENGTHS,
};
use kutup_chat_proto::{AccountRef, ChatProfileResponse, PutChatProfileRequest};

pub const PROFILE_KEY_BYTES: usize = crypto::PROFILE_KEY_BYTES;
pub const PROFILE_ACCESS_KEY_BYTES: usize = crypto::PROFILE_ACCESS_KEY_BYTES;
pub const MAX_AVATAR_BYTES: usize = crypto::MAX_PROFILE_AVATAR_BYTES;
#[cfg(test)]
const NONCE_BYTES: usize = 24;
#[cfg(test)]
const TAG_BYTES: usize = 16;
#[cfg(test)]
const NAME_PADDED_LENGTHS: [usize; 2] = PROFILE_NAME_PADDED_LENGTHS;

/// A refusal of what was asked to be sealed.
fn invalid(error: CryptoError) -> ChatError {
    ChatError::Invalid(error.to_string())
}

/// A sealed profile that doesn't open or check out.
fn content(error: CryptoError) -> ChatError {
    ChatError::Content(error.to_string())
}

/// What the account's own copy of its profile key is sealed for: the master
/// key and the account's key binding (`session.envelopeBinding`).
/// Chat's devices seal with the first generation until master-key rotation
/// exists, as its lists do.
pub fn profile_owner_key(master_key: &[u8; 32], binding: &str) -> Result<ProfileOwnerKey> {
    owner_at(master_key, MasterKeyGeneration::FIRST, binding)
}

fn owner_at(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
) -> Result<ProfileOwnerKey> {
    ProfileOwnerKey::new(master_key, generation, binding).map_err(invalid)
}

pub fn profile_version(key: &[u8]) -> Result<String> {
    crypto::profile_version(key).map_err(invalid)
}

pub fn profile_access_key(key: &[u8]) -> Result<[u8; PROFILE_ACCESS_KEY_BYTES]> {
    crypto::profile_access_key(key).map_err(invalid)
}

pub fn validate_display_name(value: &str) -> Result<String> {
    crypto::validate_display_name(value).map_err(invalid)
}

/// The "about" line: trimmed, at most 140 characters (Signal's limit), one
/// line; empty means none.
pub fn validate_about(value: Option<&str>) -> Result<Option<String>> {
    crypto::validate_about(value).map_err(invalid)
}

pub fn validate_avatar(avatar: Option<&[u8]>, content_type: Option<&str>) -> Result<()> {
    crypto::validate_avatar(avatar, content_type).map_err(invalid)
}

fn fresh_key<R: Rng + CryptoRng>(rng: &mut R) -> Vec<u8> {
    let mut key = vec![0u8; PROFILE_KEY_BYTES];
    rng.fill(key.as_mut_slice());
    key
}

pub fn create_local_profile<R: Rng + CryptoRng>(
    display_name: &str,
    avatar: Option<Vec<u8>>,
    avatar_content_type: Option<String>,
    source_device_id: u32,
    owner: &ProfileOwnerKey,
    canonical_recipient: &AccountRef,
    rng: &mut R,
) -> Result<LocalProfile> {
    prepare_local_profile(
        LocalProfileDraft {
            key: fresh_key(rng),
            display_name,
            avatar,
            avatar_content_type,
            about: None,
            revision: 1,
            source_device_id,
        },
        owner,
        canonical_recipient,
    )
}

pub(crate) struct LocalProfileUpdate<'a> {
    pub display_name: &'a str,
    pub avatar: Option<Vec<u8>>,
    pub avatar_content_type: Option<String>,
    pub about: Option<String>,
    pub source_device_id: u32,
    pub owner: &'a ProfileOwnerKey,
    pub canonical_recipient: &'a AccountRef,
}

pub(crate) fn update_local_profile<R: Rng + CryptoRng>(
    current: &LocalProfile,
    update: LocalProfileUpdate<'_>,
    _rng: &mut R,
) -> Result<LocalProfile> {
    let LocalProfileUpdate {
        display_name,
        avatar,
        avatar_content_type,
        about,
        source_device_id,
        owner,
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
            about,
            revision,
            source_device_id,
        },
        owner,
        canonical_recipient,
    )
}

pub fn rotate_local_profile<R: Rng + CryptoRng>(
    current: &LocalProfile,
    source_device_id: u32,
    owner: &ProfileOwnerKey,
    canonical_recipient: &AccountRef,
    rng: &mut R,
) -> Result<LocalProfile> {
    let revision = current
        .revision
        .checked_add(1)
        .ok_or_else(|| ChatError::Invalid("profile revision is exhausted".into()))?;
    prepare_local_profile(
        LocalProfileDraft {
            key: fresh_key(rng),
            display_name: &current.display_name,
            avatar: current.avatar.clone(),
            avatar_content_type: current.avatar_content_type.clone(),
            about: current.about.clone(),
            revision,
            source_device_id,
        },
        owner,
        canonical_recipient,
    )
}

/// Reapply a locally intended profile over a newer linked-device revision.
/// If the two devices disagree on the random profile key, generate another
/// fresh key so a stale device can never accidentally undo a block rotation.
pub(crate) fn rebase_local_profile<R: Rng + CryptoRng>(
    desired: &LocalProfile,
    remote: &LocalProfile,
    source_device_id: u32,
    owner: &ProfileOwnerKey,
    canonical_recipient: &AccountRef,
    rng: &mut R,
) -> Result<LocalProfile> {
    let rebased = update_local_profile(
        remote,
        LocalProfileUpdate {
            display_name: &desired.display_name,
            avatar: desired.avatar.clone(),
            avatar_content_type: desired.avatar_content_type.clone(),
            about: desired.about.clone(),
            source_device_id,
            owner,
            canonical_recipient,
        },
        rng,
    )?;
    if desired.key == remote.key {
        Ok(rebased)
    } else {
        rotate_local_profile(&rebased, source_device_id, owner, canonical_recipient, rng)
    }
}

/// What the account app edits (docs/plans/unified-profile.md).
#[cfg(any(test, all(feature = "wasm", target_arch = "wasm32")))]
pub struct AccountProfileUpdate {
    pub display_name: String,
    pub avatar: Option<Vec<u8>>,
    pub avatar_content_type: Option<String>,
    pub about: Option<String>,
}

/// Seal the account's next profile revision from the account app
/// (`kutup_crypto::chat_profile::seal_account_profile`). Returns the exact
/// upload.
#[cfg(any(test, all(feature = "wasm", target_arch = "wasm32")))]
pub fn seal_account_profile<R: Rng + CryptoRng>(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    current: Option<&PutChatProfileRequest>,
    update: AccountProfileUpdate,
    canonical_account: &AccountRef,
    binding: &str,
    _rng: &mut R,
) -> Result<PutChatProfileRequest> {
    let current = current.cloned().map(SealedProfile::from);
    let contents = ProfileContents {
        display_name: update.display_name,
        avatar: update.avatar,
        avatar_content_type: update.avatar_content_type,
        about: update.about,
    };
    crypto::seal_account_profile(
        &owner_at(master_key, generation, binding)?,
        current.as_ref(),
        &contents,
        canonical_account,
    )
    .map(PutChatProfileRequest::from)
    .map_err(invalid)
}

/// The account's own profile as the account app shows it.
#[cfg(any(test, all(feature = "wasm", target_arch = "wasm32")))]
pub fn open_account_profile(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    current: &PutChatProfileRequest,
    canonical_account: &AccountRef,
    binding: &str,
) -> Result<LocalProfile> {
    open_own_profile(
        current,
        &owner_at(master_key, generation, binding)?,
        canonical_account,
    )
}

pub fn open_own_profile(
    encrypted: &PutChatProfileRequest,
    owner: &ProfileOwnerKey,
    canonical_recipient: &AccountRef,
) -> Result<LocalProfile> {
    let opened = crypto::open_own_profile(
        &SealedProfile::from(encrypted.clone()),
        owner,
        canonical_recipient,
    )
    .map_err(content)?;
    Ok(LocalProfile {
        key: opened.key.to_vec(),
        display_name: opened.contents.display_name,
        avatar: opened.contents.avatar,
        avatar_content_type: opened.contents.avatar_content_type,
        about: opened.contents.about,
        revision: opened.revision,
        source_device_id: opened.source_device_id,
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
    let account = crate::address::parse_account(&peer)?;
    let opened = crypto::open_peer_profile(&SealedProfile::from(encrypted.clone()), &account, key)
        .map_err(content)?;
    Ok(PeerProfile {
        peer,
        key: key.to_vec(),
        display_name: Some(opened.contents.display_name),
        avatar: opened.contents.avatar,
        avatar_content_type: opened.contents.avatar_content_type,
        about: opened.contents.about,
        revision: opened.revision,
        source_device_id: opened.source_device_id,
    })
}

pub fn profile_key_base64(profile: &LocalProfile) -> Result<String> {
    crypto::profile_key(&profile.key).map_err(invalid)?;
    Ok(STANDARD.encode(&profile.key))
}

pub fn decode_shared_profile_key(encoded: &str) -> Result<Vec<u8>> {
    let key = STANDARD
        .decode(encoded)
        .map_err(|_| ChatError::Content("profileKey must be standard base64".into()))?;
    crypto::profile_key(&key).map_err(content)?;
    Ok(key)
}

struct LocalProfileDraft<'a> {
    key: Vec<u8>,
    display_name: &'a str,
    avatar: Option<Vec<u8>>,
    avatar_content_type: Option<String>,
    about: Option<String>,
    revision: u64,
    source_device_id: u32,
}

/// Seals a draft (`kutup_crypto::chat_profile::seal_profile`, which checks
/// its contents) and keeps it as the local profile, its upload pending.
fn prepare_local_profile(
    draft: LocalProfileDraft<'_>,
    owner: &ProfileOwnerKey,
    canonical_recipient: &AccountRef,
) -> Result<LocalProfile> {
    let key = crypto::profile_key(&draft.key).map_err(invalid)?;
    let display_name = validate_display_name(draft.display_name)?;
    validate_avatar(
        draft.avatar.as_deref(),
        draft.avatar_content_type.as_deref(),
    )?;
    let about = validate_about(draft.about.as_deref())?;
    let contents = ProfileContents {
        display_name: display_name.clone(),
        avatar: draft.avatar.clone(),
        avatar_content_type: draft.avatar_content_type.clone(),
        about: about.clone(),
    };
    let sealed = crypto::seal_profile(
        &key,
        &contents,
        draft.revision,
        draft.source_device_id,
        owner,
        canonical_recipient,
    )
    .map_err(invalid)?;
    Ok(LocalProfile {
        key: draft.key,
        display_name,
        avatar: draft.avatar,
        avatar_content_type: draft.avatar_content_type,
        about,
        revision: draft.revision,
        source_device_id: draft.source_device_id,
        pending_upload: Some(PutChatProfileRequest::from(sealed)),
        broadcast_pending: true,
    })
}

/// An item sealed under a given nonce (the tests' vectors).
#[cfg(test)]
fn encrypt_b64_with_nonce(
    plaintext: &[u8],
    root_key: &[u8; 32],
    context: &ProfileEnvelopeContextV1,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String> {
    crypto::seal_item_with_nonce(plaintext, root_key, context, nonce).map_err(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const RECIPIENT_KEY: &str = "aci:00000000-0000-4000-8000-2bd806c97f0e@example.com";
    static RECIPIENT: std::sync::LazyLock<AccountRef> =
        std::sync::LazyLock::new(|| RECIPIENT_KEY.parse().unwrap());
    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    /// The profile formats' canonical vectors
    /// (`crates/kutup-crypto/tests/vectors/profile-v1.json`), made from this
    /// code before it moves into kutup-crypto (docs/plans/chat-crypto-move.md):
    /// derived keys and verifiers, each item sealed under a fixed nonce, and a
    /// whole upload with what it opens to. `KUTUP_WRITE_PROFILE_VECTORS=1`
    /// writes the file; otherwise this code must reproduce it byte for byte.
    #[test]
    fn profile_formats_match_the_canonical_vectors() {
        use serde_json::json;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kutup-crypto/tests/vectors/profile-v1.json"
        );
        let master_key = [0x09u8; 32];
        let profile_key = [0x51u8; 32];
        let wrapping = profile_owner_key(&master_key, BINDING).unwrap();
        let version = profile_version(&profile_key).unwrap();
        let access = profile_access_key(&profile_key).unwrap();
        let delivery = derive_delivery_capability(&profile_key, &RECIPIENT).unwrap();
        let item = |purpose: ProfileEnvelopePurpose,
                    root: &[u8; 32],
                    plaintext: &[u8],
                    nonce: u8| {
            let context =
                ProfileEnvelopeContextV1::new(purpose, &RECIPIENT, &version, 4, 3).unwrap();
            json!({
                "purpose": format!("{purpose:?}"),
                "rootKey": STANDARD.encode(root),
                "revision": 4,
                "sourceDeviceId": 3,
                "nonce": STANDARD.encode([nonce; NONCE_BYTES]),
                "plaintext": STANDARD.encode(plaintext),
                "envelope": encrypt_b64_with_nonce(plaintext, root, &context, &[nonce; NONCE_BYTES]).unwrap(),
            })
        };
        let mut name = vec![0u8; NAME_PADDED_LENGTHS[0]];
        name[..13].copy_from_slice(b"Alice Example");
        let mut about = vec![0u8; PROFILE_ABOUT_PADDED_LENGTHS[0]];
        about[..9].copy_from_slice(b"Hello, Kt");
        let items = vec![
            item(
                ProfileEnvelopePurpose::DisplayName,
                &profile_key,
                &name,
                0x61,
            ),
            item(
                ProfileEnvelopePurpose::Avatar,
                &profile_key,
                &[1, 0x89, 0x50, 0x4e, 0x47],
                0x62,
            ),
            item(ProfileEnvelopePurpose::About, &profile_key, &about, 0x63),
        ];
        // A whole upload as today's code makes it (its random parts as they
        // fell), and what it opens to.
        let mut rng = StdRng::seed_from_u64(11);
        let made = create_local_profile(
            "Alice Example",
            Some(vec![0x89, 0x50, 0x4e, 0x47]),
            Some("image/png".into()),
            3,
            &wrapping,
            &RECIPIENT,
            &mut rng,
        )
        .unwrap();
        let upload = made.pending_upload.clone().unwrap();
        let opened = open_own_profile(&upload, &wrapping, &RECIPIENT).unwrap();
        let vectors = json!({
            "masterKey": STANDARD.encode(master_key),
            "binding": BINDING,
            "account": RECIPIENT_KEY,
            "profileKey": STANDARD.encode(profile_key),
            "version": version,
            "accessKey": STANDARD.encode(access),
            "accessKeyVerifier": crypto::access_key_verifier(&access),
            "deliveryCapabilityVerifier": hex::encode(capability_hash(&delivery)),
            "items": items,
            "upload": {
                "request": serde_json::to_value(&upload).unwrap(),
                "profileKey": STANDARD.encode(&opened.key),
                "displayName": opened.display_name,
                "avatar": STANDARD.encode(opened.avatar.as_deref().unwrap()),
                "avatarContentType": opened.avatar_content_type,
                "revision": opened.revision,
            },
        });
        let text = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
        if std::env::var_os("KUTUP_WRITE_PROFILE_VECTORS").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let kept: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut kept_without_upload = kept.clone();
        let mut made_without_upload = vectors.clone();
        // The upload's random parts are today's draw: what it opens to is
        // checked, and that the kept one opens the same way.
        kept_without_upload["upload"].take();
        made_without_upload["upload"].take();
        assert_eq!(made_without_upload, kept_without_upload);
        let kept_upload: PutChatProfileRequest =
            serde_json::from_value(kept["upload"]["request"].clone()).unwrap();
        let reopened = open_own_profile(&kept_upload, &wrapping, &RECIPIENT).unwrap();
        assert_eq!(STANDARD.encode(&reopened.key), kept["upload"]["profileKey"]);
        assert_eq!(reopened.display_name, kept["upload"]["displayName"]);
        assert_eq!(
            STANDARD.encode(reopened.avatar.unwrap()),
            kept["upload"]["avatar"]
        );
    }

    #[test]
    fn signal_style_name_padding_and_profile_round_trip() {
        let mut rng = StdRng::seed_from_u64(7);
        let wrapping = profile_owner_key(&[9; 32], BINDING).unwrap();
        let profile = create_local_profile(
            "Alice Example",
            Some(vec![1, 2, 3, 4]),
            Some("image/png".into()),
            3,
            &wrapping,
            &RECIPIENT,
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

        let restored = open_own_profile(upload, &wrapping, &RECIPIENT).unwrap();
        assert_eq!(restored.display_name, "Alice Example");
        assert_eq!(restored.avatar, Some(vec![1, 2, 3, 4]));
        assert_eq!(restored.avatar_content_type.as_deref(), Some("image/png"));
        assert_eq!(restored.key, profile.key);
    }

    #[test]
    fn rotation_revokes_the_old_version_and_access_capability() {
        let mut rng = StdRng::seed_from_u64(8);
        let wrapping = profile_owner_key(&[4; 32], BINDING).unwrap();
        let before =
            create_local_profile("Alice", None, None, 1, &wrapping, &RECIPIENT, &mut rng).unwrap();
        let after = rotate_local_profile(&before, 1, &wrapping, &RECIPIENT, &mut rng).unwrap();
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
        let wrapping = profile_owner_key(&[5; 32], BINDING).unwrap();
        let profile =
            create_local_profile("Alice", None, None, 1, &wrapping, &RECIPIENT, &mut rng).unwrap();
        let response = ChatProfileResponse::from(profile.pending_upload.as_ref().unwrap());
        assert!(open_peer_profile(RECIPIENT_KEY, &response, &[7; 32]).is_err());
    }

    #[test]
    fn profile_envelope_has_a_stable_canonical_vector() {
        let context = ProfileEnvelopeContextV1::new(
            ProfileEnvelopePurpose::DisplayName,
            &RECIPIENT,
            &"11".repeat(32),
            7,
            3,
        )
        .unwrap();
        let encoded =
            encrypt_b64_with_nonce(&[0x41; 53], &[0x22; 32], &context, &[0x44; 24]).unwrap();
        assert_eq!(
            encoded,
            "S1VUUFBFMQAAAQEAAAAAAAAAAAcAAAADEREREREREREREREREREREREREREREREREREREREREREAHQALZXhhbXBsZS5jb20AAAAAAABAAIAAK9gGyX8OREREREREREREREREREREREREREREREREAAAARRubdPnnHl7w4lkqUKFAIV1FnKmbfaHhj1CHrJNw7WKL2bb1XTvm246n7PdiYKbSbs9nuCj58HUhcu3j9oQpdTZeOlHvnA=="
        );
    }

    #[test]
    fn stale_linked_device_rebase_preserves_edit_without_undoing_rotation() {
        let mut rng = StdRng::seed_from_u64(10);
        let wrapping = profile_owner_key(&[6; 32], BINDING).unwrap();
        let original =
            create_local_profile("Alice", None, None, 1, &wrapping, &RECIPIENT, &mut rng).unwrap();
        let desired = update_local_profile(
            &original,
            LocalProfileUpdate {
                display_name: "Alice Local Edit",
                avatar: None,
                avatar_content_type: None,
                about: Some("Out hiking".into()),
                source_device_id: 1,
                owner: &wrapping,
                canonical_recipient: &RECIPIENT,
            },
            &mut rng,
        )
        .unwrap();
        let remote = rotate_local_profile(&original, 2, &wrapping, &RECIPIENT, &mut rng).unwrap();

        let rebased =
            rebase_local_profile(&desired, &remote, 1, &wrapping, &RECIPIENT, &mut rng).unwrap();
        assert_eq!(rebased.display_name, "Alice Local Edit");
        assert_eq!(rebased.about.as_deref(), Some("Out hiking"));
        assert!(rebased.revision > remote.revision);
        assert_ne!(rebased.key, original.key);
        assert_ne!(rebased.key, remote.key);
    }

    #[test]
    fn about_is_padded_encrypted_and_opened_by_owner_and_peer() {
        let mut rng = StdRng::seed_from_u64(11);
        let wrapping = profile_owner_key(&[7; 32], BINDING).unwrap();
        let original =
            create_local_profile("Alice", None, None, 1, &wrapping, &RECIPIENT, &mut rng).unwrap();
        let about = "Out hiking 🥾 until Monday";
        let updated = update_local_profile(
            &original,
            LocalProfileUpdate {
                display_name: "Alice",
                avatar: None,
                avatar_content_type: None,
                about: Some(format!("  {about}  ")),
                source_device_id: 1,
                owner: &wrapping,
                canonical_recipient: &RECIPIENT,
            },
            &mut rng,
        )
        .unwrap();
        assert_eq!(updated.about.as_deref(), Some(about));
        let upload = updated.pending_upload.clone().unwrap();
        // Only the bucket shows: 128 bytes of plaintext plus the tag.
        let envelope = decode_profile_envelope(upload.about.as_deref().unwrap()).unwrap();
        assert_eq!(envelope.ciphertext.len(), 128 + TAG_BYTES);
        let own = open_own_profile(&upload, &wrapping, &RECIPIENT).unwrap();
        assert_eq!(own.about.as_deref(), Some(about));
        let peer = open_peer_profile(
            RECIPIENT_KEY,
            &ChatProfileResponse::from(&upload),
            &updated.key,
        )
        .unwrap();
        assert_eq!(peer.about.as_deref(), Some(about));

        for bad in ["x".repeat(141), "two\nlines".to_string()] {
            assert!(validate_about(Some(&bad)).is_err(), "{bad:?}");
        }
        assert_eq!(validate_about(Some("   ")).unwrap(), None);
    }

    #[test]
    fn the_account_app_seals_and_reopens_the_profile_from_the_master_key() {
        let mut rng = rand::rng();
        let master = [7u8; 32];
        let first = seal_account_profile(
            &master,
            MasterKeyGeneration::FIRST,
            None,
            AccountProfileUpdate {
                display_name: "Ada".into(),
                avatar: None,
                avatar_content_type: None,
                about: Some("Counting things".into()),
            },
            &RECIPIENT,
            BINDING,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            (first.revision, first.source_device_id),
            (1, kutup_chat_proto::ACCOUNT_PROFILE_SOURCE)
        );
        let opened = open_account_profile(
            &master,
            MasterKeyGeneration::FIRST,
            &first,
            &RECIPIENT,
            BINDING,
        )
        .unwrap();
        assert_eq!(opened.display_name, "Ada");
        assert_eq!(opened.about.as_deref(), Some("Counting things"));

        let next = seal_account_profile(
            &master,
            MasterKeyGeneration::FIRST,
            Some(&first),
            AccountProfileUpdate {
                display_name: "Ada L.".into(),
                avatar: None,
                avatar_content_type: None,
                about: None,
            },
            &RECIPIENT,
            BINDING,
            &mut rng,
        )
        .unwrap();
        assert_eq!(next.revision, 2);
        assert_eq!(
            next.version, first.version,
            "same key: contacts keep reading it"
        );
        // A chat device opens it with the same master-derived wrapping key.
        let device_view = open_own_profile(
            &next,
            &profile_owner_key(&master, BINDING).unwrap(),
            &RECIPIENT,
        )
        .unwrap();
        assert_eq!(device_view.display_name, "Ada L.");
        assert_eq!(device_view.about, None);
        // Another master key, or another key binding, opens nothing.
        assert!(open_account_profile(
            &[8u8; 32],
            MasterKeyGeneration::FIRST,
            &next,
            &RECIPIENT,
            BINDING
        )
        .is_err());
        assert!(open_account_profile(
            &master,
            MasterKeyGeneration::FIRST,
            &next,
            &RECIPIENT,
            "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d"
        )
        .is_err());
        // The address is not a key binding.
        assert!(open_account_profile(
            &master,
            MasterKeyGeneration::FIRST,
            &next,
            &RECIPIENT,
            RECIPIENT_KEY
        )
        .is_err());
    }

    /// Checked-in vectors for the account's own copy of its profile key
    /// (`tests/vectors/profile-key-wrap-v1.json`): an account record
    /// (`ChatProfileKeyWrap`) under the master key, for the key binding, the
    /// profile version and the revision, and the values that must not open.
    /// Regenerate only for a deliberate format change:
    /// `KUTUP_WRITE_PROFILE_VECTORS=1 cargo test --locked --lib profile_wrap_vectors_write -- --ignored`.
    mod wrap_vectors {
        use super::*;
        use kutup_crypto::account_record::{
            self, AccountRecordPurpose, AccountRecordSuiteId, MasterKeyGeneration,
        };
        use serde::{Deserialize, Serialize};

        const PATH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/profile-key-wrap-v1.json"
        );
        const MASTER: [u8; 32] = [0x5a; 32];
        const OTHER_MASTER: [u8; 32] = [0x5b; 32];
        const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";
        const OTHER_BINDING: &str = "9e8d7c6b-5a49-4382-a716-05f4e3d2c1b0";
        const PROFILE_KEY: [u8; 32] = [0x21; 32];
        const NONCE: [u8; 24] = [0x44; 24];
        const REVISION: u64 = 3;

        #[derive(Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Vectors {
            master_key: String,
            binding: String,
            profile_key: String,
            profile_version: String,
            revision: u64,
            nonce: String,
            wrapped_key: String,
            refused: Vec<Refused>,
        }

        #[derive(Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Refused {
            case: String,
            /// The binding the opener holds.
            binding: String,
            /// The profile version and revision the opener expects.
            profile_version: String,
            revision: u64,
            wrapped_key: String,
        }

        fn version() -> String {
            profile_version(&PROFILE_KEY).unwrap()
        }

        fn wrapped(master: &[u8; 32], purpose: AccountRecordPurpose) -> String {
            STANDARD.encode(
                account_record::seal_suite(
                    AccountRecordSuiteId::V1,
                    &PROFILE_KEY,
                    master,
                    purpose,
                    MasterKeyGeneration::FIRST,
                    BINDING,
                    &hex::decode(version()).unwrap(),
                    Some(REVISION),
                    &NONCE,
                )
                .unwrap(),
            )
        }

        fn open(binding: &str, version: &str, revision: u64, wrapped: &str) -> Result<Vec<u8>> {
            let owner = profile_owner_key(&MASTER, binding)?;
            crypto::unwrap_profile_key(wrapped, &owner, version, revision)
                .map(|key| key.to_vec())
                .map_err(content)
        }

        fn refused(wrapped_key: &str) -> Vec<Refused> {
            let bytes = STANDARD.decode(wrapped_key).unwrap();
            let edit = |at: usize, value: u8| {
                let mut changed = bytes.clone();
                changed[at] = value;
                STANDARD.encode(changed)
            };
            let last = bytes.len() - 1;
            let other_version = profile_version(&[0x22; 32]).unwrap();
            let case =
                |case: &str, binding: &str, version: &str, revision: u64, wrapped_key: String| {
                    Refused {
                        case: case.into(),
                        binding: binding.into(),
                        profile_version: version.into(),
                        revision,
                        wrapped_key,
                    }
                };
            vec![
                case(
                    "another account's key binding",
                    OTHER_BINDING,
                    &version(),
                    REVISION,
                    wrapped_key.into(),
                ),
                case(
                    "an address instead of the key binding",
                    "aci:00000000-0000-4000-8000-2bd806c97f0e@kutup.dev",
                    &version(),
                    REVISION,
                    wrapped_key.into(),
                ),
                case(
                    "another profile version",
                    BINDING,
                    &other_version,
                    REVISION,
                    wrapped_key.into(),
                ),
                case(
                    "another revision",
                    BINDING,
                    &version(),
                    REVISION + 1,
                    wrapped_key.into(),
                ),
                case(
                    "magic changed",
                    BINDING,
                    &version(),
                    REVISION,
                    edit(6, b'2'),
                ),
                case(
                    "ciphertext changed",
                    BINDING,
                    &version(),
                    REVISION,
                    edit(last, bytes[last] ^ 1),
                ),
                case(
                    "sealed under another master key",
                    BINDING,
                    &version(),
                    REVISION,
                    wrapped(&OTHER_MASTER, AccountRecordPurpose::ChatProfileKeyWrap),
                ),
            ]
        }

        fn expected() -> Vectors {
            let wrapped_key = wrapped(&MASTER, AccountRecordPurpose::ChatProfileKeyWrap);
            Vectors {
                master_key: STANDARD.encode(MASTER),
                binding: BINDING.into(),
                profile_key: STANDARD.encode(PROFILE_KEY),
                profile_version: version(),
                revision: REVISION,
                nonce: STANDARD.encode(NONCE),
                refused: refused(&wrapped_key),
                wrapped_key,
            }
        }

        #[test]
        #[ignore = "writes the vectors file"]
        fn profile_wrap_vectors_write() {
            if std::env::var("KUTUP_WRITE_PROFILE_VECTORS").as_deref() != Ok("1") {
                return;
            }
            std::fs::write(
                PATH,
                serde_json::to_string_pretty(&expected()).unwrap() + "\n",
            )
            .unwrap();
        }

        #[test]
        fn profile_wrap_vectors_hold() {
            let checked_in = std::fs::read_to_string(PATH).unwrap();
            assert_eq!(
                checked_in,
                serde_json::to_string_pretty(&expected()).unwrap() + "\n"
            );
            let v: Vectors = serde_json::from_str(&checked_in).unwrap();
            assert_eq!(
                open(&v.binding, &v.profile_version, v.revision, &v.wrapped_key).unwrap(),
                STANDARD.decode(&v.profile_key).unwrap()
            );
            for case in &v.refused {
                assert!(
                    open(
                        &case.binding,
                        &case.profile_version,
                        case.revision,
                        &case.wrapped_key
                    )
                    .is_err(),
                    "{} opened",
                    case.case
                );
            }
        }
    }
}
