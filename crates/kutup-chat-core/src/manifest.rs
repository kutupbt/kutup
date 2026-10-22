//! The account self-authority, the signed V2 manifest history (one libsignal
//! identity per account, docs/plans/account-identity-key.md), and durable peer
//! pins.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use kutup_chat_proto::{
    AccountIdentitySuiteId, AccountManifestDeviceV2, AccountManifestDriveKeysV1,
    AccountManifestHistoryPageV2, AccountManifestV2, AccountPreKeyBundlesResponse, AccountRef,
    DevicePreKeyBundle, ACCOUNT_MANIFEST_V2_VERSION,
};
use serde::Serialize;

use crate::db::{AccountManifestHistoryRecord, AuthorityTrust, ManifestTrust};
use crate::error::{ChatError, Result};

/// Whether a development transport may omit signed account identity. V1
/// production engines always use [`Required`](Self::Required).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestPolicy {
    Required,
    AllowMissingForDevelopment,
}

pub(crate) struct VerifiedBundleTrust {
    pub manifest: Option<ManifestTrust>,
}

/// A bundle response's devices, each with the account's identity key: the
/// shape sessions are built from. Only after [`verify_bundle_response`].
pub(crate) fn account_bundles(response: &AccountPreKeyBundlesResponse) -> Vec<DevicePreKeyBundle> {
    response
        .devices
        .iter()
        .map(|bundle| DevicePreKeyBundle {
            device_id: bundle.device_id,
            registration_id: bundle.registration_id,
            suite: bundle.suite,
            identity_key: response.identity_key.clone(),
            signed_pre_key: bundle.signed_pre_key.clone(),
            kyber_pre_key: bundle.kyber_pre_key.clone(),
            one_time_pre_key: bundle.one_time_pre_key.clone(),
        })
        .collect()
}

/// Purpose-separated identity deterministically recovered from the account
/// master key. The server never receives the authority or Drive signing keys.
pub struct AccountAuthority {
    identity: kutup_crypto::identity::AccountIdentityKeysV1,
}

/// The safety number of two accounts, as Signal's: libsignal's numeric
/// fingerprint over each side's account id and account identity key
/// (docs/plans/account-identity-key.md). Both sides show the same sixty
/// digits; each side's QR code carries its own half first, so a scan is
/// compared with the other side's. A new identity of either side is a new
/// number; linking or removing a device changes nothing.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyNumberV2 {
    pub local_account: String,
    pub peer_account: String,
    /// Twelve five-digit groups.
    pub fingerprint: String,
    /// This side's QR code (`kutup://verify/v4/…`): what the other side scans.
    pub qr_payload: String,
    /// The peer's account identity key the number covers.
    pub identity_key: String,
    #[serde(skip)]
    scannable: libsignal_protocol::ScannableFingerprint,
    pub authority_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained_authority_key_id: Option<String>,
    /// `Verified` when this identity was verified; `Quarantined` while the
    /// account's authority itself is in question; `Tofu` otherwise.
    pub trust: AuthorityTrust,
    pub continuity_gap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_reason: Option<String>,
}

/// The QR prefix of a [`SafetyNumberV2`] (v3 was the authority's).
pub const SAFETY_QR_PREFIX: &str = "kutup://verify/v4/";
/// Signal's fingerprint version for its account identities (ACI) and
/// iteration count.
const FINGERPRINT_VERSION: u32 = 2;
const FINGERPRINT_ITERATIONS: u32 = 5200;

impl SafetyNumberV2 {
    /// Compare a scanned QR payload with the other side's half, derived here.
    /// Only the exact pair of accounts and identity keys succeeds.
    pub fn matches_qr_payload(&self, scanned: &str) -> bool {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let Some(encoded) = scanned.trim().strip_prefix(SAFETY_QR_PREFIX) else {
            return false;
        };
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
            return false;
        };
        self.scannable.compare(&bytes).unwrap_or(false)
    }
}

/// libsignal's fingerprint of two stable ids and identity keys: the displayed
/// digits (grouped by five) and the scannable form.
pub(crate) fn fingerprint(
    local_id: &[u8],
    local_key: &libsignal_protocol::IdentityKey,
    peer_id: &[u8],
    peer_key: &libsignal_protocol::IdentityKey,
) -> Result<(String, libsignal_protocol::ScannableFingerprint)> {
    let fingerprint = libsignal_protocol::Fingerprint::new(
        FINGERPRINT_VERSION,
        FINGERPRINT_ITERATIONS,
        local_id,
        local_key,
        peer_id,
        peer_key,
    )
    .map_err(|error| ChatError::Invalid(error.to_string()))?;
    let digits = fingerprint
        .display_string()
        .map_err(|error| ChatError::Invalid(error.to_string()))?;
    let grouped = digits
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).expect("digits are ASCII"))
        .collect::<Vec<_>>()
        .join(" ");
    Ok((grouped, fingerprint.scannable))
}

/// Derive the safety number with an already authenticated peer pin: this
/// account's identity key against the identity the peer's manifest lists.
pub fn derive_safety_number(
    local_account: &str,
    local_identity_key: &libsignal_protocol::IdentityKey,
    trust: &ManifestTrust,
) -> Result<SafetyNumberV2> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let local = crate::address::parse_account(local_account)?;
    let peer = crate::address::parse_account(&trust.account)?;
    if local == peer {
        return Err(ChatError::Invalid(
            "Note to Self does not have a peer safety number".into(),
        ));
    }
    let peer_key = STANDARD
        .decode(&trust.identity_key)
        .ok()
        .and_then(|bytes| libsignal_protocol::IdentityKey::decode(&bytes).ok())
        .ok_or_else(|| ChatError::Trust("the peer has no account identity pinned".into()))?;
    let (fingerprint, scannable) =
        fingerprint(&local.bytes(), local_identity_key, &peer.bytes(), &peer_key)?;
    let qr_payload = format!(
        "{SAFETY_QR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(
            scannable
                .serialize()
                .map_err(|error| ChatError::Invalid(error.to_string()))?
        )
    );
    Ok(SafetyNumberV2 {
        local_account: local.to_string(),
        peer_account: peer.to_string(),
        fingerprint,
        qr_payload,
        identity_key: trust.identity_key.clone(),
        scannable,
        authority_key_id: trust.authority_key_id.clone(),
        retained_authority_key_id: None,
        trust: if trust.trust == AuthorityTrust::Quarantined {
            AuthorityTrust::Quarantined
        } else if trust.identity_verified {
            AuthorityTrust::Verified
        } else {
            AuthorityTrust::Tofu
        },
        continuity_gap: trust.continuity_gap,
        quarantine_reason: trust.quarantine_reason.clone(),
    })
}

impl AccountAuthority {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(master_key)
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        Ok(Self { identity })
    }

    /// The self-authority's public key, which members check this account's
    /// group bindings against.
    pub fn public_key(&self) -> [u8; 32] {
        self.identity.authority_public_key()
    }

    /// This account's binding of `pseudonym` in `group_id`
    /// (`kutup_crypto::chat_group::sign_binding`).
    pub fn sign_group_binding(
        &self,
        group_id: &[u8; 32],
        pseudonym: &[u8; 32],
        account: &AccountRef,
    ) -> [u8; 64] {
        kutup_crypto::chat_group::sign_binding(
            self.identity.authority_signing_key(),
            group_id,
            pseudonym,
            account,
        )
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.identity.authority_public_key())
    }

    pub fn key_id(&self) -> String {
        self.identity.authority_key_id()
    }

    pub fn incarnation_id(&self) -> String {
        self.identity.incarnation_id()
    }

    /// The Drive keys this authority's manifests carry: the account's
    /// current suite (X-Wing).
    pub fn drive_keys(&self) -> AccountManifestDriveKeysV1 {
        AccountManifestDriveKeysV1 {
            suite: AccountIdentitySuiteId::XWingEd25519V2,
            hpke_public_key: STANDARD.encode(self.identity.drive_hpke_public_key()),
            share_signing_public_key: STANDARD.encode(self.identity.drive_signing_public_key()),
        }
    }

    /// Sign the account's manifest: its libsignal identity key
    /// (`identity_key`, canonical base64 of the 33-byte key) and its devices.
    pub fn sign_manifest(
        &self,
        account: AccountRef,
        sequence: u64,
        previous_hash: Option<String>,
        identity_key: String,
        mut devices: Vec<AccountManifestDeviceV2>,
        issued_at: impl Into<String>,
    ) -> Result<AccountManifestV2> {
        devices.sort_by_key(|device| device.device_id);
        let mut manifest = AccountManifestV2 {
            manifest_version: ACCOUNT_MANIFEST_V2_VERSION,
            account,
            incarnation_id: self.incarnation_id(),
            sequence,
            previous_hash,
            identity_key,
            drive: self.drive_keys(),
            devices,
            issued_at: issued_at.into(),
            authority_key_id: self.key_id(),
            self_authority_key: self.public_key_base64(),
            signature: String::new(),
        };
        let bytes = manifest.signing_bytes().map_err(ChatError::Invalid)?;
        manifest.signature = STANDARD.encode(
            self.identity
                .authority_signing_key()
                .sign(&bytes)
                .to_bytes(),
        );
        manifest.verify().map_err(ChatError::Invalid)?;
        Ok(manifest)
    }
}

pub fn verify_manifest(manifest: &AccountManifestV2) -> Result<()> {
    manifest.verify().map_err(ChatError::Protocol)
}

/// Verify one bundle response before any libsignal session mutation.
pub fn verify_bundle_response(
    expected_peer: &str,
    response: &AccountPreKeyBundlesResponse,
    policy: ManifestPolicy,
    prior: Option<&ManifestTrust>,
) -> Result<Option<ManifestTrust>> {
    // Every V2 bundle response carries its signed manifest.
    let _ = policy;
    let manifest = &response.manifest;
    manifest.verify().map_err(ChatError::Trust)?;
    if response.account != manifest.account {
        return Err(ChatError::Trust(
            "bundle routing identity does not match its account manifest".into(),
        ));
    }
    match_expected_account(expected_peer, &manifest.account)?;
    // The account's identity once, as its manifest lists it; each bundle a
    // listed device with its listed registration id and suite, at most once.
    // A listed device may lack a bundle (the server dropped an expired one,
    // as Signal's): it is then not sent to.
    response.check_against_manifest().map_err(|error| {
        ChatError::Trust(format!("bundles contradict the signed manifest: {error}"))
    })?;
    verify_manifest_trust(expected_peer, manifest, prior).map(Some)
}

pub(crate) fn verify_bundle_trust(
    expected_peer: &str,
    response: &AccountPreKeyBundlesResponse,
    policy: ManifestPolicy,
    prior: Option<&ManifestTrust>,
) -> Result<VerifiedBundleTrust> {
    Ok(VerifiedBundleTrust {
        manifest: verify_bundle_response(expected_peer, response, policy, prior)?,
    })
}

/// Verify the current signed manifest. A gap remains pending until the caller
/// retrieves and atomically commits every missing complete sequence.
pub(crate) fn verify_manifest_evidence(
    expected_peer: &str,
    manifest: &AccountManifestV2,
    prior: Option<&ManifestTrust>,
) -> Result<ManifestTrust> {
    verify_manifest_trust(expected_peer, manifest, prior)
}

fn verify_manifest_trust(
    expected_peer: &str,
    manifest: &AccountManifestV2,
    prior: Option<&ManifestTrust>,
) -> Result<ManifestTrust> {
    manifest.verify().map_err(ChatError::Trust)?;
    match_expected_account(expected_peer, &manifest.account)?;
    let manifest_hash = manifest.manifest_hash().map_err(ChatError::Trust)?;
    let (trust, continuity_gap) = match prior {
        None => (AuthorityTrust::Tofu, manifest.sequence != 1),
        Some(prior) => {
            if prior.trust == AuthorityTrust::Quarantined {
                return Err(ChatError::Trust(
                    "peer account identity is quarantined pending explicit verification".into(),
                ));
            }
            if prior.peer != expected_peer {
                return Err(ChatError::Trust(
                    "account-manifest pin belongs to another peer".into(),
                ));
            }
            if prior.authority_key_id != manifest.authority_key_id
                || prior.self_authority_key != manifest.self_authority_key
                || prior.incarnation_id != manifest.incarnation_id
            {
                return Err(ChatError::Trust(
                    "peer authority or incarnation changed; explicit reset acceptance is required"
                        .into(),
                ));
            }
            // The Drive key changes only by the one-way suite upgrade: from a
            // suite-1 key to X-Wing, the authority (checked above) and signing
            // key unchanged, in a manifest linked to the one before it. Seen
            // across a sequence gap, the rise is taken as part of the gap
            // (`continuity_gap` below), and `verify_manifest_history` checks
            // that it happened in a linked step before anything is committed.
            let consecutive = manifest.sequence == prior.highest_sequence.saturating_add(1);
            let linked = consecutive
                && manifest.previous_hash.as_deref() == Some(prior.manifest_hash.as_str());
            let drive_key_ok = prior.drive_hpke_public_key == manifest.drive.hpke_public_key
                || ((linked || !consecutive)
                    && legacy_suite1_for_upgrade::drive_key_rises(
                        &prior.drive_hpke_public_key,
                        manifest,
                    ));
            if prior.account != manifest.account.to_string()
                || !drive_key_ok
                || prior.drive_share_signing_public_key != manifest.drive.share_signing_public_key
            {
                return Err(ChatError::Trust(
                    "stable account identity changed inside one incarnation".into(),
                ));
            }
            if manifest.sequence < prior.highest_sequence {
                return Err(ChatError::Trust(format!(
                    "account manifest rollback from sequence {} to {}",
                    prior.highest_sequence, manifest.sequence
                )));
            }
            if manifest.sequence == prior.highest_sequence {
                if manifest_hash != prior.manifest_hash {
                    return Err(ChatError::Trust(format!(
                        "account manifest equivocation at sequence {}",
                        manifest.sequence
                    )));
                }
                return Ok(prior.clone());
            }
            let consecutive = manifest.sequence == prior.highest_sequence.saturating_add(1);
            if consecutive
                && manifest.previous_hash.as_deref() != Some(prior.manifest_hash.as_str())
            {
                return Err(ChatError::Trust(
                    "account manifest does not link to the accepted predecessor".into(),
                ));
            }
            (prior.trust, prior.continuity_gap || !consecutive)
        }
    };

    Ok(ManifestTrust {
        peer: expected_peer.to_string(),
        account: manifest.account.to_string(),
        incarnation_id: manifest.incarnation_id.clone(),
        authority_key_id: manifest.authority_key_id.clone(),
        self_authority_key: manifest.self_authority_key.clone(),
        drive_hpke_public_key: manifest.drive.hpke_public_key.clone(),
        drive_share_signing_public_key: manifest.drive.share_signing_public_key.clone(),
        highest_sequence: manifest.sequence,
        manifest_hash,
        identity_key: manifest.identity_key.clone(),
        // Verified stays with the identity it verified: a new one is not.
        identity_verified: prior.is_some_and(|prior| {
            prior.identity_verified && prior.identity_key == manifest.identity_key
        }),
        identity_verified_at_ms: prior
            .filter(|prior| prior.identity_key == manifest.identity_key)
            .map_or(0, |prior| prior.identity_verified_at_ms),
        trust,
        continuity_gap,
        quarantine_reason: None,
        pending_reset: None,
    })
}

/// Verify exact, complete manifest pages and return records ready for one
/// atomic client transaction. Pages are not independently trusted: the
/// authority signature and predecessor hash on every entry are authoritative.
pub(crate) fn verify_manifest_history(
    expected_peer: &str,
    pages: &[AccountManifestHistoryPageV2],
    prior: Option<&ManifestTrust>,
    pending: &AccountManifestV2,
) -> Result<(ManifestTrust, Vec<AccountManifestHistoryRecord>)> {
    if pages.is_empty() {
        return Err(ChatError::Trust(
            "account manifest gap recovery returned no history".into(),
        ));
    }
    let start = prior.map_or(1, |trust| trust.highest_sequence.saturating_add(1));
    let mut expected = start;
    let mut predecessor = prior.map(|trust| trust.manifest_hash.clone());
    let mut identity = prior.map(|trust| {
        (
            trust.account.clone(),
            trust.incarnation_id.clone(),
            trust.authority_key_id.clone(),
            trust.self_authority_key.clone(),
        )
    });
    let mut rolling: Option<ManifestTrust> = None;
    let mut records = Vec::new();
    for (page_index, page) in pages.iter().enumerate() {
        page.validate().map_err(ChatError::Trust)?;
        match_expected_account(expected_peer, &page.account)?;
        if page.from_sequence != expected
            || (page_index + 1 < pages.len() && page.next_sequence.is_none())
        {
            return Err(ChatError::Trust(
                "account manifest history pages are missing or reordered".into(),
            ));
        }
        for manifest in &page.manifests {
            if manifest.sequence != expected
                || manifest.previous_hash.as_ref() != predecessor.as_ref()
            {
                return Err(ChatError::Trust(
                    "account manifest history chain is incomplete or inconsistent".into(),
                ));
            }
            // Each manifest against the one before it: the identity holds
            // through the history, but for the one-way suite upgrade, which
            // only a linked successor may make.
            let checked =
                verify_manifest_trust(expected_peer, manifest, rolling.as_ref().or(prior))?;
            if let Some((account, incarnation, authority, self_authority)) = &identity {
                if account != &manifest.account.to_string()
                    || incarnation != &manifest.incarnation_id
                    || authority != &manifest.authority_key_id
                    || self_authority != &manifest.self_authority_key
                {
                    return Err(ChatError::Trust(
                        "account manifest history changes identity".into(),
                    ));
                }
            } else {
                identity = Some((
                    manifest.account.to_string(),
                    manifest.incarnation_id.clone(),
                    manifest.authority_key_id.clone(),
                    manifest.self_authority_key.clone(),
                ));
            }
            rolling = Some(checked);
            predecessor = Some(manifest.manifest_hash().map_err(ChatError::Trust)?);
            records.push(AccountManifestHistoryRecord {
                peer: expected_peer.to_string(),
                sequence: manifest.sequence,
                manifest: manifest.clone(),
            });
            expected = expected
                .checked_add(1)
                .ok_or_else(|| ChatError::Trust("account manifest sequence exhausted".into()))?;
        }
    }
    let last = records.last().ok_or_else(|| {
        ChatError::Trust("account manifest gap recovery returned no manifests".into())
    })?;
    if last.manifest != *pending || last.sequence != pending.sequence {
        return Err(ChatError::Trust(
            "account manifest history does not terminate at the pending manifest".into(),
        ));
    }
    // The pending manifest is the history's last, checked against its
    // predecessor above.
    let mut trust = rolling.ok_or_else(|| {
        ChatError::Trust("account manifest gap recovery returned no manifests".into())
    })?;
    trust.continuity_gap = false;
    Ok((trust, records))
}

/// Identity suite 1 (X25519 Drive keys), only for seeing an account rise to
/// suite 2 (docs/plans/pq-shares.md). The enforcing change, once every
/// account has upgraded, deletes this module and its two callers' use of it.
mod legacy_suite1_for_upgrade {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use kutup_chat_proto::{
        legacy_suite1_for_upgrade::HPKE_PUBLIC_KEY_LEN, AccountIdentitySuiteId, AccountManifestV2,
    };

    /// Whether `next` raises a suite-1 Drive key (`prior_key`, as pinned) to
    /// an X-Wing one. Never the other way.
    pub(super) fn drive_key_rises(prior_key: &str, next: &AccountManifestV2) -> bool {
        STANDARD.decode(prior_key).map(|key| key.len()) == Ok(HPKE_PUBLIC_KEY_LEN)
            && next.drive.suite == AccountIdentitySuiteId::XWingEd25519V2
    }
}

fn match_expected_account(expected_peer: &str, authenticated_account: &AccountRef) -> Result<()> {
    let expected = crate::address::parse_account(expected_peer)
        .map_err(|error| ChatError::Trust(error.to_string()))?;
    if expected != *authenticated_account {
        return Err(ChatError::Trust(
            "account manifest belongs to another account".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one-way suite upgrade (docs/plans/pq-shares.md): a pinned suite-1
    /// Drive key rises to X-Wing only in the linked next manifest, under the
    /// same authority and signing key; never back, never across a gap.
    #[test]
    fn a_drive_key_changes_only_by_rising_to_x_wing_in_the_next_manifest() {
        use kutup_chat_proto::{AccountManifestDeviceV2, DirectChatSuiteId};
        let peer = "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example";
        let authority = AccountAuthority::derive(&[5u8; 32]).unwrap();
        let sign = |sequence: u64, previous: Option<String>| {
            authority
                .sign_manifest(
                    peer.parse().unwrap(),
                    sequence,
                    previous,
                    vec![AccountManifestDeviceV2 {
                        device_id: 1,
                        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                        identity_key: STANDARD.encode([5u8; 33]),
                        registration_id: 7,
                        mls: None,
                    }],
                    "2026-10-18T00:00:00Z",
                )
                .unwrap()
        };
        // Pinned at sequence 4 with a suite-1 (32-byte X25519) Drive key.
        let first = sign(4, Some("22".repeat(32)));
        let mut pinned = verify_manifest_trust(peer, &first, None).unwrap();
        pinned.drive_hpke_public_key = STANDARD.encode([7u8; 32]);
        // The linked next manifest carries the X-Wing key: accepted.
        let next = sign(5, Some(pinned.manifest_hash.clone()));
        let risen = verify_manifest_trust(peer, &next, Some(&pinned)).unwrap();
        assert_eq!(risen.drive_hpke_public_key, next.drive.hpke_public_key);
        // Across a gap: a gap to recover, not a changed identity. The
        // history then has to show the rise in a linked step.
        let later = sign(6, Some("33".repeat(32)));
        let gapped = verify_manifest_trust(peer, &later, Some(&pinned)).unwrap();
        assert!(gapped.continuity_gap);
        assert_eq!(gapped.trust, pinned.trust);
        // From an X-Wing pin, another key: refused (no second change, never
        // back to suite 1).
        let mut xwing_pin = risen.clone();
        xwing_pin.drive_hpke_public_key = STANDARD.encode([9u8; 1216]);
        let after = sign(6, Some(risen.manifest_hash.clone()));
        assert!(verify_manifest_trust(peer, &after, Some(&xwing_pin)).is_err());
        // Nor across a gap.
        let much_later = sign(9, Some("44".repeat(32)));
        assert!(verify_manifest_trust(peer, &much_later, Some(&xwing_pin)).is_err());
        // The same key at the next sequence stays fine.
        assert!(verify_manifest_trust(peer, &after, Some(&risen)).is_ok());
    }

    fn trust(peer: &str, authority: &AccountAuthority) -> ManifestTrust {
        ManifestTrust {
            peer: peer.into(),
            account: peer.into(),
            incarnation_id: authority.incarnation_id(),
            authority_key_id: authority.key_id(),
            self_authority_key: authority.public_key_base64(),
            drive_hpke_public_key: STANDARD.encode([7u8; 32]),
            drive_share_signing_public_key: STANDARD.encode([8u8; 32]),
            highest_sequence: 1,
            manifest_hash: "11".repeat(32),
            trust: AuthorityTrust::Tofu,
            continuity_gap: false,
            quarantine_reason: None,
            pending_reset: None,
        }
    }

    #[test]
    fn safety_number_is_symmetric_and_losslessly_formatted() {
        let alice = AccountAuthority::derive(&[1u8; 32]).unwrap();
        let bob = AccountAuthority::derive(&[2u8; 32]).unwrap();
        let alice_view = derive_safety_number(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@alpha.example",
            &alice.public_key_base64(),
            &trust(
                "aci:00000000-0000-4000-8000-81b637d8fcd2@beta.example",
                &bob,
            ),
        )
        .unwrap();
        let bob_view = derive_safety_number(
            "aci:00000000-0000-4000-8000-81b637d8fcd2@beta.example",
            &bob.public_key_base64(),
            &trust(
                "aci:00000000-0000-4000-8000-2bd806c97f0e@alpha.example",
                &alice,
            ),
        )
        .unwrap();

        assert_eq!(alice_view.fingerprint, bob_view.fingerprint);
        let groups: Vec<_> = alice_view.fingerprint.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(groups
            .iter()
            .all(|group| group.len() == 5 && group.bytes().all(|byte| byte.is_ascii_digit())));
        // Each side scans the other's code; its own does not match.
        assert!(alice_view.matches_qr_payload(&bob_view.qr_payload));
        assert!(bob_view.matches_qr_payload(&alice_view.qr_payload));
        assert!(!alice_view.matches_qr_payload(&alice_view.qr_payload));
    }

    #[test]
    fn safety_number_rejects_another_pair_and_note_to_self() {
        let alice = AccountAuthority::derive(&[1u8; 32]).unwrap();
        let bob = AccountAuthority::derive(&[2u8; 32]).unwrap();
        let mallory = AccountAuthority::derive(&[3u8; 32]).unwrap();
        let expected = derive_safety_number(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@alpha.example",
            &alice.public_key_base64(),
            &trust(
                "aci:00000000-0000-4000-8000-81b637d8fcd2@beta.example",
                &bob,
            ),
        )
        .unwrap();
        let wrong = derive_safety_number(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@alpha.example",
            &alice.public_key_base64(),
            &trust(
                "aci:00000000-0000-4000-8000-c0a497761b17@gamma.example",
                &mallory,
            ),
        )
        .unwrap();

        assert!(!expected.matches_qr_payload(&wrong.qr_payload));
        assert!(!expected
            .matches_qr_payload(&"x".repeat(kutup_crypto::safety_number::MAX_QR_BYTES + 1)));
        assert!(derive_safety_number(
            "aci:00000000-0000-4000-8000-2bd806c97f0e@alpha.example",
            &alice.public_key_base64(),
            &trust(
                "aci:00000000-0000-4000-8000-2bd806c97f0e@alpha.example",
                &alice
            ),
        )
        .is_err());
    }
}
