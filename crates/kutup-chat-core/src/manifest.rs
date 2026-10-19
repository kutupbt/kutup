//! V1 account self-authority, signed manifest history, and durable peer pins.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use kutup_chat_proto::{
    AccountIdentitySuiteId, AccountManifestDeviceV1, AccountManifestDriveKeysV1,
    AccountManifestHistoryPageV1, AccountManifestV1, AccountRef, UserPreKeyBundlesResponse,
    ACCOUNT_MANIFEST_VERSION,
};
use serde::Serialize;

use crate::db::{AccountManifestHistoryRecordV1, AuthorityTrust, ManifestTrust};
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

/// Purpose-separated identity deterministically recovered from the account
/// master key. The server never receives the authority or Drive signing keys.
pub struct AccountAuthority {
    identity: kutup_crypto::identity::AccountIdentityKeysV1,
}

/// Human-verifiable binding between two accounts and their account
/// self-authority public keys (kutup-crypto `safety_number`, Signal's
/// fingerprint). Both participants show the same digits; each side's QR code
/// carries its own half first, so a scan is compared with the other side's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyNumberV1 {
    pub local_account: String,
    pub peer_account: String,
    /// Twelve five-digit groups: both sides' halves, the lower first.
    pub fingerprint: String,
    /// This side's QR code: what the other side scans.
    pub qr_payload: String,
    /// The derivation, which knows the other side's QR code: what a scan
    /// here must be.
    #[serde(skip)]
    derived: kutup_crypto::safety_number::SafetyNumberV3,
    pub authority_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained_authority_key_id: Option<String>,
    pub trust: AuthorityTrust,
    pub continuity_gap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_reason: Option<String>,
}

impl SafetyNumberV1 {
    /// Compare a scanned QR payload with the other side's, derived here. The
    /// QR never adds trust on its own: only the exact pair of accounts and
    /// keys succeeds.
    pub fn matches_qr_payload(&self, scanned: &str) -> bool {
        kutup_crypto::safety_number::matches_qr_payload(&self.derived, scanned)
    }
}

/// Derive the shared safety number for an already authenticated manifest pin.
pub fn derive_safety_number(
    local_account: &str,
    local_authority_public_key: &str,
    trust: &ManifestTrust,
) -> Result<SafetyNumberV1> {
    let local = crate::address::parse_account(local_account)?;
    let peer = crate::address::parse_account(&trust.account)?;
    if local == peer {
        return Err(ChatError::Invalid(
            "Note to Self does not have a peer safety number".into(),
        ));
    }
    let local_key = decode_authority_key("local self-authority key", local_authority_public_key)?;
    let peer_key = decode_authority_key("peer self-authority key", &trust.self_authority_key)?;
    // One number for every app (kutup-crypto safety_number).
    let derived = kutup_crypto::safety_number::derive(&local, &local_key, &peer, &peer_key)
        .map_err(|error| ChatError::Invalid(error.to_string()))?;

    Ok(SafetyNumberV1 {
        local_account: local.to_string(),
        peer_account: peer.to_string(),
        fingerprint: derived.fingerprint.clone(),
        qr_payload: derived.qr_payload.clone(),
        derived,
        authority_key_id: trust.authority_key_id.clone(),
        retained_authority_key_id: None,
        trust: trust.trust,
        continuity_gap: trust.continuity_gap,
        quarantine_reason: trust.quarantine_reason.clone(),
    })
}

fn decode_authority_key(label: &str, value: &str) -> Result<[u8; 32]> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ChatError::Trust(format!("{label} is not canonical base64")))?;
    if STANDARD.encode(&decoded) != value {
        return Err(ChatError::Trust(format!(
            "{label} is not canonical padded base64"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| ChatError::Trust(format!("{label} must be 32 bytes")))
}

impl AccountAuthority {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(master_key)
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        Ok(Self { identity })
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

    pub fn sign_manifest(
        &self,
        account: AccountRef,
        sequence: u64,
        previous_hash: Option<String>,
        mut devices: Vec<AccountManifestDeviceV1>,
        issued_at: impl Into<String>,
    ) -> Result<AccountManifestV1> {
        devices.sort_by_key(|device| device.device_id);
        let mut manifest = AccountManifestV1 {
            manifest_version: ACCOUNT_MANIFEST_VERSION,
            account,
            incarnation_id: self.incarnation_id(),
            sequence,
            previous_hash,
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

pub fn verify_manifest(manifest: &AccountManifestV1) -> Result<()> {
    manifest.verify().map_err(ChatError::Protocol)
}

/// Verify one bundle response before any libsignal session mutation.
pub fn verify_bundle_response(
    expected_peer: &str,
    response: &UserPreKeyBundlesResponse,
    policy: ManifestPolicy,
    prior: Option<&ManifestTrust>,
) -> Result<Option<ManifestTrust>> {
    let Some(manifest) = &response.manifest else {
        if prior.is_some() {
            return Err(ChatError::Trust(
                "server omitted a previously required account manifest".into(),
            ));
        }
        return match policy {
            ManifestPolicy::Required => Err(ChatError::Trust(
                "server omitted the required account manifest".into(),
            )),
            ManifestPolicy::AllowMissingForDevelopment => Ok(None),
        };
    };
    manifest.verify().map_err(ChatError::Trust)?;
    if response.account != manifest.account {
        return Err(ChatError::Trust(
            "bundle routing identity does not match its account manifest".into(),
        ));
    }
    match_expected_account(expected_peer, &manifest.account)?;

    if response.devices.len() != manifest.devices.len() {
        return Err(ChatError::Trust(
            "bundle device count does not match signed account manifest".into(),
        ));
    }
    let mut served = std::collections::BTreeMap::new();
    for bundle in &response.devices {
        if served.insert(bundle.device_id, bundle).is_some() {
            return Err(ChatError::Trust(format!(
                "bundle response repeats device {}",
                bundle.device_id
            )));
        }
    }
    for declared in &manifest.devices {
        let bundle = served.get(&declared.device_id).ok_or_else(|| {
            ChatError::Trust(format!(
                "signed device {} has no prekey bundle",
                declared.device_id
            ))
        })?;
        if bundle.suite != declared.direct_chat_suite
            || bundle.registration_id != declared.registration_id
            || bundle.identity_key != declared.identity_key
        {
            return Err(ChatError::Trust(format!(
                "bundle for device {} contradicts the signed account manifest",
                declared.device_id
            )));
        }
    }
    verify_manifest_trust(expected_peer, manifest, prior).map(Some)
}

pub(crate) fn verify_bundle_trust(
    expected_peer: &str,
    response: &UserPreKeyBundlesResponse,
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
    manifest: &AccountManifestV1,
    prior: Option<&ManifestTrust>,
) -> Result<ManifestTrust> {
    verify_manifest_trust(expected_peer, manifest, prior)
}

fn verify_manifest_trust(
    expected_peer: &str,
    manifest: &AccountManifestV1,
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
            // The Drive key changes only by the one-way suite upgrade: in the
            // next manifest, linked to this one, from a suite-1 key to X-Wing,
            // the authority (checked above) and signing key unchanged.
            let linked = manifest.sequence == prior.highest_sequence.saturating_add(1)
                && manifest.previous_hash.as_deref() == Some(prior.manifest_hash.as_str());
            let drive_key_ok = prior.drive_hpke_public_key == manifest.drive.hpke_public_key
                || (linked
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
    pages: &[AccountManifestHistoryPageV1],
    prior: Option<&ManifestTrust>,
    pending: &AccountManifestV1,
) -> Result<(ManifestTrust, Vec<AccountManifestHistoryRecordV1>)> {
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
            records.push(AccountManifestHistoryRecordV1 {
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
        legacy_suite1_for_upgrade::HPKE_PUBLIC_KEY_LEN, AccountIdentitySuiteId, AccountManifestV1,
    };

    /// Whether `next` raises a suite-1 Drive key (`prior_key`, as pinned) to
    /// an X-Wing one. Never the other way.
    pub(super) fn drive_key_rises(prior_key: &str, next: &AccountManifestV1) -> bool {
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
        use kutup_chat_proto::{AccountManifestDeviceV1, DirectChatSuiteId};
        let peer = "aci:00000000-0000-4000-8000-81b637d8fcd2@chat.example";
        let authority = AccountAuthority::derive(&[5u8; 32]).unwrap();
        let sign = |sequence: u64, previous: Option<String>| {
            authority
                .sign_manifest(
                    peer.parse().unwrap(),
                    sequence,
                    previous,
                    vec![AccountManifestDeviceV1 {
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
        // Across a gap: refused.
        let later = sign(6, Some("33".repeat(32)));
        assert!(verify_manifest_trust(peer, &later, Some(&pinned)).is_err());
        // From an X-Wing pin, another key: refused (no second change, never
        // back to suite 1).
        let mut xwing_pin = risen.clone();
        xwing_pin.drive_hpke_public_key = STANDARD.encode([9u8; 1216]);
        let after = sign(6, Some(risen.manifest_hash.clone()));
        assert!(verify_manifest_trust(peer, &after, Some(&xwing_pin)).is_err());
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
