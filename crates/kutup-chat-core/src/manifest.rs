//! V1 account self-authority, signed manifest history, and durable peer pins.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use kutup_chat_proto::{
    AccountAddress, AccountIdentitySuiteId, AccountManifestDeviceV1, AccountManifestDriveKeysV1,
    AccountManifestHistoryPageV1, AccountManifestV1, UserPreKeyBundlesResponse,
    ACCOUNT_MANIFEST_VERSION,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

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

const SAFETY_NUMBER_DOMAIN: &[u8] = b"kutup/chat/safety-number/v1\0";
const SAFETY_QR_PREFIX: &str = "kutup://verify/chat/v1/";
const MAX_SAFETY_QR_BYTES: usize = 1024;

/// Human-verifiable binding between two canonical accounts and their stable
/// account self-authority public keys. Both participants derive byte-for-byte
/// identical output regardless of which side opens the comparison first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyNumberV1 {
    pub local_account: String,
    pub peer_account: String,
    /// Full 256-bit value rendered as sixteen lossless five-digit groups.
    pub fingerprint: String,
    /// Versioned QR payload containing only canonical addresses and public keys.
    pub qr_payload: String,
    pub authority_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained_authority_key_id: Option<String>,
    pub trust: AuthorityTrust,
    pub continuity_gap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_reason: Option<String>,
}

impl SafetyNumberV1 {
    /// Compare a scanned QR payload to the locally derived expectation. The QR
    /// never adds trust on its own: only an exact pair/key binding succeeds.
    pub fn matches_qr_payload(&self, scanned: &str) -> bool {
        if scanned.len() > MAX_SAFETY_QR_BYTES {
            return false;
        }
        constant_time_eq(self.qr_payload.as_bytes(), scanned.as_bytes())
    }
}

/// Derive the shared safety number for an already authenticated manifest pin.
pub fn derive_safety_number(
    local_account: &str,
    local_authority_public_key: &str,
    trust: &ManifestTrust,
) -> Result<SafetyNumberV1> {
    let local = canonical_federated_account(local_account)?;
    let peer = canonical_federated_account(&trust.account)?;
    if local == peer {
        return Err(ChatError::Invalid(
            "Note to Self does not have a peer safety number".into(),
        ));
    }
    let local_key = decode_authority_key("local self-authority key", local_authority_public_key)?;
    let peer_key = decode_authority_key("peer self-authority key", &trust.self_authority_key)?;
    let mut identities = [(local.as_str(), local_key), (peer.as_str(), peer_key)];
    identities.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let mut canonical = Vec::with_capacity(
        SAFETY_NUMBER_DOMAIN.len()
            + identities
                .iter()
                .map(|entry| entry.0.len() + 36)
                .sum::<usize>(),
    );
    canonical.extend_from_slice(SAFETY_NUMBER_DOMAIN);
    for (account, key) in identities {
        let length = u32::try_from(account.len())
            .map_err(|_| ChatError::Invalid("safety-number account is too long".into()))?;
        canonical.extend_from_slice(&length.to_be_bytes());
        canonical.extend_from_slice(account.as_bytes());
        canonical.extend_from_slice(&key);
    }
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    let fingerprint = digest
        .chunks_exact(2)
        .map(|chunk| format!("{:05}", u16::from_be_bytes([chunk[0], chunk[1]])))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(SafetyNumberV1 {
        local_account: local,
        peer_account: peer,
        fingerprint,
        qr_payload: format!("{SAFETY_QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(canonical)),
        authority_key_id: trust.authority_key_id.clone(),
        retained_authority_key_id: None,
        trust: trust.trust,
        continuity_gap: trust.continuity_gap,
        quarantine_reason: trust.quarantine_reason.clone(),
    })
}

fn canonical_federated_account(value: &str) -> Result<String> {
    let address: AccountAddress = value
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Invalid(error.to_string()))?;
    if address.server.is_none() {
        return Err(ChatError::Invalid(
            "safety numbers require a canonical account@server address".into(),
        ));
    }
    Ok(address.canonical())
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let common = left.len().min(right.len());
    for index in 0..common {
        difference |= usize::from(left[index] ^ right[index]);
    }
    difference == 0
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

    pub fn sign_manifest(
        &self,
        account: impl Into<String>,
        sequence: u64,
        previous_hash: Option<String>,
        mut devices: Vec<AccountManifestDeviceV1>,
        issued_at: impl Into<String>,
    ) -> Result<AccountManifestV1> {
        devices.sort_by_key(|device| device.device_id);
        let mut manifest = AccountManifestV1 {
            manifest_version: ACCOUNT_MANIFEST_VERSION,
            account: account.into(),
            incarnation_id: self.incarnation_id(),
            sequence,
            previous_hash,
            drive: AccountManifestDriveKeysV1 {
                suite: AccountIdentitySuiteId::X25519Ed25519V1,
                hpke_public_key: STANDARD.encode(self.identity.drive_hpke_public_key()),
                share_signing_public_key: STANDARD.encode(self.identity.drive_signing_public_key()),
            },
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
    if response.username != manifest.account {
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
            if prior.account != manifest.account
                || prior.drive_hpke_public_key != manifest.drive.hpke_public_key
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
        account: manifest.account.clone(),
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
            trust.drive_hpke_public_key.clone(),
            trust.drive_share_signing_public_key.clone(),
        )
    });
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
            verify_manifest_trust(expected_peer, manifest, prior)?;
            let manifest_identity = (
                manifest.account.clone(),
                manifest.incarnation_id.clone(),
                manifest.authority_key_id.clone(),
                manifest.self_authority_key.clone(),
                manifest.drive.hpke_public_key.clone(),
                manifest.drive.share_signing_public_key.clone(),
            );
            if let Some(identity) = &identity {
                if identity != &manifest_identity {
                    return Err(ChatError::Trust(
                        "account manifest history changes identity".into(),
                    ));
                }
            } else {
                identity = Some(manifest_identity);
            }
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
    let mut trust = verify_manifest_trust(expected_peer, pending, prior)?;
    trust.continuity_gap = false;
    Ok((trust, records))
}

fn match_expected_account(expected_peer: &str, authenticated_account: &str) -> Result<()> {
    let expected: AccountAddress = expected_peer
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    let authenticated: AccountAddress = authenticated_account
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    if expected.username != authenticated.username
        || expected
            .server
            .as_ref()
            .is_some_and(|server| authenticated.server.as_ref() != Some(server))
    {
        return Err(ChatError::Trust(
            "account manifest belongs to another account".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "alice@alpha.example",
            &alice.public_key_base64(),
            &trust("bob@beta.example", &bob),
        )
        .unwrap();
        let bob_view = derive_safety_number(
            "bob@beta.example",
            &bob.public_key_base64(),
            &trust("alice@alpha.example", &alice),
        )
        .unwrap();

        assert_eq!(alice_view.fingerprint, bob_view.fingerprint);
        assert_eq!(alice_view.qr_payload, bob_view.qr_payload);
        let groups: Vec<_> = alice_view.fingerprint.split(' ').collect();
        assert_eq!(groups.len(), 16);
        assert!(groups
            .iter()
            .all(|group| group.len() == 5 && group.bytes().all(|byte| byte.is_ascii_digit())));
        assert!(alice_view.matches_qr_payload(&bob_view.qr_payload));
    }

    #[test]
    fn safety_number_rejects_another_pair_and_note_to_self() {
        let alice = AccountAuthority::derive(&[1u8; 32]).unwrap();
        let bob = AccountAuthority::derive(&[2u8; 32]).unwrap();
        let mallory = AccountAuthority::derive(&[3u8; 32]).unwrap();
        let expected = derive_safety_number(
            "alice@alpha.example",
            &alice.public_key_base64(),
            &trust("bob@beta.example", &bob),
        )
        .unwrap();
        let wrong = derive_safety_number(
            "alice@alpha.example",
            &alice.public_key_base64(),
            &trust("mallory@gamma.example", &mallory),
        )
        .unwrap();

        assert!(!expected.matches_qr_payload(&wrong.qr_payload));
        assert!(!expected.matches_qr_payload(&"x".repeat(MAX_SAFETY_QR_BYTES + 1)));
        assert!(derive_safety_number(
            "alice@alpha.example",
            &alice.public_key_base64(),
            &trust("alice@alpha.example", &alice),
        )
        .is_err());
    }
}
