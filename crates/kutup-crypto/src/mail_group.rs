//! A shared mailbox's signing key and its key-list chain (docs/plans/mail-groups.md,
//! docs/plans/account-ids.md), as Proton's Signed Key Lists: the lists are
//! signed by a key the mailbox's owners and managers hold, never by the
//! server, so a server cannot add or swap a key senders encrypt to.
//!
//! - The signing key (Ed25519) is made in a manager's browser and reaches
//!   each owner and manager as a share sealed to their account key, as the
//!   group key does ([`seal_group_signing_share`]).
//! - Its lists are [`MailKeyListV1`] signed with it as their "authority":
//!   their `authority_key_id` and `incarnation_id` are derived from its
//!   public key. For a group that `incarnation_id` names the signer, not an
//!   account incarnation; nothing treats it as one.
//! - When the signer changes (a manager left), the outgoing signer signs a
//!   [`GroupSignerHandoverV1`] naming the next one, linked to the last list
//!   it signed, as a rename chain links names.
//! - [`verify_group_key_chain`] checks a whole chain: what senders pin (the
//!   signers and the list digests) and what the server checks before it
//!   stores a list.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};
use crate::mail_key::{
    open_group_secret, seal_group_secret, GroupShareMember, MailKeyListV1, SignedMailKeyListV1,
};

const SIGNING_SHARE_DOMAIN: &[u8] = b"kutup/mail-group-signing-share/v2\0";
const HANDOVER_DOMAIN: &[u8] = b"kutup/mail-group-signer-handover/v1\0";
const HANDOVER_VERSION: u16 = 1;
/// The handover's bytes after its domain: version, group, sequence, the
/// previous list's hash, the next signer, the signature.
const HANDOVER_LEN: usize = 2 + 16 + 8 + 32 + 32 + 64;

/// A shared mailbox's signing key, made in a manager's browser.
pub struct GroupSigningKey {
    pub seed: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
}

impl GroupSigningKey {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        crate::primitives::random(seed.as_mut());
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let public_key = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        Self {
            seed: Zeroizing::new(*seed),
            public_key,
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

/// The signing key's seed sealed to one owner or manager (their account
/// key, as [`crate::mail_key::seal_group_key_share`] seals the group key),
/// bound to the group, the signing key's public key, their account and its
/// incarnation.
pub fn seal_group_signing_share(
    key: &GroupSigningKey,
    group_id: &str,
    member: &GroupShareMember<'_>,
    member_hpke_public_key: &[u8; crate::hpke_xwing::PUBLIC_KEY_LEN],
) -> Result<Vec<u8>> {
    seal_group_secret(
        SIGNING_SHARE_DOMAIN,
        key.seed.as_ref(),
        group_id,
        &key.public_key,
        member,
        member_hpke_public_key,
    )
}

/// Opens a signing-key share: the key, once it is the one `signer_public`
/// names.
pub fn open_group_signing_share(
    share: &[u8],
    group_id: &str,
    signer_public: &[u8; 32],
    member: &AccountRef,
    member_hpke_private_key: &[u8],
) -> Result<GroupSigningKey> {
    let seed = open_group_secret(
        SIGNING_SHARE_DOMAIN,
        share,
        group_id,
        signer_public,
        member,
        member_hpke_private_key,
    )?;
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthFailed)?;
    let key = GroupSigningKey::from_seed(&seed);
    if key.public_key != *signer_public {
        return Err(CryptoError::AuthFailed);
    }
    Ok(key)
}

/// The outgoing signer of a shared mailbox's key lists naming the next one:
/// from the list at `sequence`, lists are signed by `next_signer`, and that
/// list follows the one whose hash is `previous_list_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSignerHandoverV1 {
    pub group_id: [u8; 16],
    /// The sequence of the first list the next signer signs (2 or more).
    pub sequence: u64,
    /// [`SignedMailKeyListV1::hash`] of the list before it, the outgoing
    /// signer's last.
    pub previous_list_hash: [u8; 32],
    pub next_signer: [u8; 32],
    pub signature: [u8; 64],
}

impl GroupSignerHandoverV1 {
    fn signed_bytes(
        group_id: &[u8; 16],
        sequence: u64,
        previous_list_hash: &[u8; 32],
        next_signer: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(HANDOVER_DOMAIN.len() + HANDOVER_LEN - 64);
        out.extend_from_slice(HANDOVER_DOMAIN);
        out.extend_from_slice(&HANDOVER_VERSION.to_be_bytes());
        out.extend_from_slice(group_id);
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(previous_list_hash);
        out.extend_from_slice(next_signer);
        out
    }

    /// Signs the handover with the outgoing signer.
    pub fn sign(
        outgoing: &GroupSigningKey,
        group_id: &str,
        sequence: u64,
        previous_list_hash: &[u8; 32],
        next_signer: &[u8; 32],
    ) -> Result<Self> {
        let group_id = crate::drive_object::parse_canonical_uuid(group_id, "group")?;
        if sequence < 2 || *next_signer == outgoing.public_key {
            return Err(CryptoError::InvalidInput(
                "a handover starts at sequence 2 or later, to another signer".into(),
            ));
        }
        let bytes = Self::signed_bytes(&group_id, sequence, previous_list_hash, next_signer);
        Ok(Self {
            group_id,
            sequence,
            previous_list_hash: *previous_list_hash,
            next_signer: *next_signer,
            signature: outgoing.signing_key().sign(&bytes).to_bytes(),
        })
    }

    /// Whether `outgoing` signed it.
    pub fn verify(&self, outgoing: &[u8; 32]) -> Result<()> {
        let bytes = Self::signed_bytes(
            &self.group_id,
            self.sequence,
            &self.previous_list_hash,
            &self.next_signer,
        );
        VerifyingKey::from_bytes(outgoing)
            .map_err(|_| CryptoError::InvalidInput("signer key is invalid".into()))?
            .verify_strict(&bytes, &Signature::from_bytes(&self.signature))
            .map_err(|_| CryptoError::AuthFailed)
    }

    /// The handover's bytes: its signed fields after the domain, then the
    /// signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Self::signed_bytes(
            &self.group_id,
            self.sequence,
            &self.previous_list_hash,
            &self.next_signer,
        )[HANDOVER_DOMAIN.len()..]
            .to_vec();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let refused = || CryptoError::InvalidInput("not a group signer handover".into());
        if bytes.len() != HANDOVER_LEN || bytes[..2] != HANDOVER_VERSION.to_be_bytes() {
            return Err(refused());
        }
        let handover = Self {
            group_id: bytes[2..18].try_into().expect("16 bytes"),
            sequence: u64::from_be_bytes(bytes[18..26].try_into().expect("8 bytes")),
            previous_list_hash: bytes[26..58].try_into().expect("32 bytes"),
            next_signer: bytes[58..90].try_into().expect("32 bytes"),
            signature: bytes[90..154].try_into().expect("64 bytes"),
        };
        if handover.sequence < 2 {
            return Err(refused());
        }
        Ok(handover)
    }
}

/// A verified chain of a shared mailbox's key lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyChainView {
    /// The signer of the first list: what a sender pins on first sight.
    pub first_signer: [u8; 32],
    /// The signer now (of the newest list).
    pub signer: [u8; 32],
    /// Every signer in order, the first one first.
    pub signers: Vec<[u8; 32]>,
    pub newest: MailKeyListV1,
    /// The newest list's sequence (= the number of lists).
    pub sequence: u64,
    /// [`SignedMailKeyListV1::hash`] of each list in order: `digests[i]` is
    /// list `i + 1`'s.
    pub digests: Vec<[u8; 32]>,
}

/// Checks a shared mailbox's whole key-list chain:
/// - list `i` has sequence `i` (from 1, no gaps or reordering), names one
///   address throughout, and links to list `i − 1` by its hash;
/// - list 1 is signed by `first_signer`;
/// - each later list is signed by the signer in force at its sequence:
///   the one before, unless a handover at that sequence names another,
///   signed by the one before and linked to list `i − 1` (handovers in
///   order, none skipped, none left over). A list an outgoing signer signs
///   after its handover is refused.
pub fn verify_group_key_chain(
    group_id: &str,
    first_signer: &[u8; 32],
    lists: &[(&[u8], &[u8])],
    handovers: &[GroupSignerHandoverV1],
) -> Result<GroupKeyChainView> {
    let refused = |reason: &str| CryptoError::InvalidInput(format!("group key chain: {reason}"));
    let group = crate::drive_object::parse_canonical_uuid(group_id, "group")?;
    if lists.is_empty() {
        return Err(refused("no key list"));
    }
    if handovers.iter().any(|handover| handover.group_id != group) {
        return Err(refused("a handover is for another group"));
    }
    let mut signer = *first_signer;
    let mut signers = vec![signer];
    let mut digests = Vec::with_capacity(lists.len());
    let mut previous: Option<SignedMailKeyListV1> = None;
    let mut pending = handovers.iter().peekable();
    for (index, (data, signature)) in lists.iter().enumerate() {
        let sequence = index as u64 + 1;
        if let Some(handover) = pending.next_if(|handover| handover.sequence == sequence) {
            let before = previous
                .as_ref()
                .ok_or_else(|| refused("a handover before the first list"))?;
            handover
                .verify(&signer)
                .map_err(|_| refused("a handover is not signed by the signer in force"))?;
            if handover.previous_list_hash != before.hash() || handover.next_signer == signer {
                return Err(refused("a handover does not follow the list before it"));
            }
            signer = handover.next_signer;
            signers.push(signer);
        }
        let list = SignedMailKeyListV1::verify(data, signature, &signer)
            .map_err(|_| refused("a list is not signed by the signer in force"))?;
        if list.list.sequence != sequence {
            return Err(refused("the lists are not in sequence"));
        }
        if let Some(before) = &previous {
            if list.list.address != before.list.address
                || list.list.previous_hash != Some(before.hash())
            {
                return Err(refused("a list does not follow the one before"));
            }
        } else if list.list.previous_hash.is_some() {
            return Err(refused("the first list follows another"));
        }
        digests.push(list.hash());
        previous = Some(list);
    }
    if pending.next().is_some() {
        return Err(refused(
            "a handover is out of order or past the newest list",
        ));
    }
    let newest = previous.expect("one list at least");
    Ok(GroupKeyChainView {
        first_signer: *first_signer,
        signer,
        signers,
        sequence: newest.list.sequence,
        newest: newest.list,
        digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{authority_key_id_from_public, incarnation_id_from_authority_public};
    use crate::mail_key::{MailKeyEntryV1, DEFAULT_FLAGS};

    const GROUP: &str = "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b";

    fn list(
        signer: &GroupSigningKey,
        sequence: u64,
        previous: Option<&SignedMailKeyListV1>,
        fingerprint: u8,
    ) -> SignedMailKeyListV1 {
        let hex32 = |value: String| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
        MailKeyListV1 {
            incarnation_id: hex32(incarnation_id_from_authority_public(&signer.public_key)),
            authority_key_id: hex32(authority_key_id_from_public(&signer.public_key)),
            address: "hr@kutup.dev".into(),
            sequence,
            previous_hash: previous.map(SignedMailKeyListV1::hash),
            issued_at: "2026-10-16T12:00:00Z".into(),
            keys: vec![MailKeyEntryV1 {
                fingerprint: [fingerprint; 20],
                sha256_fingerprint: [fingerprint; 32],
                primary: true,
                flags: DEFAULT_FLAGS,
            }],
        }
        .sign(&signer.signing_key())
        .unwrap()
    }

    fn pairs(lists: &[SignedMailKeyListV1]) -> Vec<(&[u8], &[u8])> {
        lists
            .iter()
            .map(|list| (list.data.as_slice(), list.signature.as_slice()))
            .collect()
    }

    #[test]
    fn a_chain_follows_its_signers_through_handovers_only() {
        let (a, b) = (
            GroupSigningKey::from_seed(&[1; 32]),
            GroupSigningKey::from_seed(&[2; 32]),
        );
        let server = GroupSigningKey::from_seed(&[9; 32]);
        let one = list(&a, 1, None, 1);
        let two = list(&a, 2, Some(&one), 2);
        let handover =
            GroupSignerHandoverV1::sign(&a, GROUP, 3, &two.hash(), &b.public_key).unwrap();
        let three = list(&b, 3, Some(&two), 3);
        let chain = [one.clone(), two.clone(), three.clone()];
        let view = verify_group_key_chain(
            GROUP,
            &a.public_key,
            &pairs(&chain),
            std::slice::from_ref(&handover),
        )
        .unwrap();
        assert_eq!(view.signers, vec![a.public_key, b.public_key]);
        assert_eq!((view.signer, view.sequence), (b.public_key, 3));
        assert_eq!(view.digests, vec![one.hash(), two.hash(), three.hash()]);
        assert_eq!(
            GroupSignerHandoverV1::decode(&handover.encode()).unwrap(),
            handover
        );

        // A link the server signs, or one without its handover: refused.
        let forged = list(&server, 3, Some(&two), 3);
        assert!(verify_group_key_chain(
            GROUP,
            &a.public_key,
            &pairs(&[one.clone(), two.clone(), forged]),
            &[]
        )
        .is_err());
        assert!(verify_group_key_chain(GROUP, &a.public_key, &pairs(&chain), &[]).is_err());
        // The outgoing signer forking the chain after its handover: refused.
        let fork = list(&a, 3, Some(&two), 4);
        assert!(verify_group_key_chain(
            GROUP,
            &a.public_key,
            &pairs(&[one.clone(), two.clone(), fork]),
            std::slice::from_ref(&handover)
        )
        .is_err());
        // A handover signed by anyone else, for another group, or left over.
        let stolen =
            GroupSignerHandoverV1::sign(&server, GROUP, 3, &two.hash(), &b.public_key).unwrap();
        assert!(verify_group_key_chain(GROUP, &a.public_key, &pairs(&chain), &[stolen]).is_err());
        let elsewhere = GroupSignerHandoverV1::sign(
            &a,
            "00000000-0000-4000-8000-000000000000",
            3,
            &two.hash(),
            &b.public_key,
        )
        .unwrap();
        assert!(
            verify_group_key_chain(GROUP, &a.public_key, &pairs(&chain), &[elsewhere]).is_err()
        );
        assert!(
            verify_group_key_chain(GROUP, &a.public_key, &pairs(&chain[..2]), &[handover]).is_err()
        );
        // A gap or reordering.
        assert!(verify_group_key_chain(
            GROUP,
            &a.public_key,
            &pairs(&[one.clone(), list(&a, 3, Some(&one), 3)]),
            &[]
        )
        .is_err());
        // Another first signer (an administrator starting over) is another chain.
        assert!(verify_group_key_chain(GROUP, &b.public_key, &pairs(&chain), &[]).is_err());
    }

    #[test]
    fn a_signing_key_share_opens_for_its_member_and_signer_only() {
        let key = GroupSigningKey::from_seed(&[5; 32]);
        let bob = crate::identity::AccountIdentityKeysV1::derive(&[0x22; 32]).unwrap();
        let bob_ref = AccountRef::new("kutup.dev", "8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b").unwrap();
        let incarnation = bob.incarnation_id();
        let share = seal_group_signing_share(
            &key,
            GROUP,
            &GroupShareMember {
                account: &bob_ref,
                incarnation_id: &incarnation,
            },
            &bob.drive_hpke_public_key(),
        )
        .unwrap();
        let opened = open_group_signing_share(
            &share,
            GROUP,
            &key.public_key,
            &bob_ref,
            bob.drive_hpke_private_key(),
        )
        .unwrap();
        assert_eq!(opened.public_key, key.public_key);
        let other = GroupSigningKey::from_seed(&[6; 32]);
        assert!(open_group_signing_share(
            &share,
            GROUP,
            &other.public_key,
            &bob_ref,
            bob.drive_hpke_private_key()
        )
        .is_err());
        let carol = AccountRef::new("kutup.dev", "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70").unwrap();
        assert!(open_group_signing_share(
            &share,
            GROUP,
            &key.public_key,
            &carol,
            bob.drive_hpke_private_key()
        )
        .is_err());
    }
}
