//! Chat groups on one-to-one sessions (docs/plans/pairwise-groups.md): the
//! keys a group derives from its master key, the sealed parts of its state,
//! and the signatures its changes carry.
//!
//! - A random 32-byte master key, held by members only, gives the group id
//!   and the state key (Signal derives `GroupSecretParams` from its master key
//!   the same way). The group's server knows the id, never the key.
//! - The state key seals each encrypted field of the state (title, a
//!   member's entry, ...) with XChaCha20-Poly1305, bound to the group, the
//!   field's purpose and its subject (a pseudonym or a slot), so a sealed
//!   field cannot be moved to another place.
//! - A member is known to the server only by a pseudonym: a random Ed25519
//!   key per member per group ([`GroupKeyPair`]). Changes are signed by the
//!   actor's pseudonym; a claim of a pending slot is also signed by the slot's
//!   one-time claim key. Signatures are verified strictly.
//! - A member's binding (pseudonym → account) is signed by one of the
//!   account's Chat devices with its libsignal identity key; this module only
//!   fixes the signed bytes ([`binding_signed_bytes`]).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};

pub const MASTER_KEY_LEN: usize = 32;
pub const GROUP_ID_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const SLOT_ID_LEN: usize = 16;
pub const HASH_LEN: usize = 32;

const KDF_SALT: &[u8] = b"kutup/chat-group/v1";
const ID_INFO: &[u8] = b"kutup/chat-group/id/v1";
const STATE_KEY_INFO: &[u8] = b"kutup/chat-group/state-key/v1";

const SEAL_DOMAIN: &[u8] = b"kutup/chat-group/sealed-field/v1\0";
const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

const CHANGE_SIGNATURE_DOMAIN: &[u8] = b"kutup/chat-group/change/v1\0";
const CLAIM_DOMAIN: &[u8] = b"kutup/chat-group/claim/v1\0";
const BINDING_DOMAIN: &[u8] = b"kutup/chat-group/binding/v1\0";
const CHANGE_HASH_DOMAIN: &[u8] = b"kutup/chat-group/change-hash/v1\0";
const STATE_HASH_DOMAIN: &[u8] = b"kutup/chat-group/state-hash/v1\0";

/// A group's master key: the one secret every member holds.
pub struct GroupMasterKey(Zeroizing<[u8; MASTER_KEY_LEN]>);

impl GroupMasterKey {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        copy_randombytes(key.as_mut());
        Self(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; MASTER_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("group master key length".into()))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    /// The group's id, what the server and every message name it by.
    pub fn group_id(&self) -> [u8; GROUP_ID_LEN] {
        let mut id = [0u8; GROUP_ID_LEN];
        self.expand(ID_INFO, &mut id);
        id
    }

    /// The key that seals the state's encrypted fields.
    pub fn state_key(&self) -> GroupStateKey {
        let mut key = Zeroizing::new([0u8; 32]);
        self.expand(STATE_KEY_INFO, key.as_mut());
        GroupStateKey {
            key,
            group_id: self.group_id(),
        }
    }

    fn expand(&self, info: &[u8], out: &mut [u8]) {
        Hkdf::<Sha256>::new(Some(KDF_SALT), self.0.as_ref())
            .expand(info, out)
            .expect("HKDF output length is fixed and valid");
    }
}

/// What a sealed field is; part of its binding, so a title cannot be opened
/// as a member entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SealedField {
    Title = 1,
    Description = 2,
    Timer = 3,
    Avatar = 4,
    /// A member's entry; its subject is the member's pseudonym.
    MemberEntry = 5,
    /// A pending slot's invited account; its subject is the slot id.
    SlotEntry = 6,
    /// The banned accounts.
    BanList = 7,
}

/// The state key, with the group it belongs to.
pub struct GroupStateKey {
    key: Zeroizing<[u8; 32]>,
    group_id: [u8; GROUP_ID_LEN],
}

impl GroupStateKey {
    /// Seals `plain` as `field` of this group, for `subject` (a pseudonym, a
    /// slot id, or empty for a group-wide field).
    pub fn seal(&self, field: SealedField, subject: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        copy_randombytes(&mut nonce);
        self.seal_with_nonce(field, subject, plain, &nonce)
    }

    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_with_fixed_nonce(
        &self,
        field: SealedField,
        subject: &[u8],
        plain: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        self.seal_with_nonce(field, subject, plain, nonce)
    }

    fn seal_with_nonce(
        &self,
        field: SealedField,
        subject: &[u8],
        plain: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let ciphertext = XChaCha20Poly1305::new(self.key.as_slice().into())
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plain,
                    aad: &self.aad(field, subject)?,
                },
            )
            .map_err(|_| CryptoError::Backend("group field seal".into()))?;
        Ok([&[SEAL_VERSION][..], nonce, &ciphertext].concat())
    }

    /// Opens a sealed field; fails unless it was sealed as `field` of this
    /// group for `subject`.
    pub fn open(
        &self,
        field: SealedField,
        subject: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 1 + NONCE_LEN + TAG_LEN || sealed[0] != SEAL_VERSION {
            return Err(CryptoError::AuthFailed);
        }
        let (nonce, ciphertext) = sealed[1..].split_at(NONCE_LEN);
        let plain = XChaCha20Poly1305::new(self.key.as_slice().into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad(field, subject)?,
                },
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok(Zeroizing::new(plain))
    }

    fn aad(&self, field: SealedField, subject: &[u8]) -> Result<Vec<u8>> {
        let subject_len = u16::try_from(subject.len())
            .map_err(|_| CryptoError::InvalidInput("sealed field subject length".into()))?;
        Ok([
            SEAL_DOMAIN,
            &self.group_id,
            &[field as u8],
            &subject_len.to_be_bytes(),
            subject,
        ]
        .concat())
    }
}

/// The length a field sealed from `plain_len` bytes has.
pub const fn sealed_len(plain_len: usize) -> usize {
    1 + NONCE_LEN + plain_len + TAG_LEN
}

/// An Ed25519 key pair of a group: a member's pseudonym, or a pending slot's
/// one-time claim key.
pub struct GroupKeyPair {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; PUBLIC_KEY_LEN],
}

impl GroupKeyPair {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        copy_randombytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        Self {
            seed: Zeroizing::new(*seed),
            public,
        }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// Signs a change's signed bytes ([`change_signed_bytes`]).
    pub fn sign_change(&self, change_bytes: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.sign(&change_signed_bytes(change_bytes))
    }

    /// Signs a claim ([`claim_signed_bytes`]) with a slot's claim key.
    pub fn sign_claim(
        &self,
        group_id: &[u8; GROUP_ID_LEN],
        slot_id: &[u8; SLOT_ID_LEN],
        slot_revision: u64,
        new_pseudonym: &[u8; PUBLIC_KEY_LEN],
    ) -> [u8; SIGNATURE_LEN] {
        self.sign(&claim_signed_bytes(
            group_id,
            slot_id,
            slot_revision,
            new_pseudonym,
        ))
    }

    fn sign(&self, bytes: &[u8]) -> [u8; SIGNATURE_LEN] {
        SigningKey::from_bytes(&self.seed).sign(bytes).to_bytes()
    }
}

/// What a change's actor signs: the domain, then the change's canonical bytes
/// without its signature.
pub fn change_signed_bytes(change_bytes: &[u8]) -> Vec<u8> {
    [CHANGE_SIGNATURE_DOMAIN, change_bytes].concat()
}

/// What a slot's claim key signs: that `new_pseudonym` claims `slot_id` of
/// the group, the slot added at `slot_revision` (so the claim can't be
/// replayed into a later slot with the same id). Nothing the server sees
/// lets it sign this.
pub fn claim_signed_bytes(
    group_id: &[u8; GROUP_ID_LEN],
    slot_id: &[u8; SLOT_ID_LEN],
    slot_revision: u64,
    new_pseudonym: &[u8; PUBLIC_KEY_LEN],
) -> Vec<u8> {
    [
        CLAIM_DOMAIN,
        group_id,
        slot_id,
        &slot_revision.to_be_bytes(),
        new_pseudonym,
    ]
    .concat()
}

/// What an account's Chat device signs to bind a pseudonym of the group to
/// the account. The signature is made and checked by chat-core with the
/// device's libsignal identity key, against the account's verified manifest.
pub fn binding_signed_bytes(
    group_id: &[u8; GROUP_ID_LEN],
    pseudonym: &[u8; PUBLIC_KEY_LEN],
    account: &AccountRef,
) -> Vec<u8> {
    [BINDING_DOMAIN, group_id, pseudonym, &account.bytes()].concat()
}

/// Verifies an Ed25519 signature of a group key (strict).
fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    bytes: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    VerifyingKey::from_bytes(public)
        .map_err(|_| CryptoError::AuthFailed)?
        .verify_strict(bytes, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::AuthFailed)
}

/// Verifies a change's signature by its actor's pseudonym.
pub fn verify_change_signature(
    pseudonym: &[u8; PUBLIC_KEY_LEN],
    change_bytes: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    verify(pseudonym, &change_signed_bytes(change_bytes), signature)
}

/// Verifies a claim's signature by the slot's claim key.
pub fn verify_claim_signature(
    claim_key: &[u8; PUBLIC_KEY_LEN],
    group_id: &[u8; GROUP_ID_LEN],
    slot_id: &[u8; SLOT_ID_LEN],
    slot_revision: u64,
    new_pseudonym: &[u8; PUBLIC_KEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    verify(
        claim_key,
        &claim_signed_bytes(group_id, slot_id, slot_revision, new_pseudonym),
        signature,
    )
}

/// The hash a change is chained and notarised by: of its canonical bytes
/// with its signature.
pub fn change_hash(signed_change_bytes: &[u8]) -> [u8; HASH_LEN] {
    Sha256::new()
        .chain_update(CHANGE_HASH_DOMAIN)
        .chain_update(signed_change_bytes)
        .finalize()
        .into()
}

/// The hash of a state: of its canonical bytes, which carry the sealed
/// fields as their ciphertext, so a server can compute it.
pub fn state_hash(state_bytes: &[u8]) -> [u8; HASH_LEN] {
    Sha256::new()
        .chain_update(STATE_HASH_DOMAIN)
        .chain_update(state_bytes)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> GroupMasterKey {
        GroupMasterKey::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn ids_and_keys_are_derived_and_distinct() {
        let a = master();
        let b = GroupMasterKey::from_bytes(&[8u8; 32]).unwrap();
        assert_eq!(a.group_id(), master().group_id());
        assert_ne!(a.group_id(), b.group_id());
        assert_ne!(a.group_id().as_slice(), a.state_key().key.as_slice());
    }

    #[test]
    fn a_sealed_field_opens_only_in_its_place() {
        let key = master().state_key();
        let sealed = key
            .seal(SealedField::MemberEntry, &[1u8; 32], b"entry")
            .unwrap();
        assert_eq!(sealed.len(), sealed_len(5));
        assert_eq!(
            key.open(SealedField::MemberEntry, &[1u8; 32], &sealed)
                .unwrap()
                .as_slice(),
            b"entry"
        );
        // Another subject, another field, another group: refused.
        assert!(key
            .open(SealedField::MemberEntry, &[2u8; 32], &sealed)
            .is_err());
        assert!(key
            .open(SealedField::SlotEntry, &[1u8; 32], &sealed)
            .is_err());
        let other = GroupMasterKey::from_bytes(&[9u8; 32]).unwrap().state_key();
        assert!(other
            .open(SealedField::MemberEntry, &[1u8; 32], &sealed)
            .is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(key
            .open(SealedField::MemberEntry, &[1u8; 32], &tampered)
            .is_err());
    }

    #[test]
    fn change_and_claim_signatures_verify_only_for_their_bytes() {
        let pseudonym = GroupKeyPair::generate();
        let signature = pseudonym.sign_change(b"change");
        verify_change_signature(&pseudonym.public_key(), b"change", &signature).unwrap();
        assert!(verify_change_signature(&pseudonym.public_key(), b"other", &signature).is_err());

        let group = master().group_id();
        let claim_key = GroupKeyPair::generate();
        let claimant = GroupKeyPair::generate().public_key();
        let claim = claim_key.sign_claim(&group, &[3u8; 16], 4, &claimant);
        let key = claim_key.public_key();
        verify_claim_signature(&key, &group, &[3u8; 16], 4, &claimant, &claim).unwrap();
        // Another pseudonym, slot or slot revision: refused. A change
        // signature is not a claim.
        let thief = GroupKeyPair::generate().public_key();
        assert!(verify_claim_signature(&key, &group, &[3u8; 16], 4, &thief, &claim).is_err());
        assert!(verify_claim_signature(&key, &group, &[4u8; 16], 4, &claimant, &claim).is_err());
        assert!(verify_claim_signature(&key, &group, &[3u8; 16], 5, &claimant, &claim).is_err());
        let as_change =
            claim_key.sign_change(&claim_signed_bytes(&group, &[3u8; 16], 4, &claimant));
        assert!(
            verify_claim_signature(&key, &group, &[3u8; 16], 4, &claimant, &as_change).is_err()
        );
    }

    #[test]
    fn hashes_are_domain_separated() {
        assert_ne!(change_hash(b"x"), state_hash(b"x"));
    }
}
