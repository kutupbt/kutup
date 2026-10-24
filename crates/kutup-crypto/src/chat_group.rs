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
//! - A member's binding (pseudonym → account) is signed by the account's
//!   self-authority key, which every device derives from the account master
//!   key, so devices coming and going never touch it ([`sign_binding`],
//!   [`verify_binding`]).

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
/// v2: the id binds the group's home (its server and the federation identity
/// it was pinned at), so the same master key at another home is another
/// group.
const ID_INFO: &[u8] = b"kutup/chat-group/id/v2\0";
const HOME_DOMAIN: &[u8] = b"kutup/chat-group/home/v1\0";
/// v2: the group id follows in the info, so a state key is its group's
/// alone (each sealed field binds the id as well).
const STATE_KEY_INFO: &[u8] = b"kutup/chat-group/state-key/v2\0";

const SEAL_DOMAIN: &[u8] = b"kutup/chat-group/sealed-field/v1\0";
const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

const CHANGE_SIGNATURE_DOMAIN: &[u8] = b"kutup/chat-group/change/v1\0";
const CLAIM_DOMAIN: &[u8] = b"kutup/chat-group/claim/v1\0";
const BINDING_DOMAIN: &[u8] = b"kutup/chat-group/binding/v1\0";
const CHANGE_HASH_DOMAIN: &[u8] = b"kutup/chat-group/change-hash/v1\0";
const STATE_HASH_DOMAIN: &[u8] = b"kutup/chat-group/state-hash/v1\0";

/// A group's home, as its id binds it: the server the group lives on, for
/// its whole life, and the federation identity document it was pinned at.
/// Every notary a member takes is verified against the identity history
/// followed from that pin (chat-core's `GroupRecordV1::followed_history`).
/// A member who keeps the master key can't make the group live elsewhere: a
/// home of theirs is another group id, which no member's binding names.
#[derive(Clone, Copy, Debug)]
pub struct GroupHome<'a> {
    pub server: &'a str,
    pub identity_sequence: u64,
    pub identity_document_hash: &'a str,
}

impl GroupHome<'_> {
    /// The home's digest: SHA-256 over the domain, the server name and the
    /// identity document hash (each u16-length-prefixed), then the identity
    /// sequence (u64 big-endian). Only canonical spellings are taken, so one
    /// home has one id: the server a lowercase DNS name with no trailing dot
    /// ([`crate::account_ref::valid_server`]), the hash exactly 64 lowercase
    /// hex digits; anything else is refused, never normalised. This is the
    /// pin made at the group's creation, kept for its life: the home's
    /// identity rotating later doesn't move the id (members follow the
    /// rotation from the pin).
    fn digest(&self) -> Result<[u8; 32]> {
        let canonical_hash = self.identity_document_hash.len() == 64
            && self
                .identity_document_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !crate::account_ref::valid_server(self.server) || !canonical_hash {
            return Err(CryptoError::InvalidInput(
                "a group home must be a canonical server name and identity hash".into(),
            ));
        }
        let mut hash = Sha256::new();
        hash.update(HOME_DOMAIN);
        for text in [self.server, self.identity_document_hash] {
            hash.update((text.len() as u16).to_be_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(self.identity_sequence.to_be_bytes());
        Ok(hash.finalize().into())
    }
}

/// A group's master key, the one secret every member holds, with the home
/// it belongs to.
pub struct GroupMasterKey {
    key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    home: [u8; 32],
}

impl GroupMasterKey {
    /// A new group's key, at `home`.
    pub fn generate(home: GroupHome<'_>) -> Result<Self> {
        let home = home.digest()?;
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        copy_randombytes(key.as_mut());
        Ok(Self { key, home })
    }

    /// A group's key from its bytes, for the group at `home`.
    pub fn from_bytes(bytes: &[u8], home: GroupHome<'_>) -> Result<Self> {
        let key: [u8; MASTER_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("group master key length".into()))?;
        Ok(Self {
            key: Zeroizing::new(key),
            home: home.digest()?,
        })
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.key
    }

    /// The group's id, what the server and every message name it by: the
    /// master key's, at its home.
    pub fn group_id(&self) -> [u8; GROUP_ID_LEN] {
        let mut id = [0u8; GROUP_ID_LEN];
        self.expand(&[ID_INFO, &self.home].concat(), &mut id);
        id
    }

    /// The key that seals the state's encrypted fields: the master key's,
    /// for this group id.
    pub fn state_key(&self) -> GroupStateKey {
        let group_id = self.group_id();
        let mut key = Zeroizing::new([0u8; 32]);
        self.expand(&[STATE_KEY_INFO, &group_id].concat(), key.as_mut());
        GroupStateKey { key, group_id }
    }

    fn expand(&self, info: &[u8], out: &mut [u8]) {
        Hkdf::<Sha256>::new(Some(KDF_SALT), self.key.as_ref())
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
    /// A member's group send endorsement, as it shares it with the group
    /// (kutup-group-send's blob); its subject is the member's pseudonym.
    Endorsement = 8,
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

const PSEUDONYM_SALT: &[u8] = b"kutup/chat-group-pseudonym/v1\0";

/// Where an account's group pseudonyms come from: its master key, so any
/// device of the account finds its place in a group again, even one whose
/// group list entry was lost. A pseudonym's seed is HKDF-SHA256 over the
/// account master key, salt `kutup/chat-group-pseudonym/v1\0`, info the
/// group id then the join epoch (u32 big-endian). The join epoch counts the
/// account's joins of the group: 0 at the first, one more at each rejoin
/// after leaving, so a rejoin is a new pseudonym. Without the account key,
/// one account's pseudonyms in different groups (or epochs) are unrelated.
pub struct GroupPseudonymKey {
    hkdf: Hkdf<Sha256>,
}

impl GroupPseudonymKey {
    pub fn derive(account_master_key: &[u8; 32]) -> Self {
        Self {
            hkdf: Hkdf::<Sha256>::new(Some(PSEUDONYM_SALT), account_master_key),
        }
    }

    /// The pseudonym's seed in `group_id` at `join_epoch`.
    pub fn seed(&self, group_id: &[u8; GROUP_ID_LEN], join_epoch: u32) -> Zeroizing<[u8; 32]> {
        let mut info = [0u8; GROUP_ID_LEN + 4];
        info[..GROUP_ID_LEN].copy_from_slice(group_id);
        info[GROUP_ID_LEN..].copy_from_slice(&join_epoch.to_be_bytes());
        let mut seed = Zeroizing::new([0u8; 32]);
        self.hkdf
            .expand(&info, seed.as_mut())
            .expect("HKDF output length is fixed and valid");
        seed
    }

    /// The pseudonym in `group_id` at `join_epoch`.
    pub fn pseudonym(&self, group_id: &[u8; GROUP_ID_LEN], join_epoch: u32) -> GroupKeyPair {
        GroupKeyPair::from_seed(&self.seed(group_id, join_epoch))
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

/// What an account's self-authority signs to bind a pseudonym of the group to
/// the account: the binding domain, the group id, the pseudonym and the
/// account. Members check it against the authority key of the account's
/// verified manifest.
pub fn binding_signed_bytes(
    group_id: &[u8; GROUP_ID_LEN],
    pseudonym: &[u8; PUBLIC_KEY_LEN],
    account: &AccountRef,
) -> Vec<u8> {
    [BINDING_DOMAIN, group_id, pseudonym, &account.bytes()].concat()
}

/// The account's binding of `pseudonym` in `group_id`, signed by its
/// self-authority ([`crate::identity::AccountIdentityKeysV1::authority_signing_key`]).
pub fn sign_binding(
    authority: &SigningKey,
    group_id: &[u8; GROUP_ID_LEN],
    pseudonym: &[u8; PUBLIC_KEY_LEN],
    account: &AccountRef,
) -> [u8; SIGNATURE_LEN] {
    authority
        .sign(&binding_signed_bytes(group_id, pseudonym, account))
        .to_bytes()
}

/// Checks a binding against the account's self-authority public key (strict).
pub fn verify_binding(
    authority_public: &[u8; PUBLIC_KEY_LEN],
    group_id: &[u8; GROUP_ID_LEN],
    pseudonym: &[u8; PUBLIC_KEY_LEN],
    account: &AccountRef,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    verify(
        authority_public,
        &binding_signed_bytes(group_id, pseudonym, account),
        signature,
    )
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

/// A group's avatar (docs/plans/pairwise-groups.md §11, "Avatar"): the image,
/// padded to a size bucket, sealed under a fresh random key, so the same
/// picture in two groups gives unrelated blobs. The blob is `version (1) ‖
/// nonce (24) ‖ ciphertext ‖ tag (16)`; the home stores and serves it by its
/// SHA-256 and sees nothing else. The key travels in the group's sealed
/// avatar attribute.
pub const AVATAR_BUCKETS: [usize; 4] = [8 * 1024, 16 * 1024, 32 * 1024, 40 * 1024];
const AVATAR_VERSION: u8 = 1;
const AVATAR_AAD: &[u8] = b"kutup/chat-group/avatar/v1\0";

/// The blob length a padded bucket gives.
pub const fn avatar_blob_len(bucket: usize) -> usize {
    1 + NONCE_LEN + bucket + TAG_LEN
}

/// The largest image an avatar takes: the largest bucket, less the padding
/// marker.
pub const MAX_AVATAR_IMAGE_BYTES: usize = AVATAR_BUCKETS[AVATAR_BUCKETS.len() - 1] - 1;

/// Seals `image` as a group avatar: the blob, and the key that opens it.
pub fn seal_group_avatar(image: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let mut key = Zeroizing::new([0u8; 32]);
    copy_randombytes(key.as_mut_slice());
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    let blob = seal_group_avatar_with(image, &key, &nonce)?;
    Ok((blob, key))
}

/// [`seal_group_avatar`] with a given key and nonce, for checked-in vectors.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_group_avatar_with_fixed_key(
    image: &[u8],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    seal_group_avatar_with(image, key, nonce)
}

fn seal_group_avatar_with(
    image: &[u8],
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let bucket = AVATAR_BUCKETS
        .iter()
        .copied()
        .find(|bucket| image.len() < *bucket)
        .ok_or_else(|| CryptoError::InvalidInput("a group avatar is at most 40 KiB".into()))?;
    // ISO/IEC 7816-4: a 0x80 marker, then zeros to the bucket.
    let mut padded = Zeroizing::new(Vec::with_capacity(bucket));
    padded.extend_from_slice(image);
    padded.push(0x80);
    padded.resize(bucket, 0);
    let ciphertext = XChaCha20Poly1305::new(key.as_slice().into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &padded,
                aad: AVATAR_AAD,
            },
        )
        .map_err(|_| CryptoError::Backend("group avatar seal".into()))?;
    Ok([&[AVATAR_VERSION][..], nonce, &ciphertext].concat())
}

/// Opens a group avatar blob with its key: the image, unpadded. Any other
/// length than a bucket's, version or key fails.
pub fn open_group_avatar(blob: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    if !AVATAR_BUCKETS
        .iter()
        .any(|bucket| avatar_blob_len(*bucket) == blob.len())
        || blob[0] != AVATAR_VERSION
    {
        return Err(CryptoError::AuthFailed);
    }
    let (nonce, ciphertext) = blob[1..].split_at(NONCE_LEN);
    let padded = Zeroizing::new(
        XChaCha20Poly1305::new(key.as_slice().into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: AVATAR_AAD,
                },
            )
            .map_err(|_| CryptoError::AuthFailed)?,
    );
    let end = padded
        .iter()
        .rposition(|byte| *byte != 0)
        .filter(|at| padded[*at] == 0x80)
        .ok_or(CryptoError::AuthFailed)?;
    Ok(Zeroizing::new(padded[..end].to_vec()))
}

/// The SHA-256 of a blob as stored: what the avatar attribute names in the
/// clear, so the home can serve and clean up blobs.
pub fn avatar_blob_hash(blob: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(blob).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: GroupHome<'static> = GroupHome {
        server: "home.example",
        identity_sequence: 1,
        identity_document_hash: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
    };

    #[test]
    fn a_state_key_opens_only_its_own_groups_fields() {
        let master = |home: GroupHome<'_>| GroupMasterKey::from_bytes(&[7u8; 32], home).unwrap();
        let here = master(HOME).state_key();
        let sealed = here.seal(SealedField::Title, b"", b"Team").unwrap();
        assert_eq!(
            &*here.open(SealedField::Title, b"", &sealed).unwrap(),
            b"Team"
        );
        let elsewhere = master(GroupHome {
            server: "elsewhere.example",
            ..HOME
        })
        .state_key();
        assert!(elsewhere.open(SealedField::Title, b"", &sealed).is_err());
    }

    #[test]
    fn the_same_key_at_another_home_is_another_group() {
        let at = |home: GroupHome<'_>| {
            GroupMasterKey::from_bytes(&[7u8; 32], home)
                .unwrap()
                .group_id()
        };
        let here = at(HOME);
        assert_eq!(here, at(HOME));
        assert_ne!(
            here,
            at(GroupHome {
                server: "elsewhere.example",
                ..HOME
            })
        );
        assert_ne!(
            here,
            at(GroupHome {
                identity_sequence: 2,
                ..HOME
            })
        );
        assert_ne!(
            here,
            at(GroupHome {
                identity_document_hash:
                    "1f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
                ..HOME
            })
        );
        // Only canonical spellings: one home, one id. Anything else is
        // refused, never normalised (or cut).
        let upper_hash = "0F".repeat(32);
        let long = "a".repeat(256);
        for server in [
            "Home.Example",
            "home.example.",
            "",
            "home",
            "10.0.0.1",
            long.as_str(),
        ] {
            assert!(
                GroupMasterKey::from_bytes(&[7u8; 32], GroupHome { server, ..HOME }).is_err(),
                "{server}"
            );
        }
        for hash in [upper_hash.as_str(), "0f", "", long.as_str()] {
            assert!(
                GroupMasterKey::generate(GroupHome {
                    identity_document_hash: hash,
                    ..HOME
                })
                .is_err(),
                "{hash}"
            );
        }
    }

    fn master() -> GroupMasterKey {
        GroupMasterKey::from_bytes(&[7u8; 32], HOME).unwrap()
    }

    fn account() -> AccountRef {
        "aci:00000000-0000-4000-8000-0000000000b2@a.test"
            .parse()
            .unwrap()
    }

    #[test]
    fn a_binding_verifies_only_under_its_accounts_authority() {
        let identity = crate::identity::AccountIdentityKeysV1::derive(&[0x11u8; 32]).unwrap();
        let other = crate::identity::AccountIdentityKeysV1::derive(&[0x12u8; 32]).unwrap();
        let group_id = master().group_id();
        let pseudonym = GroupKeyPair::from_seed(&[3u8; 32]).public_key();
        let signature = sign_binding(
            identity.authority_signing_key(),
            &group_id,
            &pseudonym,
            &account(),
        );
        let authority = identity.authority_public_key();
        assert!(verify_binding(&authority, &group_id, &pseudonym, &account(), &signature).is_ok());
        // Another account's authority, group, pseudonym or account: refused.
        let another_authority = other.authority_public_key();
        assert!(verify_binding(
            &another_authority,
            &group_id,
            &pseudonym,
            &account(),
            &signature
        )
        .is_err());
        let another_group = GroupMasterKey::from_bytes(&[8u8; 32], HOME)
            .unwrap()
            .group_id();
        assert!(verify_binding(
            &authority,
            &another_group,
            &pseudonym,
            &account(),
            &signature
        )
        .is_err());
        let another_pseudonym = GroupKeyPair::from_seed(&[4u8; 32]).public_key();
        assert!(verify_binding(
            &authority,
            &group_id,
            &another_pseudonym,
            &account(),
            &signature
        )
        .is_err());
        let carol: AccountRef = "aci:00000000-0000-4000-8000-0000000000c3@a.test"
            .parse()
            .unwrap();
        assert!(verify_binding(&authority, &group_id, &pseudonym, &carol, &signature).is_err());
    }

    /// The authority signs other objects too (manifests, device
    /// registrations and revocations, renames, Drive key bindings and
    /// collection epochs, contact summaries, mail keys, Chat backup signers
    /// and manifests): none of their signatures passes as a binding,
    /// and a binding's signed bytes can't be read as one of theirs, because
    /// every domain is distinct and none is a prefix of another.
    #[test]
    fn no_other_authority_signature_passes_as_a_binding() {
        const OTHER_DOMAINS: &[&[u8]] = &[
            b"kutup/device-registration/v1\0",
            b"kutup/device-revocation/v1\0",
            b"kutup/drive-key-binding/v2\0",
            b"kutup/account-rename/v1\0",
            b"kutup/contact-summary/v2\0",
            b"kutup/mail-key-list/v1\0",
            b"kutup/mail-group-key-share/v2\0",
            b"kutup/drive/collection-key-commitment/v1\0",
            b"kutup/account-manifest/v1\0",
            b"kutup/chat-backup/signer-authorization/v1\0",
            b"kutup/chat-backup/manifest/v1\0",
            // A collection epoch statement starts with its magic.
            b"KUTPCE1\0",
        ];
        let identity = crate::identity::AccountIdentityKeysV1::derive(&[0x11u8; 32]).unwrap();
        let authority = identity.authority_public_key();
        let group_id = master().group_id();
        let pseudonym = GroupKeyPair::from_seed(&[3u8; 32]).public_key();
        let payload = [&group_id[..], &pseudonym, &account().bytes()].concat();
        for domain in OTHER_DOMAINS {
            assert!(!domain.starts_with(BINDING_DOMAIN) && !BINDING_DOMAIN.starts_with(domain));
            // The same payload under another domain, signed by the same key.
            let other = identity
                .authority_signing_key()
                .sign(&[*domain, &payload].concat())
                .to_bytes();
            assert!(verify_binding(&authority, &group_id, &pseudonym, &account(), &other).is_err());
        }
    }

    #[test]
    fn ids_and_keys_are_derived_and_distinct() {
        let a = master();
        let b = GroupMasterKey::from_bytes(&[8u8; 32], HOME).unwrap();
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
        let other = GroupMasterKey::from_bytes(&[9u8; 32], HOME)
            .unwrap()
            .state_key();
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

    #[test]
    fn a_group_avatar_pads_to_its_bucket_and_opens_with_its_key_only() {
        for (size, bucket) in [
            (1, 8 * 1024),
            (8 * 1024 - 1, 8 * 1024),
            (8 * 1024, 16 * 1024),
            (40 * 1024 - 1, 40 * 1024),
        ] {
            let image = vec![7u8; size];
            let (blob, key) = seal_group_avatar(&image).unwrap();
            assert_eq!(blob.len(), avatar_blob_len(bucket));
            assert_eq!(&open_group_avatar(&blob, &key).unwrap()[..], &image[..]);
            assert!(open_group_avatar(&blob, &[0u8; 32]).is_err());
        }
        assert_eq!(
            AVATAR_BUCKETS.map(avatar_blob_len),
            [8_233, 16_425, 32_809, 41_001]
        );
        assert!(seal_group_avatar(&vec![0u8; 40 * 1024]).is_err());
        // An image ending in zeros keeps them.
        let image = [1u8, 0, 0];
        let (blob, key) = seal_group_avatar(&image).unwrap();
        assert_eq!(&open_group_avatar(&blob, &key).unwrap()[..], &image[..]);
        // The same picture twice: unrelated blobs.
        let (again, _) = seal_group_avatar(&image).unwrap();
        assert_ne!(avatar_blob_hash(&blob), avatar_blob_hash(&again));
        // Cut or grown: refused.
        assert!(open_group_avatar(&blob[..blob.len() - 1], &key).is_err());
    }

    #[test]
    fn a_group_avatar_blob_is_fixed_for_its_key_and_nonce() {
        let blob = seal_group_avatar_with(b"avatar", &[3u8; 32], &[5u8; NONCE_LEN]).unwrap();
        assert_eq!(blob.len(), 8_233);
        assert_eq!(
            &blob[..1 + NONCE_LEN],
            &[[1u8].as_slice(), &[5u8; NONCE_LEN]].concat()[..]
        );
        assert_eq!(
            &open_group_avatar(&blob, &[3u8; 32]).unwrap()[..],
            b"avatar"
        );
    }
}
