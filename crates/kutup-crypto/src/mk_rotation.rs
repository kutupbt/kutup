//! A master-key rotation (docs/plans/mk-rotation-exercise.md): what one
//! device seals for the server's one transaction.
//!
//! A new random master key at the next generation. The account's roots are
//! re-wrapped under it at once (their plaintexts and generations kept, so no
//! peer sees a change), the previous key goes into a keyring record under
//! it, a new recovery phrase wraps it, and the next account head is sealed
//! under it. The password wrap is the caller's: it needs the OPAQUE export
//! key of the password registered again
//! ([`crate::opaque::ClientRegistrationResult`]'s `seal_master_key`, at
//! [`Rotation::generation`]). Everything else is sealed again lazily, at its
//! next write, through [`MasterKeys`].

use zeroize::Zeroizing;

use crate::account_head::{self, HeadKeys, VerifiedHead};
use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::account_roots::AccountRoots;
use crate::error::Result;
use crate::master_keys::MasterKeys;

/// What a rotation sends, besides the password wrap.
pub struct Rotation {
    /// The account's keys after the rotation: the new one current.
    pub master_keys: MasterKeys,
    /// The new recovery phrase (shown once, confirmed) and its entropy.
    pub recovery_phrase: Zeroizing<String>,
    pub recovery_entropy: Zeroizing<[u8; 32]>,
    /// The new master key wrapped under the new phrase (purpose 2), and the
    /// proof the server checks a recovery by.
    pub recovery_envelope: Vec<u8>,
    pub recovery_proof: Zeroizing<[u8; 32]>,
    /// The five roots sealed again under the new key.
    pub roots: Vec<Vec<u8>>,
    /// The previous key, under the new one.
    pub keyring: Vec<u8>,
    /// The next account head, sealed under the new key.
    pub head: Vec<u8>,
}

impl Rotation {
    /// The new master key's generation.
    pub fn generation(&self) -> MasterKeyGeneration {
        self.master_keys.generation()
    }

    /// The new master key.
    pub fn master_key(&self) -> &[u8; 32] {
        self.master_keys.current()
    }

    /// The head keys after the rotation (for committing [`Self::head`]).
    pub fn head_keys(&self, roots: &AccountRoots) -> Result<HeadKeys> {
        HeadKeys::derive(&self.master_keys, &roots.object_id)
    }
}

/// A rotation of `old` (the account's keys now) for the account bound by
/// `binding`, whose roots are `roots` and whose verified head is `head`;
/// `writer` is this device's head writer id.
pub fn prepare(
    old: &MasterKeys,
    binding: &str,
    roots: &AccountRoots,
    head: &VerifiedHead,
    writer: &str,
) -> Result<Rotation> {
    prepare_with(
        old,
        binding,
        roots,
        head,
        writer,
        &crate::primitives::random_key(),
        &crate::primitives::random_key(),
    )
}

/// [`prepare`] with the new master key and recovery entropy given, for
/// tests and checked-in vectors.
pub fn prepare_with(
    old: &MasterKeys,
    binding: &str,
    roots: &AccountRoots,
    head: &VerifiedHead,
    writer: &str,
    next: &[u8; 32],
    recovery_entropy: &[u8; 32],
) -> Result<Rotation> {
    let master_keys = old.rotated(next)?;
    let generation = master_keys.generation();
    let keyring = MasterKeys::seal_keyring(next, old.current(), old.generation(), binding)?;
    let roots_sealed = roots.seal(next, generation, binding)?;
    let recovery_envelope = account_record::seal(
        next,
        recovery_entropy,
        AccountRecordPurpose::RecoveryMasterKey,
        generation,
        binding,
    )?;
    let recovery_proof = crate::kdf::derive_recovery_auth_proof(recovery_entropy, binding)?;
    let recovery_phrase = crate::mnemonic::encode(recovery_entropy)?;
    // The next head: the same scopes and generations, sealed under the new
    // key. Its ids come from the object-id root, so no scope changes.
    let head_keys = HeadKeys::derive(&master_keys, &roots.object_id)?;
    // Its plaintext names the new key as current: a device that holds an
    // older one and is served this head learns a newer one exists.
    let next_head = head.next(writer, Vec::new())?.with_master_key(generation)?;
    let sealed_head = account_head::seal(&head_keys, binding, &next_head)?;
    Ok(Rotation {
        master_keys,
        recovery_phrase,
        recovery_entropy: Zeroizing::new(*recovery_entropy),
        recovery_envelope,
        recovery_proof,
        roots: roots_sealed,
        keyring,
        head: sealed_head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_head::{check, first, HeadStatus, RootGenerations};
    use crate::identity::AccountIdentityKeysV1;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    #[test]
    fn a_rotation_keeps_the_roots_and_continues_the_head() {
        let old = MasterKeys::first(&[1; 32]);
        let roots = AccountRoots::same_for_tests([5; 32]);
        let incarnation = AccountIdentityKeysV1::derive(&roots.identity)
            .unwrap()
            .incarnation_id();
        let gens: RootGenerations = roots.head_generations();
        let keys = HeadKeys::derive(&old, &roots.object_id).unwrap();
        let writer = keys.writer("device").unwrap();
        let (sealed_first, verified) =
            first(&keys, BINDING, &incarnation, gens, &writer, vec![]).unwrap();
        let anchor = verified.anchor().clone();

        let rotation = prepare(&old, BINDING, &roots, &verified, &writer).unwrap();
        assert_eq!(rotation.generation().get(), 2);
        assert_ne!(rotation.master_key(), old.current());

        // The roots open under the new key to the same roots.
        let authority = AccountIdentityKeysV1::derive(&roots.identity)
            .unwrap()
            .authority_public_key();
        let reopened =
            AccountRoots::open(&rotation.roots, &rotation.master_keys, BINDING, &authority)
                .unwrap();
        assert!(reopened.same_for_tests_as(&roots));
        for record in &rotation.roots {
            assert_eq!(account_record::inspect(record).unwrap().generation.get(), 2);
        }

        // The keyring gives the old key back; the phrase opens the new one.
        let keys_after = MasterKeys::open(
            rotation.master_key(),
            rotation.generation(),
            BINDING,
            std::slice::from_ref(&rotation.keyring),
        )
        .unwrap();
        assert_eq!(
            keys_after.at(MasterKeyGeneration::FIRST).unwrap(),
            old.current()
        );
        let entropy = crate::mnemonic::decode(&rotation.recovery_phrase).unwrap();
        let recovered = account_record::open(
            &rotation.recovery_envelope,
            &entropy,
            AccountRecordPurpose::RecoveryMasterKey,
            BINDING,
        )
        .unwrap();
        assert_eq!(recovered.as_slice(), rotation.master_key());

        // A device anchored before the rotation follows the head across it.
        let after = rotation.head_keys(&roots).unwrap();
        let checked = check(
            &after,
            BINDING,
            &incarnation,
            gens,
            Some(&anchor),
            &rotation.head,
            Some(&[sealed_first, rotation.head.clone()]),
        )
        .unwrap();
        assert_eq!(checked.status, HeadStatus::Extends);
    }
}
