//! The account's stored roots (docs/plans/identity-root.md).
//!
//! Five random 32-byte secrets, each an account record sealed under the
//! master key (MK), so a new MK changes nothing a peer sees and moves no
//! record id:
//!
//! - the identity root ([`IdentityRoot`]): the authority and both Drive
//!   identity keys derive from it (`identity::AccountIdentityKeysV1`); one
//!   record per identity generation, every generation kept;
//! - the Drive root ([`DriveRoot`]): the account's own collection keys and
//!   link owner copies; one record per Drive root generation;
//! - the group pseudonym root ([`GroupPseudonymRoot`]);
//! - the call-link root ([`CallLinkRoot`]);
//! - the object-id key ([`ObjectIdKey`]) of `account_record::hashed_object`.
//!
//! Each is its own type, so an MK (or another root) can't be passed where
//! one is meant:
//!
//! ```compile_fail
//! let master_key = [7u8; 32];
//! kutup_crypto::identity::AccountIdentityKeysV1::derive(&master_key).unwrap();
//! ```

use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::error::{CryptoError, Result};

/// Every root is 32 bytes.
pub const ROOT_LEN: usize = 32;

/// The start of the error [`AccountRoots::open`] gives when the newest
/// identity root doesn't derive the account's registered authority: a UI
/// shows it as "this account's keys don't match" (never a silent fallback to
/// an older generation).
pub const IDENTITY_MISMATCH: &str = "identityRootMismatch";

macro_rules! root {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(Zeroizing<[u8; ROOT_LEN]>);

        impl $name {
            pub fn from_bytes(bytes: [u8; ROOT_LEN]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// `bytes` must be exactly [`ROOT_LEN`] long.
            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                let bytes: [u8; ROOT_LEN] =
                    bytes.try_into().map_err(|_| CryptoError::InvalidLength {
                        expected: ROOT_LEN,
                        got: bytes.len(),
                    })?;
                Ok(Self::from_bytes(bytes))
            }

            pub fn as_bytes(&self) -> &[u8; ROOT_LEN] {
                &self.0
            }

            fn generate() -> Self {
                let mut bytes = Zeroizing::new([0u8; ROOT_LEN]);
                crate::primitives::random(bytes.as_mut_slice());
                Self(bytes)
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self(Zeroizing::new(*self.0))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(…)"))
            }
        }
    };
}

root!(
    /// The account identity's root: the authority, the Drive X-Wing key and
    /// the Drive share-signing key derive from it.
    IdentityRoot
);
root!(
    /// The root of the account's own Drive keys.
    DriveRoot
);
root!(
    /// The root of the account's group pseudonyms.
    GroupPseudonymRoot
);
root!(
    /// The root of the account's call-link owner secrets.
    CallLinkRoot
);
root!(
    /// The key of the account's hashed record ids.
    ObjectIdKey
);

/// A generation of a root that rotates (the identity root, the Drive root):
/// never 0, the first is 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootGeneration(u32);

impl RootGeneration {
    pub const FIRST: Self = Self(1);

    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            return Err(CryptoError::InvalidInput(
                "a root generation is never 0".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u32 {
        self.0
    }

    /// The record's object: the generation, u32 big-endian.
    pub fn object(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    fn from_object(object: &[u8]) -> Result<Self> {
        let bytes: [u8; 4] = object
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("a root generation is 4 bytes".into()))?;
        Self::new(u32::from_be_bytes(bytes))
    }
}

/// The five purposes, in the order [`AccountRoots::seal`] gives their
/// envelopes.
pub const PURPOSES: [AccountRecordPurpose; 5] = [
    AccountRecordPurpose::IdentityRoot,
    AccountRecordPurpose::DriveRoot,
    AccountRecordPurpose::GroupPseudonymRoot,
    AccountRecordPurpose::CallLinkRoot,
    AccountRecordPurpose::ObjectIdKey,
];

/// Whether `purpose` is one of the roots'.
pub fn is_root_purpose(purpose: AccountRecordPurpose) -> bool {
    PURPOSES.contains(&purpose)
}

/// The newest of a rotating root's records: no generation twice, at least
/// one.
fn newest<'a>(
    mut list: Vec<(RootGeneration, &'a [u8])>,
    what: &str,
) -> Result<(RootGeneration, &'a [u8])> {
    list.sort_by_key(|(generation, _)| *generation);
    if list.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CryptoError::InvalidInput(format!(
            "two {what} records of one generation"
        )));
    }
    list.pop()
        .ok_or_else(|| CryptoError::InvalidInput(format!("no {what} record")))
}

/// The account's current roots.
#[derive(Clone, Debug)]
pub struct AccountRoots {
    pub identity_generation: RootGeneration,
    pub identity: IdentityRoot,
    pub drive_generation: RootGeneration,
    pub drive: DriveRoot,
    pub pseudonym: GroupPseudonymRoot,
    pub call_link: CallLinkRoot,
    pub object_id: ObjectIdKey,
}

impl AccountRoots {
    /// A new account's roots: random, the rotating ones at generation 1.
    pub fn generate() -> Self {
        Self {
            identity_generation: RootGeneration::FIRST,
            identity: IdentityRoot::generate(),
            drive_generation: RootGeneration::FIRST,
            drive: DriveRoot::generate(),
            pseudonym: GroupPseudonymRoot::generate(),
            call_link: CallLinkRoot::generate(),
            object_id: ObjectIdKey::generate(),
        }
    }

    /// The five envelopes, sealed under `master_key` (of `generation`) for the
    /// account bound by `binding`, in [`PURPOSES`] order.
    pub fn seal(
        &self,
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        binding: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let seal = |purpose, root: &[u8; ROOT_LEN], object: &[u8]| {
            account_record::seal_object(root, master_key, purpose, generation, binding, object)
        };
        Ok(vec![
            seal(
                AccountRecordPurpose::IdentityRoot,
                self.identity.as_bytes(),
                &self.identity_generation.object(),
            )?,
            seal(
                AccountRecordPurpose::DriveRoot,
                self.drive.as_bytes(),
                &self.drive_generation.object(),
            )?,
            seal(
                AccountRecordPurpose::GroupPseudonymRoot,
                self.pseudonym.as_bytes(),
                &[],
            )?,
            seal(
                AccountRecordPurpose::CallLinkRoot,
                self.call_link.as_bytes(),
                &[],
            )?,
            seal(
                AccountRecordPurpose::ObjectIdKey,
                self.object_id.as_bytes(),
                &[],
            )?,
        ])
    }

    /// Opens the account's roots from its root records (any order, every
    /// kept generation): each single root exactly once, the identity and
    /// Drive roots at least once with no generation twice; the newest of
    /// each is the current one. The newest identity root must derive
    /// `registered_authority` (the account's authority public key), or the
    /// error starts with [`IDENTITY_MISMATCH`]: an older generation never
    /// stands in.
    pub fn open<E: AsRef<[u8]>>(
        envelopes: &[E],
        master_key: &[u8; 32],
        binding: &str,
        registered_authority: &[u8; 32],
    ) -> Result<Self> {
        let roots = Self::open_unchecked(envelopes, master_key, binding)?;
        let identity = crate::identity::AccountIdentityKeysV1::derive(&roots.identity)?;
        if identity.authority_public_key() != *registered_authority {
            return Err(CryptoError::InvalidInput(format!(
                "{IDENTITY_MISMATCH}: the newest identity root (generation {}) does not \
                 derive this account's authority",
                roots.identity_generation.get()
            )));
        }
        Ok(roots)
    }

    /// [`Self::open`] without the authority check: for registration and
    /// tests, where the authority is what the roots give.
    pub fn open_unchecked<E: AsRef<[u8]>>(
        envelopes: &[E],
        master_key: &[u8; 32],
        binding: &str,
    ) -> Result<Self> {
        let mut identity: Vec<(RootGeneration, &[u8])> = Vec::new();
        let mut drive: Vec<(RootGeneration, &[u8])> = Vec::new();
        let mut single: [Option<&[u8]>; 3] = [None, None, None];
        for envelope in envelopes {
            let envelope = envelope.as_ref();
            let header = account_record::inspect(envelope)?;
            match header.purpose {
                AccountRecordPurpose::IdentityRoot => {
                    identity.push((RootGeneration::from_object(&header.object_id)?, envelope))
                }
                AccountRecordPurpose::DriveRoot => {
                    drive.push((RootGeneration::from_object(&header.object_id)?, envelope))
                }
                purpose => {
                    let slot = match purpose {
                        AccountRecordPurpose::GroupPseudonymRoot => 0,
                        AccountRecordPurpose::CallLinkRoot => 1,
                        AccountRecordPurpose::ObjectIdKey => 2,
                        other => {
                            return Err(CryptoError::InvalidInput(format!(
                                "account record purpose {} is not an account root",
                                other.as_u16()
                            )))
                        }
                    };
                    if single[slot].replace(envelope).is_some() {
                        return Err(CryptoError::InvalidInput(format!(
                            "account root {} given twice",
                            purpose.as_u16()
                        )));
                    }
                }
            }
        }
        let (identity_generation, identity) = newest(identity, "identity root")?;
        let (drive_generation, drive) = newest(drive, "Drive root")?;
        let open = |envelope: &[u8], purpose: AccountRecordPurpose, object: &[u8]| {
            account_record::open_object(envelope, master_key, purpose, binding, object)
        };
        let single_root = |slot: usize, purpose: AccountRecordPurpose| {
            let envelope = single[slot].ok_or_else(|| {
                CryptoError::InvalidInput(format!("account root {} missing", purpose.as_u16()))
            })?;
            open(envelope, purpose, &[])
        };
        Ok(Self {
            identity: IdentityRoot::from_slice(&open(
                identity,
                AccountRecordPurpose::IdentityRoot,
                &identity_generation.object(),
            )?)?,
            identity_generation,
            drive: DriveRoot::from_slice(&open(
                drive,
                AccountRecordPurpose::DriveRoot,
                &drive_generation.object(),
            )?)?,
            drive_generation,
            pseudonym: GroupPseudonymRoot::from_slice(&single_root(
                0,
                AccountRecordPurpose::GroupPseudonymRoot,
            )?)?,
            call_link: CallLinkRoot::from_slice(&single_root(
                1,
                AccountRecordPurpose::CallLinkRoot,
            )?)?,
            object_id: ObjectIdKey::from_slice(&single_root(
                2,
                AccountRecordPurpose::ObjectIdKey,
            )?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MK: [u8; 32] = [7u8; 32];
    const BINDING: &str = "4b0a3c52-9a1e-4d1c-9a55-0d3f4f6e1b2a";

    fn authority(roots: &AccountRoots) -> [u8; 32] {
        crate::identity::AccountIdentityKeysV1::derive(&roots.identity)
            .unwrap()
            .authority_public_key()
    }

    #[test]
    fn roots_seal_and_open() {
        let roots = AccountRoots::generate();
        let sealed = roots
            .seal(&MK, MasterKeyGeneration::FIRST, BINDING)
            .unwrap();
        assert_eq!(sealed.len(), 5);
        // Any order.
        let mut shuffled = sealed.clone();
        shuffled.reverse();
        let opened = AccountRoots::open(&shuffled, &MK, BINDING, &authority(&roots)).unwrap();
        assert_eq!(opened.identity.as_bytes(), roots.identity.as_bytes());
        assert_eq!(opened.drive.as_bytes(), roots.drive.as_bytes());
        assert_eq!(opened.pseudonym.as_bytes(), roots.pseudonym.as_bytes());
        assert_eq!(opened.call_link.as_bytes(), roots.call_link.as_bytes());
        assert_eq!(opened.object_id.as_bytes(), roots.object_id.as_bytes());
        assert_eq!(opened.identity_generation, RootGeneration::FIRST);
    }

    #[test]
    fn roots_are_bound_to_their_account_and_master_key() {
        let roots = AccountRoots::generate();
        let sealed = roots
            .seal(&MK, MasterKeyGeneration::FIRST, BINDING)
            .unwrap();
        let authority = authority(&roots);
        assert!(AccountRoots::open(&sealed, &[8u8; 32], BINDING, &authority).is_err());
        assert!(AccountRoots::open(
            &sealed,
            &MK,
            "5c1b4d63-0b2f-4e2d-8b66-1e4f5a7f2c3b",
            &authority
        )
        .is_err());
    }

    #[test]
    fn a_missing_or_doubled_root_is_refused() {
        let roots = AccountRoots::generate();
        let sealed = roots
            .seal(&MK, MasterKeyGeneration::FIRST, BINDING)
            .unwrap();
        let authority = authority(&roots);
        for missing in 0..5 {
            let mut fewer = sealed.clone();
            fewer.remove(missing);
            assert!(AccountRoots::open(&fewer, &MK, BINDING, &authority).is_err());
        }
        for doubled in 0..5 {
            let mut more = sealed.clone();
            more.push(sealed[doubled].clone());
            assert!(AccountRoots::open(&more, &MK, BINDING, &authority).is_err());
        }
        // Not a root at all.
        let other = account_record::seal(
            &[1u8; 32],
            &MK,
            AccountRecordPurpose::ChatBackupRoot,
            MasterKeyGeneration::FIRST,
            BINDING,
        )
        .unwrap();
        let mut with_other = sealed.clone();
        with_other.push(other);
        assert!(AccountRoots::open(&with_other, &MK, BINDING, &authority).is_err());
    }

    #[test]
    fn the_newest_identity_root_must_be_the_accounts_and_none_stands_in() {
        let first = AccountRoots::generate();
        let mut sealed = first
            .seal(&MK, MasterKeyGeneration::FIRST, BINDING)
            .unwrap();
        // A second generation, of another authority.
        let second = AccountRoots::generate();
        sealed.push(
            account_record::seal_object(
                second.identity.as_bytes(),
                &MK,
                AccountRecordPurpose::IdentityRoot,
                MasterKeyGeneration::FIRST,
                BINDING,
                &RootGeneration::new(2).unwrap().object(),
            )
            .unwrap(),
        );
        // Registered: the first. The newest is the second: refused, and the
        // first does not stand in.
        let error = AccountRoots::open(&sealed, &MK, BINDING, &authority(&first)).unwrap_err();
        assert!(error.to_string().contains(IDENTITY_MISMATCH), "{error}");
        // Registered: the second: it opens as the current one.
        let opened = AccountRoots::open(&sealed, &MK, BINDING, &authority(&second)).unwrap();
        assert_eq!(opened.identity_generation.get(), 2);
        assert_eq!(opened.identity.as_bytes(), second.identity.as_bytes());
        // Two records of one generation.
        let mut doubled = sealed.clone();
        doubled.push(
            account_record::seal_object(
                second.identity.as_bytes(),
                &MK,
                AccountRecordPurpose::IdentityRoot,
                MasterKeyGeneration::FIRST,
                BINDING,
                &RootGeneration::new(2).unwrap().object(),
            )
            .unwrap(),
        );
        assert!(AccountRoots::open(&doubled, &MK, BINDING, &authority(&second)).is_err());
    }

    #[test]
    fn a_new_master_key_keeps_the_identity() {
        let roots = AccountRoots::generate();
        let authority = authority(&roots);
        let generation = MasterKeyGeneration::new(2).unwrap();
        let resealed = roots.seal(&[9u8; 32], generation, BINDING).unwrap();
        let opened = AccountRoots::open(&resealed, &[9u8; 32], BINDING, &authority).unwrap();
        assert_eq!(
            crate::identity::AccountIdentityKeysV1::derive(&opened.identity)
                .unwrap()
                .incarnation_id(),
            crate::identity::incarnation_id_from_authority_public(&authority)
        );
    }
}
