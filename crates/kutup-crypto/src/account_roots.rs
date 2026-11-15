//! The account's stored roots (docs/plans/identity-root.md).
//!
//! Five random 32-byte secrets, each an account record sealed under the
//! master key (MK), so a new MK changes nothing a peer sees and moves no
//! record id. Each has a generation, the record's object (u32 big-endian):
//! one record per generation, every generation kept, the newest current.
//!
//! - the identity root ([`IdentityRoot`]): the authority and both Drive
//!   identity keys derive from it (`identity::AccountIdentityKeysV1`);
//! - the Drive root ([`DriveRoot`]): the account's own collection keys and
//!   link owner copies;
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

/// The newest of a root's records: no generation twice, at least one.
fn newest(mut list: Vec<(RootGeneration, &[u8])>) -> Result<(RootGeneration, &[u8])> {
    list.sort_by_key(|(generation, _)| *generation);
    if list.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CryptoError::InvalidInput(
            "account root generation twice".into(),
        ));
    }
    list.pop()
        .ok_or_else(|| CryptoError::InvalidInput("account root missing".into()))
}

/// The account's current roots, each with its generation (the record's
/// object): any of them can rotate without a format change.
#[derive(Clone, Debug)]
pub struct AccountRoots {
    pub identity_generation: RootGeneration,
    pub identity: IdentityRoot,
    pub drive_generation: RootGeneration,
    pub drive: DriveRoot,
    pub pseudonym_generation: RootGeneration,
    pub pseudonym: GroupPseudonymRoot,
    pub call_link_generation: RootGeneration,
    pub call_link: CallLinkRoot,
    pub object_id_generation: RootGeneration,
    pub object_id: ObjectIdKey,
}

impl AccountRoots {
    /// A new account's roots: random, each at generation 1.
    pub fn generate() -> Self {
        Self {
            identity_generation: RootGeneration::FIRST,
            identity: IdentityRoot::generate(),
            drive_generation: RootGeneration::FIRST,
            drive: DriveRoot::generate(),
            pseudonym_generation: RootGeneration::FIRST,
            pseudonym: GroupPseudonymRoot::generate(),
            call_link_generation: RootGeneration::FIRST,
            call_link: CallLinkRoot::generate(),
            object_id_generation: RootGeneration::FIRST,
            object_id: ObjectIdKey::generate(),
        }
    }

    /// Every root `bytes`, each at generation 1: for tests across crates
    /// only (an identity derived from it is the one the same bytes gave as
    /// a master key before the roots).
    #[doc(hidden)]
    pub fn same_for_tests(bytes: [u8; ROOT_LEN]) -> Self {
        Self {
            identity_generation: RootGeneration::FIRST,
            identity: IdentityRoot::from_bytes(bytes),
            drive_generation: RootGeneration::FIRST,
            drive: DriveRoot::from_bytes(bytes),
            pseudonym_generation: RootGeneration::FIRST,
            pseudonym: GroupPseudonymRoot::from_bytes(bytes),
            call_link_generation: RootGeneration::FIRST,
            call_link: CallLinkRoot::from_bytes(bytes),
            object_id_generation: RootGeneration::FIRST,
            object_id: ObjectIdKey::from_bytes(bytes),
        }
    }

    /// The generations the account head records of these roots.
    pub fn head_generations(&self) -> crate::account_head::RootGenerations {
        crate::account_head::RootGenerations {
            identity: self.identity_generation.get(),
            drive: self.drive_generation.get(),
        }
    }

    /// Each root's generation and bytes, in [`PURPOSES`] order.
    fn parts(&self) -> [(RootGeneration, &[u8; ROOT_LEN]); 5] {
        [
            (self.identity_generation, self.identity.as_bytes()),
            (self.drive_generation, self.drive.as_bytes()),
            (self.pseudonym_generation, self.pseudonym.as_bytes()),
            (self.call_link_generation, self.call_link.as_bytes()),
            (self.object_id_generation, self.object_id.as_bytes()),
        ]
    }

    /// The five envelopes, sealed under `master_key` (of `generation`) for the
    /// account bound by `binding`, in [`PURPOSES`] order.
    pub fn seal(
        &self,
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        binding: &str,
    ) -> Result<Vec<Vec<u8>>> {
        PURPOSES
            .iter()
            .zip(self.parts())
            .map(|(purpose, (root_generation, root))| {
                account_record::seal_object(
                    root,
                    master_key,
                    *purpose,
                    generation,
                    binding,
                    &root_generation.object(),
                )
            })
            .collect()
    }

    /// Opens the account's roots from its root records (any order, every
    /// kept generation): each root at least once, no generation twice, the
    /// newest of each the current one. The newest identity root must derive
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
            return Err(CryptoError::InvalidInput(IDENTITY_MISMATCH.into()));
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
        let mut found: [Vec<(RootGeneration, &[u8])>; 5] = Default::default();
        for envelope in envelopes {
            let envelope = envelope.as_ref();
            let header = account_record::inspect(envelope)?;
            let slot = PURPOSES
                .iter()
                .position(|purpose| *purpose == header.purpose)
                .ok_or_else(|| CryptoError::InvalidInput("not an account root".into()))?;
            found[slot].push((RootGeneration::from_object(&header.object_id)?, envelope));
        }
        let mut opened = Vec::with_capacity(5);
        for (purpose, records) in PURPOSES.iter().zip(found) {
            let (generation, envelope) = newest(records)?;
            let plain = account_record::open_object(
                envelope,
                master_key,
                *purpose,
                binding,
                &generation.object(),
            )?;
            let bytes: [u8; ROOT_LEN] = plain
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidInput("account root length".into()))?;
            opened.push((generation, Zeroizing::new(bytes)));
        }
        let mut opened = opened.into_iter();
        let mut next = || opened.next().expect("five roots");
        let (identity_generation, identity) = next();
        let (drive_generation, drive) = next();
        let (pseudonym_generation, pseudonym) = next();
        let (call_link_generation, call_link) = next();
        let (object_id_generation, object_id) = next();
        Ok(Self {
            identity_generation,
            identity: IdentityRoot(identity),
            drive_generation,
            drive: DriveRoot(drive),
            pseudonym_generation,
            pseudonym: GroupPseudonymRoot(pseudonym),
            call_link_generation,
            call_link: CallLinkRoot(call_link),
            object_id_generation,
            object_id: ObjectIdKey(object_id),
        })
    }
}

/// The roots as a page holds them (`openAccountRoots` of `@kutup/crypto`,
/// `session.roots`): each root canonical base64, each with its generation.
/// One form for every client binding.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountRootsJson {
    pub identity_generation: u32,
    pub identity_root: String,
    pub drive_generation: u32,
    pub drive_root: String,
    pub pseudonym_generation: u32,
    pub pseudonym_root: String,
    pub call_link_generation: u32,
    pub call_link_root: String,
    pub object_id_generation: u32,
    pub object_id_key: String,
}

impl From<&AccountRoots> for AccountRootsJson {
    fn from(roots: &AccountRoots) -> Self {
        use base64::Engine as _;
        let b64 = |bytes: &[u8; ROOT_LEN]| base64::engine::general_purpose::STANDARD.encode(bytes);
        Self {
            identity_generation: roots.identity_generation.get(),
            identity_root: b64(roots.identity.as_bytes()),
            drive_generation: roots.drive_generation.get(),
            drive_root: b64(roots.drive.as_bytes()),
            pseudonym_generation: roots.pseudonym_generation.get(),
            pseudonym_root: b64(roots.pseudonym.as_bytes()),
            call_link_generation: roots.call_link_generation.get(),
            call_link_root: b64(roots.call_link.as_bytes()),
            object_id_generation: roots.object_id_generation.get(),
            object_id_key: b64(roots.object_id.as_bytes()),
        }
    }
}

impl TryFrom<&AccountRootsJson> for AccountRoots {
    type Error = CryptoError;

    fn try_from(json: &AccountRootsJson) -> Result<Self> {
        use base64::Engine as _;
        let root = |value: &str| -> Result<Zeroizing<[u8; ROOT_LEN]>> {
            let decoded = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| CryptoError::InvalidInput("account root encoding".into()))?,
            );
            let mut bytes = Zeroizing::new([0u8; ROOT_LEN]);
            if decoded.len() != ROOT_LEN {
                return Err(CryptoError::InvalidInput("account root length".into()));
            }
            bytes.copy_from_slice(&decoded);
            Ok(bytes)
        };
        Ok(Self {
            identity_generation: RootGeneration::new(json.identity_generation)?,
            identity: IdentityRoot(root(&json.identity_root)?),
            drive_generation: RootGeneration::new(json.drive_generation)?,
            drive: DriveRoot(root(&json.drive_root)?),
            pseudonym_generation: RootGeneration::new(json.pseudonym_generation)?,
            pseudonym: GroupPseudonymRoot(root(&json.pseudonym_root)?),
            call_link_generation: RootGeneration::new(json.call_link_generation)?,
            call_link: CallLinkRoot(root(&json.call_link_root)?),
            object_id_generation: RootGeneration::new(json.object_id_generation)?,
            object_id: ObjectIdKey(root(&json.object_id_key)?),
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
