//! The account's synced private records (docs/plans/account-records.md, W3):
//! one store for every sealed list under the account head, as Signal's
//! Storage Service is one store under its manifest. This module is the scope
//! registry the server and every client share. Each scope names its number,
//! its head scope name, its record purpose and its id form; the server keeps
//! the records opaque.
//!
//! A record's id is the string the head's index names, and the bytes it
//! decodes to are the record's sealed object, so a record moved to another
//! id fails to open. Ids are never a plaintext name or id. Each is either:
//! - `hashed_object` under the object-id root, or
//! - the one fixed id of a single-record scope.
//!
//! The one exception is Pass secrets (decision 9): they keep the vault's
//! Drive file id, which the server already knows from the Drive row. It
//! reveals only that the file is a vault the account holds a key for, as
//! before. The server uses it to refuse a key for a file that is gone or not
//! the caller's, and to drop the key with the file.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::account_record::AccountRecordPurpose;
use crate::error::{CryptoError, Result};

/// How a scope's record ids are formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdForm {
    /// `hashed_object` under the object-id root: 32 bytes as unpadded
    /// base64url (43 characters).
    Hashed,
    /// A Drive file id, canonical lowercase UUID text; the object is its 16
    /// bytes. Pass secrets only (see the module doc).
    DriveFileId,
    /// The scope holds one record, with this id and no object.
    Single(&'static str),
}

/// A scope of the account-records store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordScope {
    PassSecrets,
    Pins,
    ChatGroups,
    ChatContacts,
}

/// One registry row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeInfo {
    /// Stored in `account_records.scope`; never reused.
    pub number: i16,
    /// The head's scope name (`ScopeV1::scope`) and the API's path segment.
    pub name: &'static str,
    pub purpose: AccountRecordPurpose,
    pub id: IdForm,
}

impl RecordScope {
    /// Every scope, in number order.
    pub const ALL: [RecordScope; 4] = [
        RecordScope::PassSecrets,
        RecordScope::Pins,
        RecordScope::ChatGroups,
        RecordScope::ChatContacts,
    ];

    pub const fn info(self) -> ScopeInfo {
        match self {
            RecordScope::PassSecrets => ScopeInfo {
                number: 1,
                name: "passSecrets",
                purpose: AccountRecordPurpose::PassVaultSecret,
                id: IdForm::DriveFileId,
            },
            RecordScope::Pins => ScopeInfo {
                number: 2,
                name: "pins",
                purpose: AccountRecordPurpose::IdentityPins,
                id: IdForm::Single("pins"),
            },
            RecordScope::ChatGroups => ScopeInfo {
                number: 3,
                name: "chatGroups",
                purpose: AccountRecordPurpose::ChatGroupListEntry,
                id: IdForm::Hashed,
            },
            RecordScope::ChatContacts => ScopeInfo {
                number: 4,
                name: "chatContacts",
                purpose: AccountRecordPurpose::ChatContactListEntry,
                id: IdForm::Hashed,
            },
        }
    }

    pub fn by_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.info().name == name)
    }

    pub fn by_number(number: i16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.info().number == number)
    }

    pub fn name(self) -> &'static str {
        self.info().name
    }

    /// Checks `id` is in this scope's form and returns the record's sealed
    /// object (empty for a single-record scope). Only the canonical spelling
    /// passes, so one record has one id.
    pub fn object(self, id: &str) -> Result<Vec<u8>> {
        let bad = || CryptoError::InvalidInput(format!("not a {} record id", self.name()));
        match self.info().id {
            IdForm::Hashed => {
                let bytes = URL_SAFE_NO_PAD.decode(id).map_err(|_| bad())?;
                if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != id {
                    return Err(bad());
                }
                Ok(bytes)
            }
            IdForm::DriveFileId => {
                let bytes = crate::drive_object::parse_canonical_uuid(id, "record id")
                    .map_err(|_| bad())?;
                Ok(bytes.to_vec())
            }
            IdForm::Single(only) if id == only => Ok(Vec::new()),
            IdForm::Single(_) => Err(bad()),
        }
    }

    /// The id of a hashed scope's record for its plaintext object.
    pub fn hashed_id(
        self,
        object_id_key: &crate::account_roots::ObjectIdKey,
        plain_id: &[u8],
    ) -> Result<String> {
        match self.info().id {
            IdForm::Hashed => Ok(URL_SAFE_NO_PAD.encode(crate::account_record::hashed_object(
                object_id_key,
                self.info().purpose,
                plain_id,
            ))),
            _ => Err(CryptoError::InvalidInput(format!(
                "{} ids are not hashed",
                self.name()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_is_one_to_one() {
        let mut numbers: Vec<_> = RecordScope::ALL.iter().map(|s| s.info().number).collect();
        let mut names: Vec<_> = RecordScope::ALL.iter().map(|s| s.name()).collect();
        let mut purposes: Vec<_> = RecordScope::ALL
            .iter()
            .map(|s| s.info().purpose as u16)
            .collect();
        names.sort();
        names.dedup();
        purposes.sort();
        purposes.dedup();
        numbers.sort();
        assert_eq!(names.len(), RecordScope::ALL.len());
        assert_eq!(purposes.len(), RecordScope::ALL.len());
        for scope in RecordScope::ALL {
            assert_eq!(RecordScope::by_name(scope.name()), Some(scope));
            assert_eq!(RecordScope::by_number(scope.info().number), Some(scope));
            // Every scope's purpose is mutable: a record is replaced in place.
            assert!(scope.info().purpose.policy().mutable);
        }
        assert_eq!(numbers, vec![1, 2, 3, 4]);
    }

    #[test]
    fn ids_have_one_spelling() {
        let hashed = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert_eq!(
            RecordScope::ChatGroups.object(&hashed).unwrap(),
            vec![7u8; 32]
        );
        assert!(RecordScope::ChatGroups
            .object(&format!("{hashed}="))
            .is_err());
        assert!(RecordScope::ChatGroups.object(&hashed[..42]).is_err());
        let file = "0190a7b4-1c2d-7e3f-8a9b-0c1d2e3f4a5b";
        assert_eq!(RecordScope::PassSecrets.object(file).unwrap().len(), 16);
        assert!(RecordScope::PassSecrets
            .object(&file.to_uppercase())
            .is_err());
        assert!(RecordScope::PassSecrets.object(&hashed).is_err());
        assert_eq!(RecordScope::Pins.object("pins").unwrap(), Vec::<u8>::new());
        assert!(RecordScope::Pins.object("pin").is_err());
    }
}
