//! The Photos library record (docs/plans/photos.md): an account's own marks
//! on photos — favourites, archived, hidden — as one account record
//! (`account_record`, purpose `PhotosLibrary`) under the master key, kept in
//! the account-records store's `photosLibrary` scope
//! (docs/plans/account-records.md).
//!
//! Its object is the record's random id (the scope's id form), and its
//! revision is in the authenticated header: the account head covers the
//! scope, so a server can't roll the record back or swap it for another.
//! The server learns that a record exists, roughly its size (it is padded to
//! 256-byte buckets) and how often it changes, never which photos are
//! marked.

use serde::{Deserialize, Serialize};

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};
use crate::format::{self, Extra};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::PhotosLibrary;
const NONCE_LEN: usize = account_record::NONCE_LEN;
/// The record id's bytes (`IdForm::Random`).
pub const RECORD_ID_LEN: usize = 32;
/// Enough for 100,000 marked photos.
pub const MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MARKED_PHOTOS: usize = 100_000;

fn check_plaintext(plaintext: &[u8]) -> Result<()> {
    if plaintext.is_empty() || plaintext.len() > MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Photos library plaintext length is invalid".into(),
        ));
    }
    Ok(())
}

/// Seals `plaintext` as revision `revision` of the record `record_id`.
pub fn seal(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    record_id: &[u8; RECORD_ID_LEN],
    revision: u64,
) -> Result<Vec<u8>> {
    check_plaintext(plaintext)?;
    account_record::seal_revision(
        plaintext, master_key, PURPOSE, generation, binding, record_id, revision,
    )
}

/// Deterministic-nonce entry point for canonical vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    record_id: &[u8; RECORD_ID_LEN],
    revision: u64,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    check_plaintext(plaintext)?;
    account_record::seal_suite(
        account_record::AccountRecordSuiteId::V1,
        plaintext,
        master_key,
        PURPOSE,
        generation,
        binding,
        record_id,
        Some(revision),
        nonce,
    )
}

/// Opens the record `record_id` of the account bound by `binding`: its
/// plaintext and the revision it was sealed at (the caller checks it is the
/// one the verified index lists).
pub fn open(
    envelope: &[u8],
    master_key: &[u8; 32],
    binding: &str,
    record_id: &[u8; RECORD_ID_LEN],
) -> Result<(Vec<u8>, u64)> {
    account_record::open_revision(envelope, master_key, PURPOSE, binding, record_id)
}

/// The newest library version this reader knows.
pub const PHOTOS_LIBRARY_VERSION: u16 = 1;

/// What the record holds: `v` first (docs/plans/format-evolution.md), then
/// file ids, each set sorted and without repeats, then any fields a newer
/// writer added, kept and written back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PhotosLibraryV1 {
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
    pub favourites: Vec<String>,
    pub archived: Vec<String>,
    pub hidden: Vec<String>,
    #[serde(flatten, default, skip_serializing_if = "Extra::is_empty")]
    pub extra: Extra,
}

impl Default for PhotosLibraryV1 {
    fn default() -> Self {
        Self {
            v: PHOTOS_LIBRARY_VERSION,
            min: None,
            favourites: Vec::new(),
            archived: Vec::new(),
            hidden: Vec::new(),
            extra: Extra::new(),
        }
    }
}

impl PhotosLibraryV1 {
    pub fn validate(&self) -> Result<()> {
        format::check_version("Photos library", self.v, self.min, PHOTOS_LIBRARY_VERSION)?;
        format::check_extra("Photos library", &self.extra)?;
        let total = self.favourites.len() + self.archived.len() + self.hidden.len();
        if total > MAX_MARKED_PHOTOS {
            return Err(CryptoError::InvalidInput(
                "Photos library marks too many photos".into(),
            ));
        }
        for set in [&self.favourites, &self.archived, &self.hidden] {
            for (i, id) in set.iter().enumerate() {
                parse_canonical_uuid(id, "Photos library file")?;
                if i > 0 && set[i - 1] >= *id {
                    return Err(CryptoError::InvalidInput(
                        "Photos library sets must be sorted without repeats".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Sorted, deduplicated, checked: the canonical form of any input.
    pub fn canonicalize(mut self) -> Result<Self> {
        for set in [&mut self.favourites, &mut self.archived, &mut self.hidden] {
            set.sort();
            set.dedup();
        }
        self.validate()?;
        Ok(self)
    }
}

pub fn encode_library(library: &PhotosLibraryV1) -> Result<Vec<u8>> {
    library.validate()?;
    serde_json::to_vec(library).map_err(|_| CryptoError::InvalidInput("encode library".into()))
}

/// The library as stored: *newer than me* when its minimum reader is above
/// this one, refused when corrupt, unknown fields kept.
pub fn decode_library(bytes: &[u8]) -> Result<PhotosLibraryV1> {
    format::check_json_version("Photos library", bytes, PHOTOS_LIBRARY_VERSION)?;
    let library: PhotosLibraryV1 = serde_json::from_slice(bytes)
        .map_err(|_| CryptoError::InvalidInput("Photos library is not valid".into()))?;
    library.validate()?;
    Ok(library)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "22222222-2222-4222-8222-222222222222";
    const B: &str = "33333333-3333-4333-8333-333333333333";

    fn library() -> PhotosLibraryV1 {
        PhotosLibraryV1 {
            favourites: vec![B.into(), A.into(), A.into()],
            archived: vec![],
            hidden: vec![B.into()],
            ..Default::default()
        }
        .canonicalize()
        .unwrap()
    }

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const FIRST: MasterKeyGeneration = MasterKeyGeneration::FIRST;
    const ID: [u8; RECORD_ID_LEN] = [0x5a; RECORD_ID_LEN];

    #[test]
    fn seals_and_opens_revisions_of_one_record() {
        let key = [9u8; 32];
        let first = seal(
            &encode_library(&library()).unwrap(),
            &key,
            FIRST,
            BINDING,
            &ID,
            1,
        )
        .unwrap();
        let (opened, revision) = open(&first, &key, BINDING, &ID).unwrap();
        assert_eq!(revision, 1);
        assert_eq!(decode_library(&opened).unwrap(), library());
        let header = account_record::validate_for(&first, PURPOSE, BINDING, &ID).unwrap();
        assert_eq!(header.revision, Some(1));
        assert_eq!(header.previous, None);
        let second = seal(
            b"{\"v\":1,\"favourites\":[],\"archived\":[],\"hidden\":[]}",
            &key,
            FIRST,
            BINDING,
            &ID,
            2,
        )
        .unwrap();
        assert_eq!(open(&second, &key, BINDING, &ID).unwrap().1, 2);
        // Opened only as the record it is, by its account, under its key.
        assert!(open(&first, &key, BINDING, &[0x5b; RECORD_ID_LEN]).is_err());
        assert!(open(&first, &[8u8; 32], BINDING, &ID).is_err());
        assert!(open(&first, &key, "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d", &ID).is_err());
        let mut tampered = first.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&tampered, &key, BINDING, &ID).is_err());
        assert!(seal(b"", &key, FIRST, BINDING, &ID, 1).is_err());
    }

    #[test]
    fn the_record_is_canonical() {
        assert_eq!(
            std::str::from_utf8(&encode_library(&library()).unwrap()).unwrap(),
            format!(r#"{{"v":1,"favourites":["{A}","{B}"],"archived":[],"hidden":["{B}"]}}"#)
        );
        for bad in [
            format!(r#"{{"v":1,"favourites":["{B}","{A}"],"archived":[],"hidden":[]}}"#),
            format!(r#"{{"v":1,"favourites":["{A}","{A}"],"archived":[],"hidden":[]}}"#),
            r#"{"v":1,"favourites":["x"],"archived":[],"hidden":[]}"#.to_string(),
            r#"{"v":1,"favourites":[],"archived":[]}"#.to_string(),
            r#"{"favourites":[],"archived":[],"hidden":[]}"#.to_string(),
            "garbage".to_string(),
        ] {
            assert!(
                !decode_library(bad.as_bytes()).unwrap_err().is_newer(),
                "{bad}"
            );
        }
        // A newer writer's albums survive this reader's rewrite.
        let newer = decode_library(
            br#"{"v":1,"favourites":[],"archived":[],"hidden":[],"albums":[{"n":1}]}"#,
        )
        .unwrap();
        assert_eq!(
            encode_library(&newer.canonicalize().unwrap()).unwrap(),
            br#"{"v":1,"favourites":[],"archived":[],"hidden":[],"albums":[{"n":1}]}"#
        );
        for newer in [
            &br#"{"v":2,"favourites":[],"archived":[],"hidden":[]}"#[..],
            br#"{"v":3,"min":2,"marks":{}}"#,
        ] {
            assert!(decode_library(newer).unwrap_err().is_newer());
        }
        assert!(
            decode_library(br#"{"v":2,"min":1,"favourites":[],"archived":[],"hidden":[]}"#).is_ok()
        );
    }
}
