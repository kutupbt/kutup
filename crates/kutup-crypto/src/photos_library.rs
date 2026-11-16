//! The Photos library record (docs/plans/photos.md): an account's own marks
//! on photos — favourites, archived, hidden — as one account record
//! (`account_record`, purpose `PhotosLibrary`) under the master key.
//!
//! Its object is the account incarnation, so a record restarts at revision 1
//! after an account reset; it is chained: each record names the digest of the
//! one before it, which the server checks for compare-and-swap without
//! reading anything. The server learns that a record exists, roughly its
//! size (it is padded to 256-byte buckets) and how often it changes, never
//! which photos are marked.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};
use crate::format::{self, Extra};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::PhotosLibrary;
const NONCE_LEN: usize = 24;
const DIGEST_LEN: usize = 32;
/// Enough for 100,000 marked photos.
pub const MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MARKED_PHOTOS: usize = 100_000;

/// Which record, in whose account, and after which one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhotosLibraryContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub revision: u64,
    pub previous_envelope_digest: [u8; DIGEST_LEN],
}

fn parse_lower_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput(format!("{field} must be lowercase hex")))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(format!(
            "{field} must be canonical 32-byte lowercase hex"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidInput(format!("{field} must be 32 bytes")))
}

impl PhotosLibraryContextV1 {
    /// Revision 1 has no predecessor; every later one names it.
    pub fn new(
        account_incarnation_id: &str,
        revision: u64,
        previous_envelope_digest: Option<&str>,
    ) -> Result<Self> {
        let previous_envelope_digest = match previous_envelope_digest {
            None if revision == 1 => [0u8; DIGEST_LEN],
            Some(value) if revision > 1 => {
                let digest = parse_lower_hex_32(value, "Photos library predecessor")?;
                if digest == [0u8; DIGEST_LEN] {
                    return Err(CryptoError::InvalidInput(
                        "Photos library predecessor must be non-zero".into(),
                    ));
                }
                digest
            }
            _ => {
                return Err(CryptoError::InvalidInput(
                    "Photos library revision and predecessor do not match".into(),
                ))
            }
        };
        Ok(Self {
            account_incarnation_id: parse_lower_hex_32(
                account_incarnation_id,
                "Photos library account incarnation",
            )?,
            revision,
            previous_envelope_digest,
        })
    }
}

pub fn seal(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    context: PhotosLibraryContextV1,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    seal_with_nonce(plaintext, master_key, generation, binding, context, &nonce)
}

/// Deterministic-nonce entry point for canonical vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    context: PhotosLibraryContextV1,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_PHOTOS_LIBRARY_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Photos library plaintext length is invalid".into(),
        ));
    }
    account_record::seal_chained(
        plaintext,
        master_key,
        PURPOSE,
        generation,
        binding,
        &context.account_incarnation_id,
        context.revision,
        &context.previous_envelope_digest,
        Some(nonce),
    )
}

fn context_of(header: &account_record::AccountRecordHeader) -> Result<PhotosLibraryContextV1> {
    let invalid = || CryptoError::InvalidInput("not a Photos library record".into());
    if header.purpose != PURPOSE {
        return Err(invalid());
    }
    Ok(PhotosLibraryContextV1 {
        account_incarnation_id: header
            .object_id
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?,
        revision: header.revision.ok_or_else(invalid)?,
        previous_envelope_digest: header.previous.ok_or_else(invalid)?,
    })
}

/// The public header: which incarnation, revision and predecessor.
pub fn inspect(envelope: &[u8]) -> Result<PhotosLibraryContextV1> {
    context_of(&account_record::inspect(envelope)?)
}

/// What the server checks before storing a record: a well-formed library
/// record of the account bound by `binding`, for its current incarnation.
pub fn validate(
    envelope: &[u8],
    binding: &str,
    account_incarnation_id: &[u8; 32],
) -> Result<PhotosLibraryContextV1> {
    context_of(&account_record::validate_for(
        envelope,
        PURPOSE,
        binding,
        account_incarnation_id,
    )?)
}

/// SHA-256 of a well-formed record, lowercase hex: the next one's predecessor.
pub fn envelope_digest(envelope: &[u8]) -> Result<String> {
    inspect(envelope)?;
    Ok(hex::encode(account_record::record_digest(envelope)))
}

/// Opens a record as exactly the revision and predecessor `expected` names.
pub fn open(
    envelope: &[u8],
    master_key: &[u8; 32],
    binding: &str,
    expected: PhotosLibraryContextV1,
) -> Result<Vec<u8>> {
    let (plain, revision, previous) = account_record::open_chained(
        envelope,
        master_key,
        PURPOSE,
        binding,
        &expected.account_incarnation_id,
    )?;
    if revision != expected.revision || previous != expected.previous_envelope_digest {
        return Err(CryptoError::AuthFailed);
    }
    Ok(plain)
}

pub fn decode_canonical_b64(value: &str) -> Result<Vec<u8>> {
    if value.len() > account_record::max_record_b64_len(PURPOSE) {
        return Err(CryptoError::InvalidInput(
            "Photos library envelope is too long".into(),
        ));
    }
    let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "Photos library envelope must use canonical base64".into(),
        ));
    }
    Ok(decoded)
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

    const INCARNATION: &str = "1111111111111111111111111111111111111111111111111111111111111111";
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

    #[test]
    fn seals_and_opens_a_chain_of_revisions() {
        let key = [9u8; 32];
        let first_context = PhotosLibraryContextV1::new(INCARNATION, 1, None).unwrap();
        let first = seal(
            &encode_library(&library()).unwrap(),
            &key,
            FIRST,
            BINDING,
            first_context,
        )
        .unwrap();
        assert_eq!(inspect(&first).unwrap(), first_context);
        let incarnation = first_context.account_incarnation_id;
        assert_eq!(
            validate(&first, BINDING, &incarnation).unwrap(),
            first_context
        );
        assert!(validate(&first, "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d", &incarnation).is_err());
        assert!(validate(&first, BINDING, &[2u8; 32]).is_err());
        let opened = open(&first, &key, BINDING, first_context).unwrap();
        assert_eq!(decode_library(&opened).unwrap(), library());

        let digest = envelope_digest(&first).unwrap();
        let second_context = PhotosLibraryContextV1::new(INCARNATION, 2, Some(&digest)).unwrap();
        let second = seal(
            b"{\"v\":1,\"favourites\":[],\"archived\":[],\"hidden\":[]}",
            &key,
            FIRST,
            BINDING,
            second_context,
        )
        .unwrap();
        assert_eq!(
            inspect(&second).unwrap().previous_envelope_digest.to_vec(),
            hex::decode(&digest).unwrap()
        );
        // Opened only as what it claims to be, by its account.
        assert!(open(&second, &key, BINDING, first_context).is_err());
        assert!(open(&first, &[8u8; 32], BINDING, first_context).is_err());
        assert!(open(
            &first,
            &key,
            "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d",
            first_context
        )
        .is_err());
        let mut tampered = first.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&tampered, &key, BINDING, first_context).is_err());
    }

    #[test]
    fn contexts_follow_the_chain_rules() {
        assert!(PhotosLibraryContextV1::new(INCARNATION, 0, None).is_err());
        assert!(PhotosLibraryContextV1::new(INCARNATION, 2, None).is_err());
        assert!(PhotosLibraryContextV1::new(INCARNATION, 1, Some(INCARNATION)).is_err());
        assert!(PhotosLibraryContextV1::new(INCARNATION, 2, Some(&"00".repeat(32))).is_err());
        assert!(PhotosLibraryContextV1::new("AB", 1, None).is_err());
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
