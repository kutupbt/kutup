//! What one content revision of a Drive file is
//! (docs/plans/drive-block-format.md §2, "Binding the current revision and
//! the thumbnails"): its revision id, the SHA-256 of its sealed manifest and
//! its plaintext size, sealed under the file key as a `RevisionContent`
//! envelope (object = file, parent = revision id, epoch = the generation of
//! the file key that seals the revision's object).
//!
//! The file's metadata (`FileMetadata::content`) commits to the current
//! content only. Every other revision a reader opens (a history version, a
//! note's snapshot, the original upload) carries this record, sealed by
//! whoever uploaded it, and the reader opens it first: the object must then
//! be the one it names. No reader opens a manifest without a committed
//! digest, so a key holder can't have the server hand others an object of
//! their own making under a known revision id.
//!
//! JSON, one object, canonical (fixed field order) and strict, as
//! `file_metadata`: `{"revisionId","manifestSha256","size"}`.

use serde::{Deserialize, Serialize};

use crate::drive_envelope::{self, DriveEnvelopeContextV1};
use crate::error::{CryptoError, Result};
use crate::file_metadata::{ContentCommitmentV1, MAX_SAFE_INTEGER};

/// The largest encoded record; the envelope pads every record to one more
/// byte than this, so its length never shows the size's digits.
pub const MAX_ENCODED_BYTES: usize = 255;

/// One revision's content: which revision, its sealed manifest's digest and
/// its plaintext size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionContentV1 {
    /// A canonical lowercase UUID.
    pub revision_id: String,
    /// Canonical base64.
    pub manifest_sha256: String,
    /// The plaintext size, as the manifest fixes it.
    pub size: u64,
}

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("invalid revision content: {what}"))
}

impl RevisionContentV1 {
    pub fn new(revision_id: [u8; 16], manifest_digest: [u8; 32], size: u64) -> Self {
        let commitment = ContentCommitmentV1::new(revision_id, manifest_digest);
        Self {
            revision_id: commitment.revision_id,
            manifest_sha256: commitment.manifest_sha256,
            size,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.commitment()
            .validate()
            .map_err(|_| invalid("revisionId or manifestSha256"))?;
        if self.size > MAX_SAFE_INTEGER {
            return Err(invalid("size"));
        }
        Ok(())
    }

    /// The revision and digest, as the metadata's `content` holds them: what
    /// a reader passes to the object's opener, with [`Self::size`].
    pub fn commitment(&self) -> ContentCommitmentV1 {
        ContentCommitmentV1 {
            revision_id: self.revision_id.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
        }
    }
}

/// The canonical bytes of `content`, after checking it.
pub fn encode(content: &RevisionContentV1) -> Result<Vec<u8>> {
    content.validate()?;
    let bytes = serde_json::to_vec(content).map_err(|_| invalid("encode"))?;
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(invalid("too large"));
    }
    Ok(bytes)
}

/// A record as sealed, checked strictly (and canonically: the bytes must be
/// exactly what [`encode`] writes).
pub fn decode(bytes: &[u8]) -> Result<RevisionContentV1> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(invalid("too large"));
    }
    let content: RevisionContentV1 =
        serde_json::from_slice(bytes).map_err(|_| invalid("decode"))?;
    if encode(&content)? != bytes {
        return Err(invalid("not canonical"));
    }
    Ok(content)
}

/// Seals `content` for `file_id` under its file key of `generation` (the
/// generation that seals the revision's object).
pub fn seal_revision_content(
    content: &RevisionContentV1,
    file_key: &[u8],
    file_id: &str,
    generation: u32,
) -> Result<Vec<u8>> {
    let context =
        DriveEnvelopeContextV1::revision_content(file_id, &content.revision_id, generation)?;
    drive_envelope::seal(&encode(content)?, file_key, context)
}

/// Deterministic-nonce entry point for checked-in vectors only.
pub fn seal_revision_content_with_nonce(
    content: &RevisionContentV1,
    file_key: &[u8],
    file_id: &str,
    generation: u32,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let context =
        DriveEnvelopeContextV1::revision_content(file_id, &content.revision_id, generation)?;
    drive_envelope::seal_with_nonce(&encode(content)?, file_key, context, nonce)
}

/// Opens the record of exactly this file, revision and key generation: one
/// sealed for another revision or file, or another purpose, fails.
pub fn open_revision_content(
    envelope: &[u8],
    file_key: &[u8],
    file_id: &str,
    revision_id: &str,
    generation: u32,
) -> Result<RevisionContentV1> {
    let context = DriveEnvelopeContextV1::revision_content(file_id, revision_id, generation)?;
    let content = decode(&drive_envelope::open(envelope, file_key, context)?)?;
    // The parent slot binds the revision already; the record names it too.
    if content.revision_id != revision_id {
        return Err(CryptoError::AuthFailed);
    }
    Ok(content)
}

/// Checks an envelope's public header only (the server's check): this file,
/// this revision, this generation, the purpose and the one length.
pub fn validate(envelope: &[u8], file_id: &str, revision_id: &str, generation: u32) -> Result<()> {
    if envelope.len() != drive_envelope::REVISION_CONTENT_ENVELOPE_BYTES {
        return Err(invalid("envelope length"));
    }
    drive_envelope::validate(
        envelope,
        DriveEnvelopeContextV1::revision_content(file_id, revision_id, generation)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive_envelope::DriveEnvelopePurpose;

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_FILE: &str = "33333333-3333-4333-8333-333333333333";
    const REVISION: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER_REVISION: &str = "44444444-4444-4444-8444-444444444444";
    const KEY: [u8; 32] = [7; 32];

    fn content() -> RevisionContentV1 {
        RevisionContentV1 {
            revision_id: REVISION.into(),
            manifest_sha256: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [9u8; 32],
            ),
            size: 12_345,
        }
    }

    #[test]
    fn round_trips_canonically() {
        let bytes = encode(&content()).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"revisionId":"22222222-2222-4222-8222-222222222222","manifestSha256":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=","size":12345}"#
        );
        assert_eq!(decode(&bytes).unwrap(), content());
        // The largest size still fits.
        let mut largest = content();
        largest.size = MAX_SAFE_INTEGER;
        assert!(encode(&largest).unwrap().len() <= MAX_ENCODED_BYTES);
    }

    #[test]
    fn refuses_what_it_does_not_know() {
        let digest = content().manifest_sha256;
        for bad in [
            format!(r#"{{"revisionId":"{REVISION}","manifestSha256":"{digest}"}}"#),
            format!(r#"{{"revisionId":"{REVISION}","manifestSha256":"{digest}","size":1,"x":1}}"#),
            format!(r#"{{"revisionId":"{REVISION}","manifestSha256":"AAAA","size":1}}"#),
            format!(r#"{{"revisionId":"not-a-uuid","manifestSha256":"{digest}","size":1}}"#),
            format!(r#"{{"revisionId":"{REVISION}","manifestSha256":"{digest}","size":-1}}"#),
            format!(
                r#"{{"revisionId":"{REVISION}","manifestSha256":"{digest}","size":9007199254740992}}"#
            ),
            // Valid fields, not in canonical order or spacing.
            format!(r#"{{"size":1,"revisionId":"{REVISION}","manifestSha256":"{digest}"}}"#),
            format!(r#"{{"revisionId": "{REVISION}","manifestSha256":"{digest}","size":1}}"#),
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn opens_only_for_its_file_revision_and_generation() {
        let sealed = seal_revision_content(&content(), &KEY, FILE, 3).unwrap();
        assert_eq!(
            sealed.len(),
            drive_envelope::REVISION_CONTENT_ENVELOPE_BYTES
        );
        validate(&sealed, FILE, REVISION, 3).unwrap();
        assert_eq!(
            open_revision_content(&sealed, &KEY, FILE, REVISION, 3).unwrap(),
            content()
        );
        // Another revision as the parent, another file, another generation,
        // another key.
        assert!(open_revision_content(&sealed, &KEY, FILE, OTHER_REVISION, 3).is_err());
        assert!(open_revision_content(&sealed, &KEY, OTHER_FILE, REVISION, 3).is_err());
        assert!(open_revision_content(&sealed, &KEY, FILE, REVISION, 2).is_err());
        assert!(open_revision_content(&sealed, &[8; 32], FILE, REVISION, 3).is_err());
        assert!(validate(&sealed, FILE, OTHER_REVISION, 3).is_err());
        assert!(validate(&sealed, OTHER_FILE, REVISION, 3).is_err());
    }

    #[test]
    fn another_purpose_never_opens_as_one() {
        // The same bytes sealed as file metadata under the same ids: refused
        // by purpose, so metadata never stands in for a revision's record.
        let context =
            DriveEnvelopeContextV1::new(DriveEnvelopePurpose::FileMetadata, 3, 1, FILE, REVISION)
                .unwrap();
        let metadata = drive_envelope::seal(&encode(&content()).unwrap(), &KEY, context).unwrap();
        assert!(open_revision_content(&metadata, &KEY, FILE, REVISION, 3).is_err());
        assert!(validate(&metadata, FILE, REVISION, 3).is_err());
    }

    #[test]
    fn a_record_naming_another_revision_is_refused() {
        // Sealed (as only a key holder can) in this revision's context but
        // naming another: the reader refuses it.
        let mut other = content();
        other.revision_id = OTHER_REVISION.into();
        let context = DriveEnvelopeContextV1::revision_content(FILE, REVISION, 3).unwrap();
        let sealed = drive_envelope::seal(&encode(&other).unwrap(), &KEY, context).unwrap();
        assert!(matches!(
            open_revision_content(&sealed, &KEY, FILE, REVISION, 3),
            Err(CryptoError::AuthFailed)
        ));
    }
}
