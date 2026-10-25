//! A Drive file's metadata: the plaintext sealed in its metadata envelope
//! (`drive_envelope`, purpose `FileMetadata`, under the file key).
//!
//! JSON, one object: `name`, `mimeType`, `size`, the SHA-256 of the content
//! (`sha256`, so a move can recompute the folder's content hash without
//! reading the file), and for photos and videos an optional `media` object
//! (docs/plans/photos.md) with when and where it was taken, its size on
//! screen, its length and a caption.
//! Encoding is canonical (fixed field order, absent fields omitted); decoding
//! is strict (unknown fields and out-of-range values are refused), so every
//! client reads and writes the same thing.

use crate::primitives::{Hasher, Suite};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

/// The largest encoded metadata accepted.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
/// A file name, in Unicode scalar values.
pub const MAX_NAME_CHARS: usize = 1024;
pub const MAX_MIME_CHARS: usize = 255;
pub const MAX_CAMERA_CHARS: usize = 100;
pub const MAX_CAPTION_CHARS: usize = 2000;
/// 1800-01-01T00:00:00Z and 2200-01-01T00:00:00Z, in milliseconds.
pub const MIN_TAKEN_AT_MS: i64 = -5_364_662_400_000;
pub const MAX_TAKEN_AT_MS: i64 = 7_258_118_400_000;
/// Time zones run from UTC−14:00 to UTC+14:00.
pub const MAX_OFFSET_MINUTES: i32 = 14 * 60;
/// Pixels on one side.
pub const MAX_DIMENSION: u32 = 1_000_000;
/// A video's length: at most 10 days.
pub const MAX_DURATION_MS: u64 = 10 * 24 * 3600 * 1000;
/// JavaScript's largest exact integer: sizes must survive a browser.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Where a photo's date came from, best first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TakenFrom {
    /// The image's own EXIF, XMP or IPTC date.
    Exif,
    /// The video container's creation time.
    Video,
    /// A date in the file name.
    Filename,
    /// The file's modification date on the device it came from.
    File,
    /// Set by a person.
    Edited,
}

/// When and where a photo or video was taken, and what it is.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaMetadataV1 {
    /// UTC milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taken_at: Option<i64>,
    /// The local time zone where it was taken, in minutes east of UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taken_offset: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taken_from: Option<TakenFrom>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lon: Option<f64>,
    /// As shown (after rotation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Make and model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// A live photo's video names its still (a file id): shown as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_of: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileMetadataV1 {
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    /// SHA-256 of the plaintext content, canonical base64 (`ContentHasher`).
    /// Absent only where the writer never saw the whole content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaMetadataV1>,
}

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("file metadata: {what}"))
}

fn chars(value: &str) -> usize {
    value.chars().count()
}

impl MediaMetadataV1 {
    pub fn validate(&self) -> Result<()> {
        if let Some(at) = self.taken_at {
            if !(MIN_TAKEN_AT_MS..=MAX_TAKEN_AT_MS).contains(&at) {
                return Err(invalid("takenAt out of range"));
            }
            if self.taken_from.is_none() {
                return Err(invalid("takenAt needs takenFrom"));
            }
        } else if self.taken_offset.is_some() || self.taken_from.is_some() {
            return Err(invalid("takenOffset and takenFrom need takenAt"));
        }
        if let Some(offset) = self.taken_offset {
            if offset.abs() > MAX_OFFSET_MINUTES {
                return Err(invalid("takenOffset out of range"));
            }
        }
        match (self.lat, self.lon) {
            (None, None) => {}
            (Some(lat), Some(lon)) => {
                if !lat.is_finite()
                    || !lon.is_finite()
                    || !(-90.0..=90.0).contains(&lat)
                    || !(-180.0..=180.0).contains(&lon)
                {
                    return Err(invalid("location out of range"));
                }
                // (0, 0) is what cameras write when they know nothing.
                if lat == 0.0 && lon == 0.0 {
                    return Err(invalid("location (0, 0) means unknown"));
                }
            }
            _ => return Err(invalid("lat and lon go together")),
        }
        match (self.width, self.height) {
            (None, None) => {}
            (Some(w), Some(h)) => {
                if w == 0 || h == 0 || w > MAX_DIMENSION || h > MAX_DIMENSION {
                    return Err(invalid("dimensions out of range"));
                }
            }
            _ => return Err(invalid("width and height go together")),
        }
        if let Some(duration) = self.duration_ms {
            if duration > MAX_DURATION_MS {
                return Err(invalid("durationMs out of range"));
            }
        }
        if let Some(camera) = &self.camera {
            if camera.trim().is_empty() || chars(camera) > MAX_CAMERA_CHARS {
                return Err(invalid("camera"));
            }
        }
        if let Some(caption) = &self.caption {
            if caption.is_empty() || chars(caption) > MAX_CAPTION_CHARS {
                return Err(invalid("caption"));
            }
        }
        if let Some(still) = &self.live_of {
            crate::drive_object::parse_canonical_uuid(still, "live photo still")
                .map_err(|_| invalid("liveOf"))?;
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The fields both metadata versions share, checked once.
fn validate_fields(
    name: &str,
    mime_type: &str,
    size: u64,
    sha256: Option<&str>,
    media: Option<&MediaMetadataV1>,
) -> Result<()> {
    if name.is_empty() || chars(name) > MAX_NAME_CHARS {
        return Err(invalid("name"));
    }
    if chars(mime_type) > MAX_MIME_CHARS {
        return Err(invalid("mimeType"));
    }
    if size > MAX_SAFE_INTEGER {
        return Err(invalid("size"));
    }
    if let Some(sha256) = sha256 {
        decode_digest(sha256).map_err(|_| invalid("sha256"))?;
    }
    if let Some(media) = media {
        // An empty object says nothing: it is written as no `media`.
        if media.is_empty() {
            return Err(invalid("empty media"));
        }
        media.validate()?;
    }
    Ok(())
}

/// A UUID's canonical lowercase text.
fn canonical_uuid(bytes: &[u8; 16]) -> String {
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// A SHA-256 in canonical base64.
fn decode_digest(value: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(value).map_err(|_| invalid("digest"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(invalid("digest"));
    }
    bytes.try_into().map_err(|_| invalid("digest"))
}

impl FileMetadataV1 {
    pub fn validate(&self) -> Result<()> {
        validate_fields(
            &self.name,
            &self.mime_type,
            self.size,
            self.sha256.as_deref(),
            self.media.as_ref(),
        )
    }
}

/// The content a metadata revision commits to (docs/plans/drive-block-format.md
/// §2, "Binding the current revision"): the current content revision and the
/// SHA-256 of its sealed manifest. Older content served under newer metadata
/// fails [`ContentCommitmentV1::check`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentCommitmentV1 {
    /// A canonical lowercase UUID.
    pub revision_id: String,
    /// Canonical base64.
    pub manifest_sha256: String,
}

impl ContentCommitmentV1 {
    pub fn new(revision_id: [u8; 16], manifest_digest: [u8; 32]) -> Self {
        Self {
            revision_id: canonical_uuid(&revision_id),
            manifest_sha256: STANDARD.encode(manifest_digest),
        }
    }

    pub fn validate(&self) -> Result<()> {
        crate::drive_object::parse_canonical_uuid(&self.revision_id, "content revision")
            .map_err(|_| invalid("content.revisionId"))?;
        decode_digest(&self.manifest_sha256).map_err(|_| invalid("content.manifestSha256"))?;
        Ok(())
    }

    /// Refuses an object other than the committed one: its header's revision
    /// and its sealed manifest's digest must both match.
    pub fn check(&self, revision_id: &[u8; 16], manifest_digest: &[u8; 32]) -> Result<()> {
        let committed_revision =
            crate::drive_object::parse_canonical_uuid(&self.revision_id, "content revision")?;
        let committed_digest = decode_digest(&self.manifest_sha256)?;
        let same_revision = crate::primitives::ct_eq(&committed_revision, revision_id);
        let same_manifest = crate::primitives::ct_eq(&committed_digest, manifest_digest);
        if !(same_revision && same_manifest) {
            return Err(CryptoError::InvalidInput(
                "file content is not the revision its metadata commits to".into(),
            ));
        }
        Ok(())
    }
}

/// A Drive file's metadata in the block format: V1's fields and the content
/// it commits to, which is required.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileMetadataV2 {
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub content: ContentCommitmentV1,
    /// SHA-256 of the plaintext content, canonical base64; kept only for
    /// Photos' duplicate check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaMetadataV1>,
}

impl FileMetadataV2 {
    pub fn validate(&self) -> Result<()> {
        validate_fields(
            &self.name,
            &self.mime_type,
            self.size,
            self.sha256.as_deref(),
            self.media.as_ref(),
        )?;
        self.content.validate()
    }
}

/// The canonical bytes of `metadata`, after checking it.
pub fn encode_v2(metadata: &FileMetadataV2) -> Result<Vec<u8>> {
    metadata.validate()?;
    let bytes = serde_json::to_vec(metadata).map_err(|_| invalid("encode"))?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(invalid("too large"));
    }
    Ok(bytes)
}

/// V2 metadata as stored, checked strictly.
pub fn decode_v2(bytes: &[u8]) -> Result<FileMetadataV2> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(invalid("too large"));
    }
    let metadata: FileMetadataV2 = serde_json::from_slice(bytes).map_err(|_| invalid("decode"))?;
    metadata.validate()?;
    Ok(metadata)
}

/// The canonical bytes of `metadata`, after checking it.
pub fn encode(metadata: &FileMetadataV1) -> Result<Vec<u8>> {
    metadata.validate()?;
    let bytes = serde_json::to_vec(metadata).map_err(|_| invalid("encode"))?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(invalid("too large"));
    }
    Ok(bytes)
}

/// Metadata as stored, checked strictly.
pub fn decode(bytes: &[u8]) -> Result<FileMetadataV1> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(invalid("too large"));
    }
    let metadata: FileMetadataV1 = serde_json::from_slice(bytes).map_err(|_| invalid("decode"))?;
    metadata.validate()?;
    Ok(metadata)
}

/// A content hash, fed as the content streams past (`FileMetadataV1::sha256`).
#[derive(Clone)]
pub struct ContentHasher(Hasher);

impl Default for ContentHasher {
    fn default() -> Self {
        Self(Hasher::new(Suite::V1))
    }
}

impl ContentHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    /// Canonical base64 of the SHA-256.
    pub fn finish(self) -> String {
        STANDARD.encode(self.0.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn photo() -> FileMetadataV1 {
        FileMetadataV1 {
            name: "IMG_0001.jpg".into(),
            mime_type: "image/jpeg".into(),
            size: 2_345_678,
            sha256: Some(STANDARD.encode([7u8; 32])),
            media: Some(MediaMetadataV1 {
                taken_at: Some(1_719_835_200_000),
                taken_offset: Some(180),
                taken_from: Some(TakenFrom::Exif),
                lat: Some(41.0082),
                lon: Some(28.9784),
                width: Some(4032),
                height: Some(3024),
                camera: Some("Apple iPhone 15".into()),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn round_trips_canonically() {
        let bytes = encode(&photo()).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"name":"IMG_0001.jpg","mimeType":"image/jpeg","size":2345678,"sha256":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","media":{"takenAt":1719835200000,"takenOffset":180,"takenFrom":"exif","lat":41.0082,"lon":28.9784,"width":4032,"height":3024,"camera":"Apple iPhone 15"}}"#
        );
        assert_eq!(decode(&bytes).unwrap(), photo());
    }

    #[test]
    fn plain_files_have_no_media() {
        let plain = FileMetadataV1 {
            name: "a.txt".into(),
            mime_type: "text/plain".into(),
            size: 0,
            sha256: None,
            media: None,
        };
        let bytes = encode(&plain).unwrap();
        assert_eq!(
            bytes,
            br#"{"name":"a.txt","mimeType":"text/plain","size":0}"#
        );
        assert_eq!(decode(&bytes).unwrap(), plain);
    }

    const REVISION: [u8; 16] = [0x22; 16];

    fn photo_v2() -> FileMetadataV2 {
        let v1 = photo();
        FileMetadataV2 {
            name: v1.name,
            mime_type: v1.mime_type,
            size: v1.size,
            content: ContentCommitmentV1::new(REVISION, [9; 32]),
            sha256: v1.sha256,
            media: v1.media,
        }
    }

    #[test]
    fn v2_commits_to_its_content() {
        let bytes = encode_v2(&photo_v2()).unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().starts_with(
            r#"{"name":"IMG_0001.jpg","mimeType":"image/jpeg","size":2345678,"content":{"revisionId":"22222222-2222-2222-2222-222222222222","manifestSha256":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="},"sha256":"#
        ));
        let decoded = decode_v2(&bytes).unwrap();
        assert_eq!(decoded, photo_v2());
        decoded.content.check(&REVISION, &[9; 32]).unwrap();
        // Older content: another revision, or this one's manifest swapped.
        assert!(decoded.content.check(&[0x23; 16], &[9; 32]).is_err());
        assert!(decoded.content.check(&REVISION, &[8; 32]).is_err());
        // V1 bytes have no content commitment and V1 refuses one.
        assert!(decode_v2(&encode(&photo()).unwrap()).is_err());
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn v2_refuses_a_malformed_commitment() {
        let digest = STANDARD.encode([9u8; 32]);
        for content in [
            format!(r#"{{"revisionId":"not-a-uuid","manifestSha256":"{digest}"}}"#),
            format!(
                r#"{{"revisionId":"22222222-2222-2222-2222-22222222222A","manifestSha256":"{digest}"}}"#
            ),
            r#"{"revisionId":"22222222-2222-2222-2222-222222222222","manifestSha256":"AAAA"}"#
                .into(),
            format!(
                r#"{{"revisionId":"22222222-2222-2222-2222-222222222222","manifestSha256":"{digest}","x":1}}"#
            ),
            format!(r#"{{"manifestSha256":"{digest}"}}"#),
        ] {
            let bad = format!(r#"{{"name":"a","mimeType":"","size":1,"content":{content}}}"#);
            assert!(decode_v2(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(decode_v2(br#"{"name":"a","mimeType":"","size":1}"#).is_err());
    }

    #[test]
    fn refuses_what_it_does_not_know() {
        for bad in [
            r#"{"name":"a","mimeType":"","size":1,"extra":1}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"x":1}}"#,
            r#"{"name":"","mimeType":"","size":1}"#,
            r#"{"name":"a","mimeType":"","size":-1}"#,
            r#"{"name":"a","mimeType":"","size":9007199254740992}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"lat":1}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"lat":0,"lon":0}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"lat":91,"lon":0}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"takenAt":1}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"takenAt":1,"takenFrom":"camera"}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"takenAt":1,"takenFrom":"exif","takenOffset":900}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"takenAt":9999999999999,"takenFrom":"exif"}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"width":10}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"width":0,"height":1}}"#,
            r#"{"name":"a","mimeType":"","size":1,"sha256":"AAAA"}"#,
            r#"{"name":"a","mimeType":"","size":1,"sha256":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwd="}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"hash":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#,
            r#"{"name":"a","mimeType":"","size":1,"media":{"caption":""}}"#,
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn hashes_streamed_content() {
        let mut hasher = ContentHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        assert_eq!(
            hasher.finish(),
            "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
        );
    }
}
