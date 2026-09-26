//! A Drive file's metadata: the plaintext sealed in its metadata envelope
//! (`drive_envelope`, purpose `FileMetadata`, under the file key).
//!
//! JSON, one object: `name`, `mimeType`, `size`, and for photos and videos
//! an optional `media` object (docs/plans/photos.md) with when and where it
//! was taken, its size on screen, its length, a content hash and a caption.
//! Encoding is canonical (fixed field order, absent fields omitted); decoding
//! is strict (unknown fields and out-of-range values are refused), so every
//! client reads and writes the same thing.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// SHA-256 of the plaintext content, canonical base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileMetadataV1 {
    pub name: String,
    pub mime_type: String,
    pub size: u64,
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
        if let Some(hash) = &self.hash {
            let bytes = STANDARD.decode(hash).map_err(|_| invalid("hash"))?;
            if bytes.len() != 32 || STANDARD.encode(&bytes) != *hash {
                return Err(invalid("hash"));
            }
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl FileMetadataV1 {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || chars(&self.name) > MAX_NAME_CHARS {
            return Err(invalid("name"));
        }
        if chars(&self.mime_type) > MAX_MIME_CHARS {
            return Err(invalid("mimeType"));
        }
        if self.size > MAX_SAFE_INTEGER {
            return Err(invalid("size"));
        }
        if let Some(media) = &self.media {
            // An empty object says nothing: it is written as no `media`.
            if media.is_empty() {
                return Err(invalid("empty media"));
            }
            media.validate()?;
        }
        Ok(())
    }
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

/// A content hash, fed as the content streams past (`MediaMetadataV1::hash`).
#[derive(Default, Clone)]
pub struct ContentHasher(Sha256);

impl ContentHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    /// Canonical base64 of the SHA-256.
    pub fn finish(self) -> String {
        STANDARD.encode(self.0.finalize())
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
            media: Some(MediaMetadataV1 {
                taken_at: Some(1_719_835_200_000),
                taken_offset: Some(180),
                taken_from: Some(TakenFrom::Exif),
                lat: Some(41.0082),
                lon: Some(28.9784),
                width: Some(4032),
                height: Some(3024),
                camera: Some("Apple iPhone 15".into()),
                hash: Some(STANDARD.encode([7u8; 32])),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn round_trips_canonically() {
        let bytes = encode(&photo()).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"name":"IMG_0001.jpg","mimeType":"image/jpeg","size":2345678,"media":{"takenAt":1719835200000,"takenOffset":180,"takenFrom":"exif","lat":41.0082,"lon":28.9784,"width":4032,"height":3024,"camera":"Apple iPhone 15","hash":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#
        );
        assert_eq!(decode(&bytes).unwrap(), photo());
    }

    #[test]
    fn plain_files_have_no_media() {
        let plain = FileMetadataV1 {
            name: "a.txt".into(),
            mime_type: "text/plain".into(),
            size: 0,
            media: None,
        };
        let bytes = encode(&plain).unwrap();
        assert_eq!(
            bytes,
            br#"{"name":"a.txt","mimeType":"text/plain","size":0}"#
        );
        assert_eq!(decode(&bytes).unwrap(), plain);
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
            r#"{"name":"a","mimeType":"","size":1,"media":{"hash":"AAAA"}}"#,
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
