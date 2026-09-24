//! Drive thumbnails: a small raster preview of a file, made by a client that
//! holds the file key and sealed under it (`DriveEnvelopePurpose::Thumbnail`).
//! Design: `docs/plans/drive-thumbnails.md`.
//!
//! The sealed plaintext is a container rather than a bare image:
//!
//! ```text
//! magic    "KTH1"    4 bytes
//! format   u8        1 = JPEG, 2 = WebP, 3 = PNG
//! width    u16 BE
//! height   u16 BE
//! length   u32 BE    image byte count
//! image    [length]
//! padding  zeros up to the variant's block size
//! ```
//!
//! Dimensions let a viewer reserve the right shape before decoding; padding
//! leaves the server a few size buckets instead of a byte count that tracks
//! the picture. Parsing is strict: every rule below is a rejection, never a
//! repair.

use crate::drive_envelope::{self, DriveEnvelopeContextV1};
use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 4] = b"KTH1";
const HEADER_LEN: usize = 4 + 1 + 2 + 2 + 4;

/// The largest container of any variant (`Large`).
pub const MAX_THUMBNAIL_PLAINTEXT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThumbnailVariant {
    /// Grid cards and search results.
    Small,
    /// Quick Look for kinds without a viewer, and very large images.
    Large,
}

impl ThumbnailVariant {
    /// The id used in URLs, storage paths and the envelope binding.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "sm",
            Self::Large => "lg",
        }
    }

    pub const fn max_side(self) -> u16 {
        match self {
            Self::Small => 512,
            Self::Large => 1920,
        }
    }

    /// The container cap, padding included.
    pub const fn max_plaintext_bytes(self) -> usize {
        match self {
            Self::Small => 64 * 1024,
            Self::Large => MAX_THUMBNAIL_PLAINTEXT_BYTES,
        }
    }

    const fn block(self) -> usize {
        match self {
            Self::Small => 4 * 1024,
            Self::Large => 16 * 1024,
        }
    }
}

impl TryFrom<&str> for ThumbnailVariant {
    type Error = CryptoError;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "sm" => Ok(Self::Small),
            "lg" => Ok(Self::Large),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown thumbnail variant {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ThumbnailFormat {
    Jpeg = 1,
    Webp = 2,
    Png = 3,
}

impl ThumbnailFormat {
    /// Whether `image` starts the way this format's files do.
    fn matches(self, image: &[u8]) -> bool {
        match self {
            Self::Jpeg => image.starts_with(&[0xFF, 0xD8, 0xFF]),
            Self::Webp => image.len() >= 12 && &image[..4] == b"RIFF" && &image[8..12] == b"WEBP",
            Self::Png => image.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
        }
    }
}

impl TryFrom<u8> for ThumbnailFormat {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Jpeg),
            2 => Ok(Self::Webp),
            3 => Ok(Self::Png),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown thumbnail format {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thumbnail {
    pub format: ThumbnailFormat,
    pub width: u16,
    pub height: u16,
    pub image: Vec<u8>,
}

fn check_dimensions(width: u16, height: u16, variant: ThumbnailVariant) -> Result<()> {
    let max = variant.max_side();
    if width == 0 || height == 0 || width > max || height > max {
        return Err(CryptoError::InvalidInput(format!(
            "thumbnail dimensions {width}x{height} outside 1..={max} for {}",
            variant.as_str()
        )));
    }
    Ok(())
}

/// Frame and pad a thumbnail for `variant`.
pub fn encode(thumbnail: &Thumbnail, variant: ThumbnailVariant) -> Result<Vec<u8>> {
    check_dimensions(thumbnail.width, thumbnail.height, variant)?;
    if thumbnail.image.is_empty() || !thumbnail.format.matches(&thumbnail.image) {
        return Err(CryptoError::InvalidInput(
            "thumbnail image does not match its declared format".into(),
        ));
    }
    let used = HEADER_LEN + thumbnail.image.len();
    let padded = used.div_ceil(variant.block()) * variant.block();
    if padded > variant.max_plaintext_bytes() {
        return Err(CryptoError::InvalidInput(format!(
            "thumbnail image too large for {}",
            variant.as_str()
        )));
    }
    let length = u32::try_from(thumbnail.image.len())
        .map_err(|_| CryptoError::InvalidInput("thumbnail image too large".into()))?;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(MAGIC);
    out.push(thumbnail.format as u8);
    out.extend_from_slice(&thumbnail.width.to_be_bytes());
    out.extend_from_slice(&thumbnail.height.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&thumbnail.image);
    out.resize(padded, 0);
    Ok(out)
}

/// Parse a container, rejecting anything not exactly as `encode` makes it.
pub fn decode(container: &[u8], variant: ThumbnailVariant) -> Result<Thumbnail> {
    if container.len() > variant.max_plaintext_bytes()
        || container.len() < HEADER_LEN
        || !container.len().is_multiple_of(variant.block())
    {
        return Err(CryptoError::InvalidInput(
            "thumbnail container has an invalid size".into(),
        ));
    }
    if &container[..4] != MAGIC {
        return Err(CryptoError::InvalidInput(
            "not a thumbnail container".into(),
        ));
    }
    let format = ThumbnailFormat::try_from(container[4])?;
    let width = u16::from_be_bytes([container[5], container[6]]);
    let height = u16::from_be_bytes([container[7], container[8]]);
    check_dimensions(width, height, variant)?;
    let length =
        u32::from_be_bytes([container[9], container[10], container[11], container[12]]) as usize;
    let end = HEADER_LEN
        .checked_add(length)
        .filter(|end| *end <= container.len() && length > 0)
        .ok_or_else(|| CryptoError::InvalidInput("thumbnail length is out of range".into()))?;
    let image = &container[HEADER_LEN..end];
    if !format.matches(image) {
        return Err(CryptoError::InvalidInput(
            "thumbnail image does not match its declared format".into(),
        ));
    }
    // The padding is exactly what encode wrote: whole blocks of zeros.
    if end.div_ceil(variant.block()) * variant.block() != container.len()
        || container[end..].iter().any(|b| *b != 0)
    {
        return Err(CryptoError::InvalidInput(
            "thumbnail padding is invalid".into(),
        ));
    }
    Ok(Thumbnail {
        format,
        width,
        height,
        image: image.to_vec(),
    })
}

/// Encode and seal a thumbnail under the file key.
pub fn seal(
    thumbnail: &Thumbnail,
    variant: ThumbnailVariant,
    file_key: &[u8],
    file_id: &str,
    epoch: u32,
) -> Result<Vec<u8>> {
    let context = DriveEnvelopeContextV1::thumbnail(file_id, variant, epoch)?;
    drive_envelope::seal(&encode(thumbnail, variant)?, file_key, context)
}

/// Deterministic-nonce entry point for checked-in vectors only.
pub fn seal_with_nonce(
    thumbnail: &Thumbnail,
    variant: ThumbnailVariant,
    file_key: &[u8],
    file_id: &str,
    epoch: u32,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let context = DriveEnvelopeContextV1::thumbnail(file_id, variant, epoch)?;
    drive_envelope::seal_with_nonce(&encode(thumbnail, variant)?, file_key, context, nonce)
}

/// Open and parse a thumbnail of exactly this file, variant and epoch.
pub fn open(
    envelope: &[u8],
    variant: ThumbnailVariant,
    file_key: &[u8],
    file_id: &str,
    epoch: u32,
) -> Result<Thumbnail> {
    let context = DriveEnvelopeContextV1::thumbnail(file_id, variant, epoch)?;
    decode(&drive_envelope::open(envelope, file_key, context)?, variant)
}

/// Check an envelope's header against the thumbnail it claims to be, without
/// the key: what the server can verify on upload.
pub fn validate(
    envelope: &[u8],
    variant: ThumbnailVariant,
    file_id: &str,
    epoch: u32,
) -> Result<()> {
    if envelope.len() > drive_envelope::max_thumbnail_envelope_bytes(variant) {
        return Err(CryptoError::InvalidInput(
            "thumbnail envelope too large".into(),
        ));
    }
    let context = DriveEnvelopeContextV1::thumbnail(file_id, variant, epoch)?;
    drive_envelope::validate(envelope, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "33333333-3333-4333-8333-333333333333";
    const KEY: [u8; 32] = [7; 32];

    fn jpeg(len: usize) -> Vec<u8> {
        let mut image = vec![0xFF, 0xD8, 0xFF, 0xE0];
        image.resize(len, 0x42);
        image
    }

    fn thumb(len: usize) -> Thumbnail {
        Thumbnail {
            format: ThumbnailFormat::Jpeg,
            width: 512,
            height: 288,
            image: jpeg(len),
        }
    }

    #[test]
    fn round_trips_and_pads_to_the_variant_block() {
        let t = thumb(5000);
        let container = encode(&t, ThumbnailVariant::Small).unwrap();
        assert_eq!(container.len(), 8192);
        assert_eq!(decode(&container, ThumbnailVariant::Small).unwrap(), t);

        let envelope = seal(&t, ThumbnailVariant::Small, &KEY, FILE, 2).unwrap();
        validate(&envelope, ThumbnailVariant::Small, FILE, 2).unwrap();
        assert_eq!(
            open(&envelope, ThumbnailVariant::Small, &KEY, FILE, 2).unwrap(),
            t
        );
    }

    #[test]
    fn is_bound_to_its_file_variant_and_epoch() {
        let t = thumb(100);
        let envelope = seal(&t, ThumbnailVariant::Small, &KEY, FILE, 2).unwrap();
        assert!(open(&envelope, ThumbnailVariant::Large, &KEY, FILE, 2).is_err());
        assert!(open(&envelope, ThumbnailVariant::Small, &KEY, OTHER, 2).is_err());
        assert!(open(&envelope, ThumbnailVariant::Small, &KEY, FILE, 3).is_err());
        assert!(open(&envelope, ThumbnailVariant::Small, &[8; 32], FILE, 2).is_err());
        assert!(validate(&envelope, ThumbnailVariant::Large, FILE, 2).is_err());
        assert!(validate(&envelope, ThumbnailVariant::Small, OTHER, 2).is_err());
    }

    #[test]
    fn rejects_what_it_would_not_make() {
        let v = ThumbnailVariant::Small;
        // Wrong declared format, and a bare SVG.
        let mut t = thumb(100);
        t.format = ThumbnailFormat::Png;
        assert!(encode(&t, v).is_err());
        let svg = Thumbnail {
            format: ThumbnailFormat::Png,
            width: 1,
            height: 1,
            image: b"<svg/>".to_vec(),
        };
        assert!(encode(&svg, v).is_err());
        // Dimensions beyond the variant, and zero.
        let mut t = thumb(100);
        t.width = 513;
        assert!(encode(&t, v).is_err());
        t.width = 0;
        assert!(encode(&t, v).is_err());
        // Too large for small, fine for large.
        assert!(encode(&thumb(70_000), v).is_err());
        let mut big = thumb(70_000);
        big.width = 1920;
        assert!(encode(&big, ThumbnailVariant::Large).is_ok());

        let good = encode(&thumb(100), v).unwrap();
        // Non-zero padding.
        let mut bad = good.clone();
        *bad.last_mut().unwrap() = 1;
        assert!(decode(&bad, v).is_err());
        // Padding beyond one block.
        let mut long = good.clone();
        long.resize(good.len() + 4096, 0);
        assert!(decode(&long, v).is_err());
        // Length pointing past the end.
        let mut past = good.clone();
        past[9..13].copy_from_slice(&(10_000u32).to_be_bytes());
        assert!(decode(&past, v).is_err());
        // Unknown format byte, bad magic.
        let mut unknown = good.clone();
        unknown[4] = 9;
        assert!(decode(&unknown, v).is_err());
        let mut magic = good;
        magic[0] = b'X';
        assert!(decode(&magic, v).is_err());
    }

    #[test]
    fn accepts_each_format_by_its_signature() {
        let v = ThumbnailVariant::Small;
        let mut webp = b"RIFF\0\0\0\0WEBPVP8 ".to_vec();
        webp.resize(64, 1);
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0].to_vec();
        for (format, image) in [(ThumbnailFormat::Webp, webp), (ThumbnailFormat::Png, png)] {
            let t = Thumbnail {
                format,
                width: 10,
                height: 10,
                image,
            };
            assert_eq!(decode(&encode(&t, v).unwrap(), v).unwrap(), t);
        }
    }

    #[test]
    fn parses_variants_by_id() {
        assert_eq!(
            ThumbnailVariant::try_from("sm").unwrap(),
            ThumbnailVariant::Small
        );
        assert_eq!(
            ThumbnailVariant::try_from("lg").unwrap(),
            ThumbnailVariant::Large
        );
        assert!(ThumbnailVariant::try_from("xl").is_err());
    }
}
