//! Typed persistent Drive-object framing shared by every Kutup client.
//!
//! A V1 file blob is:
//! `[48-byte Drive header][24-byte secretstream header][secretstream frames]`.
//! The Drive header is canonical, is authenticated as associated data on every
//! frame, and binds the ciphertext to one file, collection, and key epoch.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::stream::{
    StreamDecryptor, StreamEncryptor, ABYTES, CHUNK_SIZE, HEADER_BYTES as STREAM_HEADER_BYTES,
    TAG_FINAL, TAG_MESSAGE,
};

const FILE_BLOB_MAGIC: &[u8; 8] = b"KUTPDB1\0";
const FILE_BLOB_KEY_SALT: &[u8] = b"kutup/drive-object/file-blob-key/v1\0";
const KEY_LEN: usize = 32;

/// Complete Kutup-owned Drive construction registry. Features retain their
/// own typed keys and payload purposes even when they share this suite entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DriveObjectSuiteId {
    KutupDriveV1 = 1,
}

impl DriveObjectSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for DriveObjectSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::KutupDriveV1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Drive object suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DriveObjectPurpose {
    FileBlob = 1,
}

impl DriveObjectPurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for DriveObjectPurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::FileBlob),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Drive object purpose {value}"
            ))),
        }
    }
}

/// Canonical file-blob header length: magic(8) + suite(2) + purpose(1) +
/// reserved(1) + epoch(4) + file UUID(16) + collection UUID(16).
pub const FILE_BLOB_HEADER_BYTES: usize = 48;
pub const FILE_BLOB_PREFIX_BYTES: usize = FILE_BLOB_HEADER_BYTES + STREAM_HEADER_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriveFileBlobContextV1 {
    pub epoch: u32,
    pub file_id: [u8; 16],
    pub collection_id: [u8; 16],
}

impl DriveFileBlobContextV1 {
    pub fn new(file_id: &str, collection_id: &str, epoch: u32) -> Result<Self> {
        if epoch == 0 {
            return Err(CryptoError::InvalidInput(
                "Drive file-blob epoch must be non-zero".into(),
            ));
        }
        Ok(Self {
            epoch,
            file_id: parse_canonical_uuid(file_id, "file")?,
            collection_id: parse_canonical_uuid(collection_id, "collection")?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriveFileBlobHeaderV1 {
    pub suite: DriveObjectSuiteId,
    pub purpose: DriveObjectPurpose,
    pub context: DriveFileBlobContextV1,
}

pub(crate) fn parse_canonical_uuid(value: &str, field: &str) -> Result<[u8; 16]> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(CryptoError::InvalidInput(format!(
            "Drive {field} UUID is invalid"
        )));
    }
    let mut output = [0u8; 16];
    let mut high_nibble = None;
    let mut output_index = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => {
                return Err(CryptoError::InvalidInput(format!(
                    "Drive {field} UUID is not canonical"
                )))
            }
        };
        if let Some(high) = high_nibble.take() {
            output[output_index] = (high << 4) | nibble;
            output_index += 1;
        } else {
            high_nibble = Some(nibble);
        }
    }
    if output_index != output.len() || high_nibble.is_some() {
        return Err(CryptoError::InvalidInput(format!(
            "Drive {field} UUID is invalid"
        )));
    }
    Ok(output)
}

pub fn file_blob_header(context: DriveFileBlobContextV1) -> [u8; FILE_BLOB_HEADER_BYTES] {
    let mut header = [0u8; FILE_BLOB_HEADER_BYTES];
    header[..8].copy_from_slice(FILE_BLOB_MAGIC);
    header[8..10].copy_from_slice(&DriveObjectSuiteId::KutupDriveV1.as_u16().to_be_bytes());
    header[10] = DriveObjectPurpose::FileBlob.as_u8();
    header[12..16].copy_from_slice(&context.epoch.to_be_bytes());
    header[16..32].copy_from_slice(&context.file_id);
    header[32..48].copy_from_slice(&context.collection_id);
    header
}

pub fn inspect_file_blob_header(header: &[u8]) -> Result<DriveFileBlobHeaderV1> {
    if header.len() != FILE_BLOB_HEADER_BYTES || header.get(..8) != Some(FILE_BLOB_MAGIC) {
        return Err(CryptoError::TooShort);
    }
    let suite = DriveObjectSuiteId::try_from(u16::from_be_bytes([header[8], header[9]]))?;
    let purpose = DriveObjectPurpose::try_from(header[10])?;
    if header[11] != 0 {
        return Err(CryptoError::InvalidInput(
            "Drive file-blob reserved byte is non-zero".into(),
        ));
    }
    let epoch = u32::from_be_bytes(header[12..16].try_into().expect("four-byte slice"));
    if epoch == 0 {
        return Err(CryptoError::InvalidInput(
            "Drive file-blob epoch must be non-zero".into(),
        ));
    }
    Ok(DriveFileBlobHeaderV1 {
        suite,
        purpose,
        context: DriveFileBlobContextV1 {
            epoch,
            file_id: header[16..32].try_into().expect("sixteen-byte slice"),
            collection_id: header[32..48].try_into().expect("sixteen-byte slice"),
        },
    })
}

pub fn validate_file_blob_header(header: &[u8], expected: DriveFileBlobContextV1) -> Result<()> {
    let parsed = inspect_file_blob_header(header)?;
    if parsed.suite != DriveObjectSuiteId::KutupDriveV1
        || parsed.purpose != DriveObjectPurpose::FileBlob
        || parsed.context != expected
    {
        return Err(CryptoError::InvalidInput(
            "Drive file-blob context does not match".into(),
        ));
    }
    Ok(())
}

pub fn derive_file_blob_key(
    file_key: &[u8],
    context: DriveFileBlobContextV1,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if file_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
            got: file_key.len(),
        });
    }
    let header = file_blob_header(context);
    let hkdf = Hkdf::<Sha256>::new(Some(FILE_BLOB_KEY_SALT), file_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&header, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("Drive file-blob HKDF expand".into()))?;
    Ok(key)
}

/// Encrypt a complete file blob. Streaming clients use the same header, key,
/// and associated-data functions with their incremental secretstream adapter.
pub fn encrypt_file_blob(
    plaintext: &[u8],
    file_key: &[u8],
    context: DriveFileBlobContextV1,
) -> Result<Vec<u8>> {
    let object_header = file_blob_header(context);
    let stream_key = derive_file_blob_key(file_key, context)?;
    let (mut encryptor, stream_header) =
        StreamEncryptor::new_with_aad(stream_key.as_slice(), &object_header)?;
    let chunks = plaintext.len().div_ceil(CHUNK_SIZE).max(1);
    let mut output = Vec::with_capacity(
        FILE_BLOB_PREFIX_BYTES + plaintext.len() + chunks.saturating_mul(ABYTES),
    );
    output.extend_from_slice(&object_header);
    output.extend_from_slice(&stream_header);

    if plaintext.is_empty() {
        output.extend_from_slice(&encryptor.push(&[], TAG_FINAL)?);
        return Ok(output);
    }
    for (index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let tag = if index + 1 == chunks {
            TAG_FINAL
        } else {
            TAG_MESSAGE
        };
        output.extend_from_slice(&encryptor.push(chunk, tag)?);
    }
    Ok(output)
}

pub fn decrypt_file_blob(
    ciphertext: &[u8],
    file_key: &[u8],
    expected: DriveFileBlobContextV1,
) -> Result<Vec<u8>> {
    if ciphertext.len() < FILE_BLOB_PREFIX_BYTES + ABYTES {
        return Err(CryptoError::TooShort);
    }
    let object_header = &ciphertext[..FILE_BLOB_HEADER_BYTES];
    validate_file_blob_header(object_header, expected)?;
    let stream_header = &ciphertext[FILE_BLOB_HEADER_BYTES..FILE_BLOB_PREFIX_BYTES];
    let stream_key = derive_file_blob_key(file_key, expected)?;
    let mut decryptor =
        StreamDecryptor::new_with_aad(stream_key.as_slice(), stream_header, object_header)?;
    let body = &ciphertext[FILE_BLOB_PREFIX_BYTES..];
    let frame_size = CHUNK_SIZE + ABYTES;
    let mut output = Vec::with_capacity(body.len());
    let mut offset = 0;
    let mut saw_final = false;
    while offset < body.len() {
        let end = (offset + frame_size).min(body.len());
        let (plaintext, tag) = decryptor.pull(&body[offset..end])?;
        output.extend_from_slice(&plaintext);
        offset = end;
        if tag == TAG_FINAL {
            saw_final = true;
            if offset != body.len() {
                return Err(CryptoError::InvalidInput(
                    "Drive file blob has bytes after FINAL".into(),
                ));
            }
        } else if offset == body.len() {
            return Err(CryptoError::InvalidInput(
                "Drive file blob ended before FINAL".into(),
            ));
        }
    }
    if !saw_final {
        return Err(CryptoError::InvalidInput(
            "Drive file blob has no FINAL frame".into(),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> DriveFileBlobContextV1 {
        DriveFileBlobContextV1::new(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            7,
        )
        .unwrap()
    }

    #[test]
    fn roundtrips_and_authenticates_empty_file() {
        let key = [9u8; 32];
        let ciphertext = encrypt_file_blob(&[], &key, context()).unwrap();
        assert_eq!(ciphertext.len(), FILE_BLOB_PREFIX_BYTES + ABYTES);
        assert_eq!(
            decrypt_file_blob(&ciphertext, &key, context()).unwrap(),
            b""
        );
        let mut tampered = ciphertext;
        tampered[15] ^= 1;
        assert!(decrypt_file_blob(&tampered, &key, context()).is_err());
    }

    #[test]
    fn relocation_and_truncation_fail_closed() {
        let key = [7u8; 32];
        let ciphertext = encrypt_file_blob(b"payload", &key, context()).unwrap();
        let relocated = DriveFileBlobContextV1::new(
            "33333333-3333-4333-8333-333333333333",
            "22222222-2222-4222-8222-222222222222",
            7,
        )
        .unwrap();
        assert!(decrypt_file_blob(&ciphertext, &key, relocated).is_err());
        assert!(decrypt_file_blob(&ciphertext[..ciphertext.len() - 1], &key, context()).is_err());
    }
}
