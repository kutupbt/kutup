//! The Drive object registry every Kutup client shares: the suite of
//! Drive's typed envelopes (`drive_envelope`), the purpose a file blob's
//! header names, and the canonical UUID parsing both use. File blobs are in
//! the block format (`drive_blocks`, suite 2, docs/plans/drive-block-format.md).

use crate::error::{CryptoError, Result};

/// The suite of Drive's typed envelopes (`drive_envelope`). Features retain
/// their own typed keys and payload purposes under it. File blobs have their
/// own suite (`drive_blocks::DRIVE_BLOCKS_SUITE`).
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
