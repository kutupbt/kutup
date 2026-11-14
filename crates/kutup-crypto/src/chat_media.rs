//! Chat-media identifiers shared by every attachment: the suite, the
//! object purpose and the attachment context. The object itself is in the
//! block format (`chat_media_blocks`, docs/chat-media.md).
//!
//! Direct Chat, groups, linked devices and future broadcast all carry the
//! same random attachment key inside their own E2EE content. The object is
//! encrypted once and can therefore be durably copied between homeservers
//! without teaching them a filename, MIME type, sender or conversation.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const KEY_LEN: usize = 32;

/// One protocol attachment is capped at 2 GiB of plaintext-class content.
pub const MAX_CHAT_MEDIA_PLAINTEXT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum ChatMediaSuiteId {
    /// `KUTPCM2`: the block format (`chat_media_blocks`). Suite 1 (a
    /// secretstream) is gone and no longer parses.
    KutupChatMediaBlocksV1 = 2,
}

impl ChatMediaSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<ChatMediaSuiteId> for u16 {
    fn from(value: ChatMediaSuiteId) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for ChatMediaSuiteId {
    type Error = CryptoError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            2 => Ok(Self::KutupChatMediaBlocksV1),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat-media suite {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChatMediaObjectPurpose {
    AttachmentBlob = 1,
}

impl ChatMediaObjectPurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChatMediaObjectPurpose {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::AttachmentBlob),
            _ => Err(CryptoError::InvalidInput(format!(
                "unknown Chat-media object purpose {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatMediaObjectContextV1 {
    pub attachment_id: [u8; 16],
}

impl ChatMediaObjectContextV1 {
    pub fn new(attachment_id: &str) -> Result<Self> {
        Ok(Self {
            attachment_id: parse_canonical_uuid(attachment_id, "Chat-media attachment")?,
        })
    }
}

pub fn generate_attachment_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    crate::primitives::random(key.as_mut_slice());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_block_suite_parses() {
        assert_eq!(
            ChatMediaSuiteId::try_from(2).unwrap(),
            ChatMediaSuiteId::KutupChatMediaBlocksV1
        );
        for gone in [0, 1, 3] {
            assert!(ChatMediaSuiteId::try_from(gone).is_err(), "{gone}");
        }
        assert!(ChatMediaObjectContextV1::new("not-a-uuid").is_err());
    }
}
