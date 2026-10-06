//! Call link keys and sealing (docs/chat-calls.md, "Call links").
//!
//! A call link is a call anyone holding the link can join, with or without a
//! Kutup account. Everything about it comes from the link's 32-byte secret,
//! which sits in the URL fragment and never reaches a server:
//!
//! - `roomId`: the SFU room, and what the host files the link under;
//! - `accessToken`: what a joiner presents to the host for an SFU token (the
//!   host keeps only its SHA-256, registered by the link's owner);
//! - the frame key: media frames are encrypted under it in the browser, so
//!   the SFU forwards what it cannot read;
//! - a name key: each participant's chosen name travels sealed, so the SFU
//!   sees participants only as opaque identities;
//! - an info key: the meeting's title and time, which the host stores sealed
//!   and hands to whoever holds the link;
//! - a chat key: messages written during the call, which pass through the
//!   SFU sealed and are kept nowhere.
//!
//! All come from HKDF-SHA256 with distinct labels. The owner's own
//! secret for a link is derived from the account master key and a public
//! random nonce the host stores, so the owner's other devices can show the
//! same link again without the host ever holding the secret.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};

const SALT: &[u8] = b"kutup/chat/call-link/v1";
const FRAGMENT_VERSION: u8 = 1;
pub const CALL_LINK_SECRET_BYTES: usize = 32;
pub const CALL_LINK_NONCE_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// Every sealed name has this plaintext size, so its length says nothing.
const NAME_PADDED_BYTES: usize = 128;
/// The longest name a participant can show (UTF-8 bytes).
pub const MAX_CALL_NAME_BYTES: usize = NAME_PADDED_BYTES - 4;
/// A sealed name's size: what the host accepts as a participant label.
pub const CALL_NAME_SEALED_BYTES: usize = NONCE_BYTES + NAME_PADDED_BYTES + TAG_BYTES;
/// Every sealed meeting info has this plaintext size.
const INFO_PADDED_BYTES: usize = 512;
/// A sealed info's size: what the host stores for a link.
pub const CALL_INFO_SEALED_BYTES: usize = NONCE_BYTES + INFO_PADDED_BYTES + TAG_BYTES;
/// The longest meeting title (UTF-8 bytes).
pub const MAX_CALL_TITLE_BYTES: usize = 200;
/// A meeting lasts at most a day.
pub const MAX_CALL_DURATION_MINUTES: u32 = 24 * 60;
/// Sealed messages are padded to a multiple of this.
const MESSAGE_PADDING: usize = 256;
/// The longest message text (UTF-8 bytes).
pub const MAX_CALL_MESSAGE_BYTES: usize = 4000;
const MAX_MESSAGE_SEALED_BYTES: usize = NONCE_BYTES + 4608 + TAG_BYTES;

/// What a meeting is called and when it is, as its owner set them. Anyone
/// holding the link reads it; the host stores it sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallLinkInfoV1 {
    pub title: String,
    /// When it is planned to start (Unix milliseconds), if it is scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_at_ms: Option<i64>,
    /// How long it is planned to last; only with a start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_minutes: Option<u32>,
}

impl CallLinkInfoV1 {
    pub fn validate(&self) -> std::result::Result<(), String> {
        let title = self.title.as_str();
        if title.trim() != title
            || title.is_empty()
            || title.len() > MAX_CALL_TITLE_BYTES
            || title.chars().any(char::is_control)
        {
            return Err("a meeting title is 1 to 200 bytes without control characters".into());
        }
        match (self.starts_at_ms, self.duration_minutes) {
            (None, None) => Ok(()),
            (Some(start), duration) if start > 0 => match duration {
                None => Ok(()),
                Some(minutes) if (1..=MAX_CALL_DURATION_MINUTES).contains(&minutes) => Ok(()),
                Some(_) => Err("a meeting lasts 1 minute to 24 hours".into()),
            },
            (Some(_), _) => Err("a meeting's start is a positive time".into()),
            (None, Some(_)) => Err("a meeting's length needs a start".into()),
        }
    }
}

/// One message written during a call. It reaches the others through the SFU,
/// sealed; who wrote it is the SFU participant it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallLinkMessageV1 {
    /// 32 lowercase hex characters, chosen by the sender.
    pub id: String,
    pub text: String,
    pub sent_at_ms: i64,
}

impl CallLinkMessageV1 {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.id.len() != 32
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("a call message id is 32 lowercase hex characters".into());
        }
        if self.text.trim().is_empty()
            || self.text.len() > MAX_CALL_MESSAGE_BYTES
            || self.text.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err("a call message is 1 to 4000 bytes of text".into());
        }
        if self.sent_at_ms <= 0 {
            return Err("a call message's time is positive".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Purpose {
    Name,
    Info,
    Message,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Name => b"name",
            Self::Info => b"info",
            Self::Message => b"message",
        }
    }

    /// The padded plaintext size for a body of `length` bytes.
    fn padded(self, length: usize) -> usize {
        match self {
            Self::Name => NAME_PADDED_BYTES,
            Self::Info => INFO_PADDED_BYTES,
            Self::Message => (4 + length).div_ceil(MESSAGE_PADDING) * MESSAGE_PADDING,
        }
    }

    fn accepts(self, sealed: usize) -> bool {
        match self {
            Self::Name => sealed == CALL_NAME_SEALED_BYTES,
            Self::Info => sealed == CALL_INFO_SEALED_BYTES,
            Self::Message => {
                let padded = sealed.saturating_sub(NONCE_BYTES + TAG_BYTES);
                padded >= MESSAGE_PADDING
                    && padded % MESSAGE_PADDING == 0
                    && sealed <= MAX_MESSAGE_SEALED_BYTES
            }
        }
    }
}

/// What a call link's secret gives its holder.
pub struct CallLinkKeys {
    /// The SFU room: 32 lowercase hex characters.
    pub room_id: String,
    /// Presented to the host for an SFU token (standard base64).
    pub access_token: String,
    /// What the host stores of the access token: its SHA-256 (standard base64).
    pub access_token_hash: String,
    /// The media frame key (standard base64).
    pub frame_key: Zeroizing<String>,
    name_key: Zeroizing<[u8; 32]>,
    info_key: Zeroizing<[u8; 32]>,
    chat_key: Zeroizing<[u8; 32]>,
}

fn decode_secret(secret: &str) -> Result<Zeroizing<[u8; CALL_LINK_SECRET_BYTES]>> {
    let invalid = || ChatError::Invalid("call link secret is not 32 bytes of base64".into());
    let bytes = Zeroizing::new(STANDARD.decode(secret).map_err(|_| invalid())?);
    if STANDARD.encode(bytes.as_slice()) != secret {
        return Err(invalid());
    }
    let array: [u8; CALL_LINK_SECRET_BYTES] = bytes.as_slice().try_into().map_err(|_| invalid())?;
    Ok(Zeroizing::new(array))
}

fn expand(hkdf: &Hkdf<Sha256>, label: &[u8], output: &mut [u8]) -> Result<()> {
    hkdf.expand(label, output)
        .map_err(|_| ChatError::Protocol("call link key derivation failed".into()))
}

/// A fresh nonce for a new link: public, stored by the host with the link.
pub fn new_call_link_nonce() -> String {
    let mut bytes = [0u8; CALL_LINK_NONCE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The secret of the link its owner made with `nonce` (32 lowercase hex
/// characters), from the owner's account master key (standard base64, 32
/// bytes). Only the owner can compute it, on any of their devices.
pub fn owner_call_link_secret(master_key: &str, nonce: &str) -> Result<Zeroizing<String>> {
    let invalid_key = || ChatError::Invalid("account master key is not 32 bytes of base64".into());
    let master = Zeroizing::new(STANDARD.decode(master_key).map_err(|_| invalid_key())?);
    if master.len() != 32 {
        return Err(invalid_key());
    }
    let invalid_nonce =
        || ChatError::Invalid("call link nonce is 32 lowercase hex characters".into());
    let nonce_bytes = hex::decode(nonce).map_err(|_| invalid_nonce())?;
    if nonce_bytes.len() != CALL_LINK_NONCE_BYTES || hex::encode(&nonce_bytes) != nonce {
        return Err(invalid_nonce());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), master.as_slice());
    let mut info = b"owner secret\0".to_vec();
    info.extend_from_slice(&nonce_bytes);
    let mut secret = Zeroizing::new([0u8; CALL_LINK_SECRET_BYTES]);
    expand(&hkdf, &info, secret.as_mut_slice())?;
    Ok(Zeroizing::new(STANDARD.encode(secret.as_slice())))
}

/// The owner's proof of being a meeting's host (standard base64, 32 bytes),
/// from the account master key and the meeting's nonce. Unlike the link's
/// secret, nobody the link is shared with can compute it. The host stores
/// only its SHA-256: presenting the token lets the owner into a meeting
/// with a waiting room, and lets them admit the people waiting.
pub fn owner_call_link_host_token(master_key: &str, nonce: &str) -> Result<Zeroizing<String>> {
    let invalid_key = || ChatError::Invalid("account master key is not 32 bytes of base64".into());
    let master = Zeroizing::new(STANDARD.decode(master_key).map_err(|_| invalid_key())?);
    if master.len() != 32 {
        return Err(invalid_key());
    }
    let invalid_nonce =
        || ChatError::Invalid("call link nonce is 32 lowercase hex characters".into());
    let nonce_bytes = hex::decode(nonce).map_err(|_| invalid_nonce())?;
    if nonce_bytes.len() != CALL_LINK_NONCE_BYTES || hex::encode(&nonce_bytes) != nonce {
        return Err(invalid_nonce());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), master.as_slice());
    let mut info = b"host token\0".to_vec();
    info.extend_from_slice(&nonce_bytes);
    let mut token = Zeroizing::new([0u8; 32]);
    expand(&hkdf, &info, token.as_mut_slice())?;
    Ok(Zeroizing::new(STANDARD.encode(token.as_slice())))
}

/// What the host stores of a token: its SHA-256 (standard base64).
pub fn call_link_token_hash(token: &str) -> Result<String> {
    let invalid = || ChatError::Invalid("a call link token is 32 bytes of base64".into());
    let bytes = Zeroizing::new(STANDARD.decode(token).map_err(|_| invalid())?);
    if bytes.len() != 32 {
        return Err(invalid());
    }
    Ok(STANDARD.encode(Sha256::digest(bytes.as_slice())))
}

impl CallLinkKeys {
    /// `secret` is 32 bytes of standard base64.
    pub fn derive(secret: &str) -> Result<Self> {
        let secret = decode_secret(secret)?;
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), secret.as_slice());
        let mut room = [0u8; 16];
        expand(&hkdf, b"room id", &mut room)?;
        let mut access = Zeroizing::new([0u8; 32]);
        expand(&hkdf, b"access token", access.as_mut_slice())?;
        let mut frame = Zeroizing::new([0u8; 32]);
        expand(&hkdf, b"frame key", frame.as_mut_slice())?;
        let mut name_key = Zeroizing::new([0u8; 32]);
        expand(&hkdf, b"name key", name_key.as_mut_slice())?;
        let mut info_key = Zeroizing::new([0u8; 32]);
        expand(&hkdf, b"info key", info_key.as_mut_slice())?;
        let mut chat_key = Zeroizing::new([0u8; 32]);
        expand(&hkdf, b"chat key", chat_key.as_mut_slice())?;
        Ok(Self {
            room_id: hex::encode(room),
            access_token: STANDARD.encode(access.as_slice()),
            access_token_hash: STANDARD.encode(Sha256::digest(access.as_slice())),
            frame_key: Zeroizing::new(STANDARD.encode(frame.as_slice())),
            name_key,
            info_key,
            chat_key,
        })
    }

    fn aad(&self, purpose: Purpose) -> Vec<u8> {
        let mut aad = SALT.to_vec();
        aad.push(b'/');
        aad.extend_from_slice(purpose.label());
        aad.push(0);
        aad.extend_from_slice(self.room_id.as_bytes());
        aad
    }

    fn cipher(&self, purpose: Purpose) -> Result<XChaCha20Poly1305> {
        let key = match purpose {
            Purpose::Name => &self.name_key,
            Purpose::Info => &self.info_key,
            Purpose::Message => &self.chat_key,
        };
        XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| ChatError::Protocol("invalid call link key".into()))
    }

    /// `nonce (24) || XChaCha20-Poly1305(length (u32 BE) || body || zeros)`,
    /// bound to its purpose and room.
    fn seal(&self, purpose: Purpose, body: &[u8]) -> Result<String> {
        let padded_length = purpose.padded(body.len());
        if 4 + body.len() > padded_length {
            return Err(ChatError::Invalid("call link value is too large".into()));
        }
        let mut padded = Zeroizing::new(Vec::with_capacity(padded_length));
        padded.extend_from_slice(&(body.len() as u32).to_be_bytes());
        padded.extend_from_slice(body);
        padded.resize(padded_length, 0);
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher(purpose)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &padded,
                    aad: &self.aad(purpose),
                },
            )
            .map_err(|_| ChatError::Protocol("call link sealing failed".into()))?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(sealed))
    }

    /// A value that does not open was not made by a holder of this link.
    fn open(&self, purpose: Purpose, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
        let malformed = || ChatError::Content("sealed call link value is malformed".into());
        let sealed = STANDARD.decode(sealed).map_err(|_| malformed())?;
        if !purpose.accepts(sealed.len()) {
            return Err(malformed());
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let padded = Zeroizing::new(
            self.cipher(purpose)?
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &self.aad(purpose),
                    },
                )
                .map_err(|_| ChatError::Content("sealed call link value does not open".into()))?,
        );
        let length = u32::from_be_bytes(padded[..4].try_into().expect("four bytes")) as usize;
        let body = padded.get(4..4 + length).ok_or_else(malformed)?;
        if padded[4 + length..].iter().any(|byte| *byte != 0) {
            return Err(malformed());
        }
        Ok(Zeroizing::new(body.to_vec()))
    }

    /// Seal the name a participant chose, for the others in the call.
    pub fn seal_name(&self, name: &str) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_CALL_NAME_BYTES || name.chars().any(char::is_control)
        {
            return Err(ChatError::Invalid(
                "a call name is 1 to 124 bytes without control characters".into(),
            ));
        }
        self.seal(Purpose::Name, name.as_bytes())
    }

    /// The name a participant sealed.
    pub fn open_name(&self, sealed: &str) -> Result<String> {
        let malformed = || ChatError::Content("sealed call name is malformed".into());
        let body = self.open(Purpose::Name, sealed)?;
        let name = std::str::from_utf8(&body).map_err(|_| malformed())?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(malformed());
        }
        Ok(name.to_owned())
    }

    /// Seal what the meeting is called and when it is, for the host to keep.
    pub fn seal_info(&self, info: &CallLinkInfoV1) -> Result<String> {
        info.validate().map_err(ChatError::Invalid)?;
        let json =
            serde_json::to_vec(info).map_err(|error| ChatError::Invalid(error.to_string()))?;
        self.seal(Purpose::Info, &json)
    }

    pub fn open_info(&self, sealed: &str) -> Result<CallLinkInfoV1> {
        let json = self.open(Purpose::Info, sealed)?;
        let info: CallLinkInfoV1 = serde_json::from_slice(&json)
            .map_err(|_| ChatError::Content("meeting info is malformed".into()))?;
        info.validate().map_err(ChatError::Content)?;
        Ok(info)
    }

    /// Seal a message written during the call, for the others in it.
    pub fn seal_message(&self, message: &CallLinkMessageV1) -> Result<String> {
        message.validate().map_err(ChatError::Invalid)?;
        let json =
            serde_json::to_vec(message).map_err(|error| ChatError::Invalid(error.to_string()))?;
        self.seal(Purpose::Message, &json)
    }

    pub fn open_message(&self, sealed: &str) -> Result<CallLinkMessageV1> {
        let json = self.open(Purpose::Message, sealed)?;
        let message: CallLinkMessageV1 = serde_json::from_slice(&json)
            .map_err(|_| ChatError::Content("call message is malformed".into()))?;
        message.validate().map_err(ChatError::Content)?;
        Ok(message)
    }
}

/// The part of a call link's URL after `#`, which the browser never sends
/// to any server.
pub fn call_link_fragment(secret: &str) -> Result<String> {
    let secret = decode_secret(secret)?;
    let mut bytes = Zeroizing::new(vec![FRAGMENT_VERSION]);
    bytes.extend_from_slice(secret.as_slice());
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

/// The secret (standard base64) a call link's fragment carries.
pub fn parse_call_link_fragment(fragment: &str) -> Result<Zeroizing<String>> {
    let invalid = || ChatError::Invalid("this is not a Kutup call link".into());
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(fragment).map_err(|_| invalid())?);
    if bytes.len() != 1 + CALL_LINK_SECRET_BYTES || bytes[0] != FRAGMENT_VERSION {
        return Err(invalid());
    }
    Ok(Zeroizing::new(STANDARD.encode(&bytes[1..])))
}

// --- An account's joined meetings -------------------------------------------

/// A sealed joined-meeting record is padded to this.
const JOINED_PADDED_BYTES: usize = 1024;
/// A sealed joined-meeting record: nonce + padded record + tag.
pub const JOINED_MEETING_SEALED_BYTES: usize = NONCE_BYTES + JOINED_PADDED_BYTES + TAG_BYTES;
const JOINED_AAD: &[u8] = b"kutup/chat/call-link/v1/joined";

/// One stay in a meeting, as the account that joined keeps it for its own
/// devices: sealed under a key from the account master key, so the server
/// that stores it reads none of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinedMeetingV1 {
    /// The part of the link after `#`: what joining again needs.
    pub fragment: String,
    pub title: String,
    pub joined_at_ms: i64,
    /// How long the stay lasted.
    pub seconds: u32,
}

impl JoinedMeetingV1 {
    pub fn validate(&self) -> std::result::Result<(), String> {
        parse_call_link_fragment(&self.fragment)
            .map_err(|_| "a joined meeting carries its link".to_owned())?;
        let title = self.title.as_str();
        if title.is_empty()
            || title.len() > MAX_CALL_TITLE_BYTES
            || title.chars().any(char::is_control)
        {
            return Err("a meeting title is 1 to 200 bytes without control characters".into());
        }
        if self.joined_at_ms <= 0 {
            return Err("a joined meeting's time is positive".into());
        }
        Ok(())
    }
}

fn joined_cipher(master_key: &str) -> Result<XChaCha20Poly1305> {
    let invalid_key = || ChatError::Invalid("account master key is not 32 bytes of base64".into());
    let master = Zeroizing::new(STANDARD.decode(master_key).map_err(|_| invalid_key())?);
    if master.len() != 32 {
        return Err(invalid_key());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), master.as_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    expand(&hkdf, b"joined key", key.as_mut_slice())?;
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| ChatError::Protocol("invalid joined-meetings key".into()))
}

/// Seal one stay for the account's own list:
/// `nonce (24) || XChaCha20-Poly1305(length (u32 BE) || JSON || zeros)`.
pub fn seal_joined_meeting(master_key: &str, entry: &JoinedMeetingV1) -> Result<String> {
    entry.validate().map_err(ChatError::Invalid)?;
    let json = Zeroizing::new(
        serde_json::to_vec(entry).map_err(|error| ChatError::Invalid(error.to_string()))?,
    );
    if 4 + json.len() > JOINED_PADDED_BYTES {
        return Err(ChatError::Invalid("joined meeting is too large".into()));
    }
    let mut padded = Zeroizing::new(Vec::with_capacity(JOINED_PADDED_BYTES));
    padded.extend_from_slice(&(json.len() as u32).to_be_bytes());
    padded.extend_from_slice(&json);
    padded.resize(JOINED_PADDED_BYTES, 0);
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = joined_cipher(master_key)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &padded,
                aad: JOINED_AAD,
            },
        )
        .map_err(|_| ChatError::Protocol("joined meeting sealing failed".into()))?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(sealed))
}

/// A record that does not open was not sealed by this account.
pub fn open_joined_meeting(master_key: &str, sealed: &str) -> Result<JoinedMeetingV1> {
    let malformed = || ChatError::Content("sealed joined meeting is malformed".into());
    let sealed = STANDARD.decode(sealed).map_err(|_| malformed())?;
    if sealed.len() != JOINED_MEETING_SEALED_BYTES {
        return Err(malformed());
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let padded = Zeroizing::new(
        joined_cipher(master_key)?
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: JOINED_AAD,
                },
            )
            .map_err(|_| ChatError::Content("sealed joined meeting does not open".into()))?,
    );
    let length = u32::from_be_bytes(padded[..4].try_into().expect("four bytes")) as usize;
    let body = padded.get(4..4 + length).ok_or_else(malformed)?;
    if padded[4 + length..].iter().any(|byte| *byte != 0) {
        return Err(malformed());
    }
    let entry: JoinedMeetingV1 = serde_json::from_slice(body).map_err(|_| malformed())?;
    entry.validate().map_err(ChatError::Content)?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_joined_meeting_opens_only_for_the_account_that_sealed_it() {
        let master = STANDARD.encode([0x11u8; 32]);
        let entry = JoinedMeetingV1 {
            fragment: call_link_fragment(&STANDARD.encode([0x42u8; 32])).unwrap(),
            // The longest title, at its worst for JSON.
            title: "\"".repeat(MAX_CALL_TITLE_BYTES),
            joined_at_ms: 1_700_000_000_000,
            seconds: 754,
        };
        let sealed = seal_joined_meeting(&master, &entry).unwrap();
        assert_eq!(
            STANDARD.decode(&sealed).unwrap().len(),
            JOINED_MEETING_SEALED_BYTES
        );
        assert_ne!(sealed, seal_joined_meeting(&master, &entry).unwrap());
        assert_eq!(open_joined_meeting(&master, &sealed).unwrap(), entry);
        assert!(open_joined_meeting(&STANDARD.encode([0x12u8; 32]), &sealed).is_err());
        let mut bytes = STANDARD.decode(&sealed).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(open_joined_meeting(&master, &STANDARD.encode(bytes)).is_err());

        let without_link = JoinedMeetingV1 {
            fragment: "nope".into(),
            ..entry.clone()
        };
        assert!(seal_joined_meeting(&master, &without_link).is_err());
        // Not a value the link's own keys open: a different key and purpose.
        let keys = CallLinkKeys::derive(&STANDARD.encode([0x42u8; 32])).unwrap();
        assert!(keys.open_info(&sealed).is_err());
    }

    fn secret(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    #[test]
    fn keys_are_distinct_stable_and_shaped_for_their_use() {
        let keys = CallLinkKeys::derive(&secret(7)).unwrap();
        let again = CallLinkKeys::derive(&secret(7)).unwrap();
        assert_eq!(keys.room_id, again.room_id);
        assert_eq!(keys.access_token, again.access_token);
        assert_eq!(*keys.frame_key, *again.frame_key);
        assert_eq!(keys.room_id.len(), 32);
        assert!(keys
            .room_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_ne!(keys.access_token, *keys.frame_key);
        assert_ne!(keys.access_token, secret(7));
        assert_eq!(
            keys.access_token_hash,
            STANDARD.encode(Sha256::digest(STANDARD.decode(&keys.access_token).unwrap()))
        );
        let other = CallLinkKeys::derive(&secret(8)).unwrap();
        assert_ne!(keys.room_id, other.room_id);
        assert!(CallLinkKeys::derive("short").is_err());
        assert!(CallLinkKeys::derive(&STANDARD.encode([1u8; 31])).is_err());
    }

    /// A fixed vector: these values are what every client derives, so a
    /// change here breaks every link in use.
    #[test]
    fn derivation_matches_the_fixed_vector() {
        let keys = CallLinkKeys::derive(&STANDARD.encode([0x42u8; 32])).unwrap();
        assert_eq!(keys.room_id, "897789aa3fdc09bf4cd7a03a10fb0099");
        assert_eq!(
            keys.access_token,
            "3lQiKaKfg/K7YyaY6jxa6RYIuDY7xX5KuBQ4AacPqs8="
        );
        assert_eq!(
            keys.access_token_hash,
            "3dAQM+/V/Ywv7DZeZN4ZQ1hMREajgnbdbOuNMSHN6mw="
        );
        assert_eq!(
            *keys.frame_key,
            "3YRxjNC0v2ilEivjwmeYHceXGgdym7NBAe+h+j6C+lU="
        );
        let owner =
            owner_call_link_secret(&STANDARD.encode([0x11u8; 32]), &"ab".repeat(16)).unwrap();
        assert_eq!(*owner, "Yi4tqOY3XO7WfskbMqffnc1VxRDgPaCIToP6mL6c5xY=");
        let host =
            owner_call_link_host_token(&STANDARD.encode([0x11u8; 32]), &"ab".repeat(16)).unwrap();
        assert_eq!(*host, "3ULq/fDt4/R/D8oA0NUYdLjT/g1KeYTp1s3K52qYbUs=");
    }

    #[test]
    fn the_host_token_is_the_owners_alone() {
        let master = STANDARD.encode([5u8; 32]);
        let nonce = new_call_link_nonce();
        let token = owner_call_link_host_token(&master, &nonce).unwrap();
        assert_eq!(
            *token,
            *owner_call_link_host_token(&master, &nonce).unwrap()
        );
        assert_eq!(STANDARD.decode(token.as_str()).unwrap().len(), 32);
        // Not the link's secret, nor anything a holder of the link derives.
        let secret = owner_call_link_secret(&master, &nonce).unwrap();
        let keys = CallLinkKeys::derive(&secret).unwrap();
        assert_ne!(*token, *secret);
        assert_ne!(*token, keys.access_token);
        assert_ne!(
            *token,
            *owner_call_link_host_token(&master, &new_call_link_nonce()).unwrap()
        );
        assert_ne!(
            *token,
            *owner_call_link_host_token(&STANDARD.encode([6u8; 32]), &nonce).unwrap()
        );
        assert_eq!(
            call_link_token_hash(&token).unwrap(),
            STANDARD.encode(Sha256::digest(STANDARD.decode(token.as_str()).unwrap()))
        );
        assert_eq!(
            call_link_token_hash(&keys.access_token).unwrap(),
            keys.access_token_hash
        );
        assert!(call_link_token_hash("short").is_err());
        assert!(owner_call_link_host_token(&master, "zz").is_err());
    }

    #[test]
    fn a_fragment_carries_the_secret_and_nothing_else() {
        let fragment = call_link_fragment(&secret(9)).unwrap();
        assert!(!fragment.contains(['+', '/', '=']));
        assert_eq!(*parse_call_link_fragment(&fragment).unwrap(), secret(9));
        assert!(parse_call_link_fragment("AQ").is_err());
        assert!(parse_call_link_fragment("not base64!").is_err());
        // Another version byte is another format.
        let mut other = vec![2u8];
        other.extend_from_slice(&[9u8; 32]);
        assert!(parse_call_link_fragment(&URL_SAFE_NO_PAD.encode(other)).is_err());
    }

    #[test]
    fn names_open_only_with_their_link_and_all_look_alike() {
        let keys = CallLinkKeys::derive(&secret(1)).unwrap();
        let short = keys.seal_name("Ada").unwrap();
        let long = keys.seal_name(&"ğ".repeat(62)).unwrap();
        assert_eq!(
            STANDARD.decode(&short).unwrap().len(),
            CALL_NAME_SEALED_BYTES
        );
        assert_eq!(
            STANDARD.decode(&long).unwrap().len(),
            CALL_NAME_SEALED_BYTES
        );
        assert_eq!(keys.open_name(&short).unwrap(), "Ada");
        assert_eq!(keys.open_name(&long).unwrap(), "ğ".repeat(62));
        assert_eq!(
            keys.open_name(&keys.seal_name("  Ada  ").unwrap()).unwrap(),
            "Ada"
        );
        let other = CallLinkKeys::derive(&secret(2)).unwrap();
        assert!(other.open_name(&short).is_err());
        assert!(keys.seal_name("").is_err());
        assert!(keys.seal_name("   ").is_err());
        assert!(keys
            .seal_name(&"a".repeat(MAX_CALL_NAME_BYTES + 1))
            .is_err());
        assert!(keys.seal_name("line\nbreak").is_err());
        assert!(keys.open_name("AAAA").is_err());
    }

    #[test]
    fn meeting_info_is_one_size_and_opens_only_with_its_link() {
        let keys = CallLinkKeys::derive(&secret(3)).unwrap();
        let plain = CallLinkInfoV1 {
            title: "Team sync".into(),
            starts_at_ms: None,
            duration_minutes: None,
        };
        let scheduled = CallLinkInfoV1 {
            title: "ğ".repeat(100),
            starts_at_ms: Some(1_800_000_000_000),
            duration_minutes: Some(45),
        };
        for info in [&plain, &scheduled] {
            let sealed = keys.seal_info(info).unwrap();
            assert_eq!(
                STANDARD.decode(&sealed).unwrap().len(),
                CALL_INFO_SEALED_BYTES
            );
            assert_eq!(&keys.open_info(&sealed).unwrap(), info);
            assert!(CallLinkKeys::derive(&secret(4))
                .unwrap()
                .open_info(&sealed)
                .is_err());
            // A sealed info is not a name or a message.
            assert!(keys.open_name(&sealed).is_err());
            assert!(keys.open_message(&sealed).is_err());
        }
        let invalid = |info: CallLinkInfoV1| keys.seal_info(&info).is_err();
        assert!(invalid(CallLinkInfoV1 {
            title: "".into(),
            ..plain.clone()
        }));
        assert!(invalid(CallLinkInfoV1 {
            title: " padded ".into(),
            ..plain.clone()
        }));
        assert!(invalid(CallLinkInfoV1 {
            title: "a".repeat(201),
            ..plain.clone()
        }));
        assert!(invalid(CallLinkInfoV1 {
            duration_minutes: Some(30),
            ..plain.clone()
        }));
        assert!(invalid(CallLinkInfoV1 {
            starts_at_ms: Some(0),
            ..plain.clone()
        }));
        assert!(invalid(CallLinkInfoV1 {
            duration_minutes: Some(0),
            ..scheduled.clone()
        }));
        assert!(invalid(CallLinkInfoV1 {
            duration_minutes: Some(1441),
            ..scheduled.clone()
        }));
    }

    #[test]
    fn messages_are_padded_and_open_only_with_their_link() {
        let keys = CallLinkKeys::derive(&secret(5)).unwrap();
        let message = |text: &str| CallLinkMessageV1 {
            id: "0123456789abcdef0123456789abcdef".into(),
            text: text.into(),
            sent_at_ms: 1_800_000_000_000,
        };
        let short = keys.seal_message(&message("hi")).unwrap();
        let long = keys.seal_message(&message(&"ğ".repeat(2000))).unwrap();
        assert_eq!(STANDARD.decode(&short).unwrap().len(), 24 + 256 + 16);
        assert_eq!((STANDARD.decode(&long).unwrap().len() - 40) % 256, 0);
        assert_eq!(keys.open_message(&short).unwrap(), message("hi"));
        assert_eq!(keys.open_message(&long).unwrap().text, "ğ".repeat(2000));
        assert_eq!(
            keys.open_message(&keys.seal_message(&message("two\nlines")).unwrap())
                .unwrap()
                .text,
            "two\nlines"
        );
        assert!(CallLinkKeys::derive(&secret(6))
            .unwrap()
            .open_message(&short)
            .is_err());
        assert!(keys.seal_message(&message("  ")).is_err());
        assert!(keys.seal_message(&message(&"a".repeat(4001))).is_err());
        assert!(keys.seal_message(&message("bell\u{7}")).is_err());
        assert!(keys
            .seal_message(&CallLinkMessageV1 {
                id: "short".into(),
                ..message("hi")
            })
            .is_err());
    }

    #[test]
    fn only_the_owner_can_remake_a_link_from_its_nonce() {
        let master = STANDARD.encode([5u8; 32]);
        let nonce = new_call_link_nonce();
        assert_eq!(nonce.len(), 32);
        let first = owner_call_link_secret(&master, &nonce).unwrap();
        assert_eq!(*first, *owner_call_link_secret(&master, &nonce).unwrap());
        assert_ne!(
            *first,
            *owner_call_link_secret(&master, &new_call_link_nonce()).unwrap()
        );
        assert_ne!(
            *first,
            *owner_call_link_secret(&STANDARD.encode([6u8; 32]), &nonce).unwrap()
        );
        assert!(CallLinkKeys::derive(&first).is_ok());
        assert!(owner_call_link_secret(&master, "zz").is_err());
        assert!(owner_call_link_secret(&master, &"AB".repeat(16)).is_err());
        assert!(owner_call_link_secret("short", &nonce).is_err());
    }
}
