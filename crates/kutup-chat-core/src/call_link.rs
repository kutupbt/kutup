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
//!   sees participants only as opaque identities.
//!
//! The four come from HKDF-SHA256 with distinct labels. The owner's own
//! secret for a link is derived from the account master key and a public
//! random nonce the host stores, so the owner's other devices can show the
//! same link again without the host ever holding the secret.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore as _};
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
        Ok(Self {
            room_id: hex::encode(room),
            access_token: STANDARD.encode(access.as_slice()),
            access_token_hash: STANDARD.encode(Sha256::digest(access.as_slice())),
            frame_key: Zeroizing::new(STANDARD.encode(frame.as_slice())),
            name_key,
        })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = SALT.to_vec();
        aad.extend_from_slice(b"/name\0");
        aad.extend_from_slice(self.room_id.as_bytes());
        aad
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.name_key.as_slice())
            .map_err(|_| ChatError::Protocol("invalid call link key".into()))
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
        let mut padded = Zeroizing::new(Vec::with_capacity(NAME_PADDED_BYTES));
        padded.extend_from_slice(&(name.len() as u32).to_be_bytes());
        padded.extend_from_slice(name.as_bytes());
        padded.resize(NAME_PADDED_BYTES, 0);
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher()?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &padded,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| ChatError::Protocol("call name sealing failed".into()))?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(sealed))
    }

    /// The name a participant sealed. A label that does not open was not
    /// made by a holder of this link.
    pub fn open_name(&self, sealed: &str) -> Result<String> {
        let malformed = || ChatError::Content("sealed call name is malformed".into());
        let sealed = STANDARD.decode(sealed).map_err(|_| malformed())?;
        if sealed.len() != CALL_NAME_SEALED_BYTES {
            return Err(malformed());
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let padded = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &self.aad(),
                    },
                )
                .map_err(|_| ChatError::Content("sealed call name does not open".into()))?,
        );
        let length = u32::from_be_bytes(padded[..4].try_into().expect("four bytes")) as usize;
        let body = padded.get(4..4 + length).ok_or_else(malformed)?;
        if length == 0 || padded[4 + length..].iter().any(|byte| *byte != 0) {
            return Err(malformed());
        }
        let name = std::str::from_utf8(body).map_err(|_| malformed())?;
        if name.chars().any(char::is_control) {
            return Err(malformed());
        }
        Ok(name.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

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
