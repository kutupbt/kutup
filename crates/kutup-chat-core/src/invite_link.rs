//! Group invite link keys and sealing (docs/chat-invite-links.md).
//!
//! Everything a link's host stores is derived from, or sealed under, the
//! link's 32-byte secret, so the host keeps a mailbox it cannot read:
//!
//! - `linkId`: what the host files the mailbox under;
//! - `manageToken`: what members present to change or read it (the host
//!   keeps only its SHA-256);
//! - a sealing key for the preview and the requests to join.
//!
//! The three come from HKDF-SHA256 with distinct labels. A sealed value is
//! `nonce(24) || XChaCha20-Poly1305(padded plaintext)`, bound to its purpose
//! and link id, and padded so its size says little about its content.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};
use kutup_chat_proto::{
    InviteJoinRequestV1, InviteLinkPreviewV1, MlsGroupInviteLinkV1, INVITE_LINK_TOKEN_BYTES,
    MAX_INVITE_PREVIEW_SEALED_BYTES, MAX_INVITE_REQUEST_SEALED_BYTES,
};

const SALT: &[u8] = b"kutup/chat/invite-link/v1";
const FRAGMENT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const PREVIEW_PADDING: usize = 4096;
const REQUEST_PADDING: usize = 256;

/// What a link's secret gives its holder.
pub struct InviteLinkKeys {
    pub link_id: String,
    pub manage_token: String,
    seal_key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy)]
enum Purpose {
    Preview,
    Request,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Preview => b"preview",
            Self::Request => b"request",
        }
    }

    fn padding(self) -> usize {
        match self {
            Self::Preview => PREVIEW_PADDING,
            Self::Request => REQUEST_PADDING,
        }
    }

    fn max_sealed(self) -> usize {
        match self {
            Self::Preview => MAX_INVITE_PREVIEW_SEALED_BYTES,
            Self::Request => MAX_INVITE_REQUEST_SEALED_BYTES,
        }
    }
}

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A fresh link secret, as the group information carries it.
pub fn new_invite_link_secret() -> String {
    STANDARD.encode(random_32())
}

/// A fresh token a requester keeps to read or cancel its request.
pub fn new_invite_status_token() -> String {
    STANDARD.encode(random_32())
}

impl InviteLinkKeys {
    pub fn derive(secret: &[u8; 32]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), secret);
        let expand = |label: &[u8]| -> Result<Zeroizing<[u8; 32]>> {
            let mut output = Zeroizing::new([0u8; 32]);
            hkdf.expand(label, output.as_mut_slice())
                .map_err(|_| ChatError::Protocol("invite link key derivation failed".into()))?;
            Ok(output)
        };
        Ok(Self {
            link_id: STANDARD.encode(*expand(b"link id")?),
            manage_token: STANDARD.encode(*expand(b"manage token")?),
            seal_key: expand(b"seal key")?,
        })
    }

    pub fn for_link(link: &MlsGroupInviteLinkV1) -> Result<Self> {
        link.validate().map_err(ChatError::Invalid)?;
        Self::derive(&link.secret_bytes().map_err(ChatError::Invalid)?)
    }

    fn aad(&self, purpose: Purpose) -> Vec<u8> {
        let mut aad = SALT.to_vec();
        aad.push(b'/');
        aad.extend_from_slice(purpose.label());
        aad.push(0);
        aad.extend_from_slice(self.link_id.as_bytes());
        aad
    }

    fn seal(&self, purpose: Purpose, plaintext: &[u8]) -> Result<String> {
        let length = u32::try_from(plaintext.len())
            .map_err(|_| ChatError::Invalid("invite link value is too large".into()))?;
        let padded_length = (4 + plaintext.len()).div_ceil(purpose.padding()) * purpose.padding();
        if NONCE_BYTES + padded_length + TAG_BYTES > purpose.max_sealed() {
            return Err(ChatError::Invalid("invite link value is too large".into()));
        }
        let mut padded = Zeroizing::new(Vec::with_capacity(padded_length));
        padded.extend_from_slice(&length.to_be_bytes());
        padded.extend_from_slice(plaintext);
        padded.resize(padded_length, 0);
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(self.seal_key.as_slice())
            .map_err(|_| ChatError::Protocol("invalid invite link key".into()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &padded,
                    aad: &self.aad(purpose),
                },
            )
            .map_err(|_| ChatError::Protocol("invite link sealing failed".into()))?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(sealed))
    }

    fn open(&self, purpose: Purpose, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
        let sealed = STANDARD
            .decode(sealed)
            .map_err(|_| ChatError::Content("sealed invite link value is not base64".into()))?;
        if sealed.len() < NONCE_BYTES + TAG_BYTES + 4 || sealed.len() > purpose.max_sealed() {
            return Err(ChatError::Content(
                "sealed invite link value has an invalid size".into(),
            ));
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let cipher = XChaCha20Poly1305::new_from_slice(self.seal_key.as_slice())
            .map_err(|_| ChatError::Protocol("invalid invite link key".into()))?;
        let padded = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &self.aad(purpose),
                    },
                )
                .map_err(|_| ChatError::Content("sealed invite link value does not open".into()))?,
        );
        let length = u32::from_be_bytes(padded[..4].try_into().expect("four bytes")) as usize;
        let body = padded
            .get(4..4 + length)
            .ok_or_else(|| ChatError::Content("sealed invite link value is malformed".into()))?;
        if padded[4 + length..].iter().any(|byte| *byte != 0) {
            return Err(ChatError::Content(
                "sealed invite link value is malformed".into(),
            ));
        }
        Ok(Zeroizing::new(body.to_vec()))
    }

    pub fn seal_preview(&self, preview: &InviteLinkPreviewV1) -> Result<String> {
        preview.validate().map_err(ChatError::Invalid)?;
        let json = Zeroizing::new(
            serde_json::to_vec(preview).map_err(|error| ChatError::Invalid(error.to_string()))?,
        );
        self.seal(Purpose::Preview, &json)
    }

    pub fn open_preview(&self, sealed: &str) -> Result<InviteLinkPreviewV1> {
        let json = self.open(Purpose::Preview, sealed)?;
        let preview: InviteLinkPreviewV1 = serde_json::from_slice(&json)
            .map_err(|_| ChatError::Content("invite link preview is malformed".into()))?;
        preview.validate().map_err(ChatError::Content)?;
        Ok(preview)
    }

    pub fn seal_request(&self, request: &InviteJoinRequestV1) -> Result<String> {
        request.validate().map_err(ChatError::Invalid)?;
        let json =
            serde_json::to_vec(request).map_err(|error| ChatError::Invalid(error.to_string()))?;
        self.seal(Purpose::Request, &json)
    }

    pub fn open_request(&self, sealed: &str) -> Result<InviteJoinRequestV1> {
        let json = self.open(Purpose::Request, sealed)?;
        let request: InviteJoinRequestV1 = serde_json::from_slice(&json)
            .map_err(|_| ChatError::Content("invite request is malformed".into()))?;
        request.validate().map_err(ChatError::Content)?;
        Ok(request)
    }
}

/// The part of a link URL after `#`: the secret and the host, which the
/// browser never sends to any server.
pub fn invite_link_fragment(link: &MlsGroupInviteLinkV1) -> Result<String> {
    link.validate().map_err(ChatError::Invalid)?;
    let mut bytes = vec![FRAGMENT_VERSION];
    bytes.extend_from_slice(&link.secret_bytes().map_err(ChatError::Invalid)?);
    bytes.extend_from_slice(link.host.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The secret (standard base64) and host a link fragment names.
pub fn parse_invite_link_fragment(fragment: &str) -> Result<(String, String)> {
    let invalid = || ChatError::Invalid("this is not a Kutup group link".into());
    let bytes = URL_SAFE_NO_PAD.decode(fragment).map_err(|_| invalid())?;
    if bytes.len() <= 1 + INVITE_LINK_TOKEN_BYTES || bytes[0] != FRAGMENT_VERSION {
        return Err(invalid());
    }
    let secret = STANDARD.encode(&bytes[1..1 + INVITE_LINK_TOKEN_BYTES]);
    let host = std::str::from_utf8(&bytes[1 + INVITE_LINK_TOKEN_BYTES..])
        .map_err(|_| invalid())?
        .to_owned();
    MlsGroupInviteLinkV1 {
        secret: secret.clone(),
        host: host.clone(),
        approval_required: false,
    }
    .validate()
    .map_err(|_| invalid())?;
    Ok((secret, host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn link() -> MlsGroupInviteLinkV1 {
        MlsGroupInviteLinkV1 {
            secret: new_invite_link_secret(),
            host: "a.test".into(),
            approval_required: true,
        }
    }

    fn preview() -> InviteLinkPreviewV1 {
        InviteLinkPreviewV1 {
            conversation_id: Uuid::from_u128(7),
            name: "Hikers".into(),
            description: "Saturday walks".into(),
            avatar: None,
            member_count: 3,
            approval_required: true,
        }
    }

    #[test]
    fn a_fragment_names_the_secret_and_host() {
        let link = link();
        let fragment = invite_link_fragment(&link).unwrap();
        assert!(!fragment.contains(['+', '/', '=']));
        assert_eq!(
            parse_invite_link_fragment(&fragment).unwrap(),
            (link.secret.clone(), link.host.clone())
        );
        assert!(parse_invite_link_fragment("AQ").is_err());
        assert!(parse_invite_link_fragment("not base64!").is_err());
    }

    #[test]
    fn keys_are_distinct_and_stable() {
        let link = link();
        let keys = InviteLinkKeys::for_link(&link).unwrap();
        let again = InviteLinkKeys::for_link(&link).unwrap();
        assert_eq!(keys.link_id, again.link_id);
        assert_eq!(keys.manage_token, again.manage_token);
        assert_ne!(keys.link_id, keys.manage_token);
        assert_ne!(keys.link_id, link.secret);
    }

    #[test]
    fn sealed_values_open_only_with_their_link_and_purpose() {
        let keys = InviteLinkKeys::for_link(&link()).unwrap();
        let sealed = keys.seal_preview(&preview()).unwrap();
        assert_eq!(keys.open_preview(&sealed).unwrap(), preview());
        assert_eq!(STANDARD.decode(&sealed).unwrap().len(), 24 + 4096 + 16);
        assert!(keys.open_request(&sealed).is_err());
        let other = InviteLinkKeys::for_link(&link()).unwrap();
        assert!(other.open_preview(&sealed).is_err());

        let request = InviteJoinRequestV1 {
            requester: "bob@b.test".parse().unwrap(),
            created_at_ms: 5,
        };
        let sealed = keys.seal_request(&request).unwrap();
        assert_eq!(STANDARD.decode(&sealed).unwrap().len(), 24 + 256 + 16);
        assert_eq!(keys.open_request(&sealed).unwrap(), request);
    }

    #[test]
    fn the_largest_preview_fits() {
        let keys = InviteLinkKeys::for_link(&link()).unwrap();
        let largest = InviteLinkPreviewV1 {
            name: "ğ".repeat(32),
            description: "🌲".repeat(480),
            avatar: Some(kutup_chat_proto::MlsGroupAvatarV1 {
                content_type: "image/webp".into(),
                data: STANDARD.encode(vec![1u8; 48 * 1024]),
            }),
            ..preview()
        };
        let sealed = keys.seal_preview(&largest).unwrap();
        assert_eq!(keys.open_preview(&sealed).unwrap(), largest);
    }
}
