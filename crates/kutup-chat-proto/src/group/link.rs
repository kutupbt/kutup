//! A pairwise group's invite link (docs/plans/pairwise-groups.md §4 and §11),
//! as Signal's `GroupInviteLink.contentsV1 {masterKey, inviteLinkPassword}`
//! plus the group's home: what a link holder needs to read the group's join
//! info and to join or ask. It lives only in a URL's fragment, so no server
//! log or `Referer` sees it.
//!
//! The fragment is base64url (no padding) of a fixed binary layout, short
//! enough for a QR code:
//! `version (1) ‖ master key (32) ‖ password (16) ‖ identity sequence (u64 BE)
//! ‖ identity document hash (32) ‖ server (UTF-8, the rest)`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kutup_crypto::chat_group::MASTER_KEY_LEN;

use super::{validate_home, GroupHomePinV1, INVITE_LINK_PASSWORD_LEN};

/// The layout's version.
pub const INVITE_LINK_VERSION: u8 = 1;
const HASH_LEN: usize = 32;
const FIXED_LEN: usize = 1 + MASTER_KEY_LEN + INVITE_LINK_PASSWORD_LEN + 8 + HASH_LEN;
/// A server name is a DNS name.
const MAX_SERVER_LEN: usize = 253;

/// What an invite link carries.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupInviteLinkV1 {
    pub master_key: [u8; MASTER_KEY_LEN],
    pub password: [u8; INVITE_LINK_PASSWORD_LEN],
    pub home: GroupHomePinV1,
}

/// Never prints the master key or the password.
impl std::fmt::Debug for GroupInviteLinkV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupInviteLinkV1")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Drop for GroupInviteLinkV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.master_key);
        zeroize::Zeroize::zeroize(&mut self.password);
    }
}

fn hex_to_bytes(hex: &str) -> Result<[u8; HASH_LEN], String> {
    let mut out = [0u8; HASH_LEN];
    if hex.len() != 2 * HASH_LEN {
        return Err("the identity document hash is 64 hex digits".into());
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| "the identity document hash is hex".to_string())?;
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl GroupInviteLinkV1 {
    /// The URL fragment (without `#`).
    pub fn to_fragment(&self) -> Result<String, String> {
        validate_home(&self.home)?;
        let mut bytes = Vec::with_capacity(FIXED_LEN + self.home.server.len());
        bytes.push(INVITE_LINK_VERSION);
        bytes.extend_from_slice(&self.master_key);
        bytes.extend_from_slice(&self.password);
        bytes.extend_from_slice(&self.home.identity_sequence.to_be_bytes());
        bytes.extend_from_slice(&hex_to_bytes(&self.home.identity_document_hash)?);
        bytes.extend_from_slice(self.home.server.as_bytes());
        let fragment = URL_SAFE_NO_PAD.encode(&bytes);
        zeroize::Zeroize::zeroize(&mut bytes);
        Ok(fragment)
    }

    /// Reads a fragment (with or without a leading `#`): its one canonical
    /// spelling only, a home that validates.
    pub fn from_fragment(fragment: &str) -> Result<Self, String> {
        let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
        let invalid = || "not a group invite link".to_string();
        let mut bytes =
            zeroize::Zeroizing::new(URL_SAFE_NO_PAD.decode(fragment).map_err(|_| invalid())?);
        if URL_SAFE_NO_PAD.encode(&*bytes) != fragment {
            return Err(invalid());
        }
        if bytes.len() <= FIXED_LEN || bytes.len() > FIXED_LEN + MAX_SERVER_LEN {
            return Err(invalid());
        }
        if bytes[0] != INVITE_LINK_VERSION {
            return Err("an invite link of another version".into());
        }
        let mut at = 1;
        let mut take = |len: usize| {
            let part = &bytes[at..at + len];
            at += len;
            part.to_vec()
        };
        let master_key: [u8; MASTER_KEY_LEN] =
            take(MASTER_KEY_LEN).try_into().map_err(|_| invalid())?;
        let password: [u8; INVITE_LINK_PASSWORD_LEN] = take(INVITE_LINK_PASSWORD_LEN)
            .try_into()
            .map_err(|_| invalid())?;
        let identity_sequence = u64::from_be_bytes(take(8).try_into().map_err(|_| invalid())?);
        let identity_document_hash = bytes_to_hex(&take(HASH_LEN));
        let server = String::from_utf8(bytes[at..].to_vec()).map_err(|_| invalid())?;
        bytes.iter_mut().for_each(|byte| *byte = 0);
        let home = GroupHomePinV1 {
            server,
            identity_sequence,
            identity_document_hash,
        };
        validate_home(&home)?;
        Ok(Self {
            master_key,
            password,
            home,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> GroupInviteLinkV1 {
        GroupInviteLinkV1 {
            master_key: [7u8; MASTER_KEY_LEN],
            password: [9u8; INVITE_LINK_PASSWORD_LEN],
            home: GroupHomePinV1 {
                server: "home.example".into(),
                identity_sequence: 3,
                identity_document_hash: "0f".repeat(32),
            },
        }
    }

    #[test]
    fn a_link_round_trips_and_stays_short() {
        let fragment = link().to_fragment().unwrap();
        // Room for a QR code, with a long server name too.
        assert!(fragment.len() < 160, "{}", fragment.len());
        let read = GroupInviteLinkV1::from_fragment(&format!("#{fragment}")).unwrap();
        assert_eq!(read, link());
    }

    #[test]
    fn only_the_canonical_spelling_of_a_valid_link_reads() {
        let fragment = link().to_fragment().unwrap();
        assert!(GroupInviteLinkV1::from_fragment(&format!("{fragment}=")).is_err());
        assert!(GroupInviteLinkV1::from_fragment(&fragment[..fragment.len() - 4]).is_err());
        assert!(GroupInviteLinkV1::from_fragment("not a link").is_err());
        let mut other = link();
        other.home.server = "Home.Example".into();
        assert!(other.to_fragment().is_err());
        // Another version.
        let mut bytes = URL_SAFE_NO_PAD.decode(&fragment).unwrap();
        bytes[0] = 2;
        assert!(GroupInviteLinkV1::from_fragment(&URL_SAFE_NO_PAD.encode(&bytes)).is_err());
        // A server that isn't one (uppercase, as the bytes say).
        let mut upper = URL_SAFE_NO_PAD.decode(&fragment).unwrap();
        let last = upper.len() - 1;
        upper[last] = b'E';
        assert!(GroupInviteLinkV1::from_fragment(&URL_SAFE_NO_PAD.encode(&upper)).is_err());
    }

    #[test]
    fn it_never_prints_its_secrets() {
        let printed = format!("{:?}", link());
        assert!(!printed.contains("[7, 7"));
        assert!(printed.contains("home.example"));
    }
}
