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

//!
//! The formats are kutup-crypto's (`kutup_crypto::chat_call_link`,
//! docs/plans/chat-crypto-move.md); this module keeps Chat's API and errors.

use kutup_crypto::chat_call_link as crypto;
use kutup_crypto::error::CryptoError;
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};

pub use kutup_crypto::chat_call_link::{
    CallLinkInfoV1, CallLinkMessageV1, JoinedMeetingV1, CALL_INFO_SEALED_BYTES,
    CALL_NAME_SEALED_BYTES, JOINED_MEETING_SEALED_BYTES, MAX_CALL_MESSAGE_BYTES,
    MAX_CALL_NAME_BYTES, MAX_CALL_TITLE_BYTES,
};

fn message(error: CryptoError) -> String {
    match error {
        CryptoError::InvalidInput(message) => message,
        other => other.to_string(),
    }
}

/// What the caller gave is not usable.
fn invalid(error: CryptoError) -> ChatError {
    ChatError::Invalid(message(error))
}

/// What was received does not open (or is not well formed).
fn content(error: CryptoError) -> ChatError {
    ChatError::Content(message(error))
}

/// A fresh nonce for a new link: public, stored by the host with the link.
pub fn new_call_link_nonce() -> String {
    crypto::new_call_link_nonce()
}

/// The owner's call-link root (a stored root, standard base64 of 32 bytes).
fn call_link_root(base64: &str) -> Result<kutup_crypto::account_roots::CallLinkRoot> {
    use base64::Engine as _;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|_| ChatError::Invalid("the call-link root is not base64".into()))?,
    );
    kutup_crypto::account_roots::CallLinkRoot::from_slice(&bytes).map_err(invalid)
}

/// The secret of the link its owner made with `nonce` (32 lowercase hex
/// characters), from the owner's call-link root (standard base64, 32 bytes;
/// docs/plans/identity-root.md). Only the owner can compute it, on any of
/// their devices.
pub fn owner_call_link_secret(call_link_root_b64: &str, nonce: &str) -> Result<Zeroizing<String>> {
    crypto::owner_call_link_secret(&call_link_root(call_link_root_b64)?, nonce).map_err(invalid)
}

/// The owner's proof of being a meeting's host (standard base64, 32 bytes),
/// from the owner's call-link root and the meeting's nonce. Unlike the link's
/// secret, nobody the link is shared with can compute it. The host stores
/// only its SHA-256: presenting the token lets the owner into a meeting
/// with a waiting room, and lets them admit the people waiting.
pub fn owner_call_link_host_token(
    call_link_root_b64: &str,
    nonce: &str,
) -> Result<Zeroizing<String>> {
    crypto::owner_call_link_host_token(&call_link_root(call_link_root_b64)?, nonce).map_err(invalid)
}

/// What the host stores of a token: its SHA-256 (standard base64).
pub fn call_link_token_hash(token: &str) -> Result<String> {
    crypto::call_link_token_hash(token).map_err(invalid)
}

/// What a call link's secret gives its holder: `room_id`, `access_token`,
/// `access_token_hash` and `frame_key`, and the sealing of names, info and
/// messages.
pub struct CallLinkKeys(crypto::CallLinkKeys);

impl std::ops::Deref for CallLinkKeys {
    type Target = crypto::CallLinkKeys;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CallLinkKeys {
    /// `secret` is 32 bytes of standard base64.
    pub fn derive(secret: &str) -> Result<Self> {
        crypto::CallLinkKeys::derive(secret)
            .map(Self)
            .map_err(invalid)
    }

    /// Seal the name a participant chose, for the others in the call.
    pub fn seal_name(&self, name: &str) -> Result<String> {
        self.0.seal_name(name).map_err(invalid)
    }

    /// The name a participant sealed.
    pub fn open_name(&self, sealed: &str) -> Result<String> {
        self.0.open_name(sealed).map_err(content)
    }

    /// Seal what the meeting is called and when it is, for the host to keep.
    pub fn seal_info(&self, info: &CallLinkInfoV1) -> Result<String> {
        self.0.seal_info(info).map_err(invalid)
    }

    pub fn open_info(&self, sealed: &str) -> Result<CallLinkInfoV1> {
        self.0.open_info(sealed).map_err(content)
    }

    /// Seal a message written during the call, for the others in it.
    pub fn seal_message(&self, message: &CallLinkMessageV1) -> Result<String> {
        self.0.seal_message(message).map_err(invalid)
    }

    pub fn open_message(&self, sealed: &str) -> Result<CallLinkMessageV1> {
        self.0.open_message(sealed).map_err(content)
    }
}

/// The part of a call link's URL after `#`, which the browser never sends
/// to any server.
pub fn call_link_fragment(secret: &str) -> Result<String> {
    crypto::call_link_fragment(secret).map_err(invalid)
}

/// The secret (standard base64) a call link's fragment carries.
pub fn parse_call_link_fragment(fragment: &str) -> Result<Zeroizing<String>> {
    crypto::parse_call_link_fragment(fragment).map_err(invalid)
}

/// Seal one stay for the account's own list, as the row `id`.
pub fn seal_joined_meeting(
    master_key: &str,
    generation: kutup_crypto::account_record::MasterKeyGeneration,
    binding: &str,
    id: &str,
    entry: &JoinedMeetingV1,
) -> Result<String> {
    crypto::seal_joined_meeting(master_key, generation, binding, id, entry).map_err(invalid)
}

/// A record that does not open was not sealed by this account for row `id`.
/// An unusable master key is the caller's.
pub fn open_joined_meeting(
    master_key: &str,
    binding: &str,
    id: &str,
    sealed: &str,
) -> Result<JoinedMeetingV1> {
    crypto::open_joined_meeting(master_key, binding, id, sealed).map_err(|error| match error {
        CryptoError::InvalidInput(message) if message.starts_with("account master key") => {
            ChatError::Invalid(message)
        }
        other => content(other),
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const JOINED_ID: &str = "00112233445566778899aabbccddeeff";
    const FIRST: kutup_crypto::account_record::MasterKeyGeneration =
        kutup_crypto::account_record::MasterKeyGeneration::FIRST;

    /// The call-link formats' canonical vectors
    /// (`crates/kutup-crypto/tests/vectors/call-link-v1.json`), made from this
    /// code before it moves into kutup-crypto (docs/plans/chat-crypto-move.md,
    /// slice 2): the owner's secret and host token, every key a secret gives,
    /// the fragment, and a sealed name, info, message and joined meeting with
    /// what each opens to. Their nonces are inside them, so the moved code
    /// must reseal each byte for byte. `KUTUP_WRITE_CHAT_VECTORS=1` writes the
    /// file; otherwise this code must open what it holds.
    #[test]
    fn call_link_formats_match_the_canonical_vectors() {
        use serde_json::json;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kutup-crypto/tests/vectors/call-link-v1.json"
        );
        if std::env::var_os("KUTUP_WRITE_CHAT_VECTORS").is_some() {
            let master = STANDARD.encode([0x21u8; 32]);
            let nonce = "0123456789abcdef0123456789abcdef";
            let secret = owner_call_link_secret(&master, nonce).unwrap();
            let host = owner_call_link_host_token(&master, nonce).unwrap();
            let keys = CallLinkKeys::derive(&secret).unwrap();
            let info = CallLinkInfoV1 {
                title: "Weekly sync".into(),
                starts_at_ms: Some(1_700_000_000_000),
                duration_minutes: Some(45),
            };
            let message = CallLinkMessageV1 {
                id: "00112233445566778899aabbccddeeff".into(),
                text: "Hello\nall".into(),
                sent_at_ms: 1_700_000_001_000,
            };
            let fragment = call_link_fragment(&secret).unwrap();
            let joined = JoinedMeetingV1 {
                fragment: fragment.clone(),
                title: "Weekly sync".into(),
                joined_at_ms: 1_700_000_002_000,
                seconds: 754,
            };
            let vectors = json!({
                "masterKey": master,
                "nonce": nonce,
                "ownerSecret": secret.as_str(),
                "hostToken": host.as_str(),
                "hostTokenHash": call_link_token_hash(&host).unwrap(),
                "roomId": keys.room_id,
                "accessToken": keys.access_token,
                "accessTokenHash": keys.access_token_hash,
                "frameKey": keys.frame_key.as_str(),
                "fragment": fragment,
                "name": { "plaintext": "Ayşe", "sealed": keys.seal_name("Ayşe").unwrap() },
                "info": { "plaintext": info, "sealed": keys.seal_info(&info).unwrap() },
                "message": { "plaintext": message, "sealed": keys.seal_message(&message).unwrap() },
                "joined": {
                    "binding": BINDING,
                    "id": JOINED_ID,
                    "plaintext": joined,
                    "sealed": seal_joined_meeting(&master, FIRST, BINDING, JOINED_ID, &joined).unwrap(),
                },
            });
            std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let text = |key: &str| v[key].as_str().unwrap().to_owned();
        let secret = owner_call_link_secret(&text("masterKey"), &text("nonce")).unwrap();
        assert_eq!(secret.as_str(), text("ownerSecret"));
        let host = owner_call_link_host_token(&text("masterKey"), &text("nonce")).unwrap();
        assert_eq!(host.as_str(), text("hostToken"));
        assert_eq!(call_link_token_hash(&host).unwrap(), text("hostTokenHash"));
        let keys = CallLinkKeys::derive(&secret).unwrap();
        assert_eq!(keys.room_id, text("roomId"));
        assert_eq!(keys.access_token, text("accessToken"));
        assert_eq!(keys.access_token_hash, text("accessTokenHash"));
        assert_eq!(keys.frame_key.as_str(), text("frameKey"));
        assert_eq!(call_link_fragment(&secret).unwrap(), text("fragment"));
        let sealed = |key: &str| v[key]["sealed"].as_str().unwrap().to_owned();
        assert_eq!(
            keys.open_name(&sealed("name")).unwrap(),
            v["name"]["plaintext"]
        );
        assert_eq!(
            serde_json::to_value(keys.open_info(&sealed("info")).unwrap()).unwrap(),
            v["info"]["plaintext"]
        );
        assert_eq!(
            serde_json::to_value(keys.open_message(&sealed("message")).unwrap()).unwrap(),
            v["message"]["plaintext"]
        );
        assert_eq!(
            serde_json::to_value(
                open_joined_meeting(&text("masterKey"), BINDING, JOINED_ID, &sealed("joined"))
                    .unwrap()
            )
            .unwrap(),
            v["joined"]["plaintext"]
        );
    }

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
        let sealed = seal_joined_meeting(&master, FIRST, BINDING, JOINED_ID, &entry).unwrap();
        assert_eq!(
            STANDARD.decode(&sealed).unwrap().len(),
            JOINED_MEETING_SEALED_BYTES
        );
        assert_ne!(
            sealed,
            seal_joined_meeting(&master, FIRST, BINDING, JOINED_ID, &entry).unwrap()
        );
        assert_eq!(
            open_joined_meeting(&master, BINDING, JOINED_ID, &sealed).unwrap(),
            entry
        );
        assert!(
            open_joined_meeting(&STANDARD.encode([0x12u8; 32]), BINDING, JOINED_ID, &sealed)
                .is_err()
        );
        // Another row's id, or another account: refused.
        assert!(open_joined_meeting(&master, BINDING, &"ab".repeat(16), &sealed).is_err());
        assert!(open_joined_meeting(
            &master,
            "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d",
            JOINED_ID,
            &sealed
        )
        .is_err());
        let mut bytes = STANDARD.decode(&sealed).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(open_joined_meeting(&master, BINDING, JOINED_ID, &STANDARD.encode(bytes)).is_err());

        let without_link = JoinedMeetingV1 {
            fragment: "nope".into(),
            ..entry.clone()
        };
        assert!(seal_joined_meeting(&master, FIRST, BINDING, JOINED_ID, &without_link).is_err());
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
