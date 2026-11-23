//! Opening a stored message (`openWithKeys` / `storedMessage` in
//! `mail-core/api.ts`): every message is one RFC 5322 message encrypted as
//! one OpenPGP message (docs/plans/mail.md, "Format"), so what opens is the
//! original, byte-exact, as an IMAP client or an export wants it.
//!
//! An address's mail opens with its primary key, else with an older one
//! (mail from before a rotation). Mail forwarded to the address (its row's
//! `forwardedFrom`) opens with a forwarding key only, and a forwarding key
//! opens nothing else.

use kutup_crypto::mail_key::{decrypt, DecryptedMessage};
use zeroize::Zeroizing;

/// An address's unsealed secret keys (binary OpenPGP).
pub struct OpenKeys {
    pub primary: Zeroizing<Vec<u8>>,
    /// Older keys, newest first.
    pub older: Vec<Zeroizing<Vec<u8>>>,
    pub forwarding: Vec<Zeroizing<Vec<u8>>>,
}

/// The message would not open with any key the address holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no key of the address opens this message")]
pub struct NotOpened;

/// The stored message `bytes` opened with `keys`; `forwarded` when its row
/// says it was forwarded to the address. With `signer`, its signature is
/// checked against that public key (`verified`).
pub fn open_stored(
    keys: &OpenKeys,
    bytes: &[u8],
    forwarded: bool,
    signer: Option<&[u8]>,
) -> Result<DecryptedMessage, NotOpened> {
    if forwarded {
        return keys
            .forwarding
            .iter()
            .find_map(|key| {
                kutup_crypto::mail_forwarding::decrypt_forwarded(key, bytes, signer).ok()
            })
            .ok_or(NotOpened);
    }
    std::iter::once(&keys.primary)
        .chain(&keys.older)
        .find_map(|key| decrypt(key, bytes, signer).ok())
        .ok_or(NotOpened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::mail_key::{encrypt_binary, generate_address_key};

    #[test]
    fn opens_with_the_primary_then_an_older_key_and_byte_exact() {
        let old = generate_address_key("ada@kutup.dev", 1_700_000_000).unwrap();
        let new = generate_address_key("ada@kutup.dev", 1_760_000_000).unwrap();
        let other = generate_address_key("eve@kutup.dev", 1_760_000_000).unwrap();
        let original = b"From: bob@example.org\r\nSubject: =?utf-8?q?Merhaba?=\r\n\r\nhello\r\n";
        let before = encrypt_binary(&old.public_key, original).unwrap();
        let after = encrypt_binary(&new.public_key, original).unwrap();
        let keys = OpenKeys {
            primary: new.secret_key.clone(),
            older: vec![old.secret_key.clone()],
            forwarding: vec![],
        };
        assert_eq!(
            open_stored(&keys, &after, false, None)
                .unwrap()
                .data
                .as_slice(),
            original
        );
        assert_eq!(
            open_stored(&keys, &before, false, None)
                .unwrap()
                .data
                .as_slice(),
            original
        );
        // Another address's key opens nothing; nor does a forwarding-only path.
        let eve = OpenKeys {
            primary: other.secret_key.clone(),
            older: vec![],
            forwarding: vec![],
        };
        assert_eq!(
            open_stored(&eve, &after, false, None).err(),
            Some(NotOpened)
        );
        assert_eq!(
            open_stored(&keys, &after, true, None).err(),
            Some(NotOpened)
        );
    }
}
