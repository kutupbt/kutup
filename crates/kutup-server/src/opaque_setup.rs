//! The server's OPAQUE secrets (docs/plans/opaque.md §5).
//!
//! Each `ServerSetup` (OPRF seed, server keypair) is kept in
//! `opaque_server_setups`, sealed under a key that is neither in the database
//! nor in its backups: `OPAQUE_SETUP_KEYS`, a comma list of
//! `id:base64(32 bytes)`. The highest id is the current one. A database dump
//! alone therefore gives no offline attack on passwords.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

/// The ids `OPAQUE_SETUP_KEYS` may use (`opaque_server_key_id` is a
/// smallint; 0 is never an id).
const MAX_KEY_ID: u16 = i16::MAX as u16;

/// The setup keys, by id. Never printed: `Debug` shows the ids only.
#[derive(Clone, Default)]
pub struct OpaqueSetupKeys(Vec<(u16, Zeroizing<[u8; 32]>)>);

impl std::fmt::Debug for OpaqueSetupKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("OpaqueSetupKeys")
            .field(&self.ids().collect::<Vec<_>>())
            .finish()
    }
}

impl OpaqueSetupKeys {
    /// Parses `id:base64,id:base64,…` (spaces around entries allowed). Every
    /// problem is named, never the key itself.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut keys: Vec<(u16, Zeroizing<[u8; 32]>)> = Vec::new();
        for (index, entry) in value.split(',').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let place = index + 1;
            let Some((id, key)) = entry.split_once(':') else {
                return Err(format!("entry {place} is not id:base64"));
            };
            let id: u16 = match id.trim().parse() {
                Ok(id) if (1..=MAX_KEY_ID).contains(&id) => id,
                _ => {
                    return Err(format!(
                        "entry {place}: the id must be a whole number from 1 to {MAX_KEY_ID}"
                    ))
                }
            };
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(key.trim())
                    .map_err(|_| format!("key {id} is not base64"))?,
            );
            // Canonical base64 only: one key, one spelling.
            if STANDARD.encode(bytes.as_slice()) != key.trim() {
                return Err(format!("key {id} is not canonical base64"));
            }
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("key {id} must be exactly 32 bytes"))?;
            if keys.iter().any(|(other, _)| *other == id) {
                return Err(format!("key id {id} appears twice"));
            }
            keys.push((id, Zeroizing::new(key)));
        }
        if keys.is_empty() {
            return Err("no key given".into());
        }
        keys.sort_by_key(|(id, _)| *id);
        Ok(Self(keys))
    }

    /// The ids, lowest first.
    pub fn ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().map(|(id, _)| *id)
    }

    /// The current key: the highest id.
    pub fn current(&self) -> Option<(u16, &[u8; 32])> {
        self.0.last().map(|(id, key)| (*id, &**key))
    }

    /// The key with this id.
    pub fn get(&self, id: u16) -> Option<&[u8; 32]> {
        self.0
            .iter()
            .find(|(other, _)| *other == id)
            .map(|(_, key)| &**key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    #[test]
    fn keys_parse_and_the_highest_is_current() {
        let keys = OpaqueSetupKeys::parse(&format!(" 2:{} , 1:{} ", key(2), key(1))).unwrap();
        assert_eq!(keys.ids().collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(keys.current().unwrap(), (2, &[2u8; 32]));
        assert_eq!(keys.get(1), Some(&[1u8; 32]));
        assert_eq!(keys.get(3), None);
    }

    #[test]
    fn bad_keys_are_refused_without_printing_them() {
        let secret = key(7);
        let short = STANDARD.encode([7u8; 31]);
        let cases = [
            String::new(),
            " , ".into(),
            secret.clone(),
            format!("x:{secret}"),
            format!("0:{secret}"),
            format!("40000:{secret}"),
            format!("1:{short}"),
            "1:not base64!".into(),
            format!("1:{}", secret.trim_end_matches('=')),
            format!("1:{secret},1:{}", key(8)),
        ];
        for case in cases {
            let error = OpaqueSetupKeys::parse(&case).unwrap_err();
            assert!(!error.contains(&secret), "{error}");
        }
        let keys = OpaqueSetupKeys::parse(&format!("1:{secret}")).unwrap();
        assert!(!format!("{keys:?}").contains(&secret));
    }
}
