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

/// The server's OPAQUE setups, opened at startup and kept in memory.
pub struct OpaqueServer {
    setups: std::collections::BTreeMap<u16, kutup_crypto::opaque::ServerSecrets>,
    keys: OpaqueSetupKeys,
}

impl OpaqueServer {
    /// Opens every stored setup whose key is configured, and makes the
    /// current key's setup if it has none (first start, or a new key). A
    /// stored setup that does not open under its key stops the server: that
    /// is a wrong key, and going on would lock everyone out. Setups older
    /// than the current one that no account uses any more are dropped.
    pub async fn load(pool: &sqlx::PgPool, keys: &OpaqueSetupKeys) -> Result<Self, String> {
        let (current, current_key) = keys.current().ok_or("OPAQUE_SETUP_KEYS has no key")?;
        let rows: Vec<(i16, Vec<u8>)> =
            sqlx::query_as("SELECT key_id, sealed_setup FROM opaque_server_setups")
                .fetch_all(pool)
                .await
                .map_err(|e| format!("read the OPAQUE setups: {e}"))?;
        let mut setups = std::collections::BTreeMap::new();
        for (id, sealed) in rows {
            let id = u16::try_from(id).map_err(|_| "a stored OPAQUE setup has a bad id")?;
            let Some(key) = keys.get(id) else {
                continue;
            };
            let secrets =
                kutup_crypto::opaque::open_server_setup(&sealed, key, id).map_err(|_| {
                    format!(
                    "the stored OPAQUE setup {id} does not open under OPAQUE_SETUP_KEYS key {id}: \
                     the key is wrong (restore the right one; changing it locks every account out)"
                )
                })?;
            setups.insert(id, secrets);
        }
        if !setups.contains_key(&current) {
            let secrets = kutup_crypto::opaque::ServerSecrets::generate();
            let sealed = kutup_crypto::opaque::seal_server_setup(&secrets, current_key, current)
                .map_err(|e| format!("seal the OPAQUE setup: {e}"))?;
            // Another instance starting at once may win: then use its setup.
            sqlx::query(
                "INSERT INTO opaque_server_setups (key_id, sealed_setup) VALUES ($1, $2)
                 ON CONFLICT (key_id) DO NOTHING",
            )
            .bind(current as i16)
            .bind(&sealed)
            .execute(pool)
            .await
            .map_err(|e| format!("store the OPAQUE setup: {e}"))?;
            let stored: Vec<u8> = sqlx::query_scalar(
                "SELECT sealed_setup FROM opaque_server_setups WHERE key_id = $1",
            )
            .bind(current as i16)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("read the OPAQUE setup: {e}"))?;
            let secrets = kutup_crypto::opaque::open_server_setup(&stored, current_key, current)
                .map_err(|_| {
                    format!("the stored OPAQUE setup {current} does not open under its key")
                })?;
            tracing::info!(key_id = current, "made a new OPAQUE setup");
            setups.insert(current, secrets);
        }
        // Older setups no account is registered with any more go.
        sqlx::query(
            "DELETE FROM opaque_server_setups s WHERE s.key_id < $1
             AND NOT EXISTS (SELECT 1 FROM users u WHERE u.opaque_server_key_id = s.key_id)",
        )
        .bind(current as i16)
        .execute(pool)
        .await
        .map_err(|e| format!("drop retired OPAQUE setups: {e}"))?;
        let stranded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE opaque_server_key_id IS NOT NULL
             AND NOT (opaque_server_key_id = ANY($1))",
        )
        .bind(setups.keys().map(|id| *id as i16).collect::<Vec<_>>())
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count accounts without a setup: {e}"))?;
        if stranded > 0 {
            tracing::warn!(
                accounts = stranded,
                "accounts are registered with an OPAQUE setup whose key is not in OPAQUE_SETUP_KEYS: \
                 they cannot sign in (only with their recovery phrase) until the key is restored"
            );
        }
        Ok(Self {
            setups,
            keys: keys.clone(),
        })
    }

    /// The setup new registrations use, and its id.
    pub fn current(&self) -> (u16, &kutup_crypto::opaque::ServerSecrets) {
        let (id, secrets) = self
            .setups
            .last_key_value()
            .expect("load makes the current setup");
        (*id, secrets)
    }

    /// The setup with this id, if its key is configured.
    pub fn get(&self, id: u16) -> Option<&kutup_crypto::opaque::ServerSecrets> {
        self.setups.get(&id)
    }

    /// The key a sign-in's state is sealed under while it waits (that of
    /// setup `id`).
    pub fn state_key(&self, id: u16) -> Option<&[u8; 32]> {
        self.keys.get(id)
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
