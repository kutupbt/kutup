//! The gateway's HPKE keys: one a week, derived from the federation identity
//! key (domain-separated HKDF), so nothing secret is stored beside it and a
//! restart serves the same key. The key config is signed by the same
//! identity; the previous week's key is still accepted for the overlap.

use kutup_chat_proto::group_route::{GroupGatewayKeyConfigV1, KEY_OVERLAP_SECS};
use kutup_crypto::oblivious::GatewayKey;
use kutup_crypto::primitives::{kdf, SigningKey, Suite};
use kutup_federation_proto::FederationIdentityDocumentV1;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// A key's week, in seconds (also the config's lifetime, at most the format's
/// seven days).
pub(crate) const EPOCH_SECS: i64 = 7 * 24 * 60 * 60;

/// The KEM is in the label: the derived seed is an X-Wing seed.
const KEY_INFO: &[u8] = b"kutup/chat-group/gateway-key/v2-xwing\0";

fn epoch_of(now: i64) -> i64 {
    now.div_euclid(EPOCH_SECS)
}

/// One byte, different for consecutive weeks, never zero.
fn key_id(epoch: i64) -> u8 {
    u8::try_from(epoch.rem_euclid(255) + 1).expect("1..=255")
}

/// Each week's key, derived once per process: an X-Wing key pair costs an
/// ML-KEM key generation, which a request shouldn't pay again. Keyed by the
/// identity and the week; weeks before last are dropped.
type KeyCache = std::collections::HashMap<([u8; 32], i64), std::sync::Arc<GatewayKey>>;
static KEYS: std::sync::LazyLock<std::sync::Mutex<KeyCache>> =
    std::sync::LazyLock::new(Default::default);

fn cached(identity: &SigningKey, epoch: i64) -> AppResult<std::sync::Arc<GatewayKey>> {
    let id = identity.verifying_key().to_array::<32>();
    if let Some(key) = KEYS.lock().unwrap().get(&(id, epoch)) {
        return Ok(key.clone());
    }
    let key = std::sync::Arc::new(derive(identity, epoch)?);
    let mut keys = KEYS.lock().unwrap();
    keys.retain(|(_, kept), _| *kept >= epoch - 1);
    keys.insert((id, epoch), key.clone());
    Ok(key)
}

fn derive(identity: &SigningKey, epoch: i64) -> AppResult<GatewayKey> {
    let seed = identity.seed();
    let mut info = KEY_INFO.to_vec();
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut private_key = Zeroizing::new([0u8; 32]);
    kdf(Suite::V1, seed.as_ref(), &[], &info, private_key.as_mut())
        .map_err(|_| AppError::internal("gateway key derivation"))?;
    GatewayKey::from_private_key(key_id(epoch), private_key.as_ref())
        .map_err(|error| AppError::internal(format!("gateway key: {error}")))
}

/// The key config this home serves now, signed by its identity.
pub(crate) fn current_config(
    document: &FederationIdentityDocumentV1,
    identity: &SigningKey,
    now: i64,
) -> AppResult<GroupGatewayKeyConfigV1> {
    let epoch = epoch_of(now);
    let key = cached(identity, epoch)?;
    let issued_at = epoch * EPOCH_SECS;
    GroupGatewayKeyConfigV1::sign(
        document,
        identity,
        key.key_id(),
        &key.public_key(),
        issued_at,
        issued_at + EPOCH_SECS,
    )
    .map_err(AppError::internal)
}

/// The keys a request may be sealed to now: this week's, and last week's
/// during the overlap after the change.
pub(crate) fn accepted_keys(
    identity: &SigningKey,
    now: i64,
) -> AppResult<Vec<std::sync::Arc<GatewayKey>>> {
    let epoch = epoch_of(now);
    let mut keys = vec![cached(identity, epoch)?];
    if now - epoch * EPOCH_SECS < KEY_OVERLAP_SECS {
        keys.push(cached(identity, epoch - 1)?);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> (FederationIdentityDocumentV1, SigningKey) {
        let key = SigningKey::from_seed(kutup_crypto::primitives::Suite::V1, &[3; 32]);
        (
            FederationIdentityDocumentV1::genesis("home.example", 10, &key).unwrap(),
            key,
        )
    }

    #[test]
    fn the_served_config_verifies_and_opens_with_an_accepted_key() {
        let (document, key) = identity();
        let now = 100 * EPOCH_SECS + 5;
        let config = current_config(&document, &key, now).unwrap();
        let (key_id, public_key) = config.verify(std::slice::from_ref(&document), now).unwrap();
        let (request, _) =
            kutup_crypto::oblivious::seal_request(key_id, &public_key, b"x").unwrap();
        assert!(accepted_keys(&key, now)
            .unwrap()
            .iter()
            .any(|gateway| gateway.open_request(&request).is_ok()));
    }

    #[test]
    fn last_weeks_key_lasts_through_the_overlap_only() {
        let (document, key) = identity();
        let last_week = 100 * EPOCH_SECS + 5;
        let config = current_config(&document, &key, last_week).unwrap();
        let (key_id, public_key) = config
            .verify(std::slice::from_ref(&document), last_week)
            .unwrap();
        let (request, _) =
            kutup_crypto::oblivious::seal_request(key_id, &public_key, b"x").unwrap();
        let opens = |now| {
            accepted_keys(&key, now)
                .unwrap()
                .iter()
                .any(|gateway| gateway.open_request(&request).is_ok())
        };
        assert!(opens(101 * EPOCH_SECS + KEY_OVERLAP_SECS - 1));
        assert!(!opens(101 * EPOCH_SECS + KEY_OVERLAP_SECS));
    }

    #[test]
    fn keys_differ_by_week_and_identity_and_ids_by_neighbour() {
        let (_, key) = identity();
        let other = SigningKey::from_seed(kutup_crypto::primitives::Suite::V1, &[4; 32]);
        assert_ne!(
            derive(&key, 5).unwrap().public_key(),
            derive(&key, 6).unwrap().public_key()
        );
        assert_ne!(
            derive(&key, 5).unwrap().public_key(),
            derive(&other, 5).unwrap().public_key()
        );
        assert_eq!(
            derive(&key, 5).unwrap().public_key(),
            derive(&key, 5).unwrap().public_key()
        );
        for epoch in [0, 1, 253, 254, 255, 256, -1] {
            assert_ne!(key_id(epoch), key_id(epoch + 1));
            assert_ne!(key_id(epoch), 0);
        }
    }
}
