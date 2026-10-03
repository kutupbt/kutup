//! A folder's keys across its epochs (docs/plans/drive-share-revocation.md).
//!
//! Rotating a folder adds an epoch: a new random key, an owner-signed
//! `CollectionEpochStatementV1` chained to the previous one and committing
//! to the new key, and the previous key sealed under the new one
//! (`DriveEnvelopePurpose::PreviousCollectionKey`). Whoever holds the current
//! key can therefore walk down to every older key — and each step is checked
//! against the signed chain, so a server cannot substitute a key or reorder
//! the history.

use zeroize::Zeroizing;

use crate::collection_epoch::CollectionEpochStatementV1;
use crate::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use crate::error::{CryptoError, Result};

/// One epoch of a folder's history as the server returns it.
#[derive(Clone, Debug)]
pub struct EpochLinkV1 {
    pub epoch: u32,
    /// The epoch's `CollectionEpochStatementV1`, base64.
    pub statement: String,
    /// The previous epoch's key sealed under this epoch's key, base64;
    /// absent exactly for epoch 1.
    pub previous_key_envelope: Option<String>,
}

/// The envelope context of the previous-key record stored at `epoch`.
pub fn previous_key_context(
    collection_id: &str,
    owner_user_id: &str,
    epoch: u32,
) -> Result<DriveEnvelopeContextV1> {
    if epoch < 2 {
        return Err(CryptoError::InvalidInput(
            "epoch 1 has no previous key".into(),
        ));
    }
    DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::PreviousCollectionKey,
        epoch,
        1,
        collection_id,
        owner_user_id,
    )
}

/// Seal the key of `epoch − 1` under the key of `epoch`.
pub fn seal_previous_key(
    previous_key: &[u8],
    key: &[u8],
    collection_id: &str,
    owner_user_id: &str,
    epoch: u32,
) -> Result<String> {
    drive_envelope::seal_b64(
        previous_key,
        key,
        previous_key_context(collection_id, owner_user_id, epoch)?,
    )
}

/// Check a folder's signed history without its keys: every epoch from 1 in
/// order, each statement the owner's, bound to this folder, chained to its
/// predecessor. Returns each epoch's statement hash, oldest first — what a
/// party holding no key (a federated recipient's server) pins and compares.
pub fn verify_history(
    collection_id: &str,
    owner_user_id: &str,
    owner_authority_public_key: &[u8],
    chain: &[EpochLinkV1],
) -> Result<Vec<String>> {
    Ok(verified_statements(
        collection_id,
        owner_user_id,
        owner_authority_public_key,
        chain,
    )?
    .iter()
    .map(CollectionEpochStatementV1::statement_hash)
    .collect())
}

fn verified_statements(
    collection_id: &str,
    owner_user_id: &str,
    owner_authority_public_key: &[u8],
    chain: &[EpochLinkV1],
) -> Result<Vec<CollectionEpochStatementV1>> {
    if chain.is_empty() || chain.len() > u32::MAX as usize {
        return Err(CryptoError::InvalidInput(
            "empty collection key history".into(),
        ));
    }
    let mut statements = Vec::with_capacity(chain.len());
    let mut previous_hash: Option<String> = None;
    for (index, link) in chain.iter().enumerate() {
        let epoch = u32::try_from(index + 1).expect("bounded above");
        if link.epoch != epoch || link.previous_key_envelope.is_some() != (epoch > 1) {
            return Err(CryptoError::InvalidInput(
                "collection key history is incomplete or out of order".into(),
            ));
        }
        let statement = CollectionEpochStatementV1::decode_b64(&link.statement)?;
        statement.verify_authority(owner_authority_public_key)?;
        statement.verify_binding(
            collection_id,
            owner_user_id,
            epoch,
            previous_hash.as_deref(),
        )?;
        previous_hash = Some(statement.statement_hash());
        statements.push(statement);
    }
    Ok(statements)
}

/// Every key of the folder, oldest first (index `e − 1` holds epoch `e`),
/// from its current key and its complete history.
///
/// `chain` must hold every epoch from 1 to the current one, in order. Each
/// statement must be signed by the owner's authority, bound to this folder
/// and owner, and chained to its predecessor's hash; each key recovered must
/// match its statement's commitment. The current key must match the last.
pub fn unlock(
    current_key: &[u8],
    collection_id: &str,
    owner_user_id: &str,
    owner_authority_public_key: &[u8],
    chain: &[EpochLinkV1],
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let statements = verified_statements(
        collection_id,
        owner_user_id,
        owner_authority_public_key,
        chain,
    )?;

    let mut keys: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(chain.len());
    let current = Zeroizing::new(current_key.to_vec());
    statements
        .last()
        .expect("non-empty")
        .verify_collection_key(&current)?;
    keys.push(current);
    for index in (1..chain.len()).rev() {
        let epoch = u32::try_from(index + 1).expect("bounded above");
        let envelope = chain[index]
            .previous_key_envelope
            .as_deref()
            .expect("checked above");
        let newer = keys.last().expect("non-empty");
        let older = Zeroizing::new(drive_envelope::open_b64(
            envelope,
            newer,
            previous_key_context(collection_id, owner_user_id, epoch)?,
        )?);
        statements[index - 1].verify_collection_key(&older)?;
        keys.push(older);
    }
    keys.reverse();
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const COLLECTION: &str = "11111111-1111-4111-8111-111111111111";
    const OWNER: &str = "22222222-2222-4222-8222-222222222222";

    /// A three-epoch history: keys, links and the authority.
    fn history() -> (Vec<[u8; 32]>, Vec<EpochLinkV1>, SigningKey) {
        let authority = SigningKey::from_bytes(&[9u8; 32]);
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut links = Vec::new();
        let mut previous_hash: Option<String> = None;
        for (index, key) in keys.iter().enumerate() {
            let epoch = index as u32 + 1;
            let statement = CollectionEpochStatementV1::create(
                COLLECTION,
                OWNER,
                epoch,
                previous_hash.as_deref(),
                key,
                &authority,
            )
            .unwrap();
            previous_hash = Some(statement.statement_hash());
            links.push(EpochLinkV1 {
                epoch,
                statement: statement.encode_b64(),
                previous_key_envelope: (epoch > 1).then(|| {
                    seal_previous_key(&keys[index - 1], key, COLLECTION, OWNER, epoch).unwrap()
                }),
            });
        }
        (keys.to_vec(), links, authority)
    }

    #[test]
    fn walks_down_to_every_key() {
        let (keys, links, authority) = history();
        let public = authority.verifying_key().to_bytes();
        let unlocked = unlock(&keys[2], COLLECTION, OWNER, &public, &links).unwrap();
        assert_eq!(unlocked.len(), 3);
        for (got, want) in unlocked.iter().zip(&keys) {
            assert_eq!(got.as_slice(), want);
        }
        // A folder never rotated: its one key.
        let one = unlock(&keys[0], COLLECTION, OWNER, &public, &links[..1]).unwrap();
        assert_eq!(one[0].as_slice(), &keys[0]);
    }

    #[test]
    fn history_verifies_without_keys() {
        let (_, links, authority) = history();
        let public = authority.verifying_key().to_bytes();
        let hashes = verify_history(COLLECTION, OWNER, &public, &links).unwrap();
        assert_eq!(hashes.len(), 3);
        assert_eq!(
            hashes[0],
            CollectionEpochStatementV1::decode_b64(&links[0].statement)
                .unwrap()
                .statement_hash()
        );
        assert!(verify_history(COLLECTION, OWNER, &public, &links[1..]).is_err());
    }

    #[test]
    fn refuses_a_wrong_or_stale_current_key() {
        let (keys, links, authority) = history();
        let public = authority.verifying_key().to_bytes();
        // A removed member's key (epoch 2) does not open epoch 3's history.
        assert!(unlock(&keys[1], COLLECTION, OWNER, &public, &links).is_err());
    }

    #[test]
    fn refuses_a_tampered_history() {
        let (keys, links, authority) = history();
        let public = authority.verifying_key().to_bytes();
        // Missing an epoch.
        let gap = vec![links[0].clone(), links[2].clone()];
        assert!(unlock(&keys[2], COLLECTION, OWNER, &public, &gap).is_err());
        // Another folder's history.
        assert!(unlock(
            &keys[2],
            "33333333-3333-4333-8333-333333333333",
            OWNER,
            &public,
            &links
        )
        .is_err());
        // A statement from another authority.
        let stranger = SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(unlock(&keys[2], COLLECTION, OWNER, &stranger, &links).is_err());
        // A substituted previous key (sealed correctly, but not the committed one).
        let mut swapped = links.clone();
        swapped[2].previous_key_envelope =
            Some(seal_previous_key(&[8u8; 32], &keys[2], COLLECTION, OWNER, 3).unwrap());
        assert!(unlock(&keys[2], COLLECTION, OWNER, &public, &swapped).is_err());
        // A statement out of the chain (epoch 2 re-signed with a different key).
        let mut forked = links.clone();
        forked[1].statement = CollectionEpochStatementV1::create(
            COLLECTION,
            OWNER,
            2,
            Some(
                &CollectionEpochStatementV1::decode_b64(&links[0].statement)
                    .unwrap()
                    .statement_hash(),
            ),
            &[5u8; 32],
            &authority,
        )
        .unwrap()
        .encode_b64();
        assert!(unlock(&keys[2], COLLECTION, OWNER, &public, &forked).is_err());
    }
}

#[cfg(test)]
mod vector {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    /// Prints the `collectionKeyring` vector for `tests/vectors/crypto.json`:
    /// `cargo test -p kutup-crypto print_keyring_vector -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn print_keyring_vector() {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let collection = "11111111-1111-4111-8111-111111111111";
        let owner = "22222222-2222-4222-8222-222222222222";
        let authority_seed = [0x5au8; 32];
        let authority = SigningKey::from_bytes(&authority_seed);
        let keys = [[0x61u8; 32], [0x62u8; 32], [0x63u8; 32]];
        let mut previous_hash: Option<String> = None;
        let mut links = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let epoch = index as u32 + 1;
            let statement = CollectionEpochStatementV1::create(
                collection,
                owner,
                epoch,
                previous_hash.as_deref(),
                key,
                &authority,
            )
            .unwrap();
            previous_hash = Some(statement.statement_hash());
            let previous = (epoch > 1).then(|| {
                b64(&drive_envelope::seal_with_nonce(
                    &keys[index - 1],
                    key,
                    previous_key_context(collection, owner, epoch).unwrap(),
                    &[0x44u8 + epoch as u8; 24],
                )
                .unwrap())
            });
            links.push(serde_json::json!({
                "epoch": epoch,
                "statement": statement.encode_b64(),
                "previousKeyEnvelope": previous,
            }));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "collectionId": collection,
                "ownerUserId": owner,
                "authorityPublicKey": b64(&authority.verifying_key().to_bytes()),
                "keys": keys.iter().map(|k| b64(k)).collect::<Vec<_>>(),
                "chain": links,
            }))
            .unwrap()
        );
    }
}
