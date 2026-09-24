//! A folder's keys across its epochs (docs/plans/drive-share-revocation.md).
//!
//! A folder whose owner removed someone has moved to a new key; what was
//! stored before stays under older keys, which the current key unlocks
//! through the folder's owner-signed history. Most folders have one epoch and
//! never fetch anything here.

use anyhow::{anyhow, bail, Context, Result};
use kutup_crypto::collection_keyring::{self, EpochLinkV1};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::identity::AccountIdentityKeysV1;
use serde::Deserialize;

use crate::api::{Client, Collection, File};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpochLink {
    epoch: u32,
    epoch_statement: String,
    epoch_statement_hash: String,
    #[serde(default)]
    previous_key_envelope: Option<String>,
}

/// The keys a folder has had, by epoch: every one after a history load, or
/// just the current one.
pub struct Keyring {
    keys: std::collections::BTreeMap<u32, Vec<u8>>,
    current: u32,
}

impl Keyring {
    /// A folder's keyring from its current key; its history is fetched and
    /// verified only when it has rotated.
    pub fn load(
        client: &Client,
        col: &Collection,
        current_key: &[u8],
        master_key: &[u8],
    ) -> Result<Keyring> {
        Self::load_from(
            client,
            &format!("/collections/{}/epochs", col.id),
            &col.id,
            &col.owner_user_id,
            col.key_epoch,
            Some(&col.epoch_statement_hash),
            current_key,
            || {
                if col.is_shared {
                    col.owner_authority_public_key
                        .as_deref()
                        .ok_or_else(|| anyhow!("share owner authority is missing"))
                        .and_then(decode_key)
                } else {
                    let master: &[u8; 32] = master_key
                        .try_into()
                        .context("master key must be 32 bytes")?;
                    Ok(AccountIdentityKeysV1::derive(master)?
                        .authority_public_key()
                        .to_vec())
                }
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_from(
        client: &Client,
        history_path: &str,
        collection_id: &str,
        owner_user_id: &str,
        key_epoch: u32,
        statement_hash: Option<&str>,
        current_key: &[u8],
        authority: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<Keyring> {
        if key_epoch <= 1 {
            return Ok(Self::current_only(current_key, key_epoch.max(1)));
        }
        let resp = client.get(history_path)?;
        let links: Vec<EpochLink> = crate::api::decode_json(resp).context("folder key history")?;
        if links.len() != key_epoch as usize
            || statement_hash.is_some_and(|hash| {
                links.last().map(|l| l.epoch_statement_hash.as_str()) != Some(hash)
            })
        {
            bail!("folder key history does not end at the current epoch");
        }
        let chain: Vec<EpochLinkV1> = links
            .into_iter()
            .map(|l| EpochLinkV1 {
                epoch: l.epoch,
                statement: l.epoch_statement,
                previous_key_envelope: l.previous_key_envelope,
            })
            .collect();
        let keys = collection_keyring::unlock(
            current_key,
            collection_id,
            owner_user_id,
            &authority()?,
            &chain,
        )
        .context("verify folder key history")?;
        Ok(Keyring {
            keys: (1..=key_epoch)
                .zip(keys.into_iter().map(|k| k.to_vec()))
                .collect(),
            current: key_epoch,
        })
    }

    /// Only the current key: for what is known to be sealed at the current
    /// epoch (no history fetched).
    pub fn current_only(current_key: &[u8], epoch: u32) -> Keyring {
        Keyring {
            keys: [(epoch, current_key.to_vec())].into_iter().collect(),
            current: epoch,
        }
    }

    /// The folder key at `epoch`.
    pub fn at(&self, epoch: u32) -> Result<&[u8]> {
        self.keys
            .get(&epoch)
            .map(Vec::as_slice)
            .ok_or_else(|| anyhow!("no folder key for epoch {epoch}"))
    }

    /// The folder's current key.
    pub fn current(&self) -> &[u8] {
        &self.keys[&self.current]
    }

    /// The file key content of `file` sealed at `epoch` opens with: the
    /// file's own at its current epoch, else one a re-key left behind.
    pub fn file_key_at(&self, file: &File, file_key: &[u8; 32], epoch: u32) -> Result<[u8; 32]> {
        if epoch == file.key_epoch {
            return Ok(*file_key);
        }
        let entry = file
            .key_history
            .iter()
            .find(|entry| entry.epoch == epoch)
            .ok_or_else(|| anyhow!("no file key for epoch {epoch}"))?;
        drive_envelope::open_b64(
            &entry.file_key_envelope,
            self.at(epoch)?,
            DriveEnvelopeContextV1::new(
                DriveEnvelopePurpose::FileKey,
                epoch,
                1,
                &file.id,
                &file.collection_id,
            )?,
        )?
        .try_into()
        .map_err(|_| anyhow!("file key has wrong length"))
    }
}

/// A base64 32-byte public key.
pub fn decode_key(value: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(value)?;
    if bytes.len() != 32 {
        bail!("authority key must be 32 bytes");
    }
    Ok(bytes)
}

#[cfg(test)]
pub mod tests_support {
    use super::Keyring;

    /// A keyring with exactly these epochs' keys.
    pub fn keyring(keys: &[(u32, [u8; 32])], current: u32) -> Keyring {
        Keyring {
            keys: keys.iter().map(|(e, k)| (*e, k.to_vec())).collect(),
            current,
        }
    }
}
