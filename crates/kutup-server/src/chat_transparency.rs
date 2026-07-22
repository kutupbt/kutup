//! Append-only device-manifest transparency log.
//!
//! PostgreSQL stores every complete aligned subtree, so appends and proof
//! reads are logarithmic. The cryptographic verifier and wire encoding live in
//! `kutup-chat-proto`, shared by browser/native clients.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use kutup_chat_proto::{
    hash_transparency_map_checkpoint, hash_transparency_map_leaf, hash_transparency_node,
    manifest_range_cursor, map_key_bit, transparency_map_empty_hashes, transparency_map_key,
    ChatTransparencyPolicyV1, DeviceManifest, ManifestTransparencyLeaf,
    ManifestTransparencyMapProof, ManifestTransparencyProof, ManifestUpdateRangeEntryV1,
    ManifestUpdateRangeProofV1, SubmitTransparencyWitnessRequest, TransparencyCheckpoint,
    TransparencyCheckpointAuthentication, TransparencyCheckpointResponse, TransparencyHash,
    TransparencyMapSibling, TransparencyProofProfileV1, TransparencyVerifierKey,
    TransparencyWitnessAttestation, TransparencyWitnessPolicyV1,
};
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Long-term operator identity for distinguished transparency checkpoints.
/// Witness private keys never enter this process.
pub struct TransparencyAuthority {
    signing_key: SigningKey,
    trusted_witnesses: BTreeMap<String, TransparencyVerifierKey>,
    witness_quorum: u16,
}

impl TransparencyAuthority {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        if config.chat_transparency_signing_key.is_empty() {
            anyhow::bail!(
                "CHAT_TRANSPARENCY_SIGNING_KEY is required while key transparency is enabled"
            );
        }
        let seed = STANDARD
            .decode(&config.chat_transparency_signing_key)
            .map_err(|_| anyhow::anyhow!("CHAT_TRANSPARENCY_SIGNING_KEY must be base64"))?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            anyhow::anyhow!("CHAT_TRANSPARENCY_SIGNING_KEY must decode to exactly 32 bytes")
        })?;
        let mut trusted_witnesses = BTreeMap::new();
        for entry in config
            .chat_transparency_witnesses
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (witness_id, encoded) = entry.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("CHAT_TRANSPARENCY_WITNESSES entries must be witness-id=base64-key")
            })?;
            let public = STANDARD.decode(encoded).map_err(|_| {
                anyhow::anyhow!("CHAT_TRANSPARENCY_WITNESSES contains invalid base64")
            })?;
            let public: [u8; 32] = public.try_into().map_err(|_| {
                anyhow::anyhow!("CHAT_TRANSPARENCY_WITNESSES keys must be exactly 32 bytes")
            })?;
            let public = VerifyingKey::from_bytes(&public).map_err(|_| {
                anyhow::anyhow!("CHAT_TRANSPARENCY_WITNESSES contains an invalid Ed25519 key")
            })?;
            let verifier = TransparencyVerifierKey {
                witness_id: witness_id.to_string(),
                key_id: kutup_chat_proto::transparency_signing_key_id(&public),
                public_key: STANDARD.encode(public.as_bytes()),
            };
            verifier.validate().map_err(anyhow::Error::msg)?;
            if trusted_witnesses
                .insert(verifier.witness_id.clone(), verifier)
                .is_some()
            {
                anyhow::bail!("CHAT_TRANSPARENCY_WITNESSES repeats a witness id");
            }
        }
        let witness_quorum = u16::try_from(config.chat_transparency_witness_quorum)
            .map_err(|_| anyhow::anyhow!("CHAT_TRANSPARENCY_WITNESS_QUORUM is too large"))?;
        if usize::from(witness_quorum) > trusted_witnesses.len() {
            anyhow::bail!("CHAT_TRANSPARENCY_WITNESS_QUORUM exceeds configured witnesses");
        }
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
            trusted_witnesses,
            witness_quorum,
        })
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn key_id(&self) -> String {
        kutup_chat_proto::transparency_signing_key_id(&self.signing_key.verifying_key())
    }

    pub fn witnesses(&self) -> Vec<TransparencyVerifierKey> {
        self.trusted_witnesses.values().cloned().collect()
    }

    pub fn witness_quorum(&self) -> u16 {
        self.witness_quorum
    }
}

pub async fn local_transparency_policy(
    pool: &PgPool,
    config: &Config,
    authority: &TransparencyAuthority,
) -> anyhow::Result<Option<ChatTransparencyPolicyV1>> {
    if authority.witness_quorum() == 0 {
        return Ok(None);
    }
    let log_id: String =
        sqlx::query_scalar("SELECT log_id FROM chat_transparency_log WHERE singleton = true")
            .fetch_one(pool)
            .await?;
    let mut endpoints = BTreeMap::new();
    for entry in config
        .chat_transparency_witness_endpoints
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (id, endpoint) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "CHAT_TRANSPARENCY_WITNESS_ENDPOINTS entries must be witness-id=https-url"
            )
        })?;
        if endpoints
            .insert(id.to_owned(), endpoint.to_owned())
            .is_some()
        {
            anyhow::bail!("CHAT_TRANSPARENCY_WITNESS_ENDPOINTS repeats a witness id");
        }
    }
    let witnesses = authority
        .witnesses()
        .into_iter()
        .map(|witness| TransparencyWitnessPolicyV1 {
            public_endpoint: endpoints
                .remove(&witness.witness_id)
                .unwrap_or_else(|| default_witness_endpoint(&witness.witness_id)),
            witness_id: witness.witness_id,
            key_id: witness.key_id,
            public_key: witness.public_key,
        })
        .collect();
    if !endpoints.is_empty() {
        anyhow::bail!("CHAT_TRANSPARENCY_WITNESS_ENDPOINTS names an unconfigured witness");
    }
    let policy = ChatTransparencyPolicyV1 {
        policy_version: 1,
        log_id: log_id.trim_end().to_owned(),
        operator_key_id: authority.key_id(),
        operator_public_key: authority.public_key_base64(),
        witnesses,
        required_quorum: authority.witness_quorum(),
        proof_profile: TransparencyProofProfileV1::Rfc6962IndividualInclusionV1,
        maximum_checkpoint_age_seconds: 60 * 60,
        maximum_clock_skew_seconds: 60,
        maximum_range_page_entries: 64,
        maximum_range_response_bytes: 2 * 1024 * 1024,
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    Ok(Some(policy))
}

fn default_witness_endpoint(witness_id: &str) -> String {
    format!("https://{witness_id}/v1/view")
}

#[cfg(test)]
mod tests {
    use super::default_witness_endpoint;

    #[test]
    fn generated_witness_endpoint_is_a_canonical_signed_view_path() {
        assert_eq!(
            default_witness_endpoint("audit.example"),
            "https://audit.example/v1/view"
        );
    }
}

#[derive(Clone, Debug)]
enum HashExpr {
    Stored { level: i16, node_index: i64 },
    Parent(Box<HashExpr>, Box<HashExpr>),
}

#[derive(sqlx::FromRow)]
struct SignedCheckpointRow {
    log_id: String,
    root_hash: Vec<u8>,
    map_root: Vec<u8>,
    issued_at: i64,
    operator_key_id: String,
    operator_public_key: String,
    operator_signature: String,
}

/// Atomically seed a newly migrated empty log with the current manifest of
/// every pre-existing account. Older versions were not retained before the log
/// existed, so clients correctly keep their existing continuity-gap marker.
pub async fn backfill_existing_manifests(pool: &PgPool) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    let tree_size: i64 = sqlx::query_scalar(
        "SELECT tree_size FROM chat_transparency_log WHERE singleton = true FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    if tree_size != 0 {
        tx.rollback().await?;
        return Ok(0);
    }
    let rows: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        "SELECT m.user_id, u.username, m.manifest
         FROM chat_device_manifests m
         JOIN users u ON u.id = m.user_id
         ORDER BY m.updated_at, m.user_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let count = rows.len() as u64;
    for (user_id, username, value) in rows {
        let manifest: DeviceManifest = serde_json::from_value(value)?;
        append_manifest(&mut tx, user_id, &username, &manifest)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }
    tx.commit().await?;
    Ok(count)
}

/// Seed the authenticated current-value map after migration 029. The map root
/// is appended to the already deployed chronological log, so clients holding a
/// pre-map checkpoint can verify an ordinary consistency proof across the
/// upgrade instead of resetting trust.
pub async fn backfill_current_map(
    pool: &PgPool,
    authority: &TransparencyAuthority,
) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT position FROM chat_transparency_map_checkpoints ORDER BY position DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        tx.rollback().await?;
        ensure_signed_head(pool, authority).await?;
        return Ok(0);
    }

    // Serialize with publication even when the current map is initially empty.
    let _: i64 = sqlx::query_scalar(
        "SELECT tree_size FROM chat_transparency_log WHERE singleton = true FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT u.username, m.manifest
         FROM chat_device_manifests m
         JOIN users u ON u.id = m.user_id
         ORDER BY u.username",
    )
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
        tx.rollback().await?;
        return Ok(0);
    }
    let count = rows.len() as u64;
    let mut root = None;
    for (username, value) in rows {
        let manifest: DeviceManifest = serde_json::from_value(value)?;
        let leaf = ManifestTransparencyLeaf::from_manifest(username, &manifest)
            .map_err(anyhow::Error::msg)?;
        root = Some(
            update_current_map(&mut tx, &leaf)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        );
    }
    append_map_checkpoint(&mut tx, root.expect("non-empty map has a root"), authority)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    tx.commit().await?;
    Ok(count)
}

/// Append one signed manifest event, update its current-map value, and commit
/// the new map root as the final chronological-log leaf in one transaction.
pub async fn append_manifest_update(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    username: &str,
    manifest: &DeviceManifest,
    authority: &TransparencyAuthority,
) -> AppResult<()> {
    let leaf_position = append_manifest(tx, user_id, username, manifest).await?;
    let manifest_hash = manifest.manifest_hash().map_err(AppError::internal)?;
    let manifest_value = serde_json::to_value(manifest)
        .map_err(|error| AppError::internal(format!("serialize manifest history: {error}")))?;
    sqlx::query(
        "INSERT INTO chat_device_manifest_history
             (user_id, version, manifest_hash, authority_key_id, manifest, leaf_position)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(user_id)
    .bind(manifest.version as i64)
    .bind(manifest_hash)
    .bind(&manifest.authority_key_id)
    .bind(manifest_value)
    .bind(leaf_position)
    .execute(&mut **tx)
    .await?;
    let leaf =
        ManifestTransparencyLeaf::from_manifest(username, manifest).map_err(AppError::internal)?;
    let map_root = update_current_map(tx, &leaf).await?;
    append_map_checkpoint(tx, map_root, authority).await?;
    Ok(())
}

/// Sign the current head after upgrading a database that already had the map
/// but predates migration 030. Refuse silent operator-key replacement.
pub async fn ensure_signed_head(
    pool: &PgPool,
    authority: &TransparencyAuthority,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let _: i64 = sqlx::query_scalar(
        "SELECT tree_size FROM chat_transparency_log WHERE singleton = true FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let current: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT position, map_root FROM chat_transparency_map_checkpoints
         ORDER BY position DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some((position, map_root)) = current else {
        tx.rollback().await?;
        return Ok(false);
    };
    let existing_key: Option<String> = sqlx::query_scalar(
        "SELECT operator_key_id FROM chat_transparency_signed_checkpoints
         ORDER BY tree_size DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing_key) = existing_key {
        if existing_key.trim_end() != authority.key_id() {
            anyhow::bail!(
                "configured transparency signing key does not match the persisted operator key"
            );
        }
        tx.rollback().await?;
        return Ok(false);
    }
    let tree_size = position
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("transparency tree size overflow"))?;
    let map_root =
        hash_from_bytes(&map_root).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    sign_checkpoint(&mut tx, tree_size, map_root, authority)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    tx.commit().await?;
    Ok(true)
}

pub async fn append_manifest(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    username: &str,
    manifest: &DeviceManifest,
) -> AppResult<i64> {
    let leaf =
        ManifestTransparencyLeaf::from_manifest(username, manifest).map_err(AppError::internal)?;
    let leaf_hash = leaf.hash().map_err(AppError::internal)?;
    let position = append_log_leaf(tx, leaf_hash).await?;

    sqlx::query(
        "INSERT INTO chat_transparency_leaves
             (position, user_id, username, manifest_version, manifest_hash,
              authority_key_id, leaf_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(position)
    .bind(user_id)
    .bind(username)
    .bind(manifest.version as i64)
    .bind(&leaf.manifest_hash)
    .bind(&leaf.authority_key_id)
    .bind(leaf_hash.as_slice())
    .execute(&mut **tx)
    .await?;

    Ok(position)
}

pub async fn prove_manifest(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    known_tree_size: u64,
) -> AppResult<ManifestTransparencyProof> {
    let (log_id, tree_size): (String, i64) = sqlx::query_as(
        "SELECT log_id, tree_size FROM chat_transparency_log
         WHERE singleton = true FOR SHARE",
    )
    .fetch_one(&mut **tx)
    .await?;
    let tree_size = u64::try_from(tree_size)
        .map_err(|_| AppError::internal("invalid transparency tree size"))?;
    if known_tree_size > tree_size {
        return Err(AppError::conflict(
            "transparency checkpoint is newer than this server view",
        ));
    }

    let row: Option<(i64, String, i64, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT position, username, manifest_version, manifest_hash,
                authority_key_id, leaf_hash
         FROM chat_transparency_leaves
         WHERE user_id = $1 ORDER BY manifest_version DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let (leaf_index, username, manifest_version, manifest_hash, authority_key_id, stored_hash) =
        row.ok_or_else(|| AppError::internal("current manifest has no transparency leaf"))?;
    let leaf_index = u64::try_from(leaf_index)
        .map_err(|_| AppError::internal("invalid transparency leaf position"))?;
    let manifest_version = u64::try_from(manifest_version)
        .map_err(|_| AppError::internal("invalid transparency manifest version"))?;
    let leaf = ManifestTransparencyLeaf {
        username,
        manifest_version,
        manifest_hash,
        authority_key_id,
    };
    let expected_hash = leaf.hash().map_err(AppError::internal)?;
    if hash_from_bytes(&stored_hash)? != expected_hash {
        return Err(AppError::internal(
            "stored transparency leaf hash is corrupt",
        ));
    }

    let (map_checkpoint_index, map_root_bytes, map_leaf_hash): (i64, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT position, map_root, leaf_hash
             FROM chat_transparency_map_checkpoints
             ORDER BY position DESC LIMIT 1",
        )
        .fetch_one(&mut **tx)
        .await?;
    let map_checkpoint_index = u64::try_from(map_checkpoint_index)
        .map_err(|_| AppError::internal("invalid transparency map checkpoint position"))?;
    if map_checkpoint_index.checked_add(1) != Some(tree_size) {
        return Err(AppError::internal(
            "transparency map checkpoint is not the log head",
        ));
    }
    let map_root = hash_from_bytes(&map_root_bytes)?;
    if hash_from_bytes(&map_leaf_hash)? != hash_transparency_map_checkpoint(map_root) {
        return Err(AppError::internal(
            "stored transparency map checkpoint hash is corrupt",
        ));
    }
    let map_key = transparency_map_key(&leaf.username).map_err(AppError::internal)?;
    let expected_map_leaf = hash_transparency_map_leaf(&leaf).map_err(AppError::internal)?;
    let stored_map_leaf: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT hash FROM chat_transparency_map_nodes WHERE depth = 256 AND path = $1",
    )
    .bind(map_key.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    if stored_map_leaf
        .as_deref()
        .map(hash_from_bytes)
        .transpose()?
        != Some(expected_map_leaf)
    {
        return Err(AppError::internal(
            "current transparency map leaf does not match the manifest",
        ));
    }

    let root_expr = range_expr(0, tree_size)?;
    let mut inclusion_exprs = Vec::new();
    inclusion_path(0, tree_size, leaf_index, &mut inclusion_exprs)?;
    let mut map_checkpoint_exprs = Vec::new();
    inclusion_path(
        0,
        tree_size,
        map_checkpoint_index,
        &mut map_checkpoint_exprs,
    )?;
    let mut consistency_exprs = Vec::new();
    if known_tree_size != 0 && known_tree_size != tree_size {
        consistency_path(known_tree_size, 0, tree_size, true, &mut consistency_exprs)?;
    }

    let mut coordinates = BTreeSet::new();
    collect_stored(&root_expr, &mut coordinates);
    for expr in inclusion_exprs
        .iter()
        .chain(&map_checkpoint_exprs)
        .chain(&consistency_exprs)
    {
        collect_stored(expr, &mut coordinates);
    }
    let mut hashes = BTreeMap::new();
    for (level, node_index) in coordinates {
        hashes.insert((level, node_index), load_node(tx, level, node_index).await?);
    }

    let root = evaluate(&root_expr, &hashes)?;
    let inclusion = inclusion_exprs
        .iter()
        .map(|expr| evaluate(expr, &hashes).map(hex::encode))
        .collect::<AppResult<Vec<_>>>()?;
    let consistency = consistency_exprs
        .iter()
        .map(|expr| evaluate(expr, &hashes).map(hex::encode))
        .collect::<AppResult<Vec<_>>>()?;
    let map_checkpoint_inclusion = map_checkpoint_exprs
        .iter()
        .map(|expr| evaluate(expr, &hashes).map(hex::encode))
        .collect::<AppResult<Vec<_>>>()?;
    let map_siblings = load_map_siblings(tx, &map_key).await?;
    let defaults = transparency_map_empty_hashes();
    let siblings = (0..256usize)
        .filter_map(|depth| {
            let child_depth = (depth + 1) as i16;
            let path = map_sibling_prefix(&map_key, depth);
            map_siblings
                .get(&(child_depth, path))
                .copied()
                .filter(|hash| *hash != defaults[depth + 1])
                .map(|hash| TransparencyMapSibling {
                    depth: depth as u16,
                    hash: hex::encode(hash),
                })
        })
        .collect();

    let authentication =
        load_checkpoint_authentication(tx, tree_size, &log_id, root, map_root).await?;

    let proof = ManifestTransparencyProof {
        leaf_index,
        leaf,
        checkpoint: TransparencyCheckpoint {
            log_id: log_id.trim_end().to_string(),
            tree_size,
            root_hash: hex::encode(root),
        },
        inclusion,
        consistency_from: known_tree_size,
        consistency,
        map: ManifestTransparencyMapProof {
            root_hash: hex::encode(map_root),
            checkpoint_leaf_index: map_checkpoint_index,
            checkpoint_inclusion: map_checkpoint_inclusion,
            siblings,
        },
        authentication,
    };
    proof
        .verify_authentication()
        .map_err(|error| AppError::internal(format!("stored transparency signature: {error}")))?;
    Ok(proof)
}

/// Return at most 64 complete accepted manifests from a checkpoint-stable
/// interval. The current mutable manifest table is never used as history.
#[allow(clippy::too_many_arguments)]
pub async fn prove_manifest_range(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    account: &str,
    from_version: u64,
    to_version: u64,
    page_from_version: u64,
    cursor: Option<&str>,
    known_tree_size: u64,
) -> AppResult<ManifestUpdateRangeProofV1> {
    if from_version == 0
        || to_version < from_version
        || page_from_version < from_version
        || page_from_version > to_version
    {
        return Err(AppError::bad_request(
            "manifest history versions must be positive and ordered",
        ));
    }
    let latest_version: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(version) FROM chat_device_manifest_history WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let latest_version = latest_version
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| AppError::not_found("chat manifest history not found"))?;
    if to_version > latest_version {
        return Err(AppError::not_found(
            "requested manifest history range does not exist",
        ));
    }

    // This obtains one shared log snapshot and all current map/authentication
    // material. The transaction keeps the head stable while page proofs load.
    let current = prove_manifest(tx, user_id, known_tree_size).await?;
    let expected_cursor = if page_from_version == from_version {
        None
    } else {
        Some(
            manifest_range_cursor(
                account,
                from_version,
                to_version,
                page_from_version,
                &current.checkpoint,
            )
            .map_err(AppError::internal)?,
        )
    };
    if cursor != expected_cursor.as_deref() {
        return Err(AppError::conflict(
            "manifest range cursor does not match the fixed checkpoint",
        ));
    }

    let page_to_limit = page_from_version.saturating_add(63).min(to_version);
    let rows: Vec<(i64, serde_json::Value, i64, String, String, String)> = sqlx::query_as(
        "SELECT h.version, h.manifest, h.leaf_position, l.username,
                l.manifest_hash, l.authority_key_id
         FROM chat_device_manifest_history h
         JOIN chat_transparency_leaves l ON l.position = h.leaf_position
         WHERE h.user_id = $1 AND h.version BETWEEN $2 AND $3
         ORDER BY h.version",
    )
    .bind(user_id)
    .bind(page_from_version as i64)
    .bind(page_to_limit as i64)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() != (page_to_limit - page_from_version + 1) as usize {
        return Err(AppError::conflict(
            "manifest history is incomplete for the requested range",
        ));
    }
    let mut entries = Vec::with_capacity(rows.len());
    for (version, value, position, username, manifest_hash, authority_key_id) in rows {
        let version = u64::try_from(version)
            .map_err(|_| AppError::internal("negative manifest history version"))?;
        let leaf_index = u64::try_from(position)
            .map_err(|_| AppError::internal("negative manifest history position"))?;
        let manifest: DeviceManifest = serde_json::from_value(value).map_err(|error| {
            AppError::internal(format!("stored manifest history is invalid: {error}"))
        })?;
        let leaf = ManifestTransparencyLeaf {
            username,
            manifest_version: version,
            manifest_hash,
            authority_key_id,
        };
        leaf.matches_manifest(&leaf.username, &manifest)
            .map_err(AppError::internal)?;
        entries.push(ManifestUpdateRangeEntryV1 {
            manifest,
            leaf_index,
            leaf,
            inclusion: prove_leaf_inclusion(tx, leaf_index, current.checkpoint.tree_size).await?,
        });
    }
    let next_cursor = if page_to_limit < to_version {
        Some(
            manifest_range_cursor(
                account,
                from_version,
                to_version,
                page_to_limit + 1,
                &current.checkpoint,
            )
            .map_err(AppError::internal)?,
        )
    } else {
        None
    };
    Ok(ManifestUpdateRangeProofV1 {
        account: account.to_string(),
        from_version,
        to_version,
        page_from_version,
        page_to_version: page_to_limit,
        entries,
        checkpoint: current.checkpoint,
        authentication: current.authentication,
        consistency_from: current.consistency_from,
        consistency: current.consistency,
        latest_leaf: current.leaf,
        latest_map: current.map,
        next_cursor,
    })
}

async fn prove_leaf_inclusion(
    tx: &mut Transaction<'_, Postgres>,
    leaf_index: u64,
    tree_size: u64,
) -> AppResult<Vec<String>> {
    let mut expressions = Vec::new();
    inclusion_path(0, tree_size, leaf_index, &mut expressions)?;
    let mut coordinates = BTreeSet::new();
    for expression in &expressions {
        collect_stored(expression, &mut coordinates);
    }
    let mut hashes = BTreeMap::new();
    for (level, node_index) in coordinates {
        hashes.insert((level, node_index), load_node(tx, level, node_index).await?);
    }
    expressions
        .iter()
        .map(|expression| evaluate(expression, &hashes).map(hex::encode))
        .collect()
}

/// Return the independently monitorable signed head without touching any user
/// bundle or one-time prekey state.
pub async fn prove_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    known_tree_size: u64,
) -> AppResult<TransparencyCheckpointResponse> {
    let (log_id, tree_size): (String, i64) = sqlx::query_as(
        "SELECT log_id, tree_size FROM chat_transparency_log
         WHERE singleton = true FOR SHARE",
    )
    .fetch_one(&mut **tx)
    .await?;
    let tree_size = u64::try_from(tree_size)
        .map_err(|_| AppError::internal("invalid transparency tree size"))?;
    if tree_size == 0 {
        return Err(AppError::not_found("transparency log is empty"));
    }
    if known_tree_size > tree_size {
        return Err(AppError::conflict(
            "transparency checkpoint is newer than this server view",
        ));
    }
    let (position, map_root): (i64, Vec<u8>) = sqlx::query_as(
        "SELECT position, map_root FROM chat_transparency_map_checkpoints
         ORDER BY position DESC LIMIT 1",
    )
    .fetch_one(&mut **tx)
    .await?;
    let position = u64::try_from(position)
        .map_err(|_| AppError::internal("invalid transparency map position"))?;
    if position.checked_add(1) != Some(tree_size) {
        return Err(AppError::internal(
            "transparency map checkpoint is not the log head",
        ));
    }
    let map_root = hash_from_bytes(&map_root)?;
    let root_expr = range_expr(0, tree_size)?;
    let mut consistency_exprs = Vec::new();
    if known_tree_size != 0 && known_tree_size != tree_size {
        consistency_path(known_tree_size, 0, tree_size, true, &mut consistency_exprs)?;
    }
    let mut coordinates = BTreeSet::new();
    collect_stored(&root_expr, &mut coordinates);
    for expr in &consistency_exprs {
        collect_stored(expr, &mut coordinates);
    }
    let mut hashes = BTreeMap::new();
    for (level, node_index) in coordinates {
        hashes.insert((level, node_index), load_node(tx, level, node_index).await?);
    }
    let root = evaluate(&root_expr, &hashes)?;
    let checkpoint = TransparencyCheckpoint {
        log_id: log_id.trim_end().to_string(),
        tree_size,
        root_hash: hex::encode(root),
    };
    let authentication =
        load_checkpoint_authentication(tx, tree_size, &log_id, root, map_root).await?;
    let response = TransparencyCheckpointResponse {
        checkpoint,
        map_root: hex::encode(map_root),
        authentication,
        consistency_from: known_tree_size,
        consistency: consistency_exprs
            .iter()
            .map(|expr| evaluate(expr, &hashes).map(hex::encode))
            .collect::<AppResult<Vec<_>>>()?,
    };
    response
        .authentication
        .verify(&response.checkpoint, &response.map_root)
        .map_err(|error| AppError::internal(format!("stored transparency head: {error}")))?;
    Ok(response)
}

/// Accept a self-authenticating observation only when its public identity is
/// present in the administrator's out-of-band witness allowlist.
pub async fn submit_witness_attestation(
    pool: &PgPool,
    authority: &TransparencyAuthority,
    request: &SubmitTransparencyWitnessRequest,
) -> AppResult<bool> {
    let trusted = authority
        .trusted_witnesses
        .get(&request.attestation.witness_id)
        .ok_or_else(|| AppError::unauthorized("untrusted transparency witness"))?;
    if !trusted.matches(&request.attestation) {
        return Err(AppError::unauthorized(
            "transparency witness key does not match policy",
        ));
    }
    let tree_size = i64::try_from(request.tree_size)
        .map_err(|_| AppError::bad_request("transparency tree size is too large"))?;
    let mut tx = pool.begin().await?;
    let signed: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT log_id, root_hash, map_root
         FROM chat_transparency_signed_checkpoints WHERE tree_size = $1",
    )
    .bind(tree_size)
    .fetch_optional(&mut *tx)
    .await?;
    let (log_id, root, map_root) =
        signed.ok_or_else(|| AppError::not_found("transparency checkpoint is unknown"))?;
    let root = hash_from_bytes(&root)?;
    let map_root = hash_from_bytes(&map_root)?;
    let checkpoint = TransparencyCheckpoint {
        log_id: log_id.trim_end().to_string(),
        tree_size: request.tree_size,
        root_hash: hex::encode(root),
    };
    let authentication =
        load_checkpoint_authentication(&mut tx, request.tree_size, &log_id, root, map_root).await?;
    request
        .attestation
        .verify(&authentication, &checkpoint, &hex::encode(map_root))
        .map_err(AppError::bad_request)?;
    if request.attestation.observed_at > OffsetDateTime::now_utc().unix_timestamp() + 300 {
        return Err(AppError::bad_request(
            "transparency witness observation is too far in the future",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO chat_transparency_witness_attestations
             (tree_size, witness_id, observed_at, key_id, public_key, signature)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tree_size, witness_id) DO NOTHING",
    )
    .bind(tree_size)
    .bind(&request.attestation.witness_id)
    .bind(request.attestation.observed_at)
    .bind(&request.attestation.key_id)
    .bind(&request.attestation.public_key)
    .bind(&request.attestation.signature)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !inserted {
        let existing: (i64, String, String, String) = sqlx::query_as(
            "SELECT observed_at, key_id, public_key, signature
             FROM chat_transparency_witness_attestations
             WHERE tree_size = $1 AND witness_id = $2",
        )
        .bind(tree_size)
        .bind(&request.attestation.witness_id)
        .fetch_one(&mut *tx)
        .await?;
        if existing
            != (
                request.attestation.observed_at,
                request.attestation.key_id.clone(),
                request.attestation.public_key.clone(),
                request.attestation.signature.clone(),
            )
        {
            return Err(AppError::conflict(
                "witness already submitted a different statement for this checkpoint",
            ));
        }
    }
    tx.commit().await?;
    Ok(inserted)
}

async fn load_checkpoint_authentication(
    tx: &mut Transaction<'_, Postgres>,
    tree_size: u64,
    log_id: &str,
    root: TransparencyHash,
    map_root: TransparencyHash,
) -> AppResult<TransparencyCheckpointAuthentication> {
    let tree_size = i64::try_from(tree_size)
        .map_err(|_| AppError::internal("transparency tree size does not fit the database"))?;
    let signed: Option<SignedCheckpointRow> = sqlx::query_as(
        "SELECT log_id, root_hash, map_root, issued_at, operator_key_id,
                operator_public_key, operator_signature
         FROM chat_transparency_signed_checkpoints WHERE tree_size = $1",
    )
    .bind(tree_size)
    .fetch_optional(&mut **tx)
    .await?;
    let signed =
        signed.ok_or_else(|| AppError::internal("transparency head is not operator-signed"))?;
    if signed.log_id.trim_end() != log_id.trim_end()
        || hash_from_bytes(&signed.root_hash)? != root
        || hash_from_bytes(&signed.map_root)? != map_root
    {
        return Err(AppError::internal(
            "signed transparency checkpoint contradicts the log head",
        ));
    }
    let witnesses: Vec<(String, i64, String, String, String)> = sqlx::query_as(
        "SELECT witness_id, observed_at, key_id, public_key, signature
         FROM chat_transparency_witness_attestations
         WHERE tree_size = $1 ORDER BY witness_id",
    )
    .bind(tree_size)
    .fetch_all(&mut **tx)
    .await?;
    Ok(TransparencyCheckpointAuthentication {
        issued_at: signed.issued_at,
        operator_key_id: signed.operator_key_id.trim_end().to_string(),
        operator_public_key: signed.operator_public_key,
        operator_signature: signed.operator_signature,
        witnesses: witnesses
            .into_iter()
            .map(|(witness_id, observed_at, key_id, public_key, signature)| {
                TransparencyWitnessAttestation {
                    witness_id,
                    observed_at,
                    key_id: key_id.trim_end().to_string(),
                    public_key,
                    signature,
                }
            })
            .collect(),
    })
}

async fn update_current_map(
    tx: &mut Transaction<'_, Postgres>,
    leaf: &ManifestTransparencyLeaf,
) -> AppResult<TransparencyHash> {
    let key = transparency_map_key(&leaf.username).map_err(AppError::internal)?;
    let siblings = load_map_siblings(tx, &key).await?;
    let defaults = transparency_map_empty_hashes();
    let mut node = hash_transparency_map_leaf(leaf).map_err(AppError::internal)?;
    let mut nodes = Vec::with_capacity(257);
    nodes.push((256i16, key, node));

    for depth in (0..256usize).rev() {
        let child_depth = (depth + 1) as i16;
        let sibling_path = map_sibling_prefix(&key, depth);
        let sibling = siblings
            .get(&(child_depth, sibling_path))
            .copied()
            .unwrap_or(defaults[depth + 1]);
        node = if map_key_bit(&key, depth) == 0 {
            hash_transparency_node(node, sibling)
        } else {
            hash_transparency_node(sibling, node)
        };
        nodes.push((depth as i16, map_prefix(&key, depth), node));
    }

    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO chat_transparency_map_nodes (depth, path, hash) ",
    );
    query.push_values(nodes, |mut row, (depth, path, hash)| {
        row.push_bind(depth)
            .push_bind(path.as_slice().to_vec())
            .push_bind(hash.as_slice().to_vec());
    });
    query.push(" ON CONFLICT (depth, path) DO UPDATE SET hash = EXCLUDED.hash");
    query.build().execute(&mut **tx).await?;
    Ok(node)
}

async fn load_map_siblings(
    tx: &mut Transaction<'_, Postgres>,
    key: &TransparencyHash,
) -> AppResult<BTreeMap<(i16, TransparencyHash), TransparencyHash>> {
    let coordinates = (0..256usize)
        .map(|depth| ((depth + 1) as i16, map_sibling_prefix(key, depth)))
        .collect::<Vec<_>>();
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT depth, path, hash FROM chat_transparency_map_nodes WHERE (depth, path) IN (",
    );
    for (index, (depth, path)) in coordinates.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query
            .push("(")
            .push_bind(*depth)
            .push(", ")
            .push_bind(path.as_slice().to_vec())
            .push(")");
    }
    query.push(")");
    let rows: Vec<(i16, Vec<u8>, Vec<u8>)> = query.build_query_as().fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|(depth, path, hash)| Ok(((depth, hash_from_bytes(&path)?), hash_from_bytes(&hash)?)))
        .collect()
}

fn map_prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
    debug_assert!(depth <= 256);
    let mut path = *key;
    let full_bytes = depth / 8;
    let remaining_bits = depth % 8;
    if remaining_bits == 0 {
        path[full_bytes..].fill(0);
    } else {
        path[full_bytes] &= 0xff << (8 - remaining_bits);
        path[full_bytes + 1..].fill(0);
    }
    path
}

fn map_sibling_prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
    let child_depth = depth + 1;
    let mut path = map_prefix(key, child_depth);
    path[depth / 8] ^= 1 << (7 - (depth % 8));
    path
}

async fn append_map_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    map_root: TransparencyHash,
    authority: &TransparencyAuthority,
) -> AppResult<()> {
    let leaf_hash = hash_transparency_map_checkpoint(map_root);
    let position = append_log_leaf(tx, leaf_hash).await?;
    sqlx::query(
        "INSERT INTO chat_transparency_map_checkpoints (position, map_root, leaf_hash)
         VALUES ($1,$2,$3)",
    )
    .bind(position)
    .bind(map_root.as_slice())
    .bind(leaf_hash.as_slice())
    .execute(&mut **tx)
    .await?;
    sign_checkpoint(tx, position + 1, map_root, authority).await?;
    Ok(())
}

async fn sign_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    tree_size: i64,
    map_root: TransparencyHash,
    authority: &TransparencyAuthority,
) -> AppResult<()> {
    if tree_size <= 0 {
        return Err(AppError::internal(
            "cannot sign an empty transparency checkpoint",
        ));
    }
    let (log_id, stored_size): (String, i64) = sqlx::query_as(
        "SELECT log_id, tree_size FROM chat_transparency_log WHERE singleton = true",
    )
    .fetch_one(&mut **tx)
    .await?;
    if stored_size != tree_size {
        return Err(AppError::internal(
            "transparency log moved before checkpoint signing",
        ));
    }
    let size = u64::try_from(tree_size)
        .map_err(|_| AppError::internal("invalid transparency tree size"))?;
    let root_expr = range_expr(0, size)?;
    let mut coordinates = BTreeSet::new();
    collect_stored(&root_expr, &mut coordinates);
    let mut hashes = BTreeMap::new();
    for (level, node_index) in coordinates {
        hashes.insert((level, node_index), load_node(tx, level, node_index).await?);
    }
    let root = evaluate(&root_expr, &hashes)?;
    let checkpoint = TransparencyCheckpoint {
        log_id: log_id.trim_end().to_string(),
        tree_size: size,
        root_hash: hex::encode(root),
    };
    let authentication = TransparencyCheckpointAuthentication::sign(
        &checkpoint,
        &hex::encode(map_root),
        OffsetDateTime::now_utc().unix_timestamp(),
        &authority.signing_key,
    )
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO chat_transparency_signed_checkpoints
             (tree_size, log_id, root_hash, map_root, issued_at,
              operator_key_id, operator_public_key, operator_signature)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tree_size)
    .bind(&checkpoint.log_id)
    .bind(root.as_slice())
    .bind(map_root.as_slice())
    .bind(authentication.issued_at)
    .bind(&authentication.operator_key_id)
    .bind(&authentication.operator_public_key)
    .bind(&authentication.operator_signature)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn append_log_leaf(
    tx: &mut Transaction<'_, Postgres>,
    leaf_hash: TransparencyHash,
) -> AppResult<i64> {
    let tree_size: i64 = sqlx::query_scalar(
        "SELECT tree_size FROM chat_transparency_log WHERE singleton = true FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    let mut level = 0i16;
    let mut node_index = tree_size;
    let mut node_hash = leaf_hash;
    insert_node(tx, level, node_index, node_hash).await?;
    while node_index & 1 == 1 {
        let left = load_node(tx, level, node_index - 1).await?;
        node_hash = hash_transparency_node(left, node_hash);
        node_index >>= 1;
        level += 1;
        insert_node(tx, level, node_index, node_hash).await?;
    }
    sqlx::query(
        "UPDATE chat_transparency_log SET tree_size = tree_size + 1 WHERE singleton = true",
    )
    .execute(&mut **tx)
    .await?;
    Ok(tree_size)
}

fn range_expr(start: u64, size: u64) -> AppResult<HashExpr> {
    if size == 0 {
        return Err(AppError::internal(
            "cannot build an empty transparency range",
        ));
    }
    if size.is_power_of_two() && start.is_multiple_of(size) {
        let level = i16::try_from(size.trailing_zeros())
            .map_err(|_| AppError::internal("transparency level overflow"))?;
        let node_index = i64::try_from(start / size)
            .map_err(|_| AppError::internal("transparency node index overflow"))?;
        return Ok(HashExpr::Stored { level, node_index });
    }
    let split = largest_power_less_than(size);
    Ok(HashExpr::Parent(
        Box::new(range_expr(start, split)?),
        Box::new(range_expr(start + split, size - split)?),
    ))
}

fn inclusion_path(
    start: u64,
    size: u64,
    leaf_index: u64,
    out: &mut Vec<HashExpr>,
) -> AppResult<()> {
    if size == 0 || leaf_index < start || leaf_index >= start + size {
        return Err(AppError::internal("invalid transparency inclusion range"));
    }
    if size == 1 {
        return Ok(());
    }
    let split = largest_power_less_than(size);
    if leaf_index < start + split {
        inclusion_path(start, split, leaf_index, out)?;
        out.push(range_expr(start + split, size - split)?);
    } else {
        inclusion_path(start + split, size - split, leaf_index, out)?;
        out.push(range_expr(start, split)?);
    }
    Ok(())
}

fn consistency_path(
    old_size: u64,
    start: u64,
    new_size: u64,
    complete: bool,
    out: &mut Vec<HashExpr>,
) -> AppResult<()> {
    if old_size == 0 || old_size > new_size {
        return Err(AppError::internal("invalid transparency consistency range"));
    }
    if old_size == new_size {
        if !complete {
            out.push(range_expr(start, new_size)?);
        }
        return Ok(());
    }
    let split = largest_power_less_than(new_size);
    if old_size <= split {
        consistency_path(old_size, start, split, complete, out)?;
        out.push(range_expr(start + split, new_size - split)?);
    } else {
        consistency_path(
            old_size - split,
            start + split,
            new_size - split,
            false,
            out,
        )?;
        out.push(range_expr(start, split)?);
    }
    Ok(())
}

fn largest_power_less_than(value: u64) -> u64 {
    debug_assert!(value > 1);
    1u64 << (63 - (value - 1).leading_zeros())
}

fn collect_stored(expr: &HashExpr, out: &mut BTreeSet<(i16, i64)>) {
    match expr {
        HashExpr::Stored { level, node_index } => {
            out.insert((*level, *node_index));
        }
        HashExpr::Parent(left, right) => {
            collect_stored(left, out);
            collect_stored(right, out);
        }
    }
}

fn evaluate(
    expr: &HashExpr,
    hashes: &BTreeMap<(i16, i64), TransparencyHash>,
) -> AppResult<TransparencyHash> {
    match expr {
        HashExpr::Stored { level, node_index } => hashes
            .get(&(*level, *node_index))
            .copied()
            .ok_or_else(|| AppError::internal("transparency node is missing")),
        HashExpr::Parent(left, right) => Ok(hash_transparency_node(
            evaluate(left, hashes)?,
            evaluate(right, hashes)?,
        )),
    }
}

async fn insert_node(
    tx: &mut Transaction<'_, Postgres>,
    level: i16,
    node_index: i64,
    hash: TransparencyHash,
) -> AppResult<()> {
    sqlx::query("INSERT INTO chat_transparency_nodes (level, node_index, hash) VALUES ($1,$2,$3)")
        .bind(level)
        .bind(node_index)
        .bind(hash.as_slice())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn load_node(
    tx: &mut Transaction<'_, Postgres>,
    level: i16,
    node_index: i64,
) -> AppResult<TransparencyHash> {
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT hash FROM chat_transparency_nodes WHERE level = $1 AND node_index = $2",
    )
    .bind(level)
    .bind(node_index)
    .fetch_optional(&mut **tx)
    .await?;
    hash_from_bytes(&bytes.ok_or_else(|| AppError::internal("transparency node is missing"))?)
}

fn hash_from_bytes(bytes: &[u8]) -> AppResult<TransparencyHash> {
    bytes
        .try_into()
        .map_err(|_| AppError::internal("transparency hash is not 32 bytes"))
}
