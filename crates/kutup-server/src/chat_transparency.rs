//! Append-only device-manifest transparency log.
//!
//! PostgreSQL stores every complete aligned subtree, so appends and proof
//! reads are logarithmic. The cryptographic verifier and wire encoding live in
//! `kutup-chat-proto`, shared by browser/native clients.

use std::collections::{BTreeMap, BTreeSet};

use kutup_chat_proto::{
    hash_transparency_map_checkpoint, hash_transparency_map_leaf, hash_transparency_node,
    map_key_bit, transparency_map_empty_hashes, transparency_map_key, DeviceManifest,
    ManifestTransparencyLeaf, ManifestTransparencyMapProof, ManifestTransparencyProof,
    TransparencyCheckpoint, TransparencyHash, TransparencyMapSibling,
};
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Clone, Debug)]
enum HashExpr {
    Stored { level: i16, node_index: i64 },
    Parent(Box<HashExpr>, Box<HashExpr>),
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
pub async fn backfill_current_map(pool: &PgPool) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT position FROM chat_transparency_map_checkpoints ORDER BY position DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        tx.rollback().await?;
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
    append_map_checkpoint(&mut tx, root.expect("non-empty map has a root"))
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
) -> AppResult<()> {
    append_manifest(tx, user_id, username, manifest).await?;
    let leaf =
        ManifestTransparencyLeaf::from_manifest(username, manifest).map_err(AppError::internal)?;
    let map_root = update_current_map(tx, &leaf).await?;
    append_map_checkpoint(tx, map_root).await?;
    Ok(())
}

pub async fn append_manifest(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    username: &str,
    manifest: &DeviceManifest,
) -> AppResult<()> {
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

    Ok(())
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

    Ok(ManifestTransparencyProof {
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
