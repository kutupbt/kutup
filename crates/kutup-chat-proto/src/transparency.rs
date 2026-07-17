//! Wire primitives and verifier for the append-only device-manifest log.
//!
//! Hashing follows RFC 6962's domain separation: `0x00 || leaf` for leaves and
//! `0x01 || left || right` for interior nodes. The leaf encoding itself is a
//! Kutup-owned, versioned canonical record so all clients derive one root.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::DeviceManifest;

pub type TransparencyHash = [u8; 32];

const LEAF_DOMAIN: &[u8] = b"kutup-chat-transparency-leaf-v1\0";
const MAP_KEY_DOMAIN: &[u8] = b"kutup-chat-transparency-map-key-v1\0";
const MAP_LEAF_DOMAIN: &[u8] = b"kutup-chat-transparency-map-leaf-v1\0";
const MAP_EMPTY_DOMAIN: &[u8] = b"kutup-chat-transparency-map-empty-v1\0";
const MAP_CHECKPOINT_DOMAIN: &[u8] = b"kutup-chat-transparency-map-checkpoint-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestTransparencyLeaf {
    /// Username inside this log's homeserver namespace (never a display name).
    pub username: String,
    pub manifest_version: u64,
    pub manifest_hash: String,
    pub authority_key_id: String,
}

impl ManifestTransparencyLeaf {
    pub fn from_manifest(
        username: impl Into<String>,
        manifest: &DeviceManifest,
    ) -> Result<Self, String> {
        Ok(Self {
            username: username.into(),
            manifest_version: manifest.version,
            manifest_hash: manifest.manifest_hash()?,
            authority_key_id: manifest.authority_key_id.clone(),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.username.is_empty() || self.username.len() > 255 {
            return Err("transparency username must be 1-255 bytes".into());
        }
        if self.manifest_version == 0 {
            return Err("transparency manifest version must be positive".into());
        }
        let manifest_hash = decode_hash("manifestHash", &self.manifest_hash)?;
        let authority_key_id = decode_hash("authorityKeyId", &self.authority_key_id)?;
        let mut out = Vec::with_capacity(LEAF_DOMAIN.len() + self.username.len() + 74);
        out.extend_from_slice(LEAF_DOMAIN);
        let username_len =
            u16::try_from(self.username.len()).map_err(|_| "transparency username is too long")?;
        out.extend_from_slice(&username_len.to_be_bytes());
        out.extend_from_slice(self.username.as_bytes());
        out.extend_from_slice(&self.manifest_version.to_be_bytes());
        out.extend_from_slice(&manifest_hash);
        out.extend_from_slice(&authority_key_id);
        Ok(out)
    }

    pub fn hash(&self) -> Result<TransparencyHash, String> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    pub fn matches_manifest(
        &self,
        username: &str,
        manifest: &DeviceManifest,
    ) -> Result<(), String> {
        if self.username != username
            || self.manifest_version != manifest.version
            || self.manifest_hash != manifest.manifest_hash()?
            || self.authority_key_id != manifest.authority_key_id
        {
            return Err("transparency leaf does not match the served manifest".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyCheckpoint {
    /// Stable random identifier for one homeserver log database.
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash: String,
}

impl TransparencyCheckpoint {
    pub fn validate(&self) -> Result<TransparencyHash, String> {
        decode_hash("logId", &self.log_id)?;
        decode_hash("rootHash", &self.root_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestTransparencyProof {
    /// Zero-based position of `leaf` in the append-only log.
    pub leaf_index: u64,
    pub leaf: ManifestTransparencyLeaf,
    pub checkpoint: TransparencyCheckpoint,
    /// Inclusion audit path, deepest sibling first, as lowercase SHA-256 hex.
    pub inclusion: Vec<String>,
    /// Tree size whose pinned root the consistency proof starts from. Zero is
    /// the first-observation sentinel and requires an empty proof.
    pub consistency_from: u64,
    /// RFC 6962 consistency path from `consistencyFrom` to `checkpoint.treeSize`.
    pub consistency: Vec<String>,
    /// Proof that this manifest is the account's current value in the sparse
    /// account map committed by the final leaf of `checkpoint`.
    pub map: ManifestTransparencyMapProof,
}

impl ManifestTransparencyProof {
    pub fn verify_inclusion(&self) -> Result<(), String> {
        let root = self.checkpoint.validate()?;
        let path = decode_path("inclusion", &self.inclusion)?;
        verify_inclusion(
            self.leaf.hash()?,
            self.leaf_index,
            self.checkpoint.tree_size,
            &path,
            root,
        )
    }

    pub fn verify_consistency_from(
        &self,
        prior: Option<&TransparencyCheckpoint>,
    ) -> Result<(), String> {
        let new_root = self.checkpoint.validate()?;
        let proof = decode_path("consistency", &self.consistency)?;
        match prior {
            None => {
                if self.consistency_from != 0 || !proof.is_empty() {
                    return Err("first transparency checkpoint must start at size zero".into());
                }
                Ok(())
            }
            Some(prior) => {
                let old_root = prior.validate()?;
                if prior.log_id != self.checkpoint.log_id {
                    return Err("transparency log identity changed".into());
                }
                if self.consistency_from != prior.tree_size {
                    return Err(
                        "transparency consistency proof starts at the wrong tree size".into(),
                    );
                }
                verify_consistency(
                    prior.tree_size,
                    self.checkpoint.tree_size,
                    old_root,
                    new_root,
                    &proof,
                )
            }
        }
    }

    pub fn verify_current_map(&self) -> Result<(), String> {
        self.map.verify(&self.leaf, &self.checkpoint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TransparencyMapSibling {
    /// Zero-based bit depth in the SHA-256 account-map key (0 is the root).
    pub depth: u16,
    /// Non-default sibling hash at child depth `depth + 1`.
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ManifestTransparencyMapProof {
    /// Current sparse-map root.
    pub root_hash: String,
    /// Position of the map-root commitment in the chronological log.
    pub checkpoint_leaf_index: u64,
    /// RFC 6962 inclusion path for the map-root commitment.
    pub checkpoint_inclusion: Vec<String>,
    /// Compressed sparse-map membership path. Default empty siblings are
    /// omitted and reconstructed by the verifier.
    pub siblings: Vec<TransparencyMapSibling>,
}

impl ManifestTransparencyMapProof {
    pub fn verify(
        &self,
        leaf: &ManifestTransparencyLeaf,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<(), String> {
        let expected_root = decode_hash("map rootHash", &self.root_hash)?;
        if checkpoint.tree_size == 0
            || self.checkpoint_leaf_index.checked_add(1) != Some(checkpoint.tree_size)
        {
            return Err("current map commitment must be the checkpoint's final leaf".into());
        }

        let defaults = transparency_map_empty_hashes();
        let mut siblings = BTreeMap::new();
        for sibling in &self.siblings {
            if sibling.depth >= 256 {
                return Err("transparency map sibling depth is out of range".into());
            }
            let hash = decode_hash("map sibling", &sibling.hash)?;
            if hash == defaults[sibling.depth as usize + 1] {
                return Err("transparency map proof must omit default siblings".into());
            }
            if siblings.insert(sibling.depth, hash).is_some() {
                return Err("transparency map proof repeats a sibling depth".into());
            }
        }

        let key = transparency_map_key(&leaf.username)?;
        let mut actual = hash_transparency_map_leaf(leaf)?;
        for depth in (0..256usize).rev() {
            let sibling = siblings
                .get(&(depth as u16))
                .copied()
                .unwrap_or(defaults[depth + 1]);
            actual = if map_key_bit(&key, depth) == 0 {
                hash_transparency_node(actual, sibling)
            } else {
                hash_transparency_node(sibling, actual)
            };
        }
        if actual != expected_root {
            return Err("manifest is not the current transparency map value".into());
        }

        let log_root = checkpoint.validate()?;
        let inclusion = decode_path("map checkpoint inclusion", &self.checkpoint_inclusion)?;
        verify_inclusion(
            hash_transparency_map_checkpoint(expected_root),
            self.checkpoint_leaf_index,
            checkpoint.tree_size,
            &inclusion,
            log_root,
        )
    }
}

pub fn transparency_map_key(username: &str) -> Result<TransparencyHash, String> {
    if username.is_empty() || username.len() > 255 {
        return Err("transparency username must be 1-255 bytes".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(MAP_KEY_DOMAIN);
    hasher.update((username.len() as u16).to_be_bytes());
    hasher.update(username.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn hash_transparency_map_leaf(
    leaf: &ManifestTransparencyLeaf,
) -> Result<TransparencyHash, String> {
    let key = transparency_map_key(&leaf.username)?;
    let manifest_hash = decode_hash("manifestHash", &leaf.manifest_hash)?;
    let authority_key_id = decode_hash("authorityKeyId", &leaf.authority_key_id)?;
    if leaf.manifest_version == 0 {
        return Err("transparency manifest version must be positive".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(MAP_LEAF_DOMAIN);
    hasher.update(key);
    hasher.update(leaf.manifest_version.to_be_bytes());
    hasher.update(manifest_hash);
    hasher.update(authority_key_id);
    Ok(hasher.finalize().into())
}

pub fn hash_transparency_map_checkpoint(map_root: TransparencyHash) -> TransparencyHash {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(MAP_CHECKPOINT_DOMAIN);
    hasher.update(map_root);
    hasher.finalize().into()
}

pub fn transparency_map_empty_hashes() -> Vec<TransparencyHash> {
    let mut hashes = vec![[0; 32]; 257];
    hashes[256] = Sha256::digest(MAP_EMPTY_DOMAIN).into();
    for depth in (0..256).rev() {
        hashes[depth] = hash_transparency_node(hashes[depth + 1], hashes[depth + 1]);
    }
    hashes
}

pub fn map_key_bit(key: &TransparencyHash, depth: usize) -> u8 {
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

pub fn empty_transparency_root() -> TransparencyHash {
    Sha256::digest([]).into()
}

pub fn hash_transparency_node(left: TransparencyHash, right: TransparencyHash) -> TransparencyHash {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub(crate) fn largest_power_of_two_less_than(value: u64) -> u64 {
    debug_assert!(value > 1);
    1u64 << (63 - (value - 1).leading_zeros())
}

fn verify_inclusion(
    leaf_hash: TransparencyHash,
    leaf_index: u64,
    tree_size: u64,
    proof: &[TransparencyHash],
    expected_root: TransparencyHash,
) -> Result<(), String> {
    if tree_size == 0 || leaf_index >= tree_size || proof.len() > 64 {
        return Err("invalid transparency inclusion coordinates".into());
    }
    fn rebuild(
        leaf: TransparencyHash,
        index: u64,
        size: u64,
        proof: &[TransparencyHash],
        cursor: &mut usize,
    ) -> Result<TransparencyHash, String> {
        if size == 1 {
            return Ok(leaf);
        }
        let split = largest_power_of_two_less_than(size);
        if index < split {
            let left = rebuild(leaf, index, split, proof, cursor)?;
            let right = *proof
                .get(*cursor)
                .ok_or_else(|| "transparency inclusion proof is truncated".to_string())?;
            *cursor += 1;
            Ok(hash_transparency_node(left, right))
        } else {
            let right = rebuild(leaf, index - split, size - split, proof, cursor)?;
            let left = *proof
                .get(*cursor)
                .ok_or_else(|| "transparency inclusion proof is truncated".to_string())?;
            *cursor += 1;
            Ok(hash_transparency_node(left, right))
        }
    }
    let mut cursor = 0;
    let actual = rebuild(leaf_hash, leaf_index, tree_size, proof, &mut cursor)?;
    if cursor != proof.len() || actual != expected_root {
        return Err("transparency inclusion proof does not match the checkpoint".into());
    }
    Ok(())
}

fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: TransparencyHash,
    new_root: TransparencyHash,
    proof: &[TransparencyHash],
) -> Result<(), String> {
    if old_size == 0 || old_size > new_size || proof.len() > 64 {
        return Err("invalid transparency consistency coordinates".into());
    }
    if old_size == new_size {
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err("same-size transparency checkpoints disagree".into())
        };
    }

    let mut old_node = old_size - 1;
    let mut new_node = new_size - 1;
    while old_node & 1 == 1 {
        old_node >>= 1;
        new_node >>= 1;
    }

    let (mut old_hash, mut new_hash, mut cursor) = if old_node == 0 {
        (old_root, old_root, 0)
    } else {
        let first = *proof
            .first()
            .ok_or_else(|| "transparency consistency proof is truncated".to_string())?;
        (first, first, 1)
    };

    while cursor < proof.len() {
        if new_node == 0 {
            return Err("transparency consistency proof has extra nodes".into());
        }
        let sibling = proof[cursor];
        cursor += 1;
        if old_node & 1 == 1 || old_node == new_node {
            old_hash = hash_transparency_node(sibling, old_hash);
            new_hash = hash_transparency_node(sibling, new_hash);
            while old_node != 0 && old_node & 1 == 0 {
                old_node >>= 1;
                new_node >>= 1;
            }
        } else {
            new_hash = hash_transparency_node(new_hash, sibling);
        }
        old_node >>= 1;
        new_node >>= 1;
    }

    if new_node != 0 || old_hash != old_root || new_hash != new_root {
        return Err("transparency consistency proof does not link the checkpoints".into());
    }
    Ok(())
}

fn decode_path(name: &str, values: &[String]) -> Result<Vec<TransparencyHash>, String> {
    if values.len() > 64 {
        return Err(format!("{name} proof is too long"));
    }
    values
        .iter()
        .map(|value| decode_hash(name, value))
        .collect()
}

fn decode_hash(name: &str, value: &str) -> Result<TransparencyHash, String> {
    let decoded =
        hex::decode(value).map_err(|_| format!("{name} must be lowercase SHA-256 hex"))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(index: u64) -> TransparencyHash {
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(index.to_be_bytes());
        hasher.finalize().into()
    }

    fn root(leaves: &[TransparencyHash]) -> TransparencyHash {
        match leaves.len() {
            0 => empty_transparency_root(),
            1 => leaves[0],
            len => {
                let split = largest_power_of_two_less_than(len as u64) as usize;
                hash_transparency_node(root(&leaves[..split]), root(&leaves[split..]))
            }
        }
    }

    fn inclusion(index: usize, leaves: &[TransparencyHash]) -> Vec<TransparencyHash> {
        if leaves.len() == 1 {
            return Vec::new();
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        if index < split {
            let mut proof = inclusion(index, &leaves[..split]);
            proof.push(root(&leaves[split..]));
            proof
        } else {
            let mut proof = inclusion(index - split, &leaves[split..]);
            proof.push(root(&leaves[..split]));
            proof
        }
    }

    fn consistency_subproof(
        old_size: usize,
        leaves: &[TransparencyHash],
        complete: bool,
        proof: &mut Vec<TransparencyHash>,
    ) {
        if old_size == leaves.len() {
            if !complete {
                proof.push(root(leaves));
            }
            return;
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        if old_size <= split {
            consistency_subproof(old_size, &leaves[..split], complete, proof);
            proof.push(root(&leaves[split..]));
        } else {
            consistency_subproof(old_size - split, &leaves[split..], false, proof);
            proof.push(root(&leaves[..split]));
        }
    }

    #[test]
    fn inclusion_and_consistency_verify_for_many_tree_shapes() {
        let leaves = (0..64).map(leaf).collect::<Vec<_>>();
        for size in 1..=leaves.len() {
            for index in 0..size {
                verify_inclusion(
                    leaves[index],
                    index as u64,
                    size as u64,
                    &inclusion(index, &leaves[..size]),
                    root(&leaves[..size]),
                )
                .unwrap();
            }
            for old_size in 1..=size {
                let mut proof = Vec::new();
                if old_size != size {
                    consistency_subproof(old_size, &leaves[..size], true, &mut proof);
                }
                verify_consistency(
                    old_size as u64,
                    size as u64,
                    root(&leaves[..old_size]),
                    root(&leaves[..size]),
                    &proof,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn tampered_paths_and_same_size_equivocation_fail() {
        let leaves = (0..5).map(leaf).collect::<Vec<_>>();
        let mut path = inclusion(3, &leaves);
        path[0][0] ^= 1;
        assert!(verify_inclusion(leaves[3], 3, 5, &path, root(&leaves)).is_err());
        assert!(verify_consistency(5, 5, root(&leaves), leaf(99), &[]).is_err());
    }

    #[test]
    fn current_map_proof_binds_the_latest_manifest_to_the_log_head() {
        let manifest_leaf = ManifestTransparencyLeaf {
            username: "alice".into(),
            manifest_version: 3,
            manifest_hash: "11".repeat(32),
            authority_key_id: "22".repeat(32),
        };
        let key = transparency_map_key("alice").unwrap();
        let defaults = transparency_map_empty_hashes();
        let mut map_root = hash_transparency_map_leaf(&manifest_leaf).unwrap();
        for depth in (0..256).rev() {
            map_root = if map_key_bit(&key, depth) == 0 {
                hash_transparency_node(map_root, defaults[depth + 1])
            } else {
                hash_transparency_node(defaults[depth + 1], map_root)
            };
        }
        let log_root = hash_transparency_map_checkpoint(map_root);
        let checkpoint = TransparencyCheckpoint {
            log_id: "33".repeat(32),
            tree_size: 1,
            root_hash: hex::encode(log_root),
        };
        let proof = ManifestTransparencyMapProof {
            root_hash: hex::encode(map_root),
            checkpoint_leaf_index: 0,
            checkpoint_inclusion: Vec::new(),
            siblings: Vec::new(),
        };
        proof.verify(&manifest_leaf, &checkpoint).unwrap();

        let mut tampered = manifest_leaf.clone();
        tampered.manifest_version += 1;
        assert!(proof.verify(&tampered, &checkpoint).is_err());
        let mut stale = proof.clone();
        stale.checkpoint_leaf_index = 1;
        assert!(stale.verify(&manifest_leaf, &checkpoint).is_err());
    }

    #[test]
    fn sparse_current_map_proves_many_accounts_and_rejects_omission() {
        fn prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
            let mut path = *key;
            let bytes = depth / 8;
            let bits = depth % 8;
            if bits == 0 {
                path[bytes..].fill(0);
            } else {
                path[bytes] &= 0xff << (8 - bits);
                path[bytes + 1..].fill(0);
            }
            path
        }
        fn sibling_prefix(key: &TransparencyHash, depth: usize) -> TransparencyHash {
            let mut path = prefix(key, depth + 1);
            path[depth / 8] ^= 1 << (7 - depth % 8);
            path
        }
        fn build(
            leaves: &[ManifestTransparencyLeaf],
            target: &ManifestTransparencyLeaf,
        ) -> (TransparencyHash, Vec<TransparencyMapSibling>) {
            let defaults = transparency_map_empty_hashes();
            let mut nodes = BTreeMap::new();
            for leaf in leaves {
                let key = transparency_map_key(&leaf.username).unwrap();
                let mut node = hash_transparency_map_leaf(leaf).unwrap();
                nodes.insert((256usize, key), node);
                for depth in (0..256).rev() {
                    let sibling = nodes
                        .get(&(depth + 1, sibling_prefix(&key, depth)))
                        .copied()
                        .unwrap_or(defaults[depth + 1]);
                    node = if map_key_bit(&key, depth) == 0 {
                        hash_transparency_node(node, sibling)
                    } else {
                        hash_transparency_node(sibling, node)
                    };
                    nodes.insert((depth, prefix(&key, depth)), node);
                }
            }
            let root = nodes[&(0, [0; 32])];
            let key = transparency_map_key(&target.username).unwrap();
            let siblings = (0..256)
                .filter_map(|depth| {
                    nodes
                        .get(&(depth + 1, sibling_prefix(&key, depth)))
                        .copied()
                        .filter(|hash| *hash != defaults[depth + 1])
                        .map(|hash| TransparencyMapSibling {
                            depth: depth as u16,
                            hash: hex::encode(hash),
                        })
                })
                .collect();
            (root, siblings)
        }

        let leaves = (0..16)
            .map(|index| ManifestTransparencyLeaf {
                username: format!("user{index}"),
                manifest_version: index + 1,
                manifest_hash: format!("{index:02x}").repeat(32),
                authority_key_id: format!("{:02x}", index + 16).repeat(32),
            })
            .collect::<Vec<_>>();
        for target in &leaves {
            let (map_root, siblings) = build(&leaves, target);
            let checkpoint = TransparencyCheckpoint {
                log_id: "44".repeat(32),
                tree_size: 1,
                root_hash: hex::encode(hash_transparency_map_checkpoint(map_root)),
            };
            let proof = ManifestTransparencyMapProof {
                root_hash: hex::encode(map_root),
                checkpoint_leaf_index: 0,
                checkpoint_inclusion: Vec::new(),
                siblings,
            };
            proof.verify(target, &checkpoint).unwrap();
            if !proof.siblings.is_empty() {
                let mut omitted = proof.clone();
                omitted.siblings.pop();
                assert!(omitted.verify(target, &checkpoint).is_err());
            }
        }
    }
}
