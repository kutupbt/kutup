//! Trash API — list, restore, permanently delete (`/api/trash*`).
//! Companion to `crates/kutup-server/src/handlers/trash.rs`.

use anyhow::Result;
use reqwest::Method;
use serde::Deserialize;

use super::Client;

/// `GET /api/trash` body — the caller's trash roots, newest first.
#[derive(Debug, Deserialize)]
pub struct TrashResponse {
    #[serde(default)]
    pub folders: Vec<TrashFolder>,
    #[serde(default)]
    pub files: Vec<TrashFile>,
}

/// A trashed folder root with its complete authenticated collection record.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashFolder {
    pub id: String,
    #[serde(default)]
    pub owner_user_id: String,
    #[serde(default)]
    pub name_envelope: String,
    #[serde(default)]
    pub owner_key_envelope: String,
    #[serde(default)]
    pub key_epoch: u32,
    #[serde(default)]
    pub name_revision: u64,
    #[serde(default)]
    pub epoch_statement: String,
    #[serde(default)]
    pub epoch_statement_hash: String,
    #[serde(default)]
    pub color: Option<String>,
    /// Files trashed together with this folder (its whole subtree).
    #[serde(default)]
    pub items: i64,
    #[serde(default)]
    pub deleted_at: String,
}

/// A trashed file root. Carries the parent collection's owner-wrapped key so
/// the metadata chain decrypts even when the collection isn't in the live
/// listing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashFile {
    pub id: String,
    #[serde(default)]
    pub collection_id: String,
    #[serde(default)]
    pub metadata_envelope: String,
    #[serde(default)]
    pub file_key_envelope: String,
    #[serde(default)]
    pub key_epoch: u32,
    #[serde(default)]
    pub metadata_revision: u64,
    #[serde(default)]
    pub collection_owner_user_id: String,
    #[serde(default)]
    pub collection_owner_key_envelope: String,
    #[serde(default)]
    pub collection_key_epoch: u32,
    #[serde(default)]
    pub collection_epoch_statement: String,
    #[serde(default)]
    pub collection_epoch_statement_hash: String,
    #[serde(default)]
    pub deleted_at: String,
}

impl Client {
    /// Lists the caller's trash roots (folders + files), newest first.
    pub fn list_trash(&self) -> Result<TrashResponse> {
        let resp = self.request(Method::GET, "/trash").send()?;
        super::decode_json(resp)
    }

    /// Restores one trashed root to where it was.
    pub fn restore_trash(&self, id: &str) -> Result<()> {
        let resp = self
            .request(Method::POST, &format!("/trash/{id}/restore"))
            .send()?;
        super::check_ok(resp)
    }

    /// Permanently destroys one trashed root (releases quota). Irreversible.
    pub fn purge_trash(&self, id: &str) -> Result<()> {
        let resp = self
            .request(Method::DELETE, &format!("/trash/{id}"))
            .send()?;
        super::check_ok(resp)
    }

    /// Permanently destroys everything in the trash. Irreversible.
    pub fn empty_trash(&self) -> Result<()> {
        let resp = self.request(Method::DELETE, "/trash").send()?;
        super::check_ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::TrashResponse;

    // Field names verified against the server's TrashFolderRow/TrashFileRow
    // (camelCase serde) — this is the wire-shape regression guard.
    #[test]
    fn deserializes_server_shape() {
        let body = r##"{
            "folders": [{
                "id": "f0", "ownerUserId": "u1", "nameEnvelope": "ne",
                "ownerKeyEnvelope": "oke", "keyEpoch": 1, "nameRevision": 1,
                "epochStatement": "es", "epochStatementHash": "esh",
                "color": "#ef4444", "items": 3, "deletedAt": "2026-07-01T10:00:00Z"
            }],
            "files": [{
                "id": "a1", "collectionId": "c1",
                "metadataEnvelope": "me", "fileKeyEnvelope": "fke",
                "keyEpoch": 1, "metadataRevision": 1,
                "collectionOwnerUserId": "u1", "collectionOwnerKeyEnvelope": "oke",
                "collectionKeyEpoch": 1, "collectionEpochStatement": "es",
                "collectionEpochStatementHash": "esh",
                "deletedAt": "2026-07-02T11:30:00Z"
            }]
        }"##;
        let parsed: TrashResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.folders.len(), 1);
        assert_eq!(parsed.folders[0].items, 3);
        assert_eq!(parsed.folders[0].owner_key_envelope, "oke");
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].collection_owner_key_envelope, "oke");
        assert_eq!(parsed.files[0].deleted_at, "2026-07-02T11:30:00Z");
    }
}
