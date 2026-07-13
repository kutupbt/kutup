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

/// A trashed folder root. The owner unwraps `encrypted_key` with the master
/// key, then the name with the collection key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashFolder {
    pub id: String,
    #[serde(default)]
    pub encrypted_name: String,
    #[serde(default)]
    pub name_nonce: String,
    #[serde(default)]
    pub encrypted_key: String,
    #[serde(default)]
    pub encrypted_key_nonce: String,
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
    pub encrypted_metadata: String,
    #[serde(default)]
    pub metadata_nonce: String,
    #[serde(default)]
    pub encrypted_file_key: String,
    #[serde(default)]
    pub file_key_nonce: String,
    #[serde(default)]
    pub collection_encrypted_key: String,
    #[serde(default)]
    pub collection_encrypted_key_nonce: String,
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
                "id": "f0", "encryptedName": "en", "nameNonce": "nn",
                "encryptedKey": "ek", "encryptedKeyNonce": "ekn",
                "color": "#ef4444", "items": 3, "deletedAt": "2026-07-01T10:00:00Z"
            }],
            "files": [{
                "id": "a1", "collectionId": "c1",
                "encryptedMetadata": "em", "metadataNonce": "mn",
                "encryptedFileKey": "efk", "fileKeyNonce": "fkn",
                "collectionEncryptedKey": "cek", "collectionEncryptedKeyNonce": "cekn",
                "deletedAt": "2026-07-02T11:30:00Z"
            }]
        }"##;
        let parsed: TrashResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.folders.len(), 1);
        assert_eq!(parsed.folders[0].items, 3);
        assert_eq!(parsed.folders[0].encrypted_key, "ek");
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].collection_encrypted_key, "cek");
        assert_eq!(parsed.files[0].deleted_at, "2026-07-02T11:30:00Z");
    }
}
