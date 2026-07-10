//! tus.io 1.0 protocol client — mirrors `internal/api/tus.go`.
//! Companion to `backend/handlers/tus.go`.

use anyhow::{bail, Context, Result};
use base64::Engine;
use reqwest::Method;

use super::{api_error, Client};

const TUS_VERSION: &str = "1.0.0";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl Client {
    /// Opens a new tus session; `total_bytes` is the ciphertext byte count.
    /// Returns the upload id from the `Location` header. Mirrors `TusCreate`.
    #[allow(clippy::too_many_arguments)]
    pub fn tus_create(
        &self,
        total_bytes: i64,
        collection_id: &str,
        encrypted_metadata: &str,
        metadata_nonce: &str,
        encrypted_file_key: &str,
        file_key_nonce: &str,
    ) -> Result<String> {
        // Upload-Metadata values are base64 per the tus spec (the metadata
        // strings are themselves already base64 — double-encoded, matching Go).
        let upload_meta = [
            format!("collectionId {}", b64(collection_id.as_bytes())),
            format!("encryptedMetadata {}", b64(encrypted_metadata.as_bytes())),
            format!("metadataNonce {}", b64(metadata_nonce.as_bytes())),
            format!("encryptedFileKey {}", b64(encrypted_file_key.as_bytes())),
            format!("fileKeyNonce {}", b64(file_key_nonce.as_bytes())),
        ]
        .join(",");

        let resp = self
            .upload_request(Method::POST, "/uploads/")
            .header("Tus-Resumable", TUS_VERSION)
            .header("Upload-Length", total_bytes.to_string())
            .header("Upload-Metadata", upload_meta)
            .send()?;

        if resp.status().as_u16() != 201 {
            return Err(api_error(resp)).context("tus create");
        }
        let loc = resp
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        match loc.rsplit('/').next() {
            Some(id) if !id.is_empty() => Ok(id.to_string()),
            _ => bail!("tus create: missing/garbled Location header {loc:?}"),
        }
    }

    /// Returns `(offset, length)` for resume. Mirrors `TusHead`.
    pub fn tus_head(&self, upload_id: &str) -> Result<(i64, i64)> {
        let resp = self
            .request(Method::HEAD, &format!("/uploads/{upload_id}"))
            .header("Tus-Resumable", TUS_VERSION)
            .send()?;
        if resp.status().as_u16() != 200 {
            return Err(api_error(resp)).context("tus head");
        }
        let offset = header_i64(&resp, "Upload-Offset");
        let length = header_i64(&resp, "Upload-Length");
        Ok((offset, length))
    }

    /// Ships one chunk; returns `(new_offset, file_id)` — `file_id` is only set
    /// on the final chunk. Mirrors `TusPatch`.
    pub fn tus_patch(&self, upload_id: &str, offset: i64, body: Vec<u8>) -> Result<(i64, String)> {
        let len = body.len();
        let resp = self
            .upload_request(Method::PATCH, &format!("/uploads/{upload_id}"))
            .header("Tus-Resumable", TUS_VERSION)
            .header("Upload-Offset", offset.to_string())
            .header("Content-Type", "application/offset+octet-stream")
            .header("Content-Length", len.to_string())
            .body(body)
            .send()?;
        if resp.status().as_u16() != 204 {
            return Err(api_error(resp)).context("tus patch");
        }
        let new_offset = header_i64(&resp, "Upload-Offset");
        let file_id = resp
            .headers()
            .get("X-Kutup-File-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        Ok((new_offset, file_id))
    }

    /// Cancels an in-flight upload (best-effort). Mirrors `TusDelete`.
    pub fn tus_delete(&self, upload_id: &str) -> Result<()> {
        let resp = self
            .request(Method::DELETE, &format!("/uploads/{upload_id}"))
            .header("Tus-Resumable", TUS_VERSION)
            .send()?;
        let code = resp.status().as_u16();
        if code != 204 && code != 404 {
            return Err(api_error(resp)).context("tus delete");
        }
        Ok(())
    }
}

fn header_i64(resp: &reqwest::blocking::Response, name: &str) -> i64 {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}
