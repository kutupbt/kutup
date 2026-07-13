//! Whiteboard (`.excalidraw`) asset extraction + hydration — the CLI port of
//! the web client's first-open behavior (`WhiteboardEditor.maybeUploadDirtyAssets`)
//! and the removed Go CLI's implementation.
//!
//! Upload side: every image element with an inline `dataURL` gets its binary
//! encrypted as an asset blob (AEAD under the per-file content key derived
//! from the COLLECTION key — see `kutup_crypto::asset`), uploaded, and the
//! element flipped to `status:"saved"`; the modified scene is committed as a
//! fresh snapshot so web/collab clients see the flip.
//!
//! Download side: image elements with `status:"saved"` but no inline
//! `dataURL` get their asset blobs fetched, decrypted, and re-inlined so the
//! on-disk file is self-contained.
//!
//! Both directions are best-effort: failures warn and never break the main
//! transfer. The JSON round-trips through `serde_json::Value`, preserving
//! unknown fields.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::api::versions::RecordSnapshotRequest;
use crate::api::Client;
use kutup_crypto::{asset, stream};

pub fn is_excalidraw(name: &str) -> bool {
    name.to_lowercase().ends_with(".excalidraw")
}

/// Upload-side: extract inline images from the freshly-uploaded whiteboard at
/// `local_path`, upload them as encrypted assets, and re-snapshot the scene.
pub fn extract_and_upload(
    client: &Client,
    file_id: &str,
    file_key: &[u8],
    collection_key: &[u8],
    local_path: &std::path::Path,
) -> Result<()> {
    let raw = std::fs::read(local_path).context("re-read excalidraw")?;
    let mut doc: Value = serde_json::from_slice(&raw).context("parse excalidraw json")?;

    let uploaded = extract_assets(&mut doc, |asset_id, data_url| {
        let ciphertext =
            asset::encrypt_asset(data_url.as_bytes(), file_id, asset_id, collection_key)
                .with_context(|| format!("encrypt asset {asset_id}"))?;
        client
            .upload_asset(file_id, asset_id, ciphertext)
            .with_context(|| format!("upload asset {asset_id}"))
    });
    if uploaded == 0 {
        return Ok(());
    }

    // Commit the status:"saved" flips as a fresh snapshot — the web reads the
    // newest snapshot on open, so it won't re-upload these assets.
    let out = serde_json::to_vec(&doc).context("re-encode excalidraw json")?;
    let encrypted = stream::encrypt_stream(&out, file_key).context("encrypt snapshot")?;
    let size = encrypted.len() as i64;
    let blob = client
        .upload_snapshot_blob(file_id, encrypted)
        .context("upload snapshot blob")?;
    client
        .record_snapshot(
            file_id,
            &RecordSnapshotRequest {
                s3_version_id: blob.s3_version_id,
                storage_path: blob.storage_path,
                seq_at_snapshot: 0,
                doc_key_id: 1,
                size_bytes: size,
                ..Default::default()
            },
        )
        .context("record snapshot")?;
    eprintln!("  + uploaded {uploaded} image asset(s) and re-snapshotted");
    Ok(())
}

/// Download-side: re-inline any `status:"saved"` images whose dataURL is
/// missing from the on-disk file. Returns the new byte length when the file
/// was rewritten, `None` when the scene was already self-contained.
pub fn hydrate(
    client: &Client,
    file_id: &str,
    collection_key: &[u8],
    dest_path: &std::path::Path,
) -> Result<Option<i64>> {
    let raw = std::fs::read(dest_path).context("re-read excalidraw")?;
    let mut doc: Value = serde_json::from_slice(&raw).context("parse excalidraw json")?;

    let missing = missing_saved_assets(&doc);
    if missing.is_empty() {
        return Ok(None);
    }

    let mut inlined = 0usize;
    for asset_id in &missing {
        let blob = match client.download_asset(file_id, asset_id) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: skip asset {asset_id}: {e:#}");
                continue;
            }
        };
        let plain = match asset::decrypt_asset(&blob, file_id, asset_id, collection_key) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: decrypt asset {asset_id}: {e}");
                continue;
            }
        };
        let data_url = String::from_utf8_lossy(&plain).into_owned();
        inline_asset(&mut doc, asset_id, &data_url);
        inlined += 1;
    }
    if inlined == 0 {
        return Ok(None);
    }

    let out = serde_json::to_vec(&doc).context("re-encode excalidraw json")?;
    std::fs::write(dest_path, &out).context("rewrite after hydration")?;
    Ok(Some(out.len() as i64))
}

/// Walks the scene; for every image element with an inline dataURL, calls
/// `upload(asset_id, data_url)` and — on success — flips the element to
/// `status:"saved"`, bumping version/versionNonce/updated so peers'
/// `reconcileElements` pick the change up. Returns how many uploaded.
fn extract_assets(doc: &mut Value, mut upload: impl FnMut(&str, &str) -> Result<()>) -> usize {
    // Collect (asset_id, dataURL) pairs first — `files` and `elements` can't
    // be borrowed mutably at once.
    let pending: Vec<(String, String)> = {
        let files = doc.get("files").and_then(Value::as_object);
        let elements = doc.get("elements").and_then(Value::as_array);
        let (Some(files), Some(elements)) = (files, elements) else {
            return 0;
        };
        elements
            .iter()
            .filter(|e| e.get("type").and_then(Value::as_str) == Some("image"))
            .filter_map(|e| e.get("fileId").and_then(Value::as_str))
            .filter_map(|asset_id| {
                let data_url = files.get(asset_id)?.get("dataURL")?.as_str()?;
                if data_url.is_empty() {
                    None
                } else {
                    Some((asset_id.to_string(), data_url.to_string()))
                }
            })
            .collect()
    };

    let mut uploaded = 0usize;
    for (asset_id, data_url) in pending {
        if let Err(e) = upload(&asset_id, &data_url) {
            eprintln!("warning: asset {asset_id}: {e:#}");
            continue;
        }
        flip_saved(doc, &asset_id);
        uploaded += 1;
    }
    uploaded
}

/// Marks every image element referencing `asset_id` as saved.
fn flip_saved(doc: &mut Value, asset_id: &str) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let Some(elements) = doc.get_mut("elements").and_then(Value::as_array_mut) else {
        return;
    };
    for e in elements {
        if e.get("type").and_then(Value::as_str) != Some("image")
            || e.get("fileId").and_then(Value::as_str) != Some(asset_id)
        {
            continue;
        }
        let version = e.get("version").and_then(Value::as_f64).unwrap_or(0.0);
        e["status"] = Value::from("saved");
        e["version"] = Value::from(version + 1.0);
        e["versionNonce"] = Value::from((now_ms.wrapping_mul(1_000_003)) & 0x7fff_ffff);
        e["updated"] = Value::from(now_ms);
    }
}

/// Asset ids of `status:"saved"` image elements whose `files[fileId].dataURL`
/// is absent or empty.
fn missing_saved_assets(doc: &Value) -> Vec<String> {
    let files = doc.get("files").and_then(Value::as_object);
    let Some(elements) = doc.get("elements").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in elements {
        if e.get("type").and_then(Value::as_str) != Some("image")
            || e.get("status").and_then(Value::as_str) != Some("saved")
        {
            continue;
        }
        let Some(asset_id) = e.get("fileId").and_then(Value::as_str) else {
            continue;
        };
        let inline = files
            .and_then(|f| f.get(asset_id))
            .and_then(|entry| entry.get("dataURL"))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if !inline && !out.iter().any(|x| x == asset_id) {
            out.push(asset_id.to_string());
        }
    }
    out
}

/// Inserts `files[asset_id]` with the decrypted dataURL (mime recovered from
/// the `data:<mime>;` prefix, defaulting to image/png).
fn inline_asset(doc: &mut Value, asset_id: &str, data_url: &str) {
    let mime = mime_from_data_url(data_url);
    if doc.get("files").and_then(Value::as_object).is_none() {
        doc["files"] = serde_json::json!({});
    }
    doc["files"][asset_id] = serde_json::json!({
        "id": asset_id,
        "mimeType": mime,
        "dataURL": data_url,
        "created": 0,
    });
}

fn mime_from_data_url(data_url: &str) -> &str {
    data_url
        .strip_prefix("data:")
        .and_then(|rest| rest.split(';').next())
        .filter(|m| !m.is_empty())
        .unwrap_or("image/png")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scene() -> Value {
        serde_json::json!({
            "type": "excalidraw",
            "version": 2,
            "customTopLevel": {"kept": true},
            "elements": [
                {"type": "rectangle", "id": "r1"},
                {"type": "image", "id": "i1", "fileId": "asset-1",
                 "status": "pending", "version": 5.0},
            ],
            "files": {
                "asset-1": {"id": "asset-1", "mimeType": "image/png",
                            "dataURL": "data:image/png;base64,AAAA", "created": 1}
            },
            "appState": {"zoom": 1}
        })
    }

    #[test]
    fn extract_uploads_and_flips_status() {
        let mut doc = scene();
        let mut seen = Vec::new();
        let n = extract_assets(&mut doc, |id, url| {
            seen.push((id.to_string(), url.to_string()));
            Ok(())
        });
        assert_eq!(n, 1);
        assert_eq!(
            seen,
            vec![("asset-1".into(), "data:image/png;base64,AAAA".into())]
        );
        let el = &doc["elements"][1];
        assert_eq!(el["status"], "saved");
        assert_eq!(el["version"], 6.0);
        assert!(el["versionNonce"].as_u64().unwrap() <= 0x7fff_ffff);
        // Unknown fields survive the round-trip.
        assert_eq!(doc["customTopLevel"]["kept"], true);
    }

    #[test]
    fn extract_skips_failed_uploads() {
        let mut doc = scene();
        let n = extract_assets(&mut doc, |_, _| anyhow::bail!("nope"));
        assert_eq!(n, 0);
        assert_eq!(doc["elements"][1]["status"], "pending");
    }

    #[test]
    fn hydration_round_trip() {
        // A stripped scene: saved image, no inline dataURL.
        let mut doc = serde_json::json!({
            "elements": [
                {"type": "image", "id": "i1", "fileId": "asset-1", "status": "saved"},
            ],
            "files": {}
        });
        assert_eq!(missing_saved_assets(&doc), vec!["asset-1".to_string()]);

        inline_asset(&mut doc, "asset-1", "data:image/jpeg;base64,BBBB");
        assert!(missing_saved_assets(&doc).is_empty());
        let entry = &doc["files"]["asset-1"];
        assert_eq!(entry["mimeType"], "image/jpeg");
        assert_eq!(entry["dataURL"], "data:image/jpeg;base64,BBBB");
    }

    #[test]
    fn mime_prefix_parsing() {
        assert_eq!(mime_from_data_url("data:image/jpeg;base64,x"), "image/jpeg");
        assert_eq!(
            mime_from_data_url("data:image/svg+xml;base64,x"),
            "image/svg+xml"
        );
        assert_eq!(mime_from_data_url("garbage"), "image/png");
        assert_eq!(mime_from_data_url("data:;base64,x"), "image/png");
    }

    #[test]
    fn detects_extension() {
        assert!(is_excalidraw("board.excalidraw"));
        assert!(is_excalidraw("BOARD.EXCALIDRAW"));
        assert!(!is_excalidraw("board.excalidraw.txt"));
    }
}
