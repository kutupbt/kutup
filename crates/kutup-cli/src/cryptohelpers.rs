//! Shared decryption helpers used across commands — mirrors `helpers.go`.

use anyhow::{anyhow, bail, Result};
use base64::Engine;

use crate::api::{Client, Collection, File, FileMetadata};
use crate::session::Session;
use kutup_crypto::{sealedbox, secretbox};

fn b64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

/// Decrypts a collection's key, handling both owned (secretbox under the master
/// key) and shared (sealed box under the user's keypair) collections.
pub fn decrypt_collection_key(
    col: &Collection,
    master_key: &[u8],
    sess: &Session,
) -> Result<Vec<u8>> {
    if col.is_shared {
        let private_key = sess.private_key_bytes()?;
        let public_key = sess.public_key_bytes()?;
        let enc_key = b64(&col.encrypted_key)?;
        Ok(sealedbox::open_anonymous(
            &enc_key,
            &public_key,
            &private_key,
        )?)
    } else {
        Ok(secretbox::open_b64(
            &col.encrypted_key,
            &col.encrypted_key_nonce,
            master_key,
        )?)
    }
}

/// Decrypts a collection's display name, returning `[encrypted]` on failure
/// (matching the Go behavior so a single bad row never aborts a listing).
pub fn decrypt_collection_name(col: &Collection, master_key: &[u8], sess: &Session) -> String {
    let Ok(collection_key) = decrypt_collection_key(col, master_key, sess) else {
        return "[encrypted]".to_string();
    };
    match secretbox::open_b64(&col.encrypted_name, &col.name_nonce, &collection_key) {
        Ok(name) => String::from_utf8_lossy(&name).into_owned(),
        Err(_) => "[encrypted]".to_string(),
    }
}

/// Returns a copy of `cols` with each `name` populated.
pub fn decrypt_collections(
    cols: Vec<Collection>,
    master_key: &[u8],
    sess: &Session,
) -> Vec<Collection> {
    cols.into_iter()
        .map(|mut col| {
            col.name = decrypt_collection_name(&col, master_key, sess);
            col
        })
        .collect()
}

/// Decrypts a file's name and size, returning `("[encrypted]", 0)` on failure.
pub fn decrypt_file_meta(f: &File, collection_key: &[u8]) -> (String, i64) {
    let enc = || -> Result<FileMetadata> {
        let file_key =
            secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, collection_key)?;
        let meta_bytes = secretbox::open_b64(&f.encrypted_metadata, &f.metadata_nonce, &file_key)?;
        Ok(serde_json::from_slice(&meta_bytes)?)
    };
    match enc() {
        Ok(meta) => (meta.name, meta.size),
        Err(_) => ("[encrypted]".to_string(), 0),
    }
}

/// Finds a collection by id.
pub fn find_collection<'a>(cols: &'a [Collection], id: &str) -> Option<&'a Collection> {
    cols.iter().find(|c| c.id == id)
}

/// Locates a file across the user's owned collections and unwraps its file key.
/// Mirrors `findFileAndKey` (versions.go); shared/federated collections are
/// skipped (their keys don't open with the master key directly).
pub fn find_file_and_key(
    client: &Client,
    master_key: &[u8],
    file_id: &str,
) -> Result<(File, Vec<u8>)> {
    let cols = client.list_collections()?;
    for col in &cols {
        let Ok(col_key) =
            secretbox::open_b64(&col.encrypted_key, &col.encrypted_key_nonce, master_key)
        else {
            continue;
        };
        let Ok(files) = client.list_files(&col.id) else {
            continue;
        };
        for f in files {
            if f.id != file_id {
                continue;
            }
            let fk = secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, &col_key)
                .map_err(|e| anyhow!("unwrap file key: {e}"))?;
            return Ok((f, fk));
        }
    }
    bail!("file {file_id} not found in any accessible collection")
}
