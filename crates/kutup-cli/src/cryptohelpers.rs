//! Shared decryption helpers used across commands — mirrors `helpers.go`.

use crate::api::{Client, Collection, File};
use crate::session::Session;
use anyhow::Result;

/// Decrypts a collection's key, handling both owned typed envelopes and
/// authenticated HPKE named-share envelopes.
pub fn decrypt_collection_key(
    col: &Collection,
    master_key: &[u8],
    sess: &Session,
) -> Result<Vec<u8>> {
    crate::collection_crypto::open_key(col, master_key, sess)
}

/// Decrypts a collection's display name, returning `[encrypted]` on failure
/// (matching the Go behavior so a single bad row never aborts a listing).
pub fn decrypt_collection_name(col: &Collection, master_key: &[u8], sess: &Session) -> String {
    let Ok(collection_key) = decrypt_collection_key(col, master_key, sess) else {
        return "[encrypted]".to_string();
    };
    match crate::collection_crypto::open_name(col, &collection_key) {
        Ok(name) => name,
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
    match crate::file_crypto::open(f, collection_key) {
        Ok((_, meta)) => (meta.name, meta.size),
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
        let dummy_session = Session::default();
        let Ok(col_key) = crate::collection_crypto::open_key(col, master_key, &dummy_session)
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
            let fk = crate::file_crypto::open_key(&f, &col_key)?;
            return Ok((f, fk.to_vec()));
        }
    }
    Err(crate::errors::NotFound(format!(
        "file {file_id} not found in any accessible collection"
    ))
    .into())
}
