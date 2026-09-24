//! Shared decryption helpers used across commands — mirrors `helpers.go`.

use crate::api::{Client, Collection, File};
use crate::keyring::Keyring;
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

/// A folder's keys across its epochs (its history fetched only if it rotated).
pub fn folder_keyring(
    client: &Client,
    col: &Collection,
    master_key: &[u8],
    sess: &Session,
) -> Result<Keyring> {
    let key = decrypt_collection_key(col, master_key, sess)?;
    Keyring::load(client, col, &key, master_key)
}

/// Decrypts a file's name and size, returning `("[encrypted]", 0)` on failure.
pub fn decrypt_file_meta(f: &File, keys: &Keyring) -> (String, i64) {
    match crate::file_crypto::open(f, keys) {
        Ok((_, meta)) => (meta.name, meta.size),
        Err(_) => ("[encrypted]".to_string(), 0),
    }
}

/// Finds a collection by id.
pub fn find_collection<'a>(cols: &'a [Collection], id: &str) -> Option<&'a Collection> {
    cols.iter().find(|c| c.id == id)
}

/// A file found across the user's folders, with its key and its folder's keys.
pub struct FoundFile {
    pub file: File,
    pub file_key: [u8; 32],
    pub keys: Keyring,
    pub collection: Collection,
}

/// Locates a file across the user's owned collections and unwraps its file key.
/// Mirrors `findFileAndKey` (versions.go); shared/federated collections are
/// skipped (their keys don't open with the master key directly).
pub fn find_file_and_key(client: &Client, master_key: &[u8], file_id: &str) -> Result<FoundFile> {
    let cols = client.list_collections()?;
    for col in cols {
        let dummy_session = Session::default();
        let Ok(col_key) = crate::collection_crypto::open_key(&col, master_key, &dummy_session)
        else {
            continue;
        };
        let Ok(files) = client.list_files(&col.id) else {
            continue;
        };
        let Some(f) = files.into_iter().find(|f| f.id == file_id) else {
            continue;
        };
        let keys = Keyring::load(client, &col, &col_key, master_key)?;
        let file_key = crate::file_crypto::open_key(&f, &keys)?;
        return Ok(FoundFile {
            file: f,
            file_key,
            keys,
            collection: col,
        });
    }
    Err(crate::errors::NotFound(format!(
        "file {file_id} not found in any accessible collection"
    ))
    .into())
}

/// Locates a file in any folder in `cols` the account can open — its own
/// and those shared with it — with its key and its folder's keys.
pub fn locate_file(
    client: &Client,
    master_key: &[u8],
    sess: &Session,
    cols: &[Collection],
    file_id: &str,
) -> Result<FoundFile> {
    for col in cols {
        let Ok(col_key) = decrypt_collection_key(col, master_key, sess) else {
            continue;
        };
        let Ok(files) = client.list_files(&col.id) else {
            continue;
        };
        let Some(f) = files.into_iter().find(|f| f.id == file_id) else {
            continue;
        };
        let keys = Keyring::load(client, col, &col_key, master_key)?;
        let file_key = crate::file_crypto::open_key(&f, &keys)?;
        return Ok(FoundFile {
            file: f,
            file_key,
            keys,
            collection: col.clone(),
        });
    }
    Err(crate::errors::NotFound(format!(
        "file {file_id} not found in any accessible collection"
    ))
    .into())
}

/// Gives `found` a new key generation wrapped at its folder's current epoch
/// if the folder rotated since the file was last keyed
/// (docs/plans/drive-share-revocation.md), so what is written next — or
/// where the file moves (docs/plans/drive-move.md) — is not readable with a
/// key a removed member holds. Returns the file as it now is.
pub fn rekey_if_behind(client: &Client, found: FoundFile) -> Result<FoundFile> {
    if found.file.key_epoch >= found.collection.key_epoch {
        return Ok(found);
    }
    let metadata = crate::file_crypto::open_metadata(&found.file, &found.file_key)?;
    let (request, _) = crate::file_crypto::rekey_request(
        &found.file,
        &found.file_key,
        &metadata,
        found.keys.current(),
        found.collection.key_epoch,
    )?;
    // `false`: another editor re-keyed it first; the listing below has it.
    client.rekey_file(&found.file.id, &request)?;
    // Whoever moved it, list it again for its current key and history.
    let file = client
        .list_files(&found.collection.id)?
        .into_iter()
        .find(|f| f.id == found.file.id)
        .ok_or_else(|| anyhow::anyhow!("file disappeared during re-key"))?;
    let file_key = crate::file_crypto::open_key(&file, &found.keys)?;
    Ok(FoundFile {
        file,
        file_key,
        keys: found.keys,
        collection: found.collection,
    })
}
