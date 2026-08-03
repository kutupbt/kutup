//! Purpose-bound whiteboard asset envelope.
//!
//! Assets reuse `DriveEnvelopeV1` with a dedicated purpose and an authenticated
//! binding to the file, collection, collection-key epoch and content-addressed
//! asset id. There is no parallel nonce-prefixed asset format.

use crate::drive_envelope::{self, DriveEnvelopeContextV1};
use crate::error::Result;

pub fn encrypt_asset(
    plaintext: &[u8],
    file_id: &str,
    collection_id: &str,
    asset_id: &str,
    epoch: u32,
    collection_key: &[u8],
) -> Result<Vec<u8>> {
    let context =
        DriveEnvelopeContextV1::whiteboard_asset(file_id, collection_id, asset_id, epoch)?;
    drive_envelope::seal(plaintext, collection_key, context)
}

pub fn decrypt_asset(
    blob: &[u8],
    file_id: &str,
    collection_id: &str,
    asset_id: &str,
    epoch: u32,
    collection_key: &[u8],
) -> Result<Vec<u8>> {
    let context =
        DriveEnvelopeContextV1::whiteboard_asset(file_id, collection_id, asset_id, epoch)?;
    drive_envelope::open(blob, collection_key, context)
}
