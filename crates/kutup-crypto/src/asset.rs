//! Purpose-bound whiteboard asset envelope.
//!
//! Assets reuse `DriveEnvelopeV1` with a dedicated purpose, sealed under the
//! file key and bound to the file, the key's generation and the
//! content-addressed asset id. They name no folder, so a whiteboard moves
//! with its assets untouched (docs/plans/drive-move.md).

use crate::drive_envelope::{self, DriveEnvelopeContextV1};
use crate::error::Result;

pub fn encrypt_asset(
    plaintext: &[u8],
    file_id: &str,
    asset_id: &str,
    generation: u32,
    file_key: &[u8],
) -> Result<Vec<u8>> {
    let context = DriveEnvelopeContextV1::whiteboard_asset(file_id, asset_id, generation)?;
    drive_envelope::seal(plaintext, file_key, context)
}

pub fn decrypt_asset(
    blob: &[u8],
    file_id: &str,
    asset_id: &str,
    generation: u32,
    file_key: &[u8],
) -> Result<Vec<u8>> {
    let context = DriveEnvelopeContextV1::whiteboard_asset(file_id, asset_id, generation)?;
    drive_envelope::open(blob, file_key, context)
}
