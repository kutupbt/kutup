//! Collaboration over HTTP (docs/plans/cli-yjs-sync.md): the log of a
//! file's live edits, read and written as the CLI's device of its account
//! (docs/plans/one-device-list.md).

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::Method;
use serde::Deserialize;

use super::Client;
use crate::collab_device::Device;

/// One frame of the log.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggedFrame {
    pub seq: i64,
    /// Its sender's account, which its signature covers.
    pub sender: String,
    /// The sealed frame, base64.
    pub frame: String,
}

impl LoggedFrame {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(STANDARD.decode(&self.frame)?)
    }
}

/// A page of the log after a position.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FramesPage {
    pub frames: Vec<LoggedFrame>,
    /// The log's position now.
    pub head_seq: i64,
    /// Positions up to here were trimmed into a saved version.
    pub floor: i64,
    pub current_doc_key_id: i64,
    /// This device's highest sender sequence in the file's log.
    pub my_sender_seq_high: i64,
    pub more: bool,
}

impl Client {
    /// The log of `file_id` after `after`, one page.
    pub fn collab_frames(&self, file_id: &str, device: &Device, after: i64) -> Result<FramesPage> {
        let resp = self
            .request(
                Method::GET,
                &format!("/files/{file_id}/collab/frames?after={after}"),
            )
            .header(kutup_chat_proto::DEVICE_HEADER, device.header())
            .send()?;
        super::decode_json(resp)
    }

    /// Appends one sealed frame to the log; its position.
    pub fn post_collab_frame(&self, file_id: &str, device: &Device, frame: Vec<u8>) -> Result<i64> {
        #[derive(Deserialize)]
        struct Kept {
            seq: i64,
        }
        let resp = self
            .request(Method::POST, &format!("/files/{file_id}/collab/frames"))
            .header(kutup_chat_proto::DEVICE_HEADER, device.header())
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(frame)
            .send()?;
        Ok(super::decode_json::<Kept>(resp)?.seq)
    }

    /// Claims the right to seed a file nobody has opened: true for the first
    /// caller.
    pub fn claim_seed(&self, file_id: &str) -> Result<bool> {
        #[derive(Deserialize)]
        struct Claimed {
            committed: bool,
        }
        let resp = self
            .request(Method::POST, &format!("/files/{file_id}/claim-seed"))
            .send()?;
        Ok(super::decode_json::<Claimed>(resp)?.committed)
    }
}
