//! Collaboration over HTTP (docs/plans/cli-yjs-sync.md): the CLI's
//! collaboration device, signed by the account (docs/plans/device-registration.md),
//! and the log of a file's live edits.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::Method;
use serde::Deserialize;

use super::Client;

/// The account's statement for a device key: a challenge from this server,
/// when, and the authority's signature.
pub struct DeviceStatement<'a> {
    pub challenge: &'a str,
    pub issued_at_ms: i64,
    pub signature: &'a str,
}

/// One frame of the log.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggedFrame {
    pub seq: i64,
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
    /// A one-time challenge (base64) for registering or renewing a device.
    pub fn device_challenge(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Challenge {
            challenge: String,
        }
        let resp = self.request(Method::POST, "/devices/challenge").send()?;
        Ok(super::decode_json::<Challenge>(resp)?.challenge)
    }

    /// Registers `public_signing` (base64) as a collaboration device; its id.
    pub fn register_device(
        &self,
        public_signing: &str,
        label: &str,
        statement: &DeviceStatement,
    ) -> Result<i64> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Registered {
            device_id: i64,
        }
        let resp = self
            .request(Method::POST, "/devices")
            .json(&serde_json::json!({
                "publicSigning": public_signing,
                "label": label,
                "challenge": statement.challenge,
                "issuedAtMs": statement.issued_at_ms,
                "signature": statement.signature,
            }))
            .send()?;
        Ok(super::decode_json::<Registered>(resp)?.device_id)
    }

    /// Renews a device's statement (other servers trust one 30 days).
    pub fn renew_device(&self, device_id: i64, statement: &DeviceStatement) -> Result<()> {
        let resp = self
            .request(Method::POST, &format!("/devices/{device_id}/renew"))
            .json(&serde_json::json!({
                "challenge": statement.challenge,
                "issuedAtMs": statement.issued_at_ms,
                "signature": statement.signature,
            }))
            .send()?;
        super::check_ok(resp)
    }

    /// The log of `file_id` after `after`, one page.
    pub fn collab_frames(&self, file_id: &str, device_id: i64, after: i64) -> Result<FramesPage> {
        let resp = self
            .request(
                Method::GET,
                &format!("/files/{file_id}/collab/frames?deviceId={device_id}&after={after}"),
            )
            .send()?;
        super::decode_json(resp)
    }

    /// Appends one sealed frame to the log; its position.
    pub fn post_collab_frame(&self, file_id: &str, device_id: i64, frame: Vec<u8>) -> Result<i64> {
        #[derive(Deserialize)]
        struct Kept {
            seq: i64,
        }
        let resp = self
            .request(
                Method::POST,
                &format!("/files/{file_id}/collab/frames?deviceId={device_id}"),
            )
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
