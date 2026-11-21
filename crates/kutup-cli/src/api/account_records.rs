//! The account-records store (docs/plans/account-records.md).

use anyhow::{bail, Result};
use kutup_crypto::account_records::{BatchPlan, Page, RecordScope};
use reqwest::Method;

use super::Client;

impl Client {
    /// A page of `scope`'s changes after `after`, with the head of the same
    /// snapshot.
    pub fn get_account_records(&self, scope: RecordScope, after: i64) -> Result<Page> {
        let resp = self.get(&format!("/account/records/{}?after={after}", scope.name()))?;
        super::decode_json(resp)
    }

    /// `POST /api/account/records`: `Some(seq)` once stored, `None` when
    /// another device wrote first (a head or revision conflict: read again).
    /// A device that missed a master-key rotation is told to sign in again.
    pub fn post_account_records(
        &self,
        plan: &BatchPlan,
        head: Option<&str>,
    ) -> Result<Option<i64>> {
        let resp = self
            .request(Method::POST, "/account/records")
            .json(&plan.body(head))
            .send()?;
        if resp.status().as_u16() == 409 {
            let body: serde_json::Value = resp.json().unwrap_or_default();
            return match body["code"].as_str() {
                Some("headConflict" | "revisionConflict") => Ok(None),
                Some(kutup_crypto::master_keys::MASTER_KEY_STALE) => {
                    bail!("the account's master key was rotated on another device: sign in again")
                }
                _ => bail!("the server refused the write: {body}"),
            };
        }
        #[derive(serde::Deserialize)]
        struct Stored {
            seq: i64,
        }
        Ok(Some(super::decode_json::<Stored>(resp)?.seq))
    }
}
