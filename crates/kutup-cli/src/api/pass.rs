//! Kutup Pass vault secrets (`/api/pass/vault-secrets*`).
//! Companion to `crates/kutup-server/src/handlers/pass.rs`.

use anyhow::Result;
use reqwest::Method;
use serde::Deserialize;

use super::Client;

/// One of the caller's sealed vault secrets.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSecretRow {
    pub file_id: String,
    /// Base64 of the account envelope (`kutup_crypto::pass_vault`).
    pub envelope: String,
}

impl Client {
    /// The caller's vault secrets, for vaults they can still open.
    pub fn list_vault_secrets(&self) -> Result<Vec<VaultSecretRow>> {
        let resp = self.request(Method::GET, "/pass/vault-secrets").send()?;
        super::decode_json(resp)
    }

    /// Keeps (or replaces) the caller's secret for vault `file_id`, on top
    /// of the revision the change started from (`base_revision`, 0 for none).
    /// `false`: another device kept a key first.
    pub fn put_vault_secret(
        &self,
        file_id: &str,
        envelope: &str,
        base_revision: u64,
        head: &str,
    ) -> Result<bool> {
        let resp = self
            .request(Method::PUT, &format!("/pass/vault-secrets/{file_id}"))
            .json(&serde_json::json!({ "envelope": envelope, "baseRevision": base_revision, "head": head }))
            .send()?;
        if resp.status().as_u16() == 409 {
            return Ok(false);
        }
        super::check_ok(resp)?;
        Ok(true)
    }

    /// Forgets the caller's secret for vault `file_id`, with the next account
    /// head. `false`: another device wrote first.
    pub fn delete_vault_secret(&self, file_id: &str, head: &str) -> Result<bool> {
        let resp = self
            .request(Method::DELETE, &format!("/pass/vault-secrets/{file_id}"))
            .json(&serde_json::json!({ "head": head }))
            .send()?;
        if resp.status().as_u16() == 409 {
            return Ok(false);
        }
        super::check_ok(resp)?;
        Ok(true)
    }
}
