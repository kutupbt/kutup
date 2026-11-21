//! Kutup Pass on the server: what has become of each kept key's vault
//! (`/api/pass/vault-states`). The kept keys themselves are the
//! account-records scope `passSecrets` ([`super::account_records`]).
//! Companion to `crates/kutup-server/src/handlers/pass.rs`.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;

use super::Client;

/// What has become of a secret's vault (the server's `VaultSecretState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultSecretState {
    Open,
    Trashed,
    Unreachable,
    Gone,
}

/// One of the caller's sealed vault secrets.
#[derive(Debug)]
pub struct VaultSecretRow {
    pub file_id: String,
    /// Base64 of the account envelope (`kutup_crypto::pass_vault`).
    pub envelope: String,
    /// Only an `open` vault's key is used; the others are listed as the
    /// account head lists them.
    pub state: VaultSecretState,
}

impl Client {
    /// What has become of the vault of every key the caller keeps, by file id.
    pub fn vault_states(&self) -> Result<BTreeMap<String, VaultSecretState>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Row {
            file_id: String,
            state: VaultSecretState,
        }
        let resp = self.get("/pass/vault-states")?;
        let rows: Vec<Row> = super::decode_json(resp)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.file_id, row.state))
            .collect())
    }
}
