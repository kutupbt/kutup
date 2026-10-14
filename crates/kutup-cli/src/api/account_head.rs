//! The account head (docs/plans/rollback-protection.md): the head, its chain,
//! a scope's index with the head it goes with, and starting the chain.

use anyhow::Result;
use reqwest::Method;
use serde::Deserialize;

use super::Client;

/// A scope's index and the head it was read with, in one snapshot.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountIndexRecord {
    pub head: Option<String>,
    pub values: Vec<(String, u64)>,
    /// Before the first head: what a chain start names.
    #[serde(default)]
    pub basis: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HeadRecord {
    head: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HeadsPage {
    heads: Vec<String>,
    next: Option<u64>,
}

impl Client {
    /// The account's current head (base64); `None` before the first.
    pub fn get_account_head(&self) -> Result<Option<String>> {
        let resp = self.get("/account/head")?;
        Ok(super::decode_json::<HeadRecord>(resp)?.head)
    }

    /// The chain from sequence `from` to the newest, oldest first, every page
    /// of it; `None` when `from` is past what the server keeps (`410`).
    pub fn get_account_heads(&self, from: u64) -> Result<Option<Vec<String>>> {
        let mut heads = Vec::new();
        let mut next = Some(from);
        while let Some(from) = next {
            let resp = self.get(&format!("/account/heads?from={from}"))?;
            if resp.status().as_u16() == 410 {
                return Ok(None);
            }
            let page: HeadsPage = super::decode_json(resp)?;
            heads.extend(page.heads);
            next = page.next;
        }
        Ok(Some(heads))
    }

    /// A scope's index and its head; `None` for a scope the server keeps no
    /// index of (`404`: uncovered).
    pub fn get_account_index(&self, scope: &str) -> Result<Option<AccountIndexRecord>> {
        let resp = self.get(&format!("/account/index/{scope}"))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        super::decode_json(resp).map(Some)
    }

    /// Starts the account's chain with `head` (sequence 1) on `basis`.
    /// `false`: a head exists already, or the basis moved (read again).
    pub fn start_account_head(&self, head: &str, basis: &str) -> Result<bool> {
        let resp = self
            .request(Method::POST, "/account/head")
            .json(&serde_json::json!({ "head": head, "basis": basis }))
            .send()?;
        if resp.status().as_u16() == 409 {
            return Ok(false);
        }
        super::check_ok(resp)?;
        Ok(true)
    }
}
