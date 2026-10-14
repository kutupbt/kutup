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
    /// of it; `None` when `from` is past what the server keeps (`410`). A
    /// server cannot keep this asking: the pages are as many as the kept
    /// window needs, and each must start further on than the one before.
    pub fn get_account_heads(&self, from: u64) -> Result<Option<Vec<String>>> {
        const PAGE: u64 = 200;
        let most_pages = kutup_crypto::account_head::RETENTION / PAGE + 2;
        let mut heads = Vec::new();
        let mut next = Some(from);
        let mut pages = 0;
        while let Some(at) = next {
            pages += 1;
            if pages > most_pages {
                anyhow::bail!(
                    "the server's account history did not end within the window it keeps"
                );
            }
            let resp = self.get(&format!("/account/heads?from={at}"))?;
            if resp.status().as_u16() == 410 {
                return Ok(None);
            }
            let page: HeadsPage = super::decode_json(resp)?;
            heads.extend(page.heads);
            if let Some(following) = page.next {
                if following <= at {
                    anyhow::bail!("the server's account history paged backwards");
                }
            }
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
