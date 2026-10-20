//! [`Stalwart`] over Stalwart 0.16's management API: JMAP at `/jmap` with
//! its registry methods (`x:Domain/get|set`, `x:DkimSignature/get|set`,
//! capability `urn:stalwart:jmap`), the same API `stalwart-cli` uses. It
//! signs in as a dedicated account (`kutup-domains`, made by
//! stalwart-setup) whose permissions are replaced by managing domains and
//! DKIM signatures only (docs/plans/mail-custom-domains.md §10).

use anyhow::{anyhow, bail, Context, Result};
use axum::async_trait;
use serde_json::{json, Value};

use super::reconcile::{Stalwart, StalwartDomain, StalwartSignature};

const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];
/// The account stalwart-setup makes for this (stalwart/plan-domains.ndjson).
const ACCOUNT: &str = "kutup-domains";

pub struct StalwartApi {
    http: reqwest::Client,
    /// Stalwart's HTTP listener, e.g. `http://stalwart:8080`.
    base: String,
    token: String,
}

impl StalwartApi {
    pub fn new(http: reqwest::Client, base: &str, token: &str) -> Self {
        StalwartApi {
            http,
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
        }
    }

    /// The account the registry calls name: the credential's own.
    async fn account_id(&self) -> Result<String> {
        let session: Value = self
            .http
            .get(format!("{}/jmap/session", self.base))
            .basic_auth(ACCOUNT, Some(&self.token))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        session["primaryAccounts"]["urn:stalwart:jmap"]
            .as_str()
            .or_else(|| session["primaryAccounts"]["urn:ietf:params:jmap:core"].as_str())
            .or_else(|| {
                session["accounts"]
                    .as_object()
                    .and_then(|accounts| accounts.keys().next().map(String::as_str))
            })
            .map(str::to_owned)
            .context("the Stalwart session names no account")
    }

    /// One method call; its arguments in the answer.
    async fn call(&self, method: &str, mut arguments: Value) -> Result<Value> {
        arguments["accountId"] = json!(self.account_id().await?);
        let body = json!({ "using": USING, "methodCalls": [[method, arguments, "0"]] });
        let answer: Value = self
            .http
            .post(format!("{}/jmap", self.base))
            .basic_auth(ACCOUNT, Some(&self.token))
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let response = &answer["methodResponses"][0];
        match response[0].as_str() {
            Some("error") => bail!("Stalwart refused {method}: {}", response[1]),
            Some(name) if name == method => Ok(response[1].clone()),
            _ => bail!("Stalwart answered {method} with {answer}"),
        }
    }

    async fn get(&self, object: &str, properties: &[&str]) -> Result<Vec<Value>> {
        let answer = self
            .call(
                &format!("x:{object}/get"),
                json!({ "ids": null, "properties": properties }),
            )
            .await?;
        Ok(answer["list"].as_array().cloned().unwrap_or_default())
    }

    async fn create(&self, object: &str, value: Value) -> Result<String> {
        let answer = self
            .call(
                &format!("x:{object}/set"),
                json!({ "create": { "new": value } }),
            )
            .await?;
        if let Some(error) = answer["notCreated"].get("new") {
            bail!("Stalwart didn't create the {object}: {error}");
        }
        answer["created"]["new"]["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("Stalwart named no id for the new {object}"))
    }

    async fn destroy(&self, object: &str, id: &str) -> Result<()> {
        let answer = self
            .call(&format!("x:{object}/set"), json!({ "destroy": [id] }))
            .await?;
        if let Some(error) = answer["notDestroyed"].get(id) {
            // Already gone is what was wanted.
            if error["type"] != "notFound" {
                bail!("Stalwart didn't destroy the {object} {id}: {error}");
            }
        }
        Ok(())
    }
}

fn text(value: &Value, field: &str) -> String {
    value[field].as_str().unwrap_or_default().to_owned()
}

#[async_trait]
impl Stalwart for StalwartApi {
    async fn domains(&self) -> Result<Vec<StalwartDomain>> {
        Ok(self
            .get("Domain", &["id", "name", "description"])
            .await?
            .iter()
            .map(|d| StalwartDomain {
                object_id: text(d, "id"),
                name: text(d, "name"),
                description: text(d, "description"),
            })
            .collect())
    }

    async fn signatures(&self) -> Result<Vec<StalwartSignature>> {
        Ok(self
            .get("DkimSignature", &["id", "domainId", "selector"])
            .await?
            .iter()
            .map(|s| StalwartSignature {
                object_id: text(s, "id"),
                domain_object_id: text(s, "domainId"),
                selector: text(s, "selector"),
            })
            .collect())
    }

    async fn create_domain(&self, name: &str, description: &str) -> Result<String> {
        self.create(
            "Domain",
            json!({
                "name": name,
                "description": description,
                // As MAIL_DOMAIN's (stalwart/plan.ndjson): Kutup decides who
                // receives, at RCPT; its own keys sign (below).
                "allowRelaying": true,
                "subAddressing": { "@type": "Disabled" },
                "dkimManagement": { "@type": "Manual" },
            }),
        )
        .await
    }

    async fn delete_domain(&self, object_id: &str) -> Result<()> {
        self.destroy("Domain", object_id).await
    }

    async fn create_signature(
        &self,
        domain_object_id: &str,
        selector: &str,
        private_key_pem: &str,
    ) -> Result<String> {
        self.create(
            "DkimSignature",
            json!({
                "@type": "Dkim1RsaSha256",
                "domainId": domain_object_id,
                "selector": selector,
                "privateKey": { "@type": "Text", "secret": private_key_pem },
            }),
        )
        .await
    }

    async fn delete_signature(&self, object_id: &str) -> Result<()> {
        self.destroy("DkimSignature", object_id).await
    }
}
