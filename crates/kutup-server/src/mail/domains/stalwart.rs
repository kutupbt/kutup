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
/// The account stalwart-setup makes for this (stalwart/plan-domains.ndjson);
/// it signs in as `kutup-domains@<server>`, as the sending account does.
const ACCOUNT: &str = "kutup-domains";

/// Stalwart refused the sign-in (401) or the address (403, after failed
/// sign-ins it bans the address). The reconcile then backs off: retrying
/// every sweep would keep the backend's address banned, and that address
/// also delivers mail.
#[derive(Debug)]
pub struct Refused(pub u16);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Stalwart refused the custom domains account (HTTP {})",
            self.0
        )
    }
}

impl std::error::Error for Refused {}

fn checked(response: reqwest::Response) -> Result<reqwest::Response> {
    match response.status().as_u16() {
        status @ (401 | 403) => Err(Refused(status).into()),
        _ => Ok(response.error_for_status()?),
    }
}

pub struct StalwartApi {
    http: reqwest::Client,
    /// Stalwart's HTTP listener, e.g. `http://stalwart:8080`.
    base: String,
    login: String,
    token: String,
}

impl StalwartApi {
    pub fn new(http: reqwest::Client, base: &str, server_name: &str, token: &str) -> Self {
        StalwartApi {
            http,
            base: base.trim_end_matches('/').to_owned(),
            login: format!("{ACCOUNT}@{server_name}"),
            token: token.to_owned(),
        }
    }

    /// The account the registry calls name: the credential's own.
    async fn account_id(&self) -> Result<String> {
        let session: Value = self
            .http
            .get(format!("{}/jmap/session", self.base))
            .basic_auth(&self.login, Some(&self.token))
            .send()
            .await
            .map_err(anyhow::Error::from)
            .and_then(checked)?
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
            .basic_auth(&self.login, Some(&self.token))
            .json(&body)
            .send()
            .await
            .map_err(anyhow::Error::from)
            .and_then(checked)?
            .json()
            .await?;
        let response = &answer["methodResponses"][0];
        match response[0].as_str() {
            Some("error") => bail!("Stalwart refused {method}: {}", response[1]),
            Some(name) if name == method => Ok(response[1].clone()),
            _ => bail!("Stalwart answered {method} with {answer}"),
        }
    }

    /// Every object of the kind, with every property.
    async fn get(&self, object: &str) -> Result<Vec<Value>> {
        let answer = self
            .call(
                &format!("x:{object}/get"),
                json!({ "ids": null, "properties": null }),
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
            .get("Domain")
            .await?
            .iter()
            .map(|d| StalwartDomain {
                object_id: text(d, "id"),
                name: text(d, "name"),
                description: text(d, "description"),
                content: digest(d),
            })
            .collect())
    }

    async fn signatures(&self) -> Result<Vec<StalwartSignature>> {
        Ok(self
            .get("DkimSignature")
            .await?
            .iter()
            .map(|s| StalwartSignature {
                object_id: text(s, "id"),
                domain_object_id: text(s, "domainId"),
                selector: text(s, "selector"),
                content: digest(s),
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

/// A digest of `value` with its keys sorted at every level, whatever order
/// Stalwart lists them in.
fn digest(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|k| (k.clone(), sorted(&map[k])))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(sorted(value).to_string().as_bytes()))
}
