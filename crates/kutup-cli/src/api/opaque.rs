//! OPAQUE sign-in and registration (docs/plans/opaque.md §6): the requests
//! the CLI's half of the exchange sends. The protocol itself is
//! `kutup_crypto::opaque`.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::Method;
use serde::Deserialize;

use super::{Client, LoginResponse};

/// The server's answer to a sign-in's start.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStarted {
    pub login_id: String,
    /// KE2, base64.
    pub credential_response: String,
}

impl LoginStarted {
    pub fn response(&self) -> Result<Vec<u8>> {
        Ok(STANDARD.decode(&self.credential_response)?)
    }
}

/// The server's answer to a registration's start.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStarted {
    /// `RegistrationResponse`, base64.
    pub registration_response: String,
    /// The setup it is answered under: given back with the record.
    pub server_key_id: u16,
}

impl RegisterStarted {
    pub fn response(&self) -> Result<Vec<u8>> {
        Ok(STANDARD.decode(&self.registration_response)?)
    }
}

// No Debug: it carries a one-time grant.
#[derive(Deserialize)]
struct Granted {
    grant: String,
}

impl Client {
    /// Starts a sign-in (`purpose`: `session`, or `reauth` for a grant
    /// `grant_for`, with this client's session).
    pub fn login_start(
        &self,
        name: &str,
        request: &[u8],
        purpose: &str,
        grant_for: Option<&str>,
    ) -> Result<LoginStarted> {
        let resp = self
            .request(Method::POST, "/auth/login/start")
            .json(&serde_json::json!({
                "name": name, "credentialRequest": STANDARD.encode(request),
                "purpose": purpose, "for": grant_for,
            }))
            .send()?;
        super::decode_json(resp)
    }

    /// Finishes a sign-in: the session's answer.
    pub fn login_finish(&self, login_id: &str, finalization: &[u8]) -> Result<LoginResponse> {
        let resp = self
            .request(Method::POST, "/auth/login/finish")
            .json(&serde_json::json!({
                "loginId": login_id, "credentialFinalization": STANDARD.encode(finalization),
            }))
            .send()?;
        super::decode_json(resp)
    }

    /// Finishes a reauth: its one-time grant.
    pub fn reauth_finish(&self, login_id: &str, finalization: &[u8]) -> Result<String> {
        let resp = self
            .request(Method::POST, "/auth/login/finish")
            .json(&serde_json::json!({
                "loginId": login_id, "credentialFinalization": STANDARD.encode(finalization),
            }))
            .send()?;
        Ok(super::decode_json::<Granted>(resp)?.grant)
    }

    /// Starts registering a password for `key_binding` (with `grant` for an
    /// account's own new password).
    pub fn register_start(
        &self,
        key_binding: &str,
        request: &[u8],
        grant: Option<&str>,
    ) -> Result<RegisterStarted> {
        let resp = self
            .request(Method::POST, "/auth/opaque/register/start")
            .json(&serde_json::json!({
                "keyBinding": key_binding, "registrationRequest": STANDARD.encode(request),
                "grant": grant,
            }))
            .send()?;
        super::decode_json(resp)
    }

    /// Makes a registered record the account's password, with its grant, and
    /// the master key sealed under the new password.
    pub fn register_finish(
        &self,
        grant: &str,
        key_binding: &str,
        record: &[u8],
        server_key_id: u16,
        master_key_envelope: &str,
    ) -> Result<()> {
        let resp = self
            .request(Method::POST, "/auth/opaque/register/finish")
            .json(&serde_json::json!({
                "grant": grant, "keyBinding": key_binding,
                "opaqueRecord": STANDARD.encode(record), "opaqueServerKeyId": server_key_id,
                "masterKeyEnvelope": master_key_envelope,
            }))
            .send()?;
        super::check_ok(resp)
    }

    /// A recovery grant, from the recovery phrase's proof.
    pub fn recover_grant(&self, name: &str, recovery_proof: &str) -> Result<String> {
        let resp = self
            .request(Method::POST, "/auth/recover/grant")
            .json(&serde_json::json!({ "name": name, "recoveryProof": recovery_proof }))
            .send()?;
        Ok(super::decode_json::<Granted>(resp)?.grant)
    }
}
