//! The account's devices (docs/plans/one-device-list.md): registering this
//! CLI as one, listing them, and the account manifest that lists them.

use anyhow::Result;
use kutup_chat_proto::{
    AccountDeviceV1, AccountManifestV3, RegisterDeviceRequestV1, RegisterDeviceResponseV1,
};
use kutup_crypto::account_ref::AccountRef;
use reqwest::Method;
use serde::Deserialize;

use super::Client;

impl Client {
    /// Every device of the account, of every kind.
    pub fn list_devices(&self) -> Result<Vec<AccountDeviceV1>> {
        #[derive(Deserialize)]
        struct Devices {
            devices: Vec<AccountDeviceV1>,
        }
        let resp = self.request(Method::GET, "/devices").send()?;
        Ok(super::decode_json::<Devices>(resp)?.devices)
    }

    /// Registers an editor or CLI device of the account: its id, and the
    /// `session` its manifest entry lists.
    pub fn register_device(
        &self,
        request: &RegisterDeviceRequestV1,
    ) -> Result<RegisterDeviceResponseV1> {
        let resp = self
            .request(Method::POST, "/devices")
            .json(request)
            .send()?;
        super::decode_json(resp)
    }

    /// The account's manifest as its server holds it; none while it has none
    /// (`404 noManifest`).
    pub fn account_manifest(&self, account: &AccountRef) -> Result<Option<AccountManifestV3>> {
        let resp = self
            .request(
                Method::GET,
                &format!("/chat/accounts/{}/manifest", account.account_id),
            )
            .query(&[("server", account.server.as_str())])
            .send()?;
        if resp.status().as_u16() == 404 {
            let error = super::api_error(resp);
            if error
                .chain()
                .filter_map(|e| e.downcast_ref::<super::ApiError>())
                .any(|e| e.code.as_deref() == Some("noManifest"))
            {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(Some(super::decode_json(resp)?))
    }

    /// `account`'s manifests from `from` through `to`, every page
    /// (`manifest-history`); whoever reads them verifies them.
    pub fn account_manifest_history(
        &self,
        account: &AccountRef,
        from: u64,
        to: u64,
    ) -> Result<Vec<AccountManifestV3>> {
        let mut out = Vec::new();
        let mut page_from = Some(from);
        for _ in 0..16 {
            let Some(page) = page_from else { break };
            let resp = self
                .request(
                    Method::GET,
                    &format!("/chat/accounts/{}/manifest-history", account.account_id),
                )
                .query(&[
                    ("server", account.server.clone()),
                    ("fromSequence", from.to_string()),
                    ("toSequence", to.to_string()),
                    ("pageFromSequence", page.to_string()),
                ])
                .send()?;
            let page: kutup_chat_proto::AccountManifestHistoryPageV3 = super::decode_json(resp)?;
            out.extend(page.manifests);
            page_from = page.next_sequence;
        }
        Ok(out)
    }

    /// Publishes the account's next manifest as the device `by` names
    /// (`X-Kutup-Device`).
    pub fn publish_manifest(&self, manifest: &AccountManifestV3, by: &str) -> Result<()> {
        let resp = self
            .request(Method::POST, "/chat/manifest")
            .header(kutup_chat_proto::DEVICE_HEADER, by)
            .json(manifest)
            .send()?;
        super::check_ok(resp)
    }
}
