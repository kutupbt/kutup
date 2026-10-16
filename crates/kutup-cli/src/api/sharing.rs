//! Local sharing endpoints — mirrors the share-related methods of `client.go`.

use anyhow::Result;
use reqwest::Method;

use super::{
    AccountLookup, Client, FederatedShareRequest, FederatedShareResponse, PublicShareRequest,
    PublicShareResponse, ShareRequest,
};

impl Client {
    /// Shares a collection with another local user. Mirrors `ShareCollection`.
    pub fn share_collection(&self, collection_id: &str, req: &ShareRequest) -> Result<()> {
        let resp = self
            .request(Method::POST, &format!("/collections/{collection_id}/share"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(req)
            .send()?;
        super::check_ok(resp)
    }

    /// Shares a collection with a user on another server. Mirrors `ShareFederated`.
    pub fn share_federated(
        &self,
        collection_id: &str,
        req: &FederatedShareRequest,
    ) -> Result<FederatedShareResponse> {
        let resp = self
            .request(
                Method::POST,
                &format!("/collections/{collection_id}/federated-shares"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(req)
            .send()?;
        super::decode_json(resp)
    }

    /// Creates a public link share. Mirrors `CreatePublicShare`.
    pub fn create_public_share(&self, req: &PublicShareRequest) -> Result<PublicShareResponse> {
        let resp = self
            .request(Method::POST, "/share/")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(req)
            .send()?;
        super::decode_json(resp)
    }

    /// An account and its Drive keys by its Kutup address, here or through
    /// its server: the one name lookup.
    pub fn get_user_by_address(&self, address: &str) -> Result<AccountLookup> {
        let resp = self
            .request(
                Method::GET,
                &format!("/users/by-address/{}", super::path_segment(address)),
            )
            .send()?;
        super::decode_json(resp)
    }

    /// An account by its permanent id, here or through its server: its
    /// address now (shown only) and its keys.
    pub fn get_account(
        &self,
        person: &kutup_crypto::account_ref::AccountRef,
    ) -> Result<AccountLookup> {
        let resp = self
            .request(
                Method::GET,
                &format!("/users/by-id/{}", super::path_segment(&person.account_id)),
            )
            .query(&[("server", person.server.as_str())])
            .send()?;
        super::decode_json(resp)
    }
}
