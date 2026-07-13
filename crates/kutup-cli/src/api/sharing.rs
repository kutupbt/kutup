//! Local sharing endpoints — mirrors the share-related methods of `client.go`.

use anyhow::Result;
use reqwest::Method;

use super::{
    Client, FedPubKeyResponse, FederatedShareRequest, FederatedShareResponse, PublicShareRequest,
    PublicShareResponse, ShareRequest, UserByEmail,
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
                &format!("/collections/{collection_id}/share-federated"),
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

    /// Looks up a local user's id + public key by email. Mirrors `GetUserByEmail`.
    pub fn get_user_by_email(&self, email: &str) -> Result<UserByEmail> {
        let resp = self
            .request(
                Method::GET,
                &format!("/users/by-email/{}", super::path_segment(email)),
            )
            .send()?;
        super::decode_json(resp)
    }

    /// Fetches a remote user's federation public key. Mirrors `GetFedPubKey`.
    pub fn get_fed_pubkey(&self, username: &str, server: &str) -> Result<FedPubKeyResponse> {
        // .query() encodes both values — the server arg is a full URL.
        let resp = self
            .request(Method::GET, "/collections/fed-pubkey")
            .query(&[("username", username), ("server", server)])
            .send()?;
        super::decode_json(resp)
    }
}
