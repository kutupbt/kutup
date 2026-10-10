//! Mail address keys (docs/plans/mail-address-keys.md): each account's email
//! address `username@<server name>`, its OpenPGP keys, and its signed key
//! list, as Proton keeps addresses, address keys and signed key lists.
//!
//! The server never holds a private key: clients upload the public key, the
//! master-key envelope of the secret key, and the key list signed by the
//! account authority. The server checks what it can (the public key's shape
//! and address, the envelope's purpose and account, the list's signature,
//! chain and contents) and publishes the public side: to Kutup users through
//! `GET /api/mail/keys`, to the world through WKD.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::mail_key::{self, MailKeyEntryV1, SignedMailKeyListV1, FLAG_NOT_OBSOLETE};
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

/// One key of an address, as its owner sees it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OwnMailKey {
    pub id: String,
    pub fingerprint: String,
    pub sha256_fingerprint: String,
    /// Binary OpenPGP public key, base64.
    pub public_key: String,
    /// The secret key sealed under the master key, base64.
    pub private_key_envelope: String,
    pub primary: bool,
    pub flags: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

/// A signed key list: canonical bytes and the authority's signature, base64.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeyList {
    pub data: String,
    pub signature: String,
}

/// One of the caller's addresses.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OwnMailAddress {
    pub id: String,
    pub address: String,
    pub keys: Vec<OwnMailKey>,
    /// The current signed key list; null until the first key is added.
    pub key_list: Option<SignedKeyList>,
}

/// The account (`username@server`) and its email address: the same string.
async fn account_and_address(
    state: &AppState,
    user_id: Uuid,
) -> AppResult<Option<(String, String)>> {
    let username: Option<Option<String>> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(Some(username)) = username else {
        return Ok(None);
    };
    let account = format!("{username}@{}", state.config.chat_server_name);
    let address = mail_key::canonical_address(&account)
        .map_err(|_| AppError::internal("username is not a valid mail address"))?;
    Ok(Some((account, address)))
}

/// Creates the caller's address row on first use.
async fn ensure_address(state: &AppState, user_id: Uuid, address: &str) -> AppResult<Uuid> {
    sqlx::query("INSERT INTO mail_addresses (user_id, address) VALUES ($1, $2) ON CONFLICT (address) DO NOTHING")
        .bind(user_id)
        .bind(address)
        .execute(&state.pool)
        .await?;
    let (id, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT id, user_id FROM mail_addresses WHERE address = $1")
            .bind(address)
            .fetch_one(&state.pool)
            .await?;
    if owner != user_id {
        // A recreated account under a reused username must not inherit keys.
        return Err(AppError::conflict(
            "this address belongs to another account",
        ));
    }
    Ok(id)
}

type KeyRow = (
    Uuid,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    bool,
    i32,
    time::OffsetDateTime,
);

async fn own_address(
    state: &AppState,
    address_id: Uuid,
    address: String,
) -> AppResult<OwnMailAddress> {
    let keys: Vec<KeyRow> = sqlx::query_as(
        "SELECT id, fingerprint, sha256_fingerprint, public_key, private_key_envelope, is_primary, flags, created_at
           FROM mail_address_keys WHERE address_id = $1 ORDER BY created_at, fingerprint",
    )
    .bind(address_id)
    .fetch_all(&state.pool)
    .await?;
    let list: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT data, signature FROM mail_key_lists WHERE address_id = $1 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(address_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(OwnMailAddress {
        id: address_id.to_string(),
        address,
        keys: keys
            .into_iter()
            .map(
                |(id, fingerprint, sha256, public_key, envelope, primary, flags, created_at)| {
                    OwnMailKey {
                        id: id.to_string(),
                        fingerprint,
                        sha256_fingerprint: sha256,
                        public_key: STANDARD.encode(public_key),
                        private_key_envelope: STANDARD.encode(envelope),
                        primary,
                        flags,
                        created_at,
                    }
                },
            )
            .collect(),
        key_list: list.map(|(data, signature)| SignedKeyList {
            data: STANDARD.encode(data),
            signature: STANDARD.encode(signature),
        }),
    })
}

/// `GET /api/mail/addresses` — the caller's addresses with their keys and
/// current signed key list. An account without a username has none.
#[utoipa::path(
    get,
    path = "/api/mail/addresses",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's addresses", body = [OwnMailAddress]))
)]
pub async fn list_addresses(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<OwnMailAddress>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let Some((_, address)) = account_and_address(&state, user_id).await? else {
        return Ok(Json(Vec::new()));
    };
    let id = ensure_address(&state, user_id, &address).await?;
    Ok(Json(vec![own_address(&state, id, address).await?]))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddMailKeyRequest {
    /// Binary OpenPGP public key, base64.
    pub public_key: String,
    /// The secret key sealed under the master key (purpose
    /// `MailAddressPrivateKey`), base64.
    pub private_key_envelope: String,
    /// The address's next signed key list, listing every key it keeps
    /// including this one.
    pub key_list: SignedKeyList,
}

fn decode(value: &str, field: &str) -> AppResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request(format!("{field} must be base64")))?;
    if STANDARD.encode(&bytes) != value {
        return Err(AppError::bad_request(format!(
            "{field} must be canonical base64"
        )));
    }
    Ok(bytes)
}

/// A key list change in progress: the address locked, the new list checked
/// as the direct successor of the current one.
struct ListChange {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    address_id: Uuid,
    address: String,
    signed: SignedMailKeyListV1,
}

/// Verifies `key_list` as the next signed list of the caller's address
/// `id`, against the account authority, and locks the address.
async fn begin_list_change(
    state: &AppState,
    user_id: Uuid,
    id: &str,
    key_list: &SignedKeyList,
) -> AppResult<ListChange> {
    let address_id = Uuid::parse_str(id).map_err(|_| AppError::not_found("not found"))?;
    let Some((account, address)) = account_and_address(state, user_id).await? else {
        return Err(AppError::not_found("not found"));
    };
    let data = decode(&key_list.data, "keyList.data")?;
    let signature = decode(&key_list.signature, "keyList.signature")?;
    let authority: String =
        sqlx::query_scalar("SELECT account_authority_public_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let authority: [u8; 32] = STANDARD
        .decode(&authority)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| AppError::internal("account authority key is invalid"))?;
    let signed = SignedMailKeyListV1::verify(&data, &signature, &authority)
        .map_err(|error| AppError::bad_request(format!("keyList: {error}")))?;
    if signed.list.account != account || signed.list.address != address {
        return Err(AppError::bad_request(
            "keyList is for another account or address",
        ));
    }

    let mut tx = state.pool.begin().await?;
    let owner: Option<(Uuid, String)> =
        sqlx::query_as("SELECT user_id, address FROM mail_addresses WHERE id = $1 FOR UPDATE")
            .bind(address_id)
            .fetch_optional(&mut *tx)
            .await?;
    match owner {
        Some((owner, stored)) if owner == user_id && stored == address => {}
        _ => return Err(AppError::not_found("not found")),
    }
    // The list must follow the current one exactly.
    let current: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT data, signature FROM mail_key_lists WHERE address_id = $1 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(address_id)
    .fetch_optional(&mut *tx)
    .await?;
    match current {
        Some((data, signature)) => {
            let previous = SignedMailKeyListV1::verify(&data, &signature, &authority)
                .map_err(|_| AppError::internal("stored key list does not verify"))?;
            previous
                .check_successor(&signed)
                .map_err(|_| AppError::conflict("keyList does not follow the current one"))?;
        }
        None if signed.list.sequence == 1 => {}
        None => {
            return Err(AppError::conflict(
                "keyList does not follow the current one",
            ))
        }
    }
    Ok(ListChange {
        tx,
        address_id,
        address,
        signed,
    })
}

impl ListChange {
    /// The stored keys' fingerprints, with `extra`.
    async fn check_lists_exactly(&mut self, extra: Option<(String, String)>) -> AppResult<()> {
        let stored: Vec<(String, String)> = sqlx::query_as(
            "SELECT fingerprint, sha256_fingerprint FROM mail_address_keys WHERE address_id = $1",
        )
        .bind(self.address_id)
        .fetch_all(&mut *self.tx)
        .await?;
        let mut expected: Vec<(String, String)> = stored.into_iter().chain(extra).collect();
        expected.sort();
        let mut listed: Vec<(String, String)> = self
            .signed
            .list
            .keys
            .iter()
            .map(|key: &MailKeyEntryV1| {
                (
                    hex::encode(key.fingerprint),
                    hex::encode(key.sha256_fingerprint),
                )
            })
            .collect();
        listed.sort();
        if listed != expected {
            return Err(AppError::bad_request(
                "keyList must list exactly the address's keys",
            ));
        }
        Ok(())
    }

    /// Primary and flags follow the list; the list is recorded.
    async fn finish(mut self, state: &AppState) -> AppResult<OwnMailAddress> {
        sqlx::query("UPDATE mail_address_keys SET is_primary = false WHERE address_id = $1")
            .bind(self.address_id)
            .execute(&mut *self.tx)
            .await?;
        for key in &self.signed.list.keys {
            sqlx::query("UPDATE mail_address_keys SET is_primary = $3, flags = $4 WHERE address_id = $1 AND fingerprint = $2")
                .bind(self.address_id)
                .bind(hex::encode(key.fingerprint))
                .bind(key.primary)
                .bind(key.flags as i32)
                .execute(&mut *self.tx)
                .await?;
        }
        sqlx::query("INSERT INTO mail_key_lists (address_id, sequence, data, signature) VALUES ($1, $2, $3, $4)")
            .bind(self.address_id)
            .bind(self.signed.list.sequence as i64)
            .bind(&self.signed.data)
            .bind(self.signed.signature.as_slice())
            .execute(&mut *self.tx)
            .await
            .map_err(|error| match error {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    AppError::conflict("keyList does not follow the current one")
                }
                other => other.into(),
            })?;
        self.tx.commit().await?;
        own_address(state, self.address_id, self.address).await
    }
}

/// `POST /api/mail/addresses/{id}/keys` — adds a key (generated, or
/// imported from a key file) to one of the caller's addresses together with
/// the next signed key list, in one transaction. The list may make it the
/// primary key (a new key replacing the old for new mail).
#[utoipa::path(
    post,
    path = "/api/mail/addresses/{id}/keys",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Address id")),
    request_body = AddMailKeyRequest,
    responses(
        (status = 200, description = "The address with its keys", body = OwnMailAddress),
        (status = 400, description = "The key, envelope or key list is not valid for this address"),
        (status = 409, description = "The key list does not follow the current one (another device changed it), or the key is already in use"),
    )
)]
pub async fn add_key(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<AddMailKeyRequest>,
) -> AppResult<Json<OwnMailAddress>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let Some((_, address)) = account_and_address(&state, user_id).await? else {
        return Err(AppError::not_found("not found"));
    };
    let public_key = decode(&req.public_key, "publicKey")?;
    let envelope = decode(&req.private_key_envelope, "privateKeyEnvelope")?;
    let info = mail_key::inspect_address_public_key(&public_key, &address)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let login_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    let header = account_envelope::inspect(&envelope)
        .map_err(|_| AppError::bad_request("privateKeyEnvelope is not an account envelope"))?;
    if header.purpose != AccountEnvelopePurpose::MailAddressPrivateKey
        || Some(header.canonical_login_email)
            != account_envelope::canonical_login_email(&login_email).ok()
    {
        return Err(AppError::bad_request(
            "privateKeyEnvelope is not this account's mail key",
        ));
    }

    let mut change = begin_list_change(&state, user_id, &id, &req.key_list).await?;
    let new_entry = (
        hex::encode(info.fingerprint),
        hex::encode(info.sha256_fingerprint),
    );
    change.check_lists_exactly(Some(new_entry.clone())).await?;
    let flags = change
        .signed
        .list
        .keys
        .iter()
        .find(|key| hex::encode(key.fingerprint) == new_entry.0)
        .expect("listed")
        .flags;
    let inserted = sqlx::query(
        "INSERT INTO mail_address_keys
           (address_id, fingerprint, sha256_fingerprint, public_key, private_key_envelope, is_primary, flags)
         VALUES ($1, $2, $3, $4, $5, false, $6)
         ON CONFLICT (fingerprint) DO NOTHING",
    )
    .bind(change.address_id)
    .bind(&new_entry.0)
    .bind(&new_entry.1)
    .bind(&public_key)
    .bind(&envelope)
    .bind(flags as i32)
    .execute(&mut *change.tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(AppError::conflict("this key is already in use"));
    }
    Ok(Json(change.finish(&state).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateKeyListRequest {
    /// The address's next signed key list, listing exactly its keys.
    pub key_list: SignedKeyList,
}

/// `PUT /api/mail/addresses/{id}/key-list` — publishes the next signed key
/// list for the same keys: another key made primary, or keys marked
/// obsolete (not encrypted to) or compromised (signatures not trusted).
#[utoipa::path(
    put,
    path = "/api/mail/addresses/{id}/key-list",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Address id")),
    request_body = UpdateKeyListRequest,
    responses(
        (status = 200, description = "The address with its keys", body = OwnMailAddress),
        (status = 400, description = "The key list is not valid, or does not list exactly the address's keys"),
        (status = 409, description = "The key list does not follow the current one (another device changed it)"),
    )
)]
pub async fn update_key_list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateKeyListRequest>,
) -> AppResult<Json<OwnMailAddress>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut change = begin_list_change(&state, user_id, &id, &req.key_list).await?;
    if change.signed.list.sequence == 1 {
        return Err(AppError::bad_request(
            "an address's first key list comes with its first key",
        ));
    }
    change.check_lists_exactly(None).await?;
    Ok(Json(change.finish(&state).await?))
}

#[derive(Debug, Deserialize)]
pub struct KeyLookupQuery {
    email: String,
}

/// One public key of an address.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicMailKey {
    pub fingerprint: String,
    pub sha256_fingerprint: String,
    pub public_key: String,
    pub primary: bool,
    pub flags: i32,
}

/// A Kutup address's public keys and the whole chain of its signed key
/// lists, oldest first. Clients verify the chain against the account
/// authority from the account's verified manifest (`account`).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailKeyLookup {
    pub address: String,
    pub account: String,
    /// The account authority the server holds for `account`, base64: the
    /// key the lists must chain under. A client that has verified the
    /// account (a Chat safety number) checks it against its pin.
    pub account_authority_public_key: String,
    pub keys: Vec<PublicMailKey>,
    pub key_lists: Vec<SignedKeyList>,
}

async fn public_keys(
    state: &AppState,
    address: &str,
) -> AppResult<Option<(Uuid, String, Vec<PublicMailKey>)>> {
    let row: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT a.id, u.username FROM mail_addresses a JOIN users u ON u.id = a.user_id
          WHERE a.address = $1 AND u.is_active",
    )
    .bind(address)
    .fetch_optional(&state.pool)
    .await?;
    let Some((address_id, Some(username))) = row else {
        return Ok(None);
    };
    let keys: Vec<(String, String, Vec<u8>, bool, i32)> = sqlx::query_as(
        "SELECT fingerprint, sha256_fingerprint, public_key, is_primary, flags
           FROM mail_address_keys WHERE address_id = $1 ORDER BY is_primary DESC, created_at DESC",
    )
    .bind(address_id)
    .fetch_all(&state.pool)
    .await?;
    if keys.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        address_id,
        format!("{username}@{}", state.config.chat_server_name),
        keys.into_iter()
            .map(
                |(fingerprint, sha256, public_key, primary, flags)| PublicMailKey {
                    fingerprint,
                    sha256_fingerprint: sha256,
                    public_key: STANDARD.encode(public_key),
                    primary,
                    flags,
                },
            )
            .collect(),
    )))
}

/// `GET /api/mail/keys?email=` — a Kutup address's public keys and signed
/// key-list chain (Proton's `keys/all`).
#[utoipa::path(
    get,
    path = "/api/mail/keys",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("email" = String, Query, description = "The address to look up")),
    responses(
        (status = 200, description = "Public keys and key lists", body = MailKeyLookup),
        (status = 404, description = "No Kutup address with keys"),
    )
)]
pub async fn lookup_keys(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(query): Query<KeyLookupQuery>,
) -> AppResult<Json<MailKeyLookup>> {
    let address = mail_key::canonical_address(query.email.trim().to_lowercase().as_str())
        .map_err(|_| AppError::not_found("not found"))?;
    let Some((address_id, account, keys)) = public_keys(&state, &address).await? else {
        return Err(AppError::not_found("not found"));
    };
    let authority: String = sqlx::query_scalar(
        "SELECT u.account_authority_public_key FROM mail_addresses a JOIN users u ON u.id = a.user_id
          WHERE a.id = $1",
    )
    .bind(address_id)
    .fetch_one(&state.pool)
    .await?;
    let lists: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT data, signature FROM mail_key_lists WHERE address_id = $1 ORDER BY sequence",
    )
    .bind(address_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(MailKeyLookup {
        address,
        account,
        account_authority_public_key: authority,
        keys,
        key_lists: lists
            .into_iter()
            .map(|(data, signature)| SignedKeyList {
                data: STANDARD.encode(data),
                signature: STANDARD.encode(signature),
            })
            .collect(),
    }))
}

/// z-base-32 (RFC 6189 alphabet), as WKD hashes local parts.
fn zbase32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The WKD hash of a local part.
pub(crate) fn wkd_hash(local_part: &str) -> String {
    zbase32(&Sha1::digest(local_part.to_lowercase().as_bytes()))
}

#[derive(Debug, Deserialize)]
pub struct WkdQuery {
    l: Option<String>,
}

/// `GET /.well-known/openpgpkey/hu/{hash}?l={local part}` — Web Key
/// Directory, direct method: the binary keys an outside OpenPGP client may
/// encrypt to (not obsolete), primary first.
pub async fn wkd_key(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    Query(query): Query<WkdQuery>,
) -> AppResult<Response> {
    let Some(local) = query.l.map(|local| local.to_lowercase()) else {
        return Err(AppError::not_found("not found"));
    };
    if wkd_hash(&local) != hash {
        return Err(AppError::not_found("not found"));
    }
    let address =
        mail_key::canonical_address(&format!("{local}@{}", state.config.chat_server_name))
            .map_err(|_| AppError::not_found("not found"))?;
    let Some((_, _, keys)) = public_keys(&state, &address).await? else {
        return Err(AppError::not_found("not found"));
    };
    let mut body = Vec::new();
    for key in keys
        .iter()
        .filter(|key| key.flags as u32 & FLAG_NOT_OBSOLETE != 0)
    {
        body.extend(
            STANDARD
                .decode(&key.public_key)
                .map_err(|_| AppError::internal("stored key"))?,
        );
    }
    if body.is_empty() {
        return Err(AppError::not_found("not found"));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().expect("static"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        "*".parse().expect("static"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=3600".parse().expect("static"),
    );
    Ok((StatusCode::OK, headers, body).into_response())
}

/// `GET /.well-known/openpgpkey/policy` — present (and empty) so WKD clients
/// know this domain publishes keys.
pub async fn wkd_policy() -> Response {
    ([(header::CONTENT_TYPE, "text/plain")], "").into_response()
}

/// `GET /.well-known/openpgpkey/{domain}/hu/{hash}?l=` — WKD, advanced
/// method, served on `openpgpkey.<server name>`. GnuPG and Proton ask here
/// first whenever that name resolves (a wildcard record makes it), so it
/// answers the same as the direct method, for the server name only.
pub async fn wkd_advanced_key(
    state: State<AppState>,
    Path((domain, hash)): Path<(String, String)>,
    query: Query<WkdQuery>,
) -> AppResult<Response> {
    if !domain.eq_ignore_ascii_case(&state.config.chat_server_name) {
        return Err(AppError::not_found("not found"));
    }
    wkd_key(state, Path(hash), query).await
}

/// `GET /.well-known/openpgpkey/{domain}/policy` — the advanced method's
/// policy file, for the server name only.
pub async fn wkd_advanced_policy(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    if !domain.eq_ignore_ascii_case(&state.config.chat_server_name) {
        return Err(AppError::not_found("not found"));
    }
    Ok(wkd_policy().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wkd_hash_matches_the_specification() {
        // draft-koch-openpgp-webkey-service: "Joe.Doe" → this hash.
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OutsideMailKey {
    pub address: String,
    pub source: crate::mail::outside_keys::KeySource,
    /// Binary OpenPGP public key, base64, checked: self-signed, not revoked
    /// or expired, a user ID for the address, an encryption subkey.
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: u32,
}

/// `GET /api/mail/keys/outside?email=` — an outside address's OpenPGP key,
/// from its Web Key Directory, Proton's key server or keys.openpgp.org
/// (docs/plans/mail.md, C3). Kutup addresses use `GET /api/mail/keys`.
#[utoipa::path(
    get,
    path = "/api/mail/keys/outside",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("email" = String, Query, description = "The outside address")),
    responses(
        (status = 200, description = "Its key", body = OutsideMailKey),
        (status = 400, description = "Not an outside address"),
        (status = 404, description = "No usable key found"),
    )
)]
pub async fn outside_keys(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(query): Query<KeyLookupQuery>,
) -> AppResult<Json<OutsideMailKey>> {
    let Some((local, domain)) = crate::mail::outside_keys::split(&query.email) else {
        return Err(AppError::bad_request("not an email address"));
    };
    if domain.eq_ignore_ascii_case(&state.config.chat_server_name) {
        return Err(AppError::bad_request("a Kutup address: use /api/mail/keys"));
    }
    let address = format!("{local}@{domain}");
    let found = crate::mail::outside_keys::lookup(&state, &address)
        .await
        .ok_or_else(|| AppError::not_found("no key found"))?;
    Ok(Json(OutsideMailKey {
        address,
        source: found.source,
        public_key: STANDARD.encode(&found.key.public_key),
        fingerprint: found.key.fingerprint,
        created_at: found.key.created_at_secs,
    }))
}
