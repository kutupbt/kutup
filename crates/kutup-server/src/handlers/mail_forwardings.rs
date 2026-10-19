//! Mail forwarding's API (docs/plans/mail-forwarding.md), Proton's shape
//! under `/api/mail/forwardings`: the forwarder sets a forwarding up with
//! the material its client made, the forwardee accepts or declines it, and
//! either side ends it. The proxy factors are sealed at once and no answer
//! ever carries one, the forwarder's included.
//!
//! End-to-end forwarding (to a Kutup address on this server) is built;
//! forwarding outside is refused until its slice lands.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::mail_forwarding::{self as crypto, ProxyInstance};
use kutup_crypto::mail_key;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::mail::filters::{self, Condition, Field, Match};
use crate::mail::forwarding::{self, MAX_PER_ACCOUNT, MAX_PER_ADDRESS, PENDING_DAYS};
use crate::middleware::AuthUser;
use crate::AppState;

const MAX_ACTIVATION_CHARS: usize = 65536;

/// One forwarding as either side sees it. Never a proxy factor.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailForwarding {
    pub id: String,
    /// `end_to_end` or `outside`.
    pub kind: String,
    /// `pending`, `active`, `outdated`, `paused` or `rejected`.
    pub state: String,
    pub forwarder_address: String,
    pub forwardee_email: String,
    #[serde(rename = "match")]
    pub rule: Match,
    pub conditions: Vec<Condition>,
    /// Messages that couldn't be forwarded.
    pub skipped: i64,
    /// Why an outside forwarding stopped on its own: `bounces` (paused) or
    /// `budget` (today's is spent; it goes on tomorrow).
    pub notice: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When a pending forwarding lapses.
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailForwardings {
    /// The caller's addresses' forwardings ("From me").
    pub outgoing: Vec<MailForwarding>,
    /// Forwardings to the caller's addresses ("To me").
    pub incoming: Vec<MailForwarding>,
}

/// One forwarder encryption subkey's proxy factor.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyInstanceBody {
    /// v4 fingerprints, hex.
    pub forwarder_fingerprint: String,
    pub forwardee_fingerprint: String,
    /// k, base64 (32 bytes). Sealed at once; never returned.
    pub proxy_parameter: String,
}

/// What the forwarder's client made for an end-to-end forwarding.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndToEndMaterial {
    /// The forwardee key's public part, binary OpenPGP, base64.
    pub forwardee_public_key: String,
    pub instances: Vec<ProxyInstanceBody>,
    /// The activation for the forwardee (armored; checked by their client).
    pub activation: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMailForwarding {
    /// Chosen by the forwarder's client (a UUID v4), so the activation can
    /// bind it before the server has stored anything.
    pub id: String,
    pub forwarder_address_id: String,
    pub forwardee_email: String,
    #[serde(rename = "match", default = "all")]
    pub rule: Match,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Required for a Kutup address on this server.
    pub end_to_end: Option<EndToEndMaterial>,
    /// Outside Kutup, while the address has no other outside forwarding:
    /// its next signed key list, every key as it is plus EMAIL_NO_ENCRYPT.
    pub key_list: Option<crate::handlers::mail_keys::SignedKeyList>,
}

fn all() -> Match {
    Match::All
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailForwardingConditions {
    #[serde(rename = "match")]
    pub rule: Match,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewMailForwarding {
    pub end_to_end: EndToEndMaterial,
}

/// The forwardee's accept: the forwarding key from the activation, as an
/// address key of theirs.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptMailForwarding {
    /// Binary OpenPGP public key, base64.
    pub public_key: String,
    /// The secret key sealed under the master key (purpose
    /// `MailAddressPrivateKey`), base64.
    pub private_key_envelope: String,
}

/// A pending forwarding's activation, for its forwardee only.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailForwardingActivation {
    pub forwarding_id: String,
    pub forwarder_address: String,
    pub forwardee_address: String,
    pub activation: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

fn code(error: AppError, code: &str) -> AppError {
    error.with_details(json!({ "code": code }))
}

fn check_conditions(conditions: &[Condition]) -> AppResult<()> {
    if conditions.len() > filters::MAX_CONDITIONS {
        return Err(AppError::bad_request("too many conditions"));
    }
    for condition in conditions {
        // Proton's forwarding conditions: the filters' without recipient.
        if condition.field == Field::Recipient {
            return Err(AppError::bad_request(
                "forwarding conditions are on the sender, subject or attachments",
            ));
        }
        if condition.field != Field::Attachments
            && (condition.value.trim().is_empty()
                || condition.value.chars().count() > filters::MAX_VALUE_CHARS)
        {
            return Err(AppError::bad_request("a condition needs a value"));
        }
    }
    Ok(())
}

fn fingerprint(hex_value: &str) -> AppResult<[u8; 20]> {
    let bytes = hex::decode(hex_value)
        .ok()
        .filter(|_| hex_value.len() == 40 && hex_value == hex_value.to_ascii_lowercase())
        .ok_or_else(|| AppError::bad_request("fingerprints are 40 lowercase hex characters"))?;
    Ok(bytes.try_into().expect("20 bytes"))
}

fn base64(value: &str, field: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == value)
        .ok_or_else(|| AppError::bad_request(format!("{field} must be canonical base64")))
}

/// Checked material: its proxy factors cover exactly the forwarder primary
/// key's encryption subkeys, one each, and name exactly the forwardee key's
/// subkeys.
struct Material {
    forwardee_public_key: Vec<u8>,
    instances: Vec<ProxyInstance>,
    activation: String,
}

fn check_material(material: &EndToEndMaterial, forwarder_public_key: &[u8]) -> AppResult<Material> {
    let forwardee_public_key = base64(&material.forwardee_public_key, "forwardeePublicKey")?;
    if forwardee_public_key.len() > 16 * 1024 {
        return Err(AppError::bad_request("forwardeePublicKey is too large"));
    }
    if material.activation.len() > MAX_ACTIVATION_CHARS
        || !material
            .activation
            .starts_with("-----BEGIN PGP MESSAGE-----")
    {
        return Err(AppError::bad_request(
            "activation must be an armored message",
        ));
    }
    let mut instances = Vec::with_capacity(material.instances.len());
    for body in &material.instances {
        let k: [u8; 32] = base64(&body.proxy_parameter, "proxyParameter")?
            .try_into()
            .map_err(|_| AppError::bad_request("proxyParameter is 32 bytes"))?;
        instances.push(ProxyInstance {
            forwarder_fingerprint: fingerprint(&body.forwarder_fingerprint)?,
            forwardee_fingerprint: fingerprint(&body.forwardee_fingerprint)?,
            proxy_parameter: Zeroizing::new(k),
        });
    }
    let sorted = |mut values: Vec<[u8; 20]>| {
        values.sort();
        values
    };
    let forwarder_subkeys = crypto::encryption_fingerprints(forwarder_public_key)
        .map_err(|_| AppError::internal("the forwarder's key does not parse"))?;
    let forwardee_subkeys = crypto::forwardee_fingerprints(&forwardee_public_key)
        .map_err(|_| AppError::bad_request("forwardeePublicKey is not a forwarding key"))?;
    let named = |pick: fn(&ProxyInstance) -> [u8; 20]| {
        let values = sorted(instances.iter().map(pick).collect());
        let distinct = values.windows(2).all(|pair| pair[0] != pair[1]);
        (values, distinct)
    };
    let (forwarders, distinct_forwarders) = named(|i| i.forwarder_fingerprint);
    let (forwardees, distinct_forwardees) = named(|i| i.forwardee_fingerprint);
    if !distinct_forwarders
        || !distinct_forwardees
        || forwarders != sorted(forwarder_subkeys)
        || forwardees != sorted(forwardee_subkeys)
    {
        return Err(code(
            AppError::bad_request("the material is not for this address's current key"),
            "forwardingMaterialMismatch",
        ));
    }
    Ok(Material {
        forwardee_public_key,
        instances,
        activation: material.activation.clone(),
    })
}

/// Stores checked material for `forwarding`, sealing every k; the
/// forwarding goes (back) to pending until the forwardee accepts.
async fn store_material(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    forwarding: Uuid,
    material: &Material,
) -> AppResult<()> {
    sqlx::query("DELETE FROM mail_forwarding_keys WHERE forwarding_id = $1")
        .bind(forwarding)
        .execute(&mut **tx)
        .await?;
    for instance in &material.instances {
        let (key_id, sealed) =
            forwarding::seal(&state.config.mail_forwarding_keys, forwarding, instance)
                .ok_or_else(unavailable)?;
        sqlx::query(
            "INSERT INTO mail_forwarding_keys
               (forwarding_id, forwarder_fingerprint, forwardee_fingerprint,
                forwardee_public_key, proxy_parameter_sealed, secret_version)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(forwarding)
        .bind(hex::encode(instance.forwarder_fingerprint))
        .bind(hex::encode(instance.forwardee_fingerprint))
        .bind(&material.forwardee_public_key)
        .bind(&sealed)
        .bind(key_id as i16)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "UPDATE mail_forwardings
            SET state = 'pending', activation = $2,
                expires_at = now() + ($3 * interval '1 day'), updated_at = now()
          WHERE id = $1",
    )
    .bind(forwarding)
    .bind(&material.activation)
    .bind(PENDING_DAYS)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn unavailable() -> AppError {
    code(
        AppError::conflict("this server is not set up for end-to-end forwarding"),
        "forwardingUnavailable",
    )
}

type Row = (
    Uuid,
    String,
    String,
    String,
    String,
    String,
    serde_json::Value,
    i64,
    OffsetDateTime,
    Option<OffsetDateTime>,
    Option<String>,
);

const SELECT: &str = "SELECT f.id, f.kind, f.state, a.address, f.forwardee_email, f.match,
                             f.conditions, f.skipped, f.created_at, f.expires_at,
                             f.notice
                        FROM mail_forwardings f JOIN mail_addresses a ON a.id = f.forwarder_address_id";

fn view(row: Row) -> MailForwarding {
    let (
        id,
        kind,
        state,
        forwarder,
        forwardee,
        rule,
        conditions,
        skipped,
        created_at,
        expires_at,
        notice,
    ) = row;
    MailForwarding {
        id: id.to_string(),
        kind,
        state,
        forwarder_address: forwarder,
        forwardee_email: forwardee,
        rule: if rule == "any" {
            Match::Any
        } else {
            Match::All
        },
        conditions: serde_json::from_value(conditions).unwrap_or_default(),
        skipped,
        notice,
        created_at,
        expires_at,
    }
}

/// `GET /api/mail/forwardings` — the caller's forwardings both ways.
#[utoipa::path(
    get,
    path = "/api/mail/forwardings",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Both ways", body = MailForwardings))
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<MailForwardings>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let outgoing: Vec<Row> = sqlx::query_as(&format!(
        "{SELECT} WHERE f.user_id = $1 ORDER BY f.created_at"
    ))
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let incoming: Vec<Row> = sqlx::query_as(&format!(
        "{SELECT} JOIN mail_addresses b ON b.id = f.forwardee_address_id
          WHERE b.user_id = $1 AND f.state <> 'rejected' ORDER BY f.created_at"
    ))
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(MailForwardings {
        outgoing: outgoing.into_iter().map(view).collect(),
        incoming: incoming.into_iter().map(view).collect(),
    }))
}

/// A Kutup person address on this server that receives now.
async fn local_person(state: &AppState, email: &str) -> AppResult<Option<(Uuid, Uuid, String)>> {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return Ok(None);
    };
    if !domain.eq_ignore_ascii_case(&state.config.chat_server_name) {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT a.id, a.user_id, a.address FROM mail_addresses a
           JOIN users u ON u.id = a.user_id AND u.is_active
          WHERE a.folded = kutup_fold($1) || '@' || lower($2)
            AND a.state = 'active' AND a.group_id IS NULL",
    )
    .bind(local)
    .bind(domain)
    .fetch_optional(&state.pool)
    .await?)
}

/// `POST /api/mail/forwardings` — sets a forwarding of one of the caller's
/// addresses up. To a Kutup address on this server it is end to end, and
/// the body carries the material the forwarder's client made.
#[utoipa::path(
    post,
    path = "/api/mail/forwardings",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = CreateMailForwarding,
    responses(
        (status = 201, description = "Pending until the forwardee accepts", body = MailForwarding),
        (status = 400, description = "Not a valid forwarding (codes: forwardingMaterialMismatch, endToEndRequired)"),
        (status = 409, description = "forwardingExists, forwardingLimit, forwardingUnavailable"),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateMailForwarding>,
) -> AppResult<(StatusCode, Json<MailForwarding>)> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address_id =
        Uuid::parse_str(&req.forwarder_address_id).map_err(|_| AppError::not_found("not found"))?;
    let id = Uuid::parse_str(&req.id)
        .ok()
        .filter(|id| id.get_version_num() == 4 && id.to_string() == req.id)
        .ok_or_else(|| AppError::bad_request("id must be a lowercase UUID v4"))?;
    check_conditions(&req.conditions)?;
    let forwardee_email = req.forwardee_email.trim().to_ascii_lowercase();
    // International addresses (UTF-8 local parts, IDN domains) aren't
    // forwarded to yet: said plainly, so a client can offer the punycode
    // form of the domain.
    if !forwardee_email.is_ascii() {
        return Err(code(
            AppError::bad_request("international addresses can't be forwarded to yet"),
            "internationalAddressUnsupported",
        ));
    }
    if forwardee_email.len() > 320 || !forwardee_email.contains('@') {
        return Err(AppError::bad_request("forwardeeEmail is not an address"));
    }

    let Some((forwardee_address_id, forwardee_user, forwardee_address)) =
        local_person(&state, &forwardee_email).await?
    else {
        return create_outside(&state, user_id, address_id, id, &req, &forwardee_email).await;
    };
    let mut tx = state.pool.begin().await?;
    let forwarder_key = prepare(&mut tx, user_id, address_id).await?;
    if forwardee_user == user_id {
        return Err(AppError::bad_request("forward to someone else's address"));
    }
    let Some(material) = &req.end_to_end else {
        return Err(code(
            AppError::bad_request("forwarding to a Kutup address is end to end"),
            "endToEndRequired",
        ));
    };
    // Nobody may pile requests on someone: at most a few pending to one
    // address at a time (counted under the address's lock, so concurrent
    // requests can't pass it together).
    sqlx::query("SELECT 1 FROM mail_addresses WHERE id = $1 FOR UPDATE")
        .bind(forwardee_address_id)
        .execute(&mut *tx)
        .await?;
    let pending_to: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_forwardings
          WHERE forwardee_address_id = $1 AND state = 'pending'",
    )
    .bind(forwardee_address_id)
    .fetch_one(&mut *tx)
    .await?;
    if pending_to >= forwarding::MAX_PENDING_PER_FORWARDEE {
        return Err(code(
            AppError::conflict("this address has too many forwardings waiting"),
            "forwardingLimit",
        ));
    }
    let material = check_material(material, &forwarder_key)?;
    if state.config.mail_forwarding_keys.current().is_none() {
        return Err(unavailable());
    }

    let inserted = sqlx::query(
        "INSERT INTO mail_forwardings
           (id, user_id, forwarder_address_id, forwardee_email, forwardee_address_id,
            kind, state, match, conditions)
         VALUES ($1, $2, $3, $4, $5, 'end_to_end', 'pending', $6, $7)
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(user_id)
    .bind(address_id)
    .bind(&forwardee_address)
    .bind(forwardee_address_id)
    .bind(match req.rule {
        Match::All => "all",
        Match::Any => "any",
    })
    .bind(serde_json::to_value(&req.conditions).expect("conditions serialize"))
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(code(
            AppError::conflict("this address already forwards there"),
            "forwardingExists",
        ));
    }
    store_material(&state, &mut tx, id, &material).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(one(&state, id).await?)))
}

/// Locks the account (its forwardings are counted under the lock), checks
/// the forwarder address is the caller's current one, and the limits.
/// Returns the address's primary public key.
async fn prepare(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    address_id: Uuid,
) -> AppResult<Vec<u8>> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    // The caller's current address (not one in a rename hold).
    let forwarder_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.public_key FROM mail_addresses a
           JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE a.id = $1 AND a.user_id = $2 AND a.state = 'active' AND a.group_id IS NULL",
    )
    .bind(address_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(forwarder_key) = forwarder_key else {
        return Err(AppError::not_found("not found"));
    };
    let (per_address, per_account): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE forwarder_address_id = $2), COUNT(*)
           FROM mail_forwardings WHERE user_id = $1",
    )
    .bind(user_id)
    .bind(address_id)
    .fetch_one(&mut **tx)
    .await?;
    if per_address >= MAX_PER_ADDRESS || per_account >= MAX_PER_ACCOUNT {
        return Err(code(
            AppError::conflict("too many forwardings"),
            "forwardingLimit",
        ));
    }
    if !forwarding::charge(tx, user_id, forwarding::Charge::Creation).await? {
        return Err(code(
            AppError::too_many_requests("too many forwardings made in the last hour"),
            "rateLimited",
        ));
    }
    Ok(forwarder_key)
}

/// A new confirmation link's token (sent) and its hash (kept).
fn confirmation_token() -> (String, Vec<u8>) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::Digest as _;
    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
    let text = URL_SAFE_NO_PAD.encode(token);
    (text, sha2::Sha256::digest(token).to_vec())
}

/// The hash a confirmation token is kept under; `None` for anything that
/// isn't one.
fn token_hash(token: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::Digest as _;
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    (bytes.len() == 32).then(|| sha2::Sha256::digest(bytes).to_vec())
}

/// Sends an outside forwardee the link to confirm or decline, from the
/// forwarder's address (bounces come back to the forwarding's return path).
async fn send_confirmation(
    state: &AppState,
    forwarding: Uuid,
    forwarder_address: &str,
    forwardee_email: &str,
    token: &str,
) -> anyhow::Result<()> {
    let from = forwarding::return_path(
        &state.config.mail_forwarding_keys,
        &state.config.chat_server_name,
        forwarding,
    )
    .ok_or_else(|| anyhow::anyhow!("no MAIL_FORWARDING_KEYS"))?;
    let link = format!("{}/email-forwarding#{token}", state.config.apps.account);
    let date = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_default();
    let message = format!(
        "From: {forwarder_address}\r\nTo: {forwardee_email}\r\n\
Subject: Confirm forwarding from {forwarder_address}\r\nDate: {date}\r\n\
Message-ID: <{}@{}>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
{forwarder_address} wants to forward their email to this address.\r\n\r\n\
To confirm or decline, open:\r\n{link}\r\n\r\n\
The link works for {} days. If you don't know who this is, decline or ignore this email.\r\n",
        Uuid::new_v4(),
        state.config.chat_server_name,
        PENDING_DAYS,
    );
    crate::mail::submit::submit(
        &state.config.mail_submission_addr,
        &format!("kutup@{}", state.config.chat_server_name),
        &state.config.mail_inbound_token,
        crate::mail::submit::Envelope {
            from: &from,
            recipients: &[forwardee_email.to_owned()],
            message: message.as_bytes(),
        },
    )
    .await?;
    Ok(())
}

/// A fresh link for a pending (or declined) outside forwarding, at most
/// [`forwarding::MAX_INVITES_PER_DAY`] a day. Its token, to send.
async fn reinvite_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    forwarding_id: Uuid,
) -> AppResult<String> {
    // Both allowances or neither: a refused link charges nothing.
    let mut savepoint = sqlx::Acquire::begin(&mut **tx).await?;
    let account: Uuid = sqlx::query_scalar("SELECT user_id FROM mail_forwardings WHERE id = $1")
        .bind(forwarding_id)
        .fetch_one(&mut *savepoint)
        .await?;
    if !forwarding::charge(&mut savepoint, account, forwarding::Charge::Confirmation).await? {
        return Err(code(
            AppError::too_many_requests("enough confirmation emails for today"),
            "rateLimited",
        ));
    }
    let (token, hash) = confirmation_token();
    let renewed = sqlx::query(
        "UPDATE mail_forwardings SET
                invites_today = CASE WHEN day = current_date THEN invites_today + 1 ELSE 1 END,
                sent_today = CASE WHEN day = current_date THEN sent_today ELSE 0 END,
                bounces_today = CASE WHEN day = current_date THEN bounces_today ELSE 0 END,
                day = current_date, state = 'pending', confirmation_hash = $2,
                expires_at = now() + ($3 * interval '1 day'), updated_at = now()
          WHERE id = $1 AND (day <> current_date OR invites_today < $4)",
    )
    .bind(forwarding_id)
    .bind(&hash)
    .bind(PENDING_DAYS)
    .bind(forwarding::MAX_INVITES_PER_DAY)
    .execute(&mut *savepoint)
    .await?;
    if renewed.rows_affected() != 1 {
        return Err(code(
            AppError::too_many_requests("enough confirmation emails for today"),
            "rateLimited",
        ));
    }
    savepoint.commit().await?;
    Ok(token)
}

/// Sets a forwarding outside Kutup up: pending until the forwardee confirms
/// through the emailed link. The address's end-to-end encryption goes off
/// with it, as Proton's does: the first outside forwarding brings the
/// address's next signed key list, every key unchanged but for
/// EMAIL_NO_ENCRYPT.
async fn create_outside(
    state: &AppState,
    user_id: Uuid,
    address_id: Uuid,
    id: Uuid,
    req: &CreateMailForwarding,
    forwardee_email: &str,
) -> AppResult<(StatusCode, Json<MailForwarding>)> {
    let Some(forwardee_email) = forwarding::outside_address(forwardee_email) else {
        return Err(AppError::bad_request(
            "forwardeeEmail is not a plain mailbox address",
        ));
    };
    let forwardee_email = forwardee_email.as_str();
    let (_, domain) = forwardee_email.rsplit_once('@').expect("checked");
    if domain.eq_ignore_ascii_case(&state.config.chat_server_name) {
        return Err(AppError::bad_request(
            "not a Kutup person's address that receives",
        ));
    }
    if req.end_to_end.is_some() {
        return Err(AppError::bad_request(
            "forwarding outside Kutup isn't end to end",
        ));
    }
    if state.config.mail_forwarding_keys.current().is_none() {
        return Err(unavailable());
    }
    let mut change = match &req.key_list {
        Some(list) => Some(
            crate::handlers::mail_keys::begin_list_change(
                state,
                user_id,
                &address_id.to_string(),
                list,
            )
            .await?,
        ),
        None => None,
    };
    let mut own_tx = match change {
        Some(_) => None,
        None => Some(state.pool.begin().await?),
    };
    let tx = match (&mut change, &mut own_tx) {
        (Some(change), _) => &mut change.tx,
        (None, Some(tx)) => tx,
        (None, None) => unreachable!("one of the two"),
    };
    prepare(tx, user_id, address_id).await?;
    // The address's keys as stored: the list must keep each as it is, with
    // EMAIL_NO_ENCRYPT added; without a list they must carry it already.
    let stored: Vec<(String, bool, i32)> = sqlx::query_as(
        "SELECT fingerprint, is_primary, flags FROM mail_address_keys
          WHERE address_id = $1 AND NOT is_forwarding",
    )
    .bind(address_id)
    .fetch_all(&mut **tx)
    .await?;
    let no_encrypt = mail_key::FLAG_EMAIL_NO_ENCRYPT as i32;
    match &mut change {
        None if stored.iter().all(|(_, _, flags)| flags & no_encrypt != 0) => {}
        None => {
            return Err(code(
                AppError::bad_request("the first outside forwarding brings the next key list"),
                "keyListRequired",
            ))
        }
        Some(change) => {
            change.check_lists_exactly(None).await?;
            let follows = change.signed.list.keys.iter().all(|key| {
                stored.iter().any(|(fingerprint, primary, flags)| {
                    *fingerprint == hex::encode(key.fingerprint)
                        && *primary == key.primary
                        && key.flags as i32 == (flags | no_encrypt)
                })
            });
            if !follows {
                return Err(code(
                    AppError::bad_request(
                        "the key list must keep every key as it is, with EMAIL_NO_ENCRYPT",
                    ),
                    "keyListMismatch",
                ));
            }
        }
    }
    let tx = match (&mut change, &mut own_tx) {
        (Some(change), _) => &mut change.tx,
        (None, Some(tx)) => tx,
        (None, None) => unreachable!("one of the two"),
    };
    let inserted = sqlx::query(
        "INSERT INTO mail_forwardings
           (id, user_id, forwarder_address_id, forwardee_email, kind, state, match, conditions)
         VALUES ($1, $2, $3, $4, 'outside', 'pending', $5, $6)
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(user_id)
    .bind(address_id)
    .bind(forwardee_email)
    .bind(match req.rule {
        Match::All => "all",
        Match::Any => "any",
    })
    .bind(serde_json::to_value(&req.conditions).expect("conditions serialize"))
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(code(
            AppError::conflict("this address already forwards there"),
            "forwardingExists",
        ));
    }
    let token = reinvite_in(tx, id).await?;
    let forwarder_address: String =
        sqlx::query_scalar("SELECT address FROM mail_addresses WHERE id = $1")
            .bind(address_id)
            .fetch_one(&mut **tx)
            .await?;
    match (change, own_tx) {
        (Some(change), _) => {
            change.finish(state).await?;
        }
        (None, Some(tx)) => tx.commit().await?,
        (None, None) => unreachable!("one of the two"),
    }
    if let Err(error) =
        send_confirmation(state, id, &forwarder_address, forwardee_email, &token).await
    {
        // Still pending: the forwarder can send the link again.
        tracing::warn!(%id, error = %error, "mail: a forwarding confirmation was not sent");
    }
    Ok((StatusCode::CREATED, Json(one(state, id).await?)))
}

/// `PUT /api/mail/forwardings/{id}/reinvite` — the forwarder sends an
/// outside forwardee a fresh link (a pending forwarding, or a declined one
/// asked again), at most 3 a day.
#[utoipa::path(
    put,
    path = "/api/mail/forwardings/{id}/reinvite",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    responses((status = 200, description = "Pending, link sent", body = MailForwarding), (status = 409, description = "forwardingState"), (status = 429, description = "rateLimited"))
)]
pub async fn reinvite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailForwarding>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    let (id, side, current, _) = lock(&mut tx, user_id, &id).await?;
    let (kind, forwarder_address, forwardee_email): (String, String, String) = sqlx::query_as(
        "SELECT f.kind, a.address, f.forwardee_email FROM mail_forwardings f
           JOIN mail_addresses a ON a.id = f.forwarder_address_id WHERE f.id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if side != Side::Forwarder || kind != "outside" {
        return Err(AppError::not_found("not found"));
    }
    if current != "pending" && current != "rejected" {
        return Err(code(
            AppError::conflict(format!("the forwarding is {current}")),
            "forwardingState",
        ));
    }
    // Asked again after a decline, the address may have gone back to end to
    // end meanwhile: the forwarding then needs setting up anew, key list and
    // all.
    let still_open: bool = sqlx::query_scalar(
        "SELECT COALESCE(bool_and(k.flags & 4 <> 0), false)
           FROM mail_forwardings f
           JOIN mail_address_keys k ON k.address_id = f.forwarder_address_id
          WHERE f.id = $1 AND NOT k.is_forwarding",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if !still_open {
        return Err(code(
            AppError::bad_request("the address is end to end again: set the forwarding up anew"),
            "keyListRequired",
        ));
    }
    let token = reinvite_in(&mut tx, id).await?;
    tx.commit().await?;
    if let Err(error) =
        send_confirmation(&state, id, &forwarder_address, &forwardee_email, &token).await
    {
        tracing::warn!(%id, error = %error, "mail: a forwarding confirmation was not sent");
    }
    Ok(Json(one(&state, id).await?))
}

/// A confirmation link's token, as the public page sends it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardingToken {
    pub token: String,
}

/// What the public page shows about a forwarding.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalForwarding {
    pub state: String,
    pub forwarder_email: String,
    pub forwardee_email: String,
}

/// Confirmation-page requests one client may make in a minute.
static EXTERNAL_LIMIT: std::sync::LazyLock<crate::ratelimit::RateLimiter> =
    std::sync::LazyLock::new(|| {
        crate::ratelimit::RateLimiter::new(30, std::time::Duration::from_secs(60))
    });

/// The confirmation page is public: limited per client, keyed as the
/// middleware keys clients (an IPv6 address by its /64; the socket's
/// address when the proxy's headers are missing).
fn limit_external(headers: &axum::http::HeaderMap, peer: std::net::SocketAddr) -> AppResult<()> {
    let client =
        crate::middleware::client_key(crate::middleware::client_ip_from_headers(headers), peer);
    if EXTERNAL_LIMIT.allow(&format!("forwarding-external:{client}")) {
        Ok(())
    } else {
        Err(code(
            AppError::too_many_requests("too many requests"),
            "rateLimited",
        ))
    }
}

/// A fresh link to send once the transaction that made it has committed.
struct Resend {
    id: Uuid,
    forwarder: String,
    forwardee: String,
    token: String,
}

enum Looked {
    Found(Uuid, String, String, String),
    /// The link expired; a new one is made when the day's allowances allow.
    Expired(Option<Resend>),
}

/// The outside forwarding a token names, locked.
async fn by_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
) -> AppResult<Looked> {
    let hash = token_hash(token).ok_or_else(|| AppError::not_found("not found"))?;
    let row: Option<(Uuid, String, String, String, bool)> = sqlx::query_as(
        "SELECT f.id, f.state, a.address, f.forwardee_email,
                COALESCE(f.expires_at > now(), false)
           FROM mail_forwardings f JOIN mail_addresses a ON a.id = f.forwarder_address_id
          WHERE f.kind = 'outside' AND f.confirmation_hash = $1 FOR UPDATE OF f",
    )
    .bind(&hash)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, current, forwarder, forwardee, fresh)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if fresh {
        return Ok(Looked::Found(id, current, forwarder, forwardee));
    }
    let resend = reinvite_in(tx, id).await.ok().map(|token| Resend {
        id,
        forwarder,
        forwardee,
        token,
    });
    Ok(Looked::Expired(resend))
}

/// Commits what an expired link's lookup made, then sends the new link
/// (Proton's "We just sent you a new link"): `410 linkExpired`.
async fn expired(
    state: &AppState,
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    resend: Option<Resend>,
) -> AppError {
    match tx.commit().await {
        Ok(()) => {
            if let Some(Resend {
                id,
                forwarder,
                forwardee,
                token,
            }) = resend
            {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        send_confirmation(&state, id, &forwarder, &forwardee, &token).await
                    {
                        tracing::warn!(%id, error = %error, "mail: a forwarding confirmation was not sent");
                    }
                });
            }
            code(
                AppError::new(StatusCode::GONE, "this link has expired"),
                "linkExpired",
            )
        }
        Err(error) => error.into(),
    }
}

/// `POST /api/mail/forwardings/external` — the public confirmation page
/// reads what a link is for (no account needed).
#[utoipa::path(
    post,
    path = "/api/mail/forwardings/external",
    tag = "mail",
    request_body = ForwardingToken,
    responses((status = 200, description = "The forwarding", body = ExternalForwarding), (status = 404, description = "No such link"), (status = 410, description = "linkExpired (a new one was sent)"), (status = 429, description = "rateLimited"))
)]
pub async fn external(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ForwardingToken>,
) -> AppResult<Json<ExternalForwarding>> {
    limit_external(&headers, peer)?;
    let mut tx = state.pool.begin().await?;
    match by_token(&mut tx, &req.token).await? {
        Looked::Found(_, current, forwarder, forwardee) => {
            tx.commit().await?;
            Ok(Json(ExternalForwarding {
                state: current,
                forwarder_email: forwarder,
                forwardee_email: forwardee,
            }))
        }
        Looked::Expired(resend) => Err(expired(&state, tx, resend).await),
    }
}

/// `POST /api/mail/forwardings/external/accept` — the outside forwardee
/// confirms: the forwarding is active and the link spent.
#[utoipa::path(
    post,
    path = "/api/mail/forwardings/external/accept",
    tag = "mail",
    request_body = ForwardingToken,
    responses((status = 204, description = "Active"), (status = 404, description = "No such link"), (status = 410, description = "linkExpired"), (status = 429, description = "rateLimited"))
)]
pub async fn external_accept(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ForwardingToken>,
) -> AppResult<StatusCode> {
    limit_external(&headers, peer)?;
    let mut tx = state.pool.begin().await?;
    let (id, current) = match by_token(&mut tx, &req.token).await? {
        Looked::Found(id, current, _, _) => (id, current),
        Looked::Expired(resend) => return Err(expired(&state, tx, resend).await),
    };
    if current != "pending" {
        return Err(code(
            AppError::conflict(format!("the forwarding is {current}")),
            "forwardingState",
        ));
    }
    sqlx::query(
        "UPDATE mail_forwardings SET state = 'active', confirmation_hash = NULL,
                expires_at = NULL, notice = NULL, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/mail/forwardings/external/decline` — the outside forwardee
/// declines: it is `rejected` for the forwarder, and the link spent.
#[utoipa::path(
    post,
    path = "/api/mail/forwardings/external/decline",
    tag = "mail",
    request_body = ForwardingToken,
    responses((status = 204, description = "Declined"), (status = 404, description = "No such link"), (status = 410, description = "linkExpired"), (status = 429, description = "rateLimited"))
)]
pub async fn external_decline(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ForwardingToken>,
) -> AppResult<StatusCode> {
    limit_external(&headers, peer)?;
    let mut tx = state.pool.begin().await?;
    let id = match by_token(&mut tx, &req.token).await? {
        Looked::Found(id, _, _, _) => id,
        Looked::Expired(resend) => return Err(expired(&state, tx, resend).await),
    };
    forwarding::reject(&mut tx, id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn one(state: &AppState, id: Uuid) -> AppResult<MailForwarding> {
    let row: Row = sqlx::query_as(&format!("{SELECT} WHERE f.id = $1"))
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    Ok(view(row))
}

/// Who the caller is to a forwarding.
#[derive(PartialEq)]
enum Side {
    Forwarder,
    Forwardee,
}

/// Locks the forwarding and says which side the caller is on; `404` when
/// neither.
async fn lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    id: &str,
) -> AppResult<(Uuid, Side, String, Option<Uuid>)> {
    let id = Uuid::parse_str(id).map_err(|_| AppError::not_found("not found"))?;
    let row: Option<(Uuid, Option<Uuid>, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT f.user_id, b.user_id, f.state, f.forwardee_address_id
           FROM mail_forwardings f
           LEFT JOIN mail_addresses b ON b.id = f.forwardee_address_id
          WHERE f.id = $1 FOR UPDATE OF f",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        Some((forwarder, _, state, forwardee)) if forwarder == user_id => {
            Ok((id, Side::Forwarder, state, forwardee))
        }
        Some((_, Some(forwardee_user), state, forwardee)) if forwardee_user == user_id => {
            Ok((id, Side::Forwardee, state, forwardee))
        }
        _ => Err(AppError::not_found("not found")),
    }
}

/// `DELETE /api/mail/forwardings/{id}` — either side ends it; its proxy
/// factors go with it. The forwardee keeps the forwarding key (mail already
/// forwarded needs it) until they delete it.
#[utoipa::path(
    delete,
    path = "/api/mail/forwardings/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    responses((status = 204, description = "Ended"), (status = 404, description = "Not a forwarding of the caller's"))
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    let (id, _, _, _) = lock(&mut tx, user_id, &id).await?;
    let address: Uuid = sqlx::query_scalar(
        "DELETE FROM mail_forwardings WHERE id = $1 RETURNING forwarder_address_id",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    forwarding::settle_outside(&mut tx, address).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Moves a forwarding the forwarder owns from one state to another.
async fn forwarder_moves(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    from: &str,
    to: &str,
) -> AppResult<Json<MailForwarding>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    let (id, side, current, _) = lock(&mut tx, user_id, id).await?;
    if side != Side::Forwarder {
        return Err(AppError::not_found("not found"));
    }
    if current != from {
        return Err(code(
            AppError::conflict(format!("the forwarding is {current}")),
            "forwardingState",
        ));
    }
    // Resuming clears the notice a bounce pause left; the day's bounce
    // count stays, so the next bounce that day pauses it again.
    sqlx::query(
        "UPDATE mail_forwardings SET state = $2, updated_at = now(),
                notice = CASE WHEN $2 = 'active' THEN NULL ELSE notice END
          WHERE id = $1",
    )
    .bind(id)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(one(state, id).await?))
}

/// `PUT /api/mail/forwardings/{id}/pause` — the forwarder pauses an active
/// forwarding; its proxy factors are kept.
#[utoipa::path(
    put,
    path = "/api/mail/forwardings/{id}/pause",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    responses((status = 200, description = "Paused", body = MailForwarding), (status = 409, description = "forwardingState"))
)]
pub async fn pause(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailForwarding>> {
    forwarder_moves(&state, &user, &id, "active", "paused").await
}

/// `PUT /api/mail/forwardings/{id}/resume` — and resumes it.
#[utoipa::path(
    put,
    path = "/api/mail/forwardings/{id}/resume",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    responses((status = 200, description = "Active again", body = MailForwarding), (status = 409, description = "forwardingState"))
)]
pub async fn resume(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailForwarding>> {
    forwarder_moves(&state, &user, &id, "paused", "active").await
}

/// `PUT /api/mail/forwardings/{id}/conditions` — the forwarder changes what
/// is forwarded.
#[utoipa::path(
    put,
    path = "/api/mail/forwardings/{id}/conditions",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    request_body = MailForwardingConditions,
    responses((status = 200, description = "Changed", body = MailForwarding))
)]
pub async fn conditions(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<MailForwardingConditions>,
) -> AppResult<Json<MailForwarding>> {
    let user_id = trusted_uuid(&user.user_id)?;
    check_conditions(&req.conditions)?;
    let mut tx = state.pool.begin().await?;
    let (id, side, _, _) = lock(&mut tx, user_id, &id).await?;
    if side != Side::Forwarder {
        return Err(AppError::not_found("not found"));
    }
    sqlx::query(
        "UPDATE mail_forwardings SET match = $2, conditions = $3, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(match req.rule {
        Match::All => "all",
        Match::Any => "any",
    })
    .bind(serde_json::to_value(&req.conditions).expect("conditions serialize"))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(one(&state, id).await?))
}

/// `PUT /api/mail/forwardings/{id}` — the forwarder renews an Outdated or
/// declined forwarding with new material (Proton's "Re-enable" and
/// "Request confirmation"); it is pending again.
#[utoipa::path(
    put,
    path = "/api/mail/forwardings/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    request_body = RenewMailForwarding,
    responses((status = 200, description = "Pending again", body = MailForwarding), (status = 409, description = "forwardingState, forwardingUnavailable"))
)]
pub async fn renew(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RenewMailForwarding>,
) -> AppResult<Json<MailForwarding>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    let (id, side, current, _) = lock(&mut tx, user_id, &id).await?;
    if side != Side::Forwarder {
        return Err(AppError::not_found("not found"));
    }
    if current != "outdated" && current != "rejected" {
        return Err(code(
            AppError::conflict(format!("the forwarding is {current}")),
            "forwardingState",
        ));
    }
    let forwarder_key: Vec<u8> = sqlx::query_scalar(
        "SELECT k.public_key FROM mail_forwardings f
           JOIN mail_addresses a ON a.id = f.forwarder_address_id AND a.state = 'active'
           JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE f.id = $1 AND f.kind = 'end_to_end'",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::conflict("the address no longer forwards"))?;
    let material = check_material(&req.end_to_end, &forwarder_key)?;
    store_material(&state, &mut tx, id, &material).await?;
    tx.commit().await?;
    Ok(Json(one(&state, id).await?))
}

/// `GET /api/mail/forwardings/{id}/activation` — a pending forwarding's
/// activation, for its forwardee.
#[utoipa::path(
    get,
    path = "/api/mail/forwardings/{id}/activation",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    responses((status = 200, description = "The activation", body = MailForwardingActivation), (status = 404, description = "None pending for the caller"))
)]
pub async fn activation(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailForwardingActivation>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let row: Option<(String, String, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT a.address, b.address, f.activation, f.expires_at
           FROM mail_forwardings f
           JOIN mail_addresses a ON a.id = f.forwarder_address_id
           JOIN mail_addresses b ON b.id = f.forwardee_address_id
          WHERE f.id = $1 AND b.user_id = $2 AND f.state = 'pending'
            AND f.activation IS NOT NULL AND f.expires_at > now()",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (forwarder, forwardee, activation, expires_at) =
        row.ok_or_else(|| AppError::not_found("not found"))?;
    Ok(Json(MailForwardingActivation {
        forwarding_id: id.to_string(),
        forwarder_address: forwarder,
        forwardee_address: forwardee,
        activation,
        expires_at,
    }))
}

/// `POST /api/mail/forwardings/{id}/accept` — the forwardee keeps the
/// forwarding key as an address key (never primary, never encrypted to, out
/// of the signed key list) and the forwarding becomes active. The key's
/// subkeys must be exactly the forwarding's.
#[utoipa::path(
    post,
    path = "/api/mail/forwardings/{id}/accept",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    request_body = AcceptMailForwarding,
    responses(
        (status = 200, description = "Active", body = MailForwarding),
        (status = 400, description = "Not this forwarding's key"),
        (status = 409, description = "forwardingState"),
    )
)]
pub async fn accept(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<AcceptMailForwarding>,
) -> AppResult<Json<MailForwarding>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let public_key = base64(&req.public_key, "publicKey")?;
    let envelope = base64(&req.private_key_envelope, "privateKeyEnvelope")?;
    let mut tx = state.pool.begin().await?;
    let (id, side, current, forwardee_address_id) = lock(&mut tx, user_id, &id).await?;
    let forwardee_address_id = forwardee_address_id.filter(|_| side == Side::Forwardee);
    let Some(forwardee_address_id) = forwardee_address_id else {
        return Err(AppError::not_found("not found"));
    };
    let pending: bool = sqlx::query_scalar(
        "SELECT state = 'pending' AND COALESCE(expires_at > now(), false)
           FROM mail_forwardings WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if !pending {
        return Err(code(
            AppError::conflict(format!("the forwarding is {current}")),
            "forwardingState",
        ));
    }
    let address: String = sqlx::query_scalar("SELECT address FROM mail_addresses WHERE id = $1")
        .bind(forwardee_address_id)
        .fetch_one(&mut *tx)
        .await?;
    let info = mail_key::inspect_forwarding_public_key(&public_key, &address)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let mut uploaded = crypto::forwardee_fingerprints(&public_key)
        .map_err(|_| AppError::bad_request("publicKey is not a forwarding key"))?;
    let mut stored: Vec<[u8; 20]> = sqlx::query_scalar::<_, String>(
        "SELECT forwardee_fingerprint FROM mail_forwarding_keys WHERE forwarding_id = $1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?
    .iter()
    .filter_map(|value| hex::decode(value).ok()?.try_into().ok())
    .collect();
    uploaded.sort();
    stored.sort();
    if uploaded.is_empty() || uploaded != stored {
        return Err(AppError::bad_request(
            "publicKey is not this forwarding's key",
        ));
    }
    let binding: String =
        sqlx::query_scalar("SELECT COALESCE(key_binding, '') FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if account_envelope::validate_for(
        &envelope,
        AccountEnvelopePurpose::MailAddressPrivateKey,
        &binding,
        &[],
    )
    .is_err()
    {
        return Err(AppError::bad_request(
            "privateKeyEnvelope is not this account's mail key",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO mail_address_keys
           (address_id, fingerprint, sha256_fingerprint, public_key, private_key_envelope,
            is_primary, flags, is_forwarding, forwarding_id)
         VALUES ($1, $2, $3, $4, $5, false, $6, true, $7)
         ON CONFLICT (fingerprint) DO NOTHING",
    )
    .bind(forwardee_address_id)
    .bind(hex::encode(info.fingerprint))
    .bind(hex::encode(info.sha256_fingerprint))
    .bind(&public_key)
    .bind(&envelope)
    .bind(mail_key::DEFAULT_FLAGS as i32)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(AppError::conflict("this key is already in use"));
    }
    sqlx::query(
        "UPDATE mail_forwardings SET state = 'active', activation = NULL, expires_at = NULL,
                updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(one(&state, id).await?))
}

/// `POST /api/mail/forwardings/{id}/decline` — the forwardee declines a
/// pending forwarding: its proxy factors and activation go; the forwarder
/// may ask again with new material.
#[utoipa::path(
    post,
    path = "/api/mail/forwardings/{id}/decline",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Forwarding id")),
    responses((status = 204, description = "Declined"), (status = 409, description = "forwardingState"))
)]
pub async fn decline(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    let (id, side, current, _) = lock(&mut tx, user_id, &id).await?;
    if side != Side::Forwardee {
        return Err(AppError::not_found("not found"));
    }
    if current != "pending" {
        return Err(code(
            AppError::conflict(format!("the forwarding is {current}")),
            "forwardingState",
        ));
    }
    forwarding::reject(&mut tx, id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/mail/addresses/{address}/forwarding-keys/{key}` — the
/// forwardee deletes a forwarding key; the forwarding it serves ends with
/// it (with the key gone, its proxy factors must not outlive it).
#[utoipa::path(
    delete,
    path = "/api/mail/addresses/{address}/forwarding-keys/{key}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(
        ("address" = String, Path, description = "Address id"),
        ("key" = String, Path, description = "Key id"),
    ),
    responses((status = 204, description = "Deleted"), (status = 404, description = "Not a forwarding key of the caller's"))
)]
pub async fn delete_key(
    State(state): State<AppState>,
    user: AuthUser,
    Path((address, key)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address = Uuid::parse_str(&address).map_err(|_| AppError::not_found("not found"))?;
    let key = Uuid::parse_str(&key).map_err(|_| AppError::not_found("not found"))?;
    let mut tx = state.pool.begin().await?;
    let deleted: Option<Option<Uuid>> = sqlx::query_scalar(
        "DELETE FROM mail_address_keys k USING mail_addresses a
          WHERE k.id = $1 AND k.address_id = $2 AND a.id = k.address_id AND a.user_id = $3
            AND k.is_forwarding
         RETURNING k.forwarding_id",
    )
    .bind(key)
    .bind(address)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(forwarding) = deleted else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(forwarding) = forwarding {
        sqlx::query("DELETE FROM mail_forwardings WHERE id = $1")
            .bind(forwarding)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
