//! Username renames (docs/plans/username-renames.md): the check, the rename,
//! the names an account holds, and dropping one.
//!
//! A rename is one transaction under the account row's lock: the new name
//! current, the old one held (its address receiving until `receive_until`,
//! the name free at `free_at`), the account's username, Drive key binding and
//! rename chain, the new address row, and the security event. No session
//! ends; the session version covers the username, so open apps re-read
//! `/user/me`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_rename::{verify_chain, AccountRenameV1};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::account_names::{self, Available};
use crate::error::{AppError, AppResult};
use crate::grants::{self, Purpose};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::security_events;
use crate::AppState;

/// One counted rename per this many days.
const RENAME_EVERY_DAYS: i64 = 30;
/// Going back to the name just left within this many days is not counted
/// (once per counted rename), and restarts the clock.
const FREE_UNDO_DAYS: i64 = 7;
/// The most held names of one account that still receive: a dropped name
/// (receiving ended) stays held until freed but no longer counts.
const MAX_HELD: i64 = 5;
/// How far a statement's time may be from the server's.
const CLOCK_SKEW_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Deserialize, IntoParams)]
pub struct CheckQuery {
    name: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CheckView {
    available: bool,
    /// One of the account's own held names: taking it back.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    take_back: bool,
    /// Whether a rename to it sends the address's first key (`mailAddress`):
    /// always for a new name; for one taken back, only when its address has
    /// none.
    #[serde(skip_serializing_if = "Option::is_none")]
    needs_key: Option<bool>,
    /// For a name taken back: its spelling, the one a rename must use (its
    /// address and keys name it so).
    #[serde(skip_serializing_if = "Option::is_none")]
    spelling: Option<String>,
    /// Why not: `taken`, `held`, `reserved` or `invalid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// `GET /api/user/rename/check?name=` — whether the caller could rename to
/// `name` (any spelling of a name in use or held counts as taken).
#[utoipa::path(
    get,
    path = "/api/user/rename/check",
    tag = "user",
    security(("BearerAuth" = [])),
    params(CheckQuery),
    responses((status = 200, body = CheckView), (status = 429, description = "rateLimited"))
)]
pub async fn check(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<CheckQuery>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    if !crate::ratelimit::RENAME_CHECKS.allow(&user_id.to_string()) {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(json!({ "code": "rateLimited" })));
    }
    let incarnation: String =
        sqlx::query_scalar("SELECT account_incarnation_id FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await?;
    let mut conn = state.pool.acquire().await?;
    let view = match account_names::available(
        &mut conn,
        &state.config.chat_server_name,
        &state.config.break_glass_admin_username,
        &query.name,
        Some((user_id, &incarnation)),
    )
    .await?
    {
        Ok(found) => {
            let keyed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM mail_addresses a
                                  JOIN mail_address_keys k ON k.address_id = a.id
                                 WHERE a.user_id = $1 AND a.state <> 'freed'
                                   AND a.folded = kutup_fold($2) || '@' || lower($3))",
            )
            .bind(user_id)
            .bind(&query.name)
            .bind(&state.config.chat_server_name)
            .fetch_one(&mut *conn)
            .await?;
            let spelling = if found == Available::TakeBack {
                sqlx::query_scalar("SELECT name FROM account_names WHERE folded = kutup_fold($1)")
                    .bind(&query.name)
                    .fetch_optional(&mut *conn)
                    .await?
            } else {
                None
            };
            CheckView {
                available: true,
                take_back: found == Available::TakeBack,
                needs_key: Some(found == Available::Free || !keyed),
                spelling,
                reason: None,
            }
        }
        Err(unavailable) => CheckView {
            available: false,
            take_back: false,
            needs_key: None,
            spelling: None,
            reason: Some(unavailable.reason()),
        },
    };
    Ok(Json(view).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenameRequest {
    /// A `rename` grant from a reauth of this session.
    grant: String,
    /// The `AccountRenameV1` statement, as signed by the account authority.
    #[schema(value_type = Object)]
    rename: AccountRenameV1,
    /// The new address's first key and key list (as `POST
    /// /api/mail/addresses/{id}/keys` takes them), so mail to it is never
    /// deferred. None only when taking back a held name whose address still
    /// has its keys.
    #[serde(default)]
    mail_address: Option<crate::handlers::mail_keys::AddMailKeyRequest>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenameView {
    username: String,
    address: String,
    sequence: u64,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    old_address_receives_until: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    old_name_free_at: time::OffsetDateTime,
}

fn rename_conflict() -> AppError {
    AppError::conflict("the account's names moved: read them again and sign anew")
        .with_details(json!({ "code": "renameConflict" }))
}

fn rename_invalid(why: &str) -> AppError {
    AppError::bad_request(format!("the rename does not check out: {why}"))
        .with_details(json!({ "code": "renameInvalid" }))
}

/// `POST /api/user/rename` — a new username (docs/plans/username-renames.md).
#[utoipa::path(
    post,
    path = "/api/user/rename",
    tag = "user",
    security(("BearerAuth" = [])),
    request_body = RenameRequest,
    responses(
        (status = 200, body = RenameView),
        (status = 400, description = "renameInvalid"),
        (status = 403, description = "grantInvalid, breakGlassAccount"),
        (status = 409, description = "setupRequired, nameTaken, nameReserved, renameConflict, tooManyHeldNames"),
        (status = 429, description = "renameTooSoon (retryAt)")
    )
)]
pub async fn rename(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RenameRequest>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let server = state.config.chat_server_name.to_ascii_lowercase();
    let mut tx = state.pool.begin().await?;
    type Account = (String, String, String, bool, bool);
    let (username, incarnation, authority, first_login, break_glass): Account = sqlx::query_as(
        "SELECT COALESCE(username, ''), account_incarnation_id, account_authority_public_key,
                is_first_login, is_break_glass
           FROM users WHERE id = $1 AND is_active FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::unauthorized("unauthorized"))?;
    if first_login || incarnation.is_empty() {
        return Err(AppError::conflict("the account has no keys yet")
            .with_details(json!({ "code": "setupRequired" })));
    }
    grants::take_for_session(&mut *tx, &req.grant, Purpose::Rename, &user).await?;
    if break_glass {
        return Err(
            AppError::forbidden("the break-glass account keeps its name")
                .with_details(json!({ "code": "breakGlassAccount" })),
        );
    }

    // The statement: this account's, from its current address to a new one
    // on this server, the next of its chain, signed now.
    let statement = &req.rename;
    let old_address = format!("{username}@{server}");
    // Another device renamed meanwhile: the chain moved, or the statement
    // starts from an address this account has since left. Read again and
    // sign anew (a conflict, not a wrong statement).
    let (stored_len, left_before): (i64, bool) = sqlx::query_as(
        "SELECT COUNT(*),
                COALESCE(bool_or(previous = $2 OR current = $2), false)
           FROM account_renames WHERE incarnation_id = $1",
    )
    .bind(&incarnation)
    .bind(&statement.previous)
    .fetch_one(&mut *tx)
    .await?;
    if statement.sequence != stored_len as u64 + 1
        || (statement.previous != old_address && left_before)
    {
        return Err(
            AppError::conflict("the chain moved: read it again and sign anew")
                .with_details(json!({ "code": "renameConflict", "sequence": stored_len })),
        );
    }
    let (new_name, new_server) = statement
        .current
        .rsplit_once('@')
        .ok_or_else(|| rename_invalid("no address"))?;
    if new_server != server || statement.previous != old_address {
        return Err(rename_invalid(
            "not from this account's address to this server",
        ));
    }
    let new_name = new_name.to_owned();
    if kutup_crypto::names::fold(&new_name) == kutup_crypto::names::fold(&username) {
        return Err(rename_invalid("the same name in another spelling"));
    }
    let authority_key: [u8; 32] = STANDARD
        .decode(&authority)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| AppError::internal("account authority"))?;
    statement
        .verify(&authority_key)
        .map_err(|_| rename_invalid("signature"))?;
    if statement.incarnation_id != incarnation {
        return Err(rename_invalid("another incarnation"));
    }
    type Stored = (serde_json::Value, bool, time::OffsetDateTime, String);
    let stored: Vec<Stored> = sqlx::query_as(
        "SELECT statement, counted, accepted_at, previous FROM account_renames
          WHERE incarnation_id = $1 ORDER BY sequence",
    )
    .bind(&incarnation)
    .fetch_all(&mut *tx)
    .await?;
    if statement.sequence != stored.len() as u64 + 1 {
        return Err(
            AppError::conflict("the chain moved: read it again and sign anew")
                .with_details(json!({ "code": "renameConflict", "sequence": stored.len() })),
        );
    }
    let now = time::OffsetDateTime::now_utc();
    let now_ms = (now.unix_timestamp_nanos() / 1_000_000) as i64;
    if (statement.issued_at_ms - now_ms).abs() > CLOCK_SKEW_MS {
        return Err(rename_invalid("signed too far from now"));
    }
    let mut chain: Vec<AccountRenameV1> = stored
        .iter()
        .map(|(value, ..)| serde_json::from_value(value.clone()))
        .collect::<Result<_, _>>()
        .map_err(|_| AppError::internal("a stored rename"))?;
    chain.push(statement.clone());
    let view = verify_chain(&authority_key, &chain).map_err(|_| rename_invalid("the chain"))?;

    // The limits: one counted rename per 30 days; going back to the name just
    // left within 7 days of that rename is free, once, and restarts the clock.
    let undo = stored.last().is_some_and(|(_, counted, at, previous)| {
        *counted
            && kutup_crypto::names::fold(previous.split('@').next().unwrap_or(""))
                == kutup_crypto::names::fold(&new_name)
            && now - *at <= time::Duration::days(FREE_UNDO_DAYS)
    });
    if !undo {
        if let Some((_, _, at, _)) = stored.last() {
            let next = *at + time::Duration::days(RENAME_EVERY_DAYS);
            if now < next {
                return Err(
                    AppError::too_many_requests("one rename per 30 days").with_details(json!({
                        "code": "renameTooSoon",
                        "retryAt": next.format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                    })),
                );
            }
        }
    }

    // The name: free, or one this account holds.
    let found = match account_names::available(
        &mut tx,
        &server,
        &state.config.break_glass_admin_username,
        &new_name,
        Some((user_id, &incarnation)),
    )
    .await?
    {
        Ok(found) => found,
        Err(unavailable) => return Err(unavailable.error()),
    };
    if found == Available::TakeBack {
        let spelled: String =
            sqlx::query_scalar("SELECT name FROM account_names WHERE folded = kutup_fold($1)")
                .bind(&new_name)
                .fetch_one(&mut *tx)
                .await?;
        if spelled != new_name {
            return Err(
                rename_invalid("a held name is taken back as it was spelled")
                    .with_details(json!({ "code": "renameInvalid", "spelling": spelled })),
            );
        }
    }
    let held: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM account_names
          WHERE user_id = $1 AND state = 'held' AND receive_until > now()",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if found == Available::Free && held >= MAX_HELD {
        return Err(AppError::conflict(
            "this account's old names receive the most they may: drop one first",
        )
        .with_details(json!({ "code": "tooManyHeldNames" })));
    }
    // The Drive key binding names the account id, not the name
    // (docs/plans/account-ids.md): a rename leaves it as it is.

    // In one transaction: the names, the account, the chain, the addresses.
    let (hold_days, receive_days) =
        crate::site_settings::name_holds(&state.pool, &state.config).await?;
    let receive_until = now + time::Duration::days(receive_days);
    let free_at = now + time::Duration::days(hold_days);
    sqlx::query(
        "UPDATE account_names SET state = 'held', receive_until = $2, free_at = $3
          WHERE user_id = $1 AND state = 'current'",
    )
    .bind(user_id)
    .bind(receive_until)
    .bind(free_at)
    .execute(&mut *tx)
    .await?;
    match found {
        Available::TakeBack => {
            // As it was spelled: its address, keys and key lists name it so.
            let taken = sqlx::query(
                "UPDATE account_names SET state = 'current', receive_until = NULL, free_at = NULL
                  WHERE folded = kutup_fold($2) AND name = $2 AND user_id = $1 AND state = 'held'",
            )
            .bind(user_id)
            .bind(&new_name)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if taken != 1 {
                return Err(rename_conflict());
            }
        }
        Available::Free => {
            account_names::claim(&mut tx, &new_name, user_id, Some(&incarnation)).await?
        }
    }
    sqlx::query("UPDATE users SET username = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(&new_name)
        .execute(&mut *tx)
        .await
        .map_err(crate::handlers::auth::map_insert_conflict)?;
    sqlx::query(
        "INSERT INTO account_renames
             (incarnation_id, sequence, user_id, authority_public_key, previous, current,
              counted, statement, digest)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&incarnation)
    .bind(statement.sequence as i32)
    .bind(user_id)
    .bind(&authority)
    .bind(&statement.previous)
    .bind(&statement.current)
    .bind(!undo)
    .bind(serde_json::to_value(statement).expect("serialisable"))
    .bind(hex::encode(
        view.digests.last().expect("a verified chain has one"),
    ))
    .execute(&mut *tx)
    .await?;
    // The old address receives only, until its date; the new one is the
    // account's (its keys come as a new account's do, from the client), in
    // the old one's place in the account's order. Its addresses on custom
    // domains stay as they are.
    let place: Option<i32> = sqlx::query_scalar(
        "UPDATE mail_addresses SET state = 'receiving', receive_until = $2
          WHERE user_id = $1 AND state = 'active' AND domain_id IS NULL
          RETURNING position",
    )
    .bind(user_id)
    .bind(receive_until)
    .fetch_optional(&mut *tx)
    .await?;
    let reused: u64 = sqlx::query(
        "UPDATE mail_addresses SET state = 'active', receive_until = NULL
          WHERE user_id = $1 AND folded = kutup_fold($2) || '@' || $3 AND state <> 'freed'",
    )
    .bind(user_id)
    .bind(&new_name)
    .bind(&server)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if reused == 0
        && !crate::handlers::mail_keys::create_own_address(&mut tx, &server, user_id, &new_name)
            .await?
    {
        return Err(account_names::Unavailable::Taken.error());
    }
    // Its key comes with the rename: a new address gets the one sent, a
    // name taken back keeps its own.
    let (address_id, keyed): (Uuid, bool) = sqlx::query_as(
        "SELECT a.id, EXISTS (SELECT 1 FROM mail_address_keys k WHERE k.address_id = a.id)
           FROM mail_addresses a
          WHERE a.user_id = $1 AND a.state = 'active' AND a.domain_id IS NULL",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(place) = place {
        sqlx::query("UPDATE mail_addresses SET position = $2 WHERE id = $1")
            .bind(address_id)
            .bind(place)
            .execute(&mut *tx)
            .await?;
    }
    match (keyed, &req.mail_address) {
        (false, Some(first)) => {
            crate::handlers::mail_keys::first_key(
                &mut tx,
                user_id,
                address_id,
                &statement.current,
                first,
            )
            .await?
        }
        (true, None) => {}
        (false, None) => return Err(rename_invalid("the new address needs its key")),
        (true, Some(_)) => return Err(rename_invalid("the address has its keys already")),
    }
    // The display name and signature go with the account to its new
    // address; the old one, receiving only, has no identity to send as.
    sqlx::query(
        "UPDATE mail_identities SET address_id = $2
          WHERE address_id = (SELECT id FROM mail_addresses WHERE user_id = $1 AND state = 'receiving'
                                ORDER BY receive_until DESC LIMIT 1)
            AND NOT EXISTS (SELECT 1 FROM mail_identities WHERE address_id = $2)",
    )
    .bind(user_id)
    .bind(address_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM mail_identities
          WHERE address_id IN (SELECT id FROM mail_addresses WHERE user_id = $1 AND state <> 'active')",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    security_events::record_names(
        &mut tx,
        user_id,
        security_events::Kind::Rename,
        Some(user.session.session_id),
        None,
        &username,
        Some(&new_name),
    )
    .await?;
    // Peers learn of it from the announce, sent after this commits.
    crate::remote_renames::enqueue(&mut tx, &server, &incarnation, view.sequence).await?;
    tx.commit().await?;
    crate::remote_renames::announce_soon();
    tracing::info!(%user_id, sequence = view.sequence, "account renamed");
    Ok(Json(RenameView {
        username: new_name,
        address: statement.current.clone(),
        sequence: view.sequence,
        old_address_receives_until: receive_until,
        old_name_free_at: free_at,
    })
    .into_response())
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct HeldName {
    name: String,
    state: String,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    receive_until: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    free_at: Option<time::OffsetDateTime>,
}

/// `GET /api/user/names` — the caller's names: the current one and those it
/// holds, with when each stops receiving and is freed.
#[utoipa::path(
    get,
    path = "/api/user/names",
    tag = "user",
    security(("BearerAuth" = [])),
    responses((status = 200, body = [HeldName]))
)]
pub async fn names(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<HeldName> = sqlx::query_as(
        "SELECT name, state, receive_until, free_at FROM account_names
          WHERE user_id = $1 ORDER BY state = 'current' DESC, free_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DropName {
    /// A `rename` grant from a reauth of this session.
    grant: String,
}

/// `DELETE /api/user/names/{name}` — stop receiving at a held name now. The
/// name stays held until its date.
#[utoipa::path(
    delete,
    path = "/api/user/names/{name}",
    tag = "user",
    security(("BearerAuth" = [])),
    params(("name" = String, Path, description = "A name the account holds")),
    request_body = DropName,
    responses((status = 204), (status = 409, description = "notHeld"), (status = 429, description = "dropTooSoon"))
)]
pub async fn drop_name(
    State(state): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Json(req): Json<DropName>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    grants::take_for_session(&mut *tx, &req.grant, Purpose::Rename, &user).await?;
    // One drop per 30 days, as a rename: dropping is closing an address
    // people may still write to, not something to repeat at will.
    let last: Option<time::OffsetDateTime> = sqlx::query_scalar(
        "SELECT max(at) FROM account_security_events
          WHERE user_id = $1 AND kind = 'nameDropped' AND admin_user_id IS NULL",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(next) = last.map(|at| at + time::Duration::days(RENAME_EVERY_DAYS)) {
        if time::OffsetDateTime::now_utc() < next {
            return Err(
                AppError::too_many_requests("one dropped name per 30 days").with_details(json!({
                    "code": "dropTooSoon",
                    "retryAt": next.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                })),
            );
        }
    }
    let dropped: Option<String> = sqlx::query_scalar(
        "UPDATE account_names SET receive_until = LEAST(COALESCE(receive_until, now()), now())
          WHERE user_id = $1 AND folded = kutup_fold($2) AND state = 'held'
         RETURNING name",
    )
    .bind(user_id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(dropped) = dropped else {
        return Err(AppError::conflict("not a name this account holds")
            .with_details(json!({ "code": "notHeld" })));
    };
    close_address(&mut tx, user_id, &dropped, &state.config.chat_server_name).await?;
    security_events::record_names(
        &mut tx,
        user_id,
        security_events::Kind::NameDropped,
        Some(user.session.session_id),
        None,
        &dropped,
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Ends receiving at `name`'s address of `user_id` now.
pub(crate) async fn close_address(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    name: &str,
    server: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE mail_addresses SET state = 'closed', receive_until = now()
          WHERE user_id = $1 AND folded = kutup_fold($2) || '@' || lower($3)
            AND state = 'receiving'",
    )
    .bind(user_id)
    .bind(name)
    .bind(server)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What an administrator does to a held name.
#[derive(Clone, Copy)]
enum AdminAction {
    /// Receiving at it ends now.
    Close,
    /// It is free now, before its date.
    Free,
}

async fn admin_name(
    state: &AppState,
    admin: &crate::middleware::AdminUser,
    name: &str,
    action: AdminAction,
) -> AppResult<Response> {
    let admin_id = trusted_uuid(&admin.user_id)?;
    let mut tx = state.pool.begin().await?;
    let held: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT name, user_id FROM account_names
          WHERE folded = kutup_fold($1) AND state = 'held' FOR UPDATE",
    )
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((held_name, owner)) = held else {
        return Err(
            AppError::conflict("not a held name").with_details(json!({ "code": "notHeld" }))
        );
    };
    let (kind, audit_action) = match action {
        AdminAction::Close => {
            sqlx::query(
                "UPDATE account_names SET receive_until = LEAST(COALESCE(receive_until, now()), now())
                  WHERE folded = kutup_fold($1)",
            )
            .bind(&held_name)
            .execute(&mut *tx)
            .await?;
            if let Some(owner) = owner {
                close_address(&mut tx, owner, &held_name, &state.config.chat_server_name).await?;
            }
            (security_events::Kind::NameClosed, "name.close")
        }
        AdminAction::Free => {
            sqlx::query("DELETE FROM account_names WHERE folded = kutup_fold($1)")
                .bind(&held_name)
                .execute(&mut *tx)
                .await?;
            if let Some(owner) = owner {
                sqlx::query(
                    "UPDATE mail_addresses SET state = 'freed', receive_until = NULL
                      WHERE user_id = $1 AND split_part(folded, '@', 1) = kutup_fold($2)
                        AND state IN ('receiving', 'closed')",
                )
                .bind(owner)
                .bind(&held_name)
                .execute(&mut *tx)
                .await?;
            }
            (security_events::Kind::NameFreed, "name.free")
        }
    };
    if let Some(owner) = owner {
        security_events::record_names(&mut tx, owner, kind, None, Some(admin_id), &held_name, None)
            .await?;
    }
    tx.commit().await?;
    crate::handlers::admin::audit(
        &state.pool,
        &admin.user_id,
        audit_action,
        owner,
        json!({ "name": held_name }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/admin/names/{name}/close` — receiving at a held name ends now.
#[utoipa::path(
    post,
    path = "/api/admin/names/{name}/close",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("name" = String, Path, description = "A held name")),
    responses((status = 204), (status = 409, description = "notHeld"))
)]
pub async fn admin_close(
    State(state): State<AppState>,
    admin: crate::middleware::AdminUser,
    Path(name): Path<String>,
) -> AppResult<Response> {
    admin_name(&state, &admin, &name, AdminAction::Close).await
}

/// `POST /api/admin/names/{name}/free` — a held name is free now: anyone may
/// take it (a new owner is another incarnation; pins of the old one warn).
#[utoipa::path(
    post,
    path = "/api/admin/names/{name}/free",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("name" = String, Path, description = "A held name")),
    responses((status = 204), (status = 409, description = "notHeld"))
)]
pub async fn admin_free(
    State(state): State<AppState>,
    admin: crate::middleware::AdminUser,
    Path(name): Path<String>,
) -> AppResult<Response> {
    admin_name(&state, &admin, &name, AdminAction::Free).await
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ChainsQuery {
    /// Only this incarnation's chain.
    incarnation_id: Option<String>,
}

/// `GET /api/users/renames/{address}` — every rename chain that names the
/// address (a reused name is in more than one), as `{ version: 1, chains }`,
/// newest first. Clients verify each chain against their own pins.
#[utoipa::path(
    get,
    path = "/api/users/renames/{address}",
    tag = "user",
    security(("BearerAuth" = [])),
    params(("address" = String, Path, description = "username@server"), ChainsQuery),
    responses((status = 200, description = "The chains (an empty list when none names it)"))
)]
pub async fn chains(
    State(state): State<AppState>,
    user: AuthUser,
    Path(address): Path<String>,
    Query(query): Query<ChainsQuery>,
) -> AppResult<Response> {
    let address = address.trim().to_ascii_lowercase();
    let Some((_, server)) = address.rsplit_once('@') else {
        return Err(AppError::bad_request("an address is username@server"));
    };
    // Another server's: the chains kept of it, asked of that server when
    // none is fresh (crate::remote_renames).
    if server != state.config.chat_server_name.to_ascii_lowercase() {
        let mut found =
            crate::remote_renames::lookup(&state, trusted_uuid(&user.user_id)?, &address).await?;
        if let (Some(incarnation), Some(chains)) = (
            query.incarnation_id.as_deref(),
            found["chains"].as_array_mut(),
        ) {
            chains.retain(|chain| chain["incarnationId"] == incarnation);
        }
        return Ok(Json(found).into_response());
    }
    let found =
        account_names::chains(&state.pool, &address, query.incarnation_id.as_deref()).await?;
    Ok(Json(found).into_response())
}
