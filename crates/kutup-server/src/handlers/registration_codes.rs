//! Referral codes, for administrators (docs/plans/registration-codes.md):
//! make one (shown once), list them with their use, revoke one, and see who
//! signed up with it. Every change is in the audit log.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::admin::audit;
use crate::middleware::AdminUser;
use crate::registration;
use crate::AppState;

/// The longest a note may be.
const MAX_NOTE_CHARS: usize = 200;
/// The most uses one code may be given (`NULL`: unlimited).
const MAX_USES: i32 = 100_000;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRegistrationCode {
    /// What the code is for ("beta testers", a name); at most 200 characters.
    #[serde(default)]
    pub note: String,
    /// When it stops admitting anyone; `null`: never.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// How many accounts it may admit (1 to 100000); `null`: unlimited.
    #[serde(default)]
    pub max_uses: Option<i32>,
}

/// A code as an administrator sees it: never the code itself, only its hint.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCodeRow {
    pub id: Uuid,
    /// The code's last four characters.
    pub hint: String,
    pub note: String,
    /// Who made it (absent once that account is gone).
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub max_uses: Option<i32>,
    pub uses: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    /// `active`, `expired`, `usedUp` or `revoked`.
    pub state: &'static str,
}

/// A code just made: the only time its text is returned.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreatedRegistrationCode {
    /// The code, in groups (`7KQ2M-9XD4T-PAV3W-8HCNR`). Not shown again.
    pub code: String,
    #[serde(flatten)]
    pub row: RegistrationCodeRow,
}

/// One account that signed up with a code.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCodeUse {
    pub user_id: Uuid,
    pub username: String,
    #[serde(with = "time::serde::rfc3339")]
    pub used_at: OffsetDateTime,
}

type Row = (
    Uuid,
    String,
    String,
    Option<String>,
    OffsetDateTime,
    Option<OffsetDateTime>,
    Option<i32>,
    i32,
    Option<OffsetDateTime>,
);

const ROW_SELECT: &str = "SELECT c.id, c.hint, c.note, u.username, c.created_at, c.expires_at,
        c.max_uses, c.uses, c.revoked_at
   FROM registration_codes c LEFT JOIN users u ON u.id = c.created_by";

fn to_row(
    (id, hint, note, created_by, created_at, expires_at, max_uses, uses, revoked_at): Row,
) -> RegistrationCodeRow {
    let state = if revoked_at.is_some() {
        "revoked"
    } else if expires_at.is_some_and(|at| at <= OffsetDateTime::now_utc()) {
        "expired"
    } else if max_uses.is_some_and(|max| uses >= max) {
        "usedUp"
    } else {
        "active"
    };
    RegistrationCodeRow {
        id,
        hint,
        note,
        created_by,
        created_at,
        expires_at,
        max_uses,
        uses,
        revoked_at,
        state,
    }
}

async fn fetch(state: &AppState, id: Uuid) -> AppResult<RegistrationCodeRow> {
    let row: Option<Row> = sqlx::query_as(&format!("{ROW_SELECT} WHERE c.id = $1"))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    row.map(to_row)
        .ok_or_else(|| AppError::not_found("no such referral code"))
}

/// `POST /api/admin/registration-codes` — makes a code. The response holds
/// its text, which is never shown again.
#[utoipa::path(
    post,
    path = "/api/admin/registration-codes",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = CreateRegistrationCode,
    responses(
        (status = 201, description = "Made", body = CreatedRegistrationCode),
        (status = 400, description = "A note too long, an expiry in the past, or uses out of range")
    )
)]
pub async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CreateRegistrationCode>,
) -> AppResult<Response> {
    let note = req.note.trim();
    if note.chars().count() > MAX_NOTE_CHARS || note.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "a note is at most 200 characters, without control characters",
        ));
    }
    if req
        .expires_at
        .is_some_and(|at| at <= OffsetDateTime::now_utc())
    {
        return Err(AppError::bad_request("the expiry must be in the future"));
    }
    if req
        .max_uses
        .is_some_and(|max| !(1..=MAX_USES).contains(&max))
    {
        return Err(AppError::bad_request(
            "a code admits 1 to 100000 accounts, or any number",
        ));
    }
    let admin_id =
        Uuid::parse_str(&admin.user_id).map_err(|_| AppError::unauthorized("invalid session"))?;
    let key = registration::codes_key(&state.pool).await?;
    let code = registration::generate();
    let canonical = registration::canonical(&code).expect("a generated code reads back");
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO registration_codes (code_hash, hint, note, created_by, expires_at, max_uses)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(registration::hash(&key, &canonical).as_slice())
    .bind(registration::hint(&canonical))
    .bind(note)
    .bind(admin_id)
    .bind(req.expires_at)
    .bind(req.max_uses)
    .fetch_one(&state.pool)
    .await?;
    let row = fetch(&state, id).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "registration_code.created",
        None,
        json!({
            "id": id,
            "hint": row.hint,
            "note": row.note,
            "maxUses": row.max_uses,
            "expiresAt": row.expires_at.map(|at| at.unix_timestamp()),
        }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(CreatedRegistrationCode { code, row }),
    )
        .into_response())
}

/// `GET /api/admin/registration-codes` — every code, newest first, with its
/// use and state.
#[utoipa::path(
    get,
    path = "/api/admin/registration-codes",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The codes", body = Vec<RegistrationCodeRow>))
)]
pub async fn list(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Response> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{ROW_SELECT} ORDER BY c.created_at DESC"))
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(rows.into_iter().map(to_row).collect::<Vec<_>>()).into_response())
}

/// `POST /api/admin/registration-codes/{id}/revoke` — stops a code at once
/// (also what "expire now" does). Revoking a revoked code changes nothing.
#[utoipa::path(
    post,
    path = "/api/admin/registration-codes/{id}/revoke",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "The code's id")),
    responses(
        (status = 200, description = "Revoked", body = RegistrationCodeRow),
        (status = 404, description = "No such code")
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let admin_id =
        Uuid::parse_str(&admin.user_id).map_err(|_| AppError::unauthorized("invalid session"))?;
    let revoked = sqlx::query(
        "UPDATE registration_codes SET revoked_at = now(), revoked_by = $2
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(admin_id)
    .execute(&state.pool)
    .await?
    .rows_affected()
        == 1;
    let row = fetch(&state, id).await?;
    if revoked {
        audit(
            &state.pool,
            &admin.user_id,
            "registration_code.revoked",
            None,
            json!({ "id": id, "hint": row.hint }),
        )
        .await;
    }
    Ok(Json(row).into_response())
}

/// `GET /api/admin/registration-codes/{id}/uses` — the accounts that signed
/// up with a code, oldest first.
#[utoipa::path(
    get,
    path = "/api/admin/registration-codes/{id}/uses",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "The code's id")),
    responses(
        (status = 200, description = "Who signed up with it", body = Vec<RegistrationCodeUse>),
        (status = 404, description = "No such code")
    )
)]
pub async fn uses(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    fetch(&state, id).await?;
    let rows: Vec<(Uuid, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT u.id, COALESCE(u.username, ''), r.used_at
           FROM registration_code_uses r JOIN users u ON u.id = r.user_id
          WHERE r.code_id = $1 ORDER BY r.used_at",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(user_id, username, used_at)| RegistrationCodeUse {
                user_id,
                username,
                used_at,
            })
            .collect::<Vec<_>>(),
    )
    .into_response())
}

/// The code an account signed up with, for its administration page.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignedUpWith {
    pub code_id: Uuid,
    pub hint: String,
    pub note: String,
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub used_at: OffsetDateTime,
}

/// `GET /api/admin/users/{id}/registration-code` — which referral code an
/// account signed up with; `null` when it used none.
#[utoipa::path(
    get,
    path = "/api/admin/users/{id}/registration-code",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path, description = "The account's id")),
    responses((status = 200, description = "The code, or null", body = Option<SignedUpWith>))
)]
pub async fn user_code(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> AppResult<Response> {
    let row: Option<(Uuid, String, String, Option<String>, OffsetDateTime)> = sqlx::query_as(
        "SELECT c.id, c.hint, c.note, creator.username, r.used_at
           FROM registration_code_uses r
           JOIN registration_codes c ON c.id = r.code_id
           LEFT JOIN users creator ON creator.id = c.created_by
          WHERE r.user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(Json(
        row.map(|(code_id, hint, note, created_by, used_at)| SignedUpWith {
            code_id,
            hint,
            note,
            created_by,
            used_at,
        }),
    )
    .into_response())
}
