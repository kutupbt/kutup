//! Admin handlers — mirrors `backend/handlers/admin.go`.
//!
//! User CRUD, aggregate stats, and the registration toggle. Every route is behind the
//! `AdminUser` extractor (authenticated + `isAdmin`), so the handlers trust the caller.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::AdminUser;
use crate::AppState;

/// `^[a-z0-9_-]{3,32}$` — mirrors `adminUsernameRegexp`.
fn valid_admin_username(s: &str) -> bool {
    let len = s.len();
    (3..=32).contains(&len)
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Whether `email` is the protected break-glass admin (case-insensitive) — mirrors
/// `isBreakGlass`. The break-glass admin can never be demoted, disabled, or deleted.
fn is_break_glass(state: &AppState, email: &str) -> bool {
    let bg = &state.config.break_glass_admin_email;
    !bg.is_empty() && bg.eq_ignore_ascii_case(email)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserRow {
    id: Uuid,
    email: String,
    username: String,
    storage_quota_bytes: i64,
    storage_used_bytes: i64,
    is_admin: bool,
    is_active: bool,
    #[serde(rename = "totpEnabled")]
    totp_enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// Marks the break-glass admin — the UI disables demote/disable/delete for this user.
    is_protected: bool,
}

/// `GET /api/admin/users` — mirrors `ListUsers`.
pub async fn list_users(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Response> {
    type Row = (
        Uuid,
        String,
        String,
        i64,
        i64,
        bool,
        bool,
        bool,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT id, email, COALESCE(username, ''), storage_quota_bytes, storage_used_bytes,
                  is_admin, is_active, totp_enabled, created_at
           FROM users ORDER BY created_at DESC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let users: Vec<UserRow> = rows
        .into_iter()
        .map(
            |(id, email, username, quota, used, is_admin, is_active, totp, created)| {
                let is_protected = is_break_glass(&state, &email);
                UserRow {
                    id,
                    email,
                    username,
                    storage_quota_bytes: quota,
                    storage_used_bytes: used,
                    is_admin,
                    is_active,
                    totp_enabled: totp,
                    created_at: created,
                    is_protected,
                }
            },
        )
        .collect();
    Ok(Json(users).into_response())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateUserRequest {
    email: String,
    username: String,
    temp_password: String,
    storage_quota_bytes: i64,
}

/// `POST /api/admin/users` — mirrors `CreateUser`. Creates a first-login account with a
/// temp password; the user establishes their E2EE key material on first login.
pub async fn create_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(mut req): Json<CreateUserRequest>,
) -> AppResult<Response> {
    if req.email.is_empty() || req.temp_password.is_empty() {
        return Err(AppError::bad_request("email and tempPassword required"));
    }
    if req.username.is_empty() {
        return Err(AppError::bad_request("username required"));
    }
    if !valid_admin_username(&req.username) {
        return Err(AppError::bad_request(
            "invalid username: must be 3-32 chars, lowercase letters, numbers, _ and -",
        ));
    }
    if req.storage_quota_bytes == 0 {
        req.storage_quota_bytes = 10 * 1024 * 1024 * 1024; // 10 GB default
    }

    let hash =
        bcrypt::hash(&req.temp_password, 10).map_err(|_| AppError::internal("internal error"))?;

    let res = sqlx::query(
        r#"INSERT INTO users (
               email, username, login_key_hash,
               encrypted_master_key, master_key_nonce,
               encrypted_recovery_key, recovery_key_nonce,
               encrypted_private_key, private_key_nonce,
               public_key, kdf_salt, login_key_salt,
               is_admin, is_first_login, storage_quota_bytes
           ) VALUES ($1,$2,$3,'','','','','','','','','',false,true,$4)"#,
    )
    .bind(&req.email)
    .bind(&req.username)
    .bind(&hash)
    .bind(req.storage_quota_bytes)
    .execute(&state.pool)
    .await;
    if let Err(e) = res {
        return Err(map_insert_conflict(e));
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({"message": "user created"})),
    )
        .into_response())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateUserRequest {
    storage_quota_bytes: Option<i64>,
    is_active: Option<bool>,
    is_admin: Option<bool>,
}

/// `PUT /api/admin/users/{id}` — mirrors `UpdateUser`. Each present field is one UPDATE.
pub async fn update_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> AppResult<Response> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    // Load the target's current state for the break-glass + last-admin guards.
    let (target_email, target_is_admin, target_is_active): (String, bool, bool) =
        sqlx::query_as("SELECT email, is_admin, is_active FROM users WHERE id = $1")
            .bind(target)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| AppError::not_found("not found"))?;

    let wants_demote = req.is_admin == Some(false);
    let wants_disable = req.is_active == Some(false);

    // Break-glass admin is immutable: never demote or disable it.
    if is_break_glass(&state, &target_email) && (wants_demote || wants_disable) {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }

    // Last-admin guard: don't let a demote/disable leave zero usable admins.
    if (wants_demote || wants_disable) && target_is_admin && target_is_active {
        let other_usable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE is_admin AND is_active AND id != $1",
        )
        .bind(target)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
        if other_usable == 0 {
            return Err(AppError::bad_request("cannot remove the last admin"));
        }
    }

    if let Some(q) = req.storage_quota_bytes {
        sqlx::query("UPDATE users SET storage_quota_bytes = $1 WHERE id = $2")
            .bind(q)
            .bind(target)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("internal error"))?;
    }
    if let Some(a) = req.is_active {
        sqlx::query("UPDATE users SET is_active = $1 WHERE id = $2")
            .bind(a)
            .bind(target)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("internal error"))?;
    }
    if let Some(a) = req.is_admin {
        sqlx::query("UPDATE users SET is_admin = $1 WHERE id = $2")
            .bind(a)
            .bind(target)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("internal error"))?;
    }
    Ok(Json(json!({"message": "updated"})).into_response())
}

/// `DELETE /api/admin/users/{id}` — mirrors `DeleteUser` (cascades via FKs).
pub async fn delete_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    // Break-glass admin can never be deleted.
    let target_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(target)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("not found"))?;
    if is_break_glass(&state, &target_email) {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }

    let res = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(target)
        .execute(&state.pool)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => Ok(StatusCode::NO_CONTENT.into_response()),
        _ => Err(AppError::not_found("not found")),
    }
}

/// `DELETE /api/admin/users/{id}/2fa` — mirrors `ForceDisable2FA`. Clears the target's TOTP
/// (the admin caller is already authenticated + admin-gated, so no TOTP-code challenge).
/// Allowed on the break-glass admin too — it's a recovery aid and can't lock anyone out.
pub async fn force_disable_2fa(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let res =
        sqlx::query("UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1")
            .bind(target)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("internal error"))?;
    if res.rows_affected() == 0 {
        return Err(AppError::not_found("not found"));
    }
    Ok(Json(json!({"message": "2fa disabled"})).into_response())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsResponse {
    total_users: i64,
    active_users: i64,
    total_files: i64,
    /// DB sum — logical per-account usage.
    #[serde(rename = "totalStorageUsedBytes")]
    total_storage_used: i64,
    total_collections: i64,
    /// The storage backend's real total capacity — from the live SeaweedFS probe, falling back
    /// to `STORAGE_TOTAL_BYTES`, then 0 ("unknown").
    storage_total_bytes: i64,
    /// The storage backend's real on-disk usage (from the probe); 0 when no probe is available.
    storage_backend_used_bytes: i64,
}

/// `GET /api/admin/stats` — mirrors `GetStats`.
pub async fn get_stats(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Response> {
    let scalar = |sql: &'static str| {
        let pool = state.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&pool)
                .await
                .unwrap_or(0)
        }
    };

    // Storage capacity: prefer the live SeaweedFS probe; fall back to the configured env var.
    let mut storage_total_bytes = state.config.storage_total_bytes;
    let mut storage_backend_used_bytes = 0;
    if let Some(probe) = &state.storage_probe {
        if let Some(probed) = probe.probe().await {
            storage_total_bytes = probed.total_bytes;
            storage_backend_used_bytes = probed.used_bytes;
        }
    }

    let stats = StatsResponse {
        total_users: scalar("SELECT COUNT(*) FROM users").await,
        active_users: scalar("SELECT COUNT(*) FROM users WHERE is_active = true").await,
        total_files: scalar("SELECT COUNT(*) FROM files").await,
        total_storage_used: scalar("SELECT COALESCE(SUM(storage_used_bytes),0) FROM users").await,
        total_collections: scalar("SELECT COUNT(*) FROM collections").await,
        storage_total_bytes,
        storage_backend_used_bytes,
    };
    Ok(Json(stats).into_response())
}

/// `GET /api/admin/settings` — mirrors `GetSettings`.
pub async fn get_settings(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Response> {
    let val: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key='registration_enabled'")
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let enabled = val.as_deref() != Some("false");
    Ok(Json(json!({"registrationEnabled": enabled})).into_response())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateSettingsRequest {
    registration_enabled: bool,
}

/// `PUT /api/admin/settings` — mirrors `UpdateSettings`.
pub async fn update_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> AppResult<Response> {
    let val = if req.registration_enabled {
        "true"
    } else {
        "false"
    };
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ('registration_enabled', $1) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(val)
    .execute(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;
    Ok(Json(json!({"registrationEnabled": req.registration_enabled})).into_response())
}

/// Maps a unique-violation INSERT error to the right 409 — mirrors the Go duplicate check.
fn map_insert_conflict(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &err {
        if db.code().as_deref() == Some("23505") {
            if db.constraint().unwrap_or("").contains("username") {
                return AppError::conflict("username already taken");
            }
            return AppError::conflict("email already registered");
        }
    }
    AppError::internal("internal error")
}
