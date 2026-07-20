//! Admin handlers — user CRUD, aggregate stats, the registration toggle, and the
//! audit-log feed. Every route is behind the `AdminUser` extractor (authenticated +
//! `isAdmin`), so the handlers trust the caller.
//!
//! Every mutating handler writes an `admin_audit_log` row (who did what to whom,
//! when). The write is best-effort: an audit insert failure is logged but never
//! fails the admin action itself.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::chat_federation_policy::{self, FederationMode, FederationRuleAction};
use crate::error::{AppError, AppResult};
use crate::jobs;
use crate::middleware::AdminUser;
use crate::AppState;

/// Best-effort audit-log write. The payload snapshots human-readable identities
/// (emails, usernames) at action time so the trail stays meaningful after the
/// referenced users are deleted.
pub(crate) async fn audit(
    pool: &PgPool,
    admin_user_id: &str,
    action: &str,
    target_user_id: Option<Uuid>,
    payload: serde_json::Value,
) {
    let Ok(admin_uuid) = Uuid::parse_str(admin_user_id) else {
        return;
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO admin_audit_log (admin_user_id, action, target_user_id, payload) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(admin_uuid)
    .bind(action)
    .bind(target_user_id)
    .bind(payload)
    .execute(pool)
    .await
    {
        tracing::warn!("audit log write failed ({action}): {e}");
    }
}

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

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = AdminUserRow)]
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
    /// Still on the admin-issued temp password (no key material yet). Gates the
    /// admin "rotate temp password" action.
    is_first_login: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// Marks the break-glass admin — the UI disables demote/disable/delete for this user.
    is_protected: bool,
}

/// `GET /api/admin/users` — mirrors `ListUsers`.
#[utoipa::path(
    get,
    path = "/api/admin/users",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "All user accounts", body = Vec<UserRow>))
)]
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
        bool,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT id, email, COALESCE(username, ''), storage_quota_bytes, storage_used_bytes,
                  is_admin, is_active, totp_enabled, is_first_login, created_at
           FROM users ORDER BY created_at DESC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let users: Vec<UserRow> = rows
        .into_iter()
        .map(
            |(id, email, username, quota, used, is_admin, is_active, totp, first, created)| {
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
                    is_first_login: first,
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
#[utoipa::path(
    post,
    path = "/api/admin/users",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = crate::models::CreateAdminUserRequest,
    responses((status = 201, description = "First-login account created"))
)]
pub async fn create_user(
    State(state): State<AppState>,
    admin: AdminUser,
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

    let res: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        r#"INSERT INTO users (
               email, username, login_key_hash,
               encrypted_master_key, master_key_nonce,
               encrypted_recovery_key, recovery_key_nonce,
               encrypted_private_key, private_key_nonce,
               public_key, kdf_salt, login_key_salt,
               is_admin, is_first_login, storage_quota_bytes
           ) VALUES ($1,$2,$3,'','','','','','','','','',false,true,$4)
           RETURNING id"#,
    )
    .bind(&req.email)
    .bind(&req.username)
    .bind(&hash)
    .bind(req.storage_quota_bytes)
    .fetch_one(&state.pool)
    .await;
    let new_id = match res {
        Ok(id) => id,
        Err(e) => return Err(map_insert_conflict(e)),
    };
    audit(
        &state.pool,
        &admin.user_id,
        "user.create",
        Some(new_id),
        json!({
            "email": req.email,
            "username": req.username,
            "storageQuotaBytes": req.storage_quota_bytes,
        }),
    )
    .await;
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
#[utoipa::path(
    put,
    path = "/api/admin/users/{id}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    request_body = crate::models::UpdateAdminUserRequest,
    responses((status = 200, description = "User updated"))
)]
pub async fn update_user(
    State(state): State<AppState>,
    admin: AdminUser,
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

    // Snapshot only the fields that were actually changed.
    let mut changes = serde_json::Map::new();
    if let Some(q) = req.storage_quota_bytes {
        changes.insert("storageQuotaBytes".into(), json!(q));
    }
    if let Some(a) = req.is_active {
        changes.insert("isActive".into(), json!(a));
    }
    if let Some(a) = req.is_admin {
        changes.insert("isAdmin".into(), json!(a));
    }
    audit(
        &state.pool,
        &admin.user_id,
        "user.update",
        Some(target),
        json!({"email": target_email, "changes": changes}),
    )
    .await;
    Ok(Json(json!({"message": "updated"})).into_response())
}

/// `DELETE /api/admin/users/{id}` — mirrors `DeleteUser` (cascades via FKs).
#[utoipa::path(
    delete,
    path = "/api/admin/users/{id}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    responses((status = 204, description = "User deleted"))
)]
pub async fn delete_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    // Break-glass admin can never be deleted.
    let (target_email, target_username): (String, Option<String>) =
        sqlx::query_as("SELECT email, username FROM users WHERE id = $1")
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
        Ok(r) if r.rows_affected() > 0 => {
            audit(
                &state.pool,
                &admin.user_id,
                "user.delete",
                Some(target),
                json!({
                    "email": target_email,
                    "username": target_username.unwrap_or_default(),
                }),
            )
            .await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(AppError::not_found("not found")),
    }
}

/// `DELETE /api/admin/users/{id}/2fa` — mirrors `ForceDisable2FA`. Clears the target's TOTP
/// (the admin caller is already authenticated + admin-gated, so no TOTP-code challenge).
/// Allowed on the break-glass admin too — it's a recovery aid and can't lock anyone out.
#[utoipa::path(
    delete,
    path = "/api/admin/users/{id}/2fa",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    responses((status = 200, description = "TOTP cleared for the target user"))
)]
pub async fn force_disable_2fa(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let email: Option<String> = sqlx::query_scalar(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1 RETURNING email",
    )
    .bind(target)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;
    let Some(email) = email else {
        return Err(AppError::not_found("not found"));
    };
    audit(
        &state.pool,
        &admin.user_id,
        "user.2fa_disable",
        Some(target),
        json!({"email": email}),
    )
    .await;
    Ok(Json(json!({"message": "2fa disabled"})).into_response())
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = AdminStatsResponse)]
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
#[utoipa::path(
    get,
    path = "/api/admin/stats",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Aggregate instance stats", body = StatsResponse))
)]
pub async fn get_stats(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Response> {
    let scalar = |sql: &'static str| {
        let pool = state.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| {
                    // A decode/query failure must not silently render as a 0 stat.
                    tracing::warn!("admin stats query failed ({sql}): {e}");
                    0
                })
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
        // ::bigint — SUM(bigint) yields NUMERIC, which sqlx cannot decode as i64;
        // without the cast this silently fell back to 0 via unwrap_or.
        total_storage_used: scalar("SELECT COALESCE(SUM(storage_used_bytes),0)::bigint FROM users")
            .await,
        total_collections: scalar("SELECT COUNT(*) FROM collections").await,
        storage_total_bytes,
        storage_backend_used_bytes,
    };
    Ok(Json(stats).into_response())
}

/// `GET /api/admin/settings` — mirrors `GetSettings`.
#[utoipa::path(
    get,
    path = "/api/admin/settings",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Site settings", body = crate::models::SettingsResponse))
)]
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
#[utoipa::path(
    put,
    path = "/api/admin/settings",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = crate::models::UpdateAdminSettingsRequest,
    responses((status = 200, description = "Updated site settings", body = crate::models::SettingsResponse))
)]
pub async fn update_settings(
    State(state): State<AppState>,
    admin: AdminUser,
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
    audit(
        &state.pool,
        &admin.user_id,
        "settings.update",
        None,
        json!({"registrationEnabled": req.registration_enabled}),
    )
    .await;
    Ok(Json(json!({"registrationEnabled": req.registration_enabled})).into_response())
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationDomainRuleResponse {
    domain: String,
    inbound: FederationRuleAction,
    outbound: FederationRuleAction,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationPolicyResponse {
    configured: bool,
    server_name: Option<String>,
    mode: FederationMode,
    rules: Vec<FederationDomainRuleResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFederationPolicyRequest {
    mode: FederationMode,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpsertFederationDomainRuleRequest {
    inbound: FederationRuleAction,
    outbound: FederationRuleAction,
}

/// `GET /api/admin/chat-federation` — operational federation mode and all
/// persisted directional domain rules. Rules are returned even in open or
/// disabled mode because they are intentionally preserved across mode changes.
#[utoipa::path(
    get,
    path = "/api/admin/chat-federation",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Chat federation admission policy", body = FederationPolicyResponse))
)]
pub async fn get_federation_policy(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Response> {
    type RuleRow = (String, String, String, OffsetDateTime, OffsetDateTime);
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT domain, inbound_action, outbound_action, created_at, updated_at \
         FROM chat_federation_domain_rules ORDER BY domain",
    )
    .fetch_all(&state.pool)
    .await?;
    let rules = rows
        .into_iter()
        .map(|(domain, inbound, outbound, created_at, updated_at)| {
            let inbound = inbound
                .parse()
                .map_err(|_| AppError::internal("invalid stored inbound federation rule"))?;
            let outbound = outbound
                .parse()
                .map_err(|_| AppError::internal("invalid stored outbound federation rule"))?;
            Ok(FederationDomainRuleResponse {
                domain,
                inbound,
                outbound,
                created_at,
                updated_at,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let server_name = state
        .chat_federation
        .as_ref()
        .map(|federation| federation.server_name().to_string());
    Ok(Json(FederationPolicyResponse {
        configured: server_name.is_some(),
        server_name,
        mode: chat_federation_policy::load_mode(&state.pool).await?,
        rules,
    })
    .into_response())
}

/// `PUT /api/admin/chat-federation` — switch the global admission mode.
#[utoipa::path(
    put,
    path = "/api/admin/chat-federation",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = UpdateFederationPolicyRequest,
    responses((status = 200, description = "Federation mode updated", body = FederationPolicyResponse))
)]
pub async fn update_federation_policy(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<UpdateFederationPolicyRequest>,
) -> AppResult<Response> {
    let previous = chat_federation_policy::load_mode(&state.pool).await?;
    sqlx::query(
        "UPDATE chat_federation_policy SET mode = $1, updated_at = now() \
         WHERE singleton = TRUE",
    )
    .bind(req.mode.to_string())
    .execute(&state.pool)
    .await?;
    if req.mode != FederationMode::Disabled {
        sqlx::query(
            "UPDATE chat_federation_outbox SET next_attempt_at = now() \
             WHERE state = 'pending'",
        )
        .execute(&state.pool)
        .await?;
    }
    audit(
        &state.pool,
        &admin.user_id,
        "federation.policy.update",
        None,
        json!({"previousMode": previous, "mode": req.mode}),
    )
    .await;
    get_federation_policy(State(state), admin).await
}

/// `PUT /api/admin/chat-federation/servers/{domain}` — create or replace the
/// domain's independent inbound and outbound actions.
#[utoipa::path(
    put,
    path = "/api/admin/chat-federation/servers/{domain}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("domain" = String, Path, description = "Canonical lowercase DNS homeserver name")),
    request_body = UpsertFederationDomainRuleRequest,
    responses((status = 200, description = "Directional domain rule stored", body = FederationPolicyResponse))
)]
pub async fn upsert_federation_domain_rule(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(domain): Path<String>,
    Json(req): Json<UpsertFederationDomainRuleRequest>,
) -> AppResult<Response> {
    let domain = chat_federation_policy::canonical_domain(&domain)?;
    if state
        .chat_federation
        .as_ref()
        .is_some_and(|federation| federation.server_name() == domain)
    {
        return Err(AppError::bad_request(
            "cannot create a federation rule for the local server",
        ));
    }
    sqlx::query(
        "INSERT INTO chat_federation_domain_rules \
            (domain, inbound_action, outbound_action) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (domain) DO UPDATE SET \
            inbound_action = EXCLUDED.inbound_action, \
            outbound_action = EXCLUDED.outbound_action, updated_at = now()",
    )
    .bind(&domain)
    .bind(req.inbound.to_string())
    .bind(req.outbound.to_string())
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "UPDATE chat_federation_outbox SET next_attempt_at = now() \
         WHERE destination = $1 AND state = 'pending'",
    )
    .bind(&domain)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        &admin.user_id,
        "federation.rule.upsert",
        None,
        json!({"domain": domain, "inbound": req.inbound, "outbound": req.outbound}),
    )
    .await;
    get_federation_policy(State(state), admin).await
}

/// `DELETE /api/admin/chat-federation/servers/{domain}` — remove the explicit
/// actions and return that domain to the active mode's default.
#[utoipa::path(
    delete,
    path = "/api/admin/chat-federation/servers/{domain}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("domain" = String, Path, description = "Canonical lowercase DNS homeserver name")),
    responses(
        (status = 200, description = "Domain rule removed", body = FederationPolicyResponse),
        (status = 404, description = "No rule exists for the domain")
    )
)]
pub async fn delete_federation_domain_rule(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    let domain = chat_federation_policy::canonical_domain(&domain)?;
    let result = sqlx::query("DELETE FROM chat_federation_domain_rules WHERE domain = $1")
        .bind(&domain)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("federation domain rule not found"));
    }
    sqlx::query(
        "UPDATE chat_federation_outbox SET next_attempt_at = now() \
         WHERE destination = $1 AND state = 'pending'",
    )
    .bind(&domain)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool,
        &admin.user_id,
        "federation.rule.delete",
        None,
        json!({"domain": domain}),
    )
    .await;
    get_federation_policy(State(state), admin).await
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RotateTempPasswordRequest {
    temp_password: String,
}

/// `POST /api/admin/users/{id}/rotate-temp-password` — replaces the temp password of an
/// account still in `is_first_login` state. Such an account has no key material yet, so
/// this destroys nothing. For an established account this is a `409`: under E2EE the
/// server cannot reset a password without destroying the user's data — they self-serve
/// via `/auth/recover`, or the admin wipes (see `wipe_user`).
/// Design: `docs/research/10-admin-password-reset.md`.
#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/rotate-temp-password",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    request_body = RotateTempPasswordRequest,
    responses(
        (status = 200, description = "Temp password rotated"),
        (status = 409, description = "User has completed setup — recovery phrase or wipe instead")
    )
)]
pub async fn rotate_temp_password(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(req): Json<RotateTempPasswordRequest>,
) -> AppResult<Response> {
    if req.temp_password.is_empty() {
        return Err(AppError::bad_request("tempPassword required"));
    }
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT email, is_first_login FROM users WHERE id = $1")
            .bind(target)
            .fetch_optional(&state.pool)
            .await?;
    let Some((email, is_first_login)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if !is_first_login {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "user has completed setup; only the user can reset their password (recovery phrase), or wipe the account",
        ));
    }

    let hash =
        bcrypt::hash(&req.temp_password, 10).map_err(|_| AppError::internal("internal error"))?;
    sqlx::query(
        "UPDATE users SET login_key_hash = $1, updated_at = NOW() WHERE id = $2 AND is_first_login",
    )
    .bind(&hash)
    .bind(target)
    .execute(&state.pool)
    .await?;

    audit(
        &state.pool,
        &admin.user_id,
        "user.rotate_temp_password",
        Some(target),
        json!({"email": email}),
    )
    .await;
    Ok(Json(json!({"message": "temp password rotated"})).into_response())
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct WipeUserRequest {
    temp_password: String,
}

/// `POST /api/admin/users/{id}/wipe` — the destructive "reset" for a user who lost both
/// password and recovery phrase. Their data is cryptographically unreachable anyway;
/// this makes it official: purges every owned collection (files, versions, assets, S3
/// blobs, shares), erases the key bundle + TOTP + device signing keys, and resets the
/// account to `is_first_login` with the supplied temp password. Email/username/quota
/// survive. Irreversible. Design: `docs/research/10-admin-password-reset.md`.
#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/wipe",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    request_body = WipeUserRequest,
    responses((status = 200, description = "Account wiped + reset to first-login"))
)]
pub async fn wipe_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(req): Json<WipeUserRequest>,
) -> AppResult<Response> {
    if req.temp_password.is_empty() {
        return Err(AppError::bad_request("tempPassword required"));
    }
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT email, username FROM users WHERE id = $1")
            .bind(target)
            .fetch_optional(&state.pool)
            .await?;
    let Some((email, username)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if is_break_glass(&state, &email) {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }

    // 1. Purge every owned collection — same machinery as a permanent trash purge
    //    (quota release + S3 GC + FK-cascaded children). Covers trashed items too.
    let colls: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM collections WHERE owner_user_id = $1")
            .bind(target)
            .fetch_all(&state.pool)
            .await?;
    if !colls.is_empty() {
        let files: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM files WHERE collection_id = ANY($1)")
                .bind(&colls)
                .fetch_all(&state.pool)
                .await?;
        for fid in files {
            jobs::purge_file_root(&state.pool, &state.storage, fid)
                .await
                .map_err(|e| {
                    tracing::error!("wipe {target}: purge file {fid}: {e:#}");
                    AppError::internal("internal error")
                })?;
        }
        // Public share links pointing at the purged tree (no FK ties them down).
        sqlx::query("DELETE FROM public_shares WHERE target_id = ANY($1)")
            .bind(&colls)
            .execute(&state.pool)
            .await?;
        sqlx::query("DELETE FROM collections WHERE id = ANY($1)")
            .bind(&colls)
            .execute(&state.pool)
            .await?;
    }

    // 2. Everything keyed to the lost key material: collab signing devices, incoming
    //    federated shares (their wrapped keys are unreachable), local shares received.
    sqlx::query("DELETE FROM user_devices WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM federated_incoming_shares WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM collection_shares WHERE recipient_user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;

    // 3. Erase the key bundle + TOTP and reset to first-login with the new temp password.
    let hash =
        bcrypt::hash(&req.temp_password, 10).map_err(|_| AppError::internal("internal error"))?;
    sqlx::query(
        r#"UPDATE users SET
               encrypted_master_key = '', master_key_nonce = '',
               encrypted_recovery_key = '', recovery_key_nonce = '',
               encrypted_private_key = '', private_key_nonce = '',
               public_key = '', kdf_salt = '', login_key_salt = '',
               login_key_hash = $1, totp_secret = NULL, totp_enabled = false,
               is_first_login = true, updated_at = NOW()
           WHERE id = $2"#,
    )
    .bind(&hash)
    .bind(target)
    .execute(&state.pool)
    .await?;

    // 4. Recompute quota: uploads into OTHER people's folders survive (they're the
    //    folder-owner's data view) and still count against this user.
    sqlx::query(
        r#"UPDATE users SET storage_used_bytes = (
               SELECT COALESCE((SELECT SUM(encrypted_size_bytes) FROM files WHERE uploader_user_id = $1), 0)
                    + COALESCE((SELECT SUM(size_bytes) FROM file_assets WHERE uploader_user_id = $1), 0)
                    + COALESCE((SELECT SUM(size_bytes) FROM file_versions WHERE author_user_id = $1), 0)
           ) WHERE id = $1"#,
    )
    .bind(target)
    .execute(&state.pool)
    .await?;

    audit(
        &state.pool,
        &admin.user_id,
        "user.wipe",
        Some(target),
        json!({"email": email, "username": username.unwrap_or_default()}),
    )
    .await;
    Ok(Json(json!({"message": "account wiped"})).into_response())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ActivityQuery {
    /// Page size, clamped to 1..=100 (default 50).
    limit: Option<i64>,
    /// Cursor: return entries with `id <` this (from the previous page's `nextBefore`).
    before: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ActivityEntry {
    id: i64,
    action: String,
    admin_user_id: Uuid,
    /// The acting admin's live identity — `null` once that account is deleted.
    admin_email: Option<String>,
    admin_username: Option<String>,
    target_user_id: Option<Uuid>,
    /// The target's live email — `null` once deleted; the payload keeps the
    /// at-action-time snapshot.
    target_email: Option<String>,
    payload: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ActivityResponse {
    entries: Vec<ActivityEntry>,
    /// Pass as `?before=` to fetch the next (older) page; `null` = no more pages.
    next_before: Option<i64>,
}

/// `GET /api/admin/activity?limit=50&before=<id>` — the audit-log feed, newest first.
#[utoipa::path(
    get,
    path = "/api/admin/activity",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Page size, clamped to 1..=100 (default 50)"),
        ("before" = Option<i64>, Query, description = "Cursor: entries with id < this (previous page's nextBefore)")
    ),
    responses((status = 200, description = "Audit-log page, newest first", body = ActivityResponse))
)]
pub async fn activity(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ActivityQuery>,
) -> AppResult<Response> {
    let limit = q.limit.unwrap_or(50).clamp(1, 100);

    type Row = (
        i64,
        String,
        Uuid,
        Option<String>,
        Option<String>,
        Option<Uuid>,
        Option<String>,
        serde_json::Value,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT l.id, l.action, l.admin_user_id, a.email, a.username,
                  l.target_user_id, t.email, l.payload, l.occurred_at
           FROM admin_audit_log l
           LEFT JOIN users a ON a.id = l.admin_user_id
           LEFT JOIN users t ON t.id = l.target_user_id
           WHERE ($1::bigint IS NULL OR l.id < $1)
           ORDER BY l.id DESC
           LIMIT $2"#,
    )
    .bind(q.before)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let full_page = rows.len() as i64 == limit;
    let entries: Vec<ActivityEntry> = rows
        .into_iter()
        .map(
            |(id, action, admin_id, a_email, a_username, target_id, t_email, payload, at)| {
                ActivityEntry {
                    id,
                    action,
                    admin_user_id: admin_id,
                    admin_email: a_email,
                    admin_username: a_username,
                    target_user_id: target_id,
                    target_email: t_email,
                    payload,
                    occurred_at: at,
                }
            },
        )
        .collect();
    let next_before = if full_page {
        entries.last().map(|e| e.id)
    } else {
        None
    };
    Ok(Json(ActivityResponse {
        entries,
        next_before,
    })
    .into_response())
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
