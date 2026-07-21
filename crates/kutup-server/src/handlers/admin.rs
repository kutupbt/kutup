//! Admin handlers — user CRUD, aggregate stats, the registration toggle, and the
//! audit-log feed. Every route is behind the `AdminUser` extractor (authenticated +
//! `isAdmin`), so the handlers trust the caller.
//!
//! Every mutating handler writes an `admin_audit_log` row (who did what to whom,
//! when). The write is best-effort: an audit insert failure is logged but never
//! fails the admin action itself.

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::collections::BTreeSet;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::federation::{FederationDirection, FederationPolicyFeature};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FederationMode {
    Disabled,
    Allowlist,
    Blocklist,
    Open,
}

impl FederationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
            Self::Open => "open",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FederationRuleAction {
    Inherit,
    Allow,
    Block,
}

impl FederationRuleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FederationTrustRequirement {
    Inherit,
    Tofu,
    Verified,
}

impl FederationTrustRequirement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Tofu => "tofu",
            Self::Verified => "verified",
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationFeaturePolicyResponse {
    feature: String,
    mode: String,
    minimum_trust: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationDomainRuleResponse {
    domain: String,
    feature: String,
    inbound: String,
    outbound: String,
    trust_requirement: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationPeerResponse {
    domain: String,
    trust: String,
    sequence: u64,
    fingerprint: String,
    fingerprint_display: String,
    api_base: Option<String>,
    capabilities: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    first_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    last_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    verified_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    discovery_expires_at: Option<OffsetDateTime>,
    quarantine_reason: Option<String>,
    pending_fingerprint: Option<String>,
    last_discovery_error: Option<String>,
    diagnostics: FederationPeerDiagnosticsResponse,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationPeerDiagnosticsResponse {
    chat_pending_transactions: i64,
    chat_mismatch_transactions: i64,
    drive_incoming_shares: i64,
    drive_outgoing_shares: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationOperationalSummaryResponse {
    peer_total: usize,
    tofu_peers: usize,
    verified_peers: usize,
    quarantined_peers: usize,
    chat_pending_transactions: i64,
    chat_mismatch_transactions: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    oldest_chat_pending_at: Option<OffsetDateTime>,
    drive_incoming_shares: i64,
    drive_outgoing_shares: i64,
    active_replay_reservations: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationControlPlaneResponse {
    configured: bool,
    server_name: Option<String>,
    fingerprint: Option<String>,
    fingerprint_display: Option<String>,
    identity_sequence: Option<u64>,
    capabilities: Vec<String>,
    global_enabled: bool,
    features: Vec<FederationFeaturePolicyResponse>,
    rules: Vec<FederationDomainRuleResponse>,
    peers: Vec<FederationPeerResponse>,
    operational: FederationOperationalSummaryResponse,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationPeerEvidenceDocumentResponse {
    sequence: u64,
    document_hash: String,
    fingerprint: String,
    fingerprint_display: String,
    acceptance: String,
    document: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    recorded_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationPeerEvidenceResponse {
    domain: String,
    trust: String,
    current_document_hash: String,
    pending_document_hash: Option<String>,
    quarantine_reason: Option<String>,
    documents: Vec<FederationPeerEvidenceDocumentResponse>,
    truncated: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkRetryFederationPeersRequest {
    domains: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationPeerRetryResultResponse {
    domain: String,
    refreshed: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkRetryFederationPeersResponse {
    results: Vec<FederationPeerRetryResultResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFederationPolicyRequest {
    global_enabled: bool,
    feature: String,
    mode: FederationMode,
    minimum_trust: FederationTrustRequirement,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpsertFederationDomainRuleRequest {
    inbound: FederationRuleAction,
    outbound: FederationRuleAction,
    trust_requirement: FederationTrustRequirement,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFederationPeerRequest {
    fingerprint: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepinFederationPeerRequest {
    old_fingerprint: String,
    new_fingerprint: String,
    confirm_domain: String,
}

#[utoipa::path(
    get,
    path = "/api/admin/federation",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Unified federation policy and peer trust state", body = FederationControlPlaneResponse))
)]
pub async fn get_federation_control_plane(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Response> {
    type FeatureRow = (String, String, String);
    let global_enabled: bool =
        sqlx::query_scalar("SELECT global_enabled FROM federation_policy WHERE singleton = TRUE")
            .fetch_one(&state.pool)
            .await?;
    let features: Vec<FederationFeaturePolicyResponse> = sqlx::query_as::<_, FeatureRow>(
        "SELECT feature, mode, minimum_trust FROM federation_feature_policies ORDER BY feature",
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(
        |(feature, mode, minimum_trust)| FederationFeaturePolicyResponse {
            feature,
            mode,
            minimum_trust,
        },
    )
    .collect();

    type RuleRow = (
        String,
        String,
        String,
        String,
        String,
        OffsetDateTime,
        OffsetDateTime,
    );
    let rules = sqlx::query_as::<_, RuleRow>(
        "SELECT domain, feature, inbound_action, outbound_action, trust_requirement,
                created_at, updated_at
         FROM federation_domain_rules ORDER BY domain, feature",
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(
        |(domain, feature, inbound, outbound, trust_requirement, created_at, updated_at)| {
            FederationDomainRuleResponse {
                domain,
                feature,
                inbound,
                outbound,
                trust_requirement,
                created_at,
                updated_at,
            }
        },
    )
    .collect();

    #[derive(sqlx::FromRow)]
    struct PeerRow {
        domain: String,
        trust_state: String,
        current_sequence: i64,
        current_key_id: String,
        current_api_base: Option<String>,
        capabilities: serde_json::Value,
        first_seen_at: OffsetDateTime,
        last_seen_at: OffsetDateTime,
        verified_at: Option<OffsetDateTime>,
        discovery_expires_at: Option<OffsetDateTime>,
        quarantine_reason: Option<String>,
        pending_fingerprint: Option<String>,
        last_discovery_error: Option<String>,
        chat_pending_transactions: i64,
        chat_mismatch_transactions: i64,
        drive_incoming_shares: i64,
        drive_outgoing_shares: i64,
    }
    let peers = sqlx::query_as::<_, PeerRow>(
        "SELECT domain, trust_state, current_sequence, current_key_id,
                current_api_base, capabilities, first_seen_at, last_seen_at,
                verified_at, discovery_expires_at, quarantine_reason,
                pending_document->'key'->>'keyId' AS pending_fingerprint,
                last_discovery_error,
                (SELECT COUNT(*) FROM chat_federation_outbox o
                 WHERE o.destination = federation_peer_identities.domain AND o.state = 'pending')
                    AS chat_pending_transactions,
                (SELECT COUNT(*) FROM chat_federation_outbox o
                 WHERE o.destination = federation_peer_identities.domain AND o.state = 'mismatch')
                    AS chat_mismatch_transactions,
                (SELECT COUNT(*) FROM federated_incoming_shares s
                 WHERE s.remote_domain = federation_peer_identities.domain)
                    AS drive_incoming_shares,
                (SELECT COUNT(*) FROM federated_outgoing_shares s
                 WHERE s.recipient_domain = federation_peer_identities.domain)
                    AS drive_outgoing_shares
         FROM federation_peer_identities ORDER BY domain",
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| {
        let capabilities: Vec<kutup_federation_proto::FederationCapabilityId> =
            serde_json::from_value(row.capabilities)
                .map_err(|_| AppError::internal("invalid stored federation capabilities"))?;
        Ok(FederationPeerResponse {
            domain: row.domain,
            trust: row.trust_state,
            sequence: u64::try_from(row.current_sequence)
                .map_err(|_| AppError::internal("invalid stored federation sequence"))?,
            fingerprint_display: kutup_federation_proto::grouped_fingerprint(&row.current_key_id)
                .map_err(|error| AppError::internal(error.to_string()))?,
            fingerprint: row.current_key_id,
            api_base: row.current_api_base,
            capabilities: capabilities.into_iter().map(String::from).collect(),
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            verified_at: row.verified_at,
            discovery_expires_at: row.discovery_expires_at,
            quarantine_reason: row.quarantine_reason,
            pending_fingerprint: row.pending_fingerprint,
            last_discovery_error: row.last_discovery_error,
            diagnostics: FederationPeerDiagnosticsResponse {
                chat_pending_transactions: row.chat_pending_transactions,
                chat_mismatch_transactions: row.chat_mismatch_transactions,
                drive_incoming_shares: row.drive_incoming_shares,
                drive_outgoing_shares: row.drive_outgoing_shares,
            },
        })
    })
    .collect::<AppResult<Vec<_>>>()?;

    type OperationalRow = (i64, i64, Option<OffsetDateTime>, i64, i64, i64);
    let (
        chat_pending_transactions,
        chat_mismatch_transactions,
        oldest_chat_pending_at,
        drive_incoming_shares,
        drive_outgoing_shares,
        active_replay_reservations,
    ): OperationalRow = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM chat_federation_outbox WHERE state = 'pending'),
            (SELECT COUNT(*) FROM chat_federation_outbox WHERE state = 'mismatch'),
            (SELECT MIN(created_at) FROM chat_federation_outbox WHERE state = 'pending'),
            (SELECT COUNT(*) FROM federated_incoming_shares),
            (SELECT COUNT(*) FROM federated_outgoing_shares),
            (SELECT COUNT(*) FROM federation_request_replays WHERE expires_at > now())",
    )
    .fetch_one(&state.pool)
    .await?;
    let operational = FederationOperationalSummaryResponse {
        peer_total: peers.len(),
        tofu_peers: peers.iter().filter(|peer| peer.trust == "tofu").count(),
        verified_peers: peers.iter().filter(|peer| peer.trust == "verified").count(),
        quarantined_peers: peers
            .iter()
            .filter(|peer| peer.trust == "quarantined")
            .count(),
        chat_pending_transactions,
        chat_mismatch_transactions,
        oldest_chat_pending_at,
        drive_incoming_shares,
        drive_outgoing_shares,
        active_replay_reservations,
    };

    let enabled_capabilities = if global_enabled {
        let mut capabilities = vec!["identity.v1".to_owned()];
        for feature in &features {
            if feature.mode == "disabled" {
                continue;
            }
            match feature.feature.as_str() {
                "chat" => capabilities.push("chat.v1".to_owned()),
                "drive" => capabilities.push("drive.v1".to_owned()),
                _ => {}
            }
        }
        capabilities
    } else {
        Vec::new()
    };
    let (server_name, fingerprint, fingerprint_display, identity_sequence, capabilities) =
        match state.federation.as_ref() {
            Some(federation) => {
                let fingerprint = federation.local_identity().fingerprint().to_owned();
                (
                    Some(federation.server_name().to_owned()),
                    Some(fingerprint.clone()),
                    Some(
                        kutup_federation_proto::grouped_fingerprint(&fingerprint)
                            .map_err(|error| AppError::internal(error.to_string()))?,
                    ),
                    Some(federation.local_identity().document().sequence),
                    enabled_capabilities,
                )
            }
            None => (None, None, None, None, Vec::new()),
        };
    Ok(Json(FederationControlPlaneResponse {
        configured: server_name.is_some(),
        server_name,
        fingerprint,
        fingerprint_display,
        identity_sequence,
        capabilities,
        global_enabled,
        features,
        rules,
        peers,
        operational,
    })
    .into_response())
}

#[utoipa::path(
    put,
    path = "/api/admin/federation",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = UpdateFederationPolicyRequest,
    responses((status = 200, description = "Unified federation policy updated", body = FederationControlPlaneResponse))
)]
pub async fn update_federation_policy(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<UpdateFederationPolicyRequest>,
) -> AppResult<Response> {
    let feature = canonical_federation_feature(&req.feature)?;
    if matches!(req.minimum_trust, FederationTrustRequirement::Inherit) {
        return Err(AppError::bad_request(
            "feature minimumTrust must be tofu or verified",
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE federation_policy SET global_enabled = $1, updated_at = now() WHERE singleton = TRUE")
        .bind(req.global_enabled)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE federation_feature_policies
         SET mode = $2, minimum_trust = $3, updated_at = now() WHERE feature = $1",
    )
    .bind(feature)
    .bind(req.mode.as_str())
    .bind(req.minimum_trust.as_str())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    wake_federation_outbox(&state.pool, None).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "federation.policy.update",
        None,
        json!({"globalEnabled": req.global_enabled, "feature": feature,
               "mode": req.mode, "minimumTrust": req.minimum_trust}),
    )
    .await;
    get_federation_control_plane(State(state), admin).await
}

#[utoipa::path(
    put,
    path = "/api/admin/federation/rules/{feature}/{domain}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("feature" = String, Path), ("domain" = String, Path)),
    request_body = UpsertFederationDomainRuleRequest,
    responses((status = 200, description = "Feature-scoped domain rule stored", body = FederationControlPlaneResponse))
)]
pub async fn upsert_federation_domain_rule(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((feature, domain)): Path<(String, String)>,
    Json(req): Json<UpsertFederationDomainRuleRequest>,
) -> AppResult<Response> {
    let feature = canonical_federation_feature(&feature)?;
    let domain = canonical_federation_domain(&domain)?;
    if state
        .federation
        .as_ref()
        .is_some_and(|stack| stack.server_name() == domain)
    {
        return Err(AppError::bad_request(
            "cannot create a federation rule for the local server",
        ));
    }
    sqlx::query(
        "INSERT INTO federation_domain_rules
            (domain, feature, inbound_action, outbound_action, trust_requirement)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (domain, feature) DO UPDATE SET
            inbound_action = EXCLUDED.inbound_action,
            outbound_action = EXCLUDED.outbound_action,
            trust_requirement = EXCLUDED.trust_requirement, updated_at = now()",
    )
    .bind(&domain)
    .bind(feature)
    .bind(req.inbound.as_str())
    .bind(req.outbound.as_str())
    .bind(req.trust_requirement.as_str())
    .execute(&state.pool)
    .await?;
    wake_federation_outbox(&state.pool, Some(&domain)).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "federation.rule.upsert",
        None,
        json!({"domain": domain, "feature": feature, "inbound": req.inbound,
                 "outbound": req.outbound, "trustRequirement": req.trust_requirement}),
    )
    .await;
    get_federation_control_plane(State(state), admin).await
}

#[utoipa::path(
    delete,
    path = "/api/admin/federation/rules/{feature}/{domain}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("feature" = String, Path), ("domain" = String, Path)),
    responses((status = 200, description = "Feature-scoped domain rule removed", body = FederationControlPlaneResponse))
)]
pub async fn delete_federation_domain_rule(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((feature, domain)): Path<(String, String)>,
) -> AppResult<Response> {
    let feature = canonical_federation_feature(&feature)?;
    let domain = canonical_federation_domain(&domain)?;
    let result =
        sqlx::query("DELETE FROM federation_domain_rules WHERE domain = $1 AND feature = $2")
            .bind(&domain)
            .bind(feature)
            .execute(&state.pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("federation domain rule not found"));
    }
    wake_federation_outbox(&state.pool, Some(&domain)).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "federation.rule.delete",
        None,
        json!({"domain": domain, "feature": feature}),
    )
    .await;
    get_federation_control_plane(State(state), admin).await
}

#[utoipa::path(
    get,
    path = "/api/admin/federation/peers/{domain}/evidence",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("domain" = String, Path)),
    responses(
        (status = 200, description = "Immutable accepted and quarantined peer identity evidence", body = FederationPeerEvidenceResponse),
        (status = 404, description = "Federation peer is not pinned")
    )
)]
pub async fn get_federation_peer_evidence(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    let domain = canonical_federation_domain(&domain)?;
    type PeerEvidenceRow = (String, String, Option<String>, Option<String>);
    let peer: PeerEvidenceRow = sqlx::query_as(
        "SELECT trust_state, current_document_hash, pending_document_hash, quarantine_reason
         FROM federation_peer_identities WHERE domain = $1",
    )
    .bind(&domain)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("federation peer not found"))?;

    type DocumentRow = (
        i64,
        String,
        String,
        serde_json::Value,
        String,
        OffsetDateTime,
    );
    let mut rows: Vec<DocumentRow> = sqlx::query_as(
        "SELECT sequence, document_hash, key_id, document, acceptance, recorded_at
         FROM federation_peer_identity_documents
         WHERE domain = $1
         ORDER BY sequence DESC, recorded_at DESC, document_hash
         LIMIT 201",
    )
    .bind(&domain)
    .fetch_all(&state.pool)
    .await?;
    let truncated = rows.len() > 200;
    rows.truncate(200);
    let documents = rows
        .into_iter()
        .map(
            |(sequence, document_hash, fingerprint, document, acceptance, recorded_at)| {
                Ok(FederationPeerEvidenceDocumentResponse {
                    sequence: u64::try_from(sequence)
                        .map_err(|_| AppError::internal("invalid stored federation sequence"))?,
                    fingerprint_display: kutup_federation_proto::grouped_fingerprint(&fingerprint)
                        .map_err(|error| AppError::internal(error.to_string()))?,
                    fingerprint,
                    document_hash,
                    acceptance,
                    document,
                    recorded_at,
                })
            },
        )
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(FederationPeerEvidenceResponse {
        domain,
        trust: peer.0,
        current_document_hash: peer.1,
        pending_document_hash: peer.2,
        quarantine_reason: peer.3,
        documents,
        truncated,
    })
    .into_response())
}

#[utoipa::path(
    post,
    path = "/api/admin/federation/peers/{domain}/verify",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("domain" = String, Path)),
    request_body = VerifyFederationPeerRequest,
    responses((status = 200, description = "Pinned peer fingerprint verified", body = FederationControlPlaneResponse))
)]
pub async fn verify_federation_peer(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(domain): Path<String>,
    Json(req): Json<VerifyFederationPeerRequest>,
) -> AppResult<Response> {
    let domain = canonical_federation_domain(&domain)?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::bad_request("federation is not configured"))?;
    let admin_id = Uuid::parse_str(&admin.user_id)
        .map_err(|_| AppError::internal("invalid administrator identity"))?;
    federation
        .trust()
        .verify_peer(
            &domain,
            &req.fingerprint,
            admin_id,
            OffsetDateTime::now_utc(),
        )
        .await?;
    federation.evict_peer_cache(&domain).await;
    wake_federation_outbox(&state.pool, Some(&domain)).await?;
    get_federation_control_plane(State(state), admin).await
}

#[utoipa::path(
    post,
    path = "/api/admin/federation/peers/{domain}/retry",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("domain" = String, Path)),
    responses((status = 200, description = "Peer discovery retried", body = FederationControlPlaneResponse))
)]
pub async fn retry_federation_peer(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    let domain = canonical_federation_domain(&domain)?;
    let result = retry_peer_resolution(&state, &domain).await;
    wake_federation_outbox(&state.pool, Some(&domain)).await?;
    audit(
        &state.pool,
        &admin.user_id,
        "federation.peer.retry",
        None,
        json!({"domain": domain, "refreshed": result.is_ok(), "error": result.err()}),
    )
    .await;
    get_federation_control_plane(State(state), admin).await
}

#[utoipa::path(
    post,
    path = "/api/admin/federation/peers/retry",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = BulkRetryFederationPeersRequest,
    responses((status = 200, description = "Selected peer discoveries retried independently", body = BulkRetryFederationPeersResponse))
)]
pub async fn bulk_retry_federation_peers(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<BulkRetryFederationPeersRequest>,
) -> AppResult<Response> {
    if req.domains.is_empty() {
        return Err(AppError::bad_request(
            "at least one federation peer is required",
        ));
    }
    if req.domains.len() > 100 {
        return Err(AppError::bad_request(
            "at most 100 federation peers may be retried at once",
        ));
    }
    let mut domains = BTreeSet::new();
    for domain in req.domains {
        domains.insert(canonical_federation_domain(&domain)?);
    }
    let mut results: Vec<FederationPeerRetryResultResponse> =
        stream::iter(domains.into_iter().map(|domain| {
            let state = state.clone();
            async move {
                let result = retry_peer_resolution(&state, &domain).await;
                let wake_error = wake_federation_outbox(&state.pool, Some(&domain))
                    .await
                    .err()
                    .map(|error| error.to_string());
                FederationPeerRetryResultResponse {
                    domain,
                    refreshed: result.is_ok() && wake_error.is_none(),
                    error: result.err().or(wake_error),
                }
            }
        }))
        .buffer_unordered(8)
        .collect()
        .await;
    results.sort_by(|left, right| left.domain.cmp(&right.domain));
    audit(
        &state.pool,
        &admin.user_id,
        "federation.peer.retry-bulk",
        None,
        json!({"results": results.iter().map(|result| json!({
            "domain": result.domain,
            "refreshed": result.refreshed,
            "error": result.error,
        })).collect::<Vec<_>>() }),
    )
    .await;
    Ok(Json(BulkRetryFederationPeersResponse { results }).into_response())
}

async fn retry_peer_resolution(state: &AppState, domain: &str) -> Result<(), String> {
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM federation_peer_identities WHERE domain = $1)",
    )
    .bind(domain)
    .fetch_one(&state.pool)
    .await
    {
        Ok(true) => {}
        Ok(false) => return Err("federation peer is not pinned".to_owned()),
        Err(error) => return Err(format!("could not load federation peer: {error}")),
    }
    let Some(federation) = state.federation.as_ref() else {
        return Err("federation is not configured".to_owned());
    };
    federation.evict_peer_cache(domain).await;
    let mut errors = Vec::new();
    for feature in [
        kutup_federation_proto::FederationFeature::ChatV1,
        kutup_federation_proto::FederationFeature::DriveV1,
    ] {
        match federation
            .resolve_peer(
                domain,
                feature,
                FederationDirection::Outbound,
                OffsetDateTime::now_utc(),
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                errors.push(error.to_string());
                federation.evict_peer_cache(domain).await;
            }
        }
    }
    let error = errors.join("; ");
    Err(error.chars().take(500).collect())
}

#[utoipa::path(
    post,
    path = "/api/admin/federation/peers/{domain}/repin",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("domain" = String, Path)),
    request_body = RepinFederationPeerRequest,
    responses((status = 200, description = "Quarantined peer explicitly re-pinned", body = FederationControlPlaneResponse))
)]
pub async fn repin_federation_peer(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(domain): Path<String>,
    Json(req): Json<RepinFederationPeerRequest>,
) -> AppResult<Response> {
    let domain = canonical_federation_domain(&domain)?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::bad_request("federation is not configured"))?;
    let admin_id = Uuid::parse_str(&admin.user_id)
        .map_err(|_| AppError::internal("invalid administrator identity"))?;
    federation
        .trust()
        .repin_quarantined_peer(
            &domain,
            &req.old_fingerprint,
            &req.new_fingerprint,
            &req.confirm_domain,
            admin_id,
            OffsetDateTime::now_utc(),
        )
        .await?;
    federation.evict_peer_cache(&domain).await;
    wake_federation_outbox(&state.pool, Some(&domain)).await?;
    get_federation_control_plane(State(state), admin).await
}

fn canonical_federation_feature(value: &str) -> AppResult<&'static str> {
    match value {
        "chat" => Ok(FederationPolicyFeature::Chat.as_str()),
        "drive" => Ok(FederationPolicyFeature::Drive.as_str()),
        _ => Err(AppError::bad_request(
            "federation feature must be chat or drive",
        )),
    }
}

fn canonical_federation_domain(value: &str) -> AppResult<String> {
    kutup_federation_proto::validate_server_name(value)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    Ok(value.to_owned())
}

async fn wake_federation_outbox(pool: &PgPool, domain: Option<&str>) -> AppResult<()> {
    if let Some(domain) = domain {
        sqlx::query("UPDATE chat_federation_outbox SET next_attempt_at = now() WHERE destination = $1 AND state = 'pending'")
            .bind(domain).execute(pool).await?;
    } else {
        sqlx::query(
            "UPDATE chat_federation_outbox SET next_attempt_at = now() WHERE state = 'pending'",
        )
        .execute(pool)
        .await?;
    }
    Ok(())
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
    /// Optional action prefix, for example `federation.`.
    action_prefix: Option<String>,
    /// Optional exact federation domain from the structured audit payload.
    domain: Option<String>,
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

/// `GET /api/admin/activity?limit=50&before=<id>` — the filterable audit-log feed.
#[utoipa::path(
    get,
    path = "/api/admin/activity",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Page size, clamped to 1..=100 (default 50)"),
        ("before" = Option<i64>, Query, description = "Cursor: entries with id < this (previous page's nextBefore)"),
        ("actionPrefix" = Option<String>, Query, description = "Exact action namespace prefix, such as federation."),
        ("domain" = Option<String>, Query, description = "Exact federation domain in the structured audit payload")
    ),
    responses((status = 200, description = "Audit-log page, newest first", body = ActivityResponse))
)]
pub async fn activity(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ActivityQuery>,
) -> AppResult<Response> {
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    validate_activity_query(&q)?;
    let entries = load_activity_entries(&state.pool, &q, limit).await?;
    let next_before = if entries.len() as i64 == limit {
        entries.last().map(|entry| entry.id)
    } else {
        None
    };
    Ok(Json(ActivityResponse {
        entries,
        next_before,
    })
    .into_response())
}

#[utoipa::path(
    get,
    path = "/api/admin/activity/export",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Export size, clamped to 1..=5000 (default 1000)"),
        ("before" = Option<i64>, Query, description = "Optional older-than cursor"),
        ("actionPrefix" = Option<String>, Query, description = "Exact action namespace prefix, such as federation."),
        ("domain" = Option<String>, Query, description = "Exact federation domain in the structured audit payload")
    ),
    responses((status = 200, description = "Filtered audit events as spreadsheet-safe CSV", content_type = "text/csv"))
)]
pub async fn activity_export(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ActivityQuery>,
) -> AppResult<Response> {
    validate_activity_query(&q)?;
    let limit = q.limit.unwrap_or(1000).clamp(1, 5000);
    let entries = load_activity_entries(&state.pool, &q, limit).await?;
    let mut csv = String::from(
        "id,occurred_at,action,admin_user_id,admin_email,admin_username,target_user_id,target_email,payload\n",
    );
    for entry in entries {
        let values = [
            entry.id.to_string(),
            entry
                .occurred_at
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| AppError::internal("could not format audit timestamp"))?,
            entry.action,
            entry.admin_user_id.to_string(),
            entry.admin_email.unwrap_or_default(),
            entry.admin_username.unwrap_or_default(),
            entry
                .target_user_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            entry.target_email.unwrap_or_default(),
            serde_json::to_string(&entry.payload)
                .map_err(|_| AppError::internal("could not serialize audit payload"))?,
        ];
        csv.push_str(&values.map(|value| csv_cell(&value)).join(","));
        csv.push('\n');
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"kutup-admin-audit.csv\"",
            ),
        ],
        csv,
    )
        .into_response())
}

fn validate_activity_query(q: &ActivityQuery) -> AppResult<()> {
    if let Some(prefix) = q.action_prefix.as_deref() {
        if prefix.is_empty()
            || prefix.len() > 80
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(AppError::bad_request("invalid audit action prefix"));
        }
    }
    if let Some(domain) = q.domain.as_deref() {
        canonical_federation_domain(domain)?;
    }
    Ok(())
}

async fn load_activity_entries(
    pool: &PgPool,
    q: &ActivityQuery,
    limit: i64,
) -> AppResult<Vec<ActivityEntry>> {
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
             AND ($2::text IS NULL OR left(l.action, char_length($2)) = $2)
             AND ($3::text IS NULL
                  OR l.payload->>'domain' = $3
                  OR EXISTS (
                      SELECT 1
                      FROM jsonb_array_elements(
                          CASE WHEN jsonb_typeof(l.payload->'results') = 'array'
                               THEN l.payload->'results' ELSE '[]'::jsonb END
                      ) result
                      WHERE result->>'domain' = $3
                  ))
           ORDER BY l.id DESC
           LIMIT $4"#,
    )
    .bind(q.before)
    .bind(&q.action_prefix)
    .bind(&q.domain)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    Ok(rows
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
        .collect())
}

fn csv_cell(value: &str) -> String {
    let spreadsheet_safe = if value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'))
    {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", spreadsheet_safe.replace('"', "\"\""))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_csv_cells_escape_quotes_and_spreadsheet_formulas() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-1"), "\"'-1\"");
    }

    #[test]
    fn audit_filters_accept_only_bounded_prefixes_and_canonical_domains() {
        let valid = ActivityQuery {
            action_prefix: Some("federation.identity.".to_owned()),
            domain: Some("chat.example.com".to_owned()),
            ..ActivityQuery::default()
        };
        assert!(validate_activity_query(&valid).is_ok());

        let wildcard = ActivityQuery {
            action_prefix: Some("federation.%".to_owned()),
            ..ActivityQuery::default()
        };
        assert!(validate_activity_query(&wildcard).is_err());

        let noncanonical_domain = ActivityQuery {
            domain: Some("https://chat.example.com".to_owned()),
            ..ActivityQuery::default()
        };
        assert!(validate_activity_query(&noncanonical_domain).is_err());
    }
}
