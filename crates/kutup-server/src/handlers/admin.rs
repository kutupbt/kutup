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
/// (usernames) at action time so the trail stays meaningful after the
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

/// Whether account `id` is the protected break-glass admin: the one
/// `bootstrap_admin` made, recorded by its id. It can never be demoted,
/// disabled, wiped or deleted.
async fn is_break_glass(state: &AppState, id: Uuid) -> AppResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT is_break_glass FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or(false),
    )
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = AdminUserRow)]
#[serde(rename_all = "camelCase")]
struct UserRow {
    id: Uuid,
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
        i64,
        i64,
        bool,
        bool,
        bool,
        bool,
        OffsetDateTime,
        bool,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT id, COALESCE(username, '') AS username, storage_quota_bytes, storage_used_bytes,
                  is_admin, is_active, totp_enabled, is_first_login, created_at, is_break_glass
           FROM users ORDER BY created_at DESC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let users: Vec<UserRow> = rows
        .into_iter()
        .map(
            |(
                id,
                username,
                quota,
                used,
                is_admin,
                is_active,
                totp,
                first,
                created,
                is_protected,
            )| {
                UserRow {
                    id,
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

/// A temporary password as the administrator's client registered it
/// (docs/plans/opaque.md, "Admin temporary passwords"): an OPAQUE record
/// under a key binding that client drew. The server never sees the password;
/// at first sign-in the person registers their own under a key binding of
/// their own.
#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct TempRegistration {
    key_binding: String,
    #[serde(flatten)]
    record: crate::handlers::opaque::RecordUpload,
}

impl TempRegistration {
    /// The key binding, record and setup id to store.
    fn checked(&self, state: &AppState) -> AppResult<(String, Vec<u8>, i16)> {
        if !crate::handlers::auth::is_key_binding(&self.key_binding) {
            return Err(AppError::bad_request("keyBinding is a lowercase UUID v4"));
        }
        let (record, key_id) = self.record.checked(state)?;
        Ok((self.key_binding.clone(), record, key_id))
    }
}

/// Uses an admin-reset grant for `target`, issued to this admin's session
/// (`reset-grant`), or refuses.
async fn take_reset_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
    admin: &AdminUser,
    target: Uuid,
) -> AppResult<()> {
    let admin_id = Uuid::parse_str(&admin.user_id).map_err(|_| AppError::forbidden("forbidden"))?;
    match crate::grants::take(&mut **tx, token, &[crate::grants::Purpose::AdminReset]).await? {
        Some((_, grant))
            if grant.user_id == admin_id
                && grant.target_user_id == Some(target)
                && grant.session_id == Some(admin.session_id) =>
        {
            Ok(())
        }
        _ => Err(crate::grants::invalid()),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateUserRequest {
    username: String,
    /// The temporary password, registered by the administrator's client.
    #[serde(flatten)]
    setup: TempRegistration,
    storage_quota_bytes: i64,
}

/// `POST /api/admin/users` — creates a first-login account under a temporary
/// password the administrator's browser derived (the server never sees it);
/// the user establishes their E2EE key material on first sign-in. It signs in
/// with its username; no email is asked (a recovery email is the user's own).
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
    let (key_binding, opaque_record, opaque_server_key_id) = req.setup.checked(&state)?;
    if req.username.is_empty() {
        return Err(AppError::bad_request("username required"));
    }
    if !valid_admin_username(&req.username) {
        return Err(AppError::bad_request(
            "invalid username: must be 3-32 chars, lowercase letters, numbers, _ and -",
        ));
    }
    if req.storage_quota_bytes == 0 {
        // The account's one storage pool, for every app (crate::storage_pool).
        req.storage_quota_bytes = crate::storage_pool::default_quota(&state.pool).await?;
    }
    if req.storage_quota_bytes <= 0 {
        return Err(AppError::bad_request("storage quota must be positive"));
    }

    let mut tx = state.pool.begin().await?;
    // One account per folded name (docs/plans/username-renames.md). The
    // break-glass account itself is made by `bootstrap_admin`, not here.
    if let Err(unavailable) = crate::account_names::available(
        &mut tx,
        &state.config.chat_server_name,
        &state.config.break_glass_admin_username,
        &req.username,
        None,
    )
    .await?
    {
        return Err(unavailable.error());
    }
    let res: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
        r#"INSERT INTO users (
               username, key_binding, opaque_record, opaque_suite, opaque_server_key_id,
               master_key_envelope, recovery_key_envelope,
               drive_private_key_envelope,
               public_key, account_authority_public_key, account_authority_key_id,
               account_incarnation_id, drive_signing_public_key,
               is_admin, is_first_login, storage_quota_bytes
           ) VALUES ($1,$2,$3,$4,$5,'','','','','','','','',false,true,$6)
           RETURNING id"#,
    )
    .bind(&req.username)
    .bind(&key_binding)
    .bind(&opaque_record)
    .bind(kutup_crypto::opaque::SUITE as i16)
    .bind(opaque_server_key_id)
    .bind(req.storage_quota_bytes)
    .fetch_one(&mut *tx)
    .await;
    let new_id = match res {
        Ok(id) => id,
        Err(e) => return Err(map_insert_conflict(e)),
    };
    crate::account_names::claim(&mut tx, &req.username, new_id, None).await?;
    if !crate::handlers::mail_keys::create_own_address(
        &mut tx,
        &state.config.chat_server_name,
        new_id,
        &req.username,
    )
    .await?
    {
        return Err(AppError::conflict("username already taken"));
    }
    tx.commit().await?;
    audit(
        &state.pool,
        &admin.user_id,
        "user.create",
        Some(new_id),
        json!({
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
    let (target_username, target_is_admin, target_is_active): (String, bool, bool) =
        sqlx::query_as(
            "SELECT COALESCE(username, ''), is_admin, is_active FROM users WHERE id = $1",
        )
        .bind(target)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::not_found("not found"))?;

    let wants_demote = req.is_admin == Some(false);
    let wants_disable = req.is_active == Some(false);

    // Break-glass admin is immutable: never demote or disable it.
    if is_break_glass(&state, target).await? && (wants_demote || wants_disable) {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }

    // Last-admin guard: don't let a demote/disable leave zero usable admins.
    if (wants_demote || wants_disable) && target_is_admin && target_is_active {
        let other_usable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE is_admin AND is_active AND id != $1",
        )
        .bind(target)
        .fetch_one(&state.pool)
        .await?;
        if other_usable == 0 {
            return Err(AppError::bad_request("cannot remove the last admin"));
        }
    }

    if let Some(q) = req.storage_quota_bytes {
        if q <= 0 {
            return Err(AppError::bad_request("storage quota must be positive"));
        }
        sqlx::query("UPDATE users SET storage_quota_bytes = $1 WHERE id = $2")
            .bind(q)
            .bind(target)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::internal("internal error"))?;
    }
    if let Some(a) = req.is_active {
        let mut tx = state.pool.begin().await?;
        if !a {
            // The shared mailboxes it signs for need a new signer: it may
            // still hold the seed (docs/plans/mail-groups.md).
            crate::mail::group_keys::signer_leaving(&mut tx, target).await?;
        }
        sqlx::query("UPDATE users SET is_active = $1 WHERE id = $2")
            .bind(a)
            .bind(target)
            .execute(&mut *tx)
            .await
            .map_err(|_| AppError::internal("internal error"))?;
        tx.commit().await?;
        // A disabled account keeps no live sign-in anywhere.
        if !a {
            crate::sessions::revoke_all_for_user(&state.pool, target, None).await?;
            // Their public links are down with them (link_reports::ensure_link_up):
            // reports on those links are answered.
            if let Ok(admin_uuid) = Uuid::parse_str(&admin.user_id) {
                crate::handlers::link_reports::resolve_reports_of_owner(
                    &state.pool,
                    target,
                    admin_uuid,
                )
                .await?;
            }
        }
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
        json!({"username": target_username, "changes": changes}),
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
    let target_username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(target)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("not found"))?;
    if is_break_glass(&state, target).await? {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }

    // Everything the account holds goes with it, bytes included (a bare
    // row delete would cascade the rows and leave every object in the
    // bucket), while what it added to other people's folders stays theirs.
    super::chat_backup::purge_for_account(&state, target).await?;
    purge_chat_media(&state, target).await?;
    purge_owned_drive(&state, target).await?;
    purge_mail(&state, target).await?;
    hand_over_contributions(&state.pool, target).await?;

    // Its names stay held, receiving nothing, until the hold ends: nobody
    // takes a deleted person's name, nor their mail, before then
    // (docs/plans/username-renames.md).
    let (hold_days, _) = crate::site_settings::name_holds(&state.pool, &state.config).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE account_names SET state = 'held', receive_until = now(),
                free_at = now() + make_interval(days => $2::int)
          WHERE user_id = $1",
    )
    .bind(target)
    .bind(hold_days as i32)
    .execute(&mut *tx)
    .await?;
    // Its account id is never given to anyone again (docs/plans/account-ids.md).
    crate::account_ids::retire(&mut tx, target).await?;
    // The shared mailboxes it signed for need a new signer: its signing
    // shares go with it, but it may still hold the seed.
    crate::mail::group_keys::signer_leaving(&mut tx, target).await?;
    let res = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(target)
        .execute(&mut *tx)
        .await;
    if res.as_ref().is_ok_and(|r| r.rows_affected() > 0) {
        tx.commit().await?;
    }
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            audit(
                &state.pool,
                &admin.user_id,
                "user.delete",
                Some(target),
                json!({
                    "username": target_username.unwrap_or_default(),
                }),
            )
            .await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(AppError::not_found("not found")),
    }
}

/// Removes a user's stored mail; the rows go with the account.
async fn purge_mail(state: &AppState, target: Uuid) -> AppResult<()> {
    state
        .storage
        .delete_prefix(&crate::mail::object_prefix(target))
        .await
        .map_err(|_| AppError::internal("failed to delete stored mail"))
}

/// Removes a user's Chat media: aborts their open uploads, drops their
/// references and deletes every object no one else references.
async fn purge_chat_media(state: &AppState, target: Uuid) -> AppResult<()> {
    let media_uploads: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id,storage_path,s3_upload_id FROM chat_media_uploads WHERE user_id=$1",
    )
    .bind(target)
    .fetch_all(&state.pool)
    .await?;
    for (_, path, upload_id) in &media_uploads {
        state
            .storage
            .abort_multipart(path, upload_id)
            .await
            .map_err(|_| AppError::internal("failed to abort Chat media upload"))?;
    }
    sqlx::query("DELETE FROM chat_media_uploads WHERE user_id=$1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM chat_media_references WHERE user_id=$1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    let orphan_media_paths: Vec<String> = sqlx::query_scalar(
        "DELETE FROM chat_media_objects object
         WHERE NOT EXISTS (SELECT 1 FROM chat_media_references reference
                           WHERE reference.attachment_id=object.attachment_id)
         RETURNING storage_path",
    )
    .fetch_all(&state.pool)
    .await?;
    sqlx::query("DELETE FROM chat_attachment_ledger_entities WHERE user_id=$1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM chat_attachment_ledger_operations WHERE user_id=$1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    for path in orphan_media_paths {
        if let Err(error) = state.storage.delete(&path).await {
            tracing::warn!(error = %error, "wiped Chat media object requires orphan cleanup");
        }
    }
    Ok(())
}

/// Permanently removes everything in a user's own Drive — every folder they
/// own, trashed or not, with each file's blobs, versions, assets and
/// thumbnails and the charges they hold (whoever pays them) — plus the
/// uploads in flight into it and the public links onto it.
async fn purge_owned_drive(state: &AppState, target: Uuid) -> AppResult<()> {
    // Open uploads by the user anywhere, or by anyone into the user's
    // folders: their multipart parts would otherwise stay in the bucket.
    let open_uploads: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT u.id, u.storage_path, u.s3_upload_id FROM uploads u
         WHERE u.user_id = $1
            OR u.collection_id IN (SELECT id FROM collections WHERE owner_user_id = $1)",
    )
    .bind(target)
    .fetch_all(&state.pool)
    .await?;
    for (id, path, upload_id) in open_uploads {
        if let Err(error) = state.storage.abort_multipart(&path, &upload_id).await {
            tracing::warn!(%error, "purge {target}: abort upload {id}");
        }
        sqlx::query("DELETE FROM uploads WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    let colls: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM collections WHERE owner_user_id = $1")
            .bind(target)
            .fetch_all(&state.pool)
            .await?;
    if colls.is_empty() {
        return Ok(());
    }
    let files: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM files WHERE collection_id = ANY($1)")
        .bind(&colls)
        .fetch_all(&state.pool)
        .await?;
    for fid in files {
        jobs::purge_file_root(&state.pool, &state.storage, fid, jobs::PurgeGuard::Any)
            .await
            .map_err(|e| {
                tracing::error!("purge {target}: file {fid}: {e:#}");
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
    Ok(())
}

/// Hands what a departing user added to other people's folders — files,
/// versions, assets, thumbnails — to each folder's owner, charges and all,
/// so deleting the account neither deletes their data nor leaves bytes that
/// no one pays for. (A folder may go over its owner's quota; they can store
/// nothing more until they free space, as after any quota cut.)
async fn hand_over_contributions(pool: &PgPool, target: Uuid) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"WITH moved AS (
              SELECT c.owner_user_id AS owner, SUM(x.bytes) AS total FROM (
                  SELECT f.collection_id, (CASE WHEN f.original_pruned THEN 0 ELSE f.encrypted_size_bytes END) AS bytes
                    FROM files f WHERE f.uploader_user_id = $1
                  UNION ALL
                  SELECT f.collection_id, v.size_bytes FROM file_versions v JOIN files f ON f.id = v.file_id
                   WHERE v.author_user_id = $1
                  UNION ALL
                  SELECT f.collection_id, a.size_bytes FROM file_assets a JOIN files f ON f.id = a.file_id
                   WHERE a.uploader_user_id = $1
                  UNION ALL
                  SELECT f.collection_id, t.size_bytes FROM file_thumbnails t JOIN files f ON f.id = t.file_id
                   WHERE t.uploader_user_id = $1) x
              JOIN collections c ON c.id = x.collection_id
              WHERE c.owner_user_id <> $1
              GROUP BY c.owner_user_id)
           UPDATE users u SET storage_used_bytes = u.storage_used_bytes + moved.total
           FROM moved WHERE u.id = moved.owner"#,
    )
    .bind(target)
    .execute(&mut *tx)
    .await?;
    for (table, column) in [
        ("files", "uploader_user_id"),
        ("file_versions", "author_user_id"),
        ("file_assets", "uploader_user_id"),
        ("file_thumbnails", "uploader_user_id"),
    ] {
        let file_column = if table == "files" { "id" } else { "file_id" };
        sqlx::query(&format!(
            "UPDATE {table} t SET {column} = c.owner_user_id
             FROM files f JOIN collections c ON c.id = f.collection_id
             WHERE t.{file_column} = f.id AND t.{column} = $1 AND c.owner_user_id <> $1"
        ))
        .bind(target)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
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
    let username: Option<String> = sqlx::query_scalar(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1
         RETURNING COALESCE(username, '')",
    )
    .bind(target)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;
    let Some(username) = username else {
        return Err(AppError::not_found("not found"));
    };
    audit(
        &state.pool,
        &admin.user_id,
        "user.2fa_disable",
        Some(target),
        json!({"username": username}),
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
    responses((status = 200, description = "Site settings", body = crate::models::AdminSettingsResponse))
)]
pub async fn get_settings(State(state): State<AppState>, _admin: AdminUser) -> AppResult<Response> {
    let registration_mode = crate::registration::mode(&state).await?;
    let chat_mailbox_retention_days = crate::site_settings::chat_delivery_retention_days(
        &state.pool,
        crate::site_settings::CHAT_MAILBOX_RETENTION_DAYS,
        state.config.chat_mailbox_retention_days,
    )
    .await?;
    let chat_media_delivery_retention_days = crate::site_settings::chat_delivery_retention_days(
        &state.pool,
        crate::site_settings::CHAT_MEDIA_DELIVERY_RETENTION_DAYS,
        state.config.chat_media_delivery_retention_days,
    )
    .await?;
    let default_storage_quota_bytes = crate::storage_pool::default_quota(&state.pool).await?;
    let (name_hold_days, old_address_receive_days) =
        crate::site_settings::name_holds(&state.pool, &state.config).await?;
    let (link_joins_per_relay_group, link_joins_per_relay) =
        crate::site_settings::chat_group_link_joins(&state.pool).await?;
    let avatar = crate::site_settings::chat_group_avatar_limits(&state.pool).await?;
    let mut numeric = serde_json::Map::new();
    for setting in crate::site_settings::numeric_settings() {
        numeric.insert(
            setting.field.to_owned(),
            json!(setting.load(&state.pool).await?),
        );
    }
    let mut settings = json!({
        "registrationMode": registration_mode,
        "defaultStorageQuotaBytes": default_storage_quota_bytes,
        "chatMailboxRetentionDays": chat_mailbox_retention_days,
        "chatMediaDeliveryRetentionDays": chat_media_delivery_retention_days,
        "nameHoldDays": name_hold_days,
        "oldAddressReceiveDays": old_address_receive_days,
        "chatGroupLinkJoinsPerRelayGroupPerMin": link_joins_per_relay_group,
        "chatGroupLinkJoinsPerRelayPerMin": link_joins_per_relay,
        "chatGroupAvatarMaxBytes": avatar.max_bytes,
        "chatGroupAvatarStoragePerGroupBytes": avatar.storage_bytes,
        "chatGroupAvatarPendingSeconds": avatar.pending_seconds,
        "passVaultMaxBytes": crate::site_settings::pass_vault_max_bytes(&state.pool).await?,
    });
    if let Some(object) = settings.as_object_mut() {
        object.extend(numeric);
    }
    Ok(Json(settings).into_response())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateSettingsRequest {
    registration_mode: Option<crate::registration::RegistrationMode>,
    default_storage_quota_bytes: Option<i64>,
    chat_mailbox_retention_days: Option<i64>,
    chat_media_delivery_retention_days: Option<i64>,
    name_hold_days: Option<i64>,
    old_address_receive_days: Option<i64>,
    /// `null` resets to the configured first value (the stored one goes).
    #[serde(deserialize_with = "present")]
    chat_group_link_joins_per_relay_group_per_min: Option<Option<i64>>,
    #[serde(deserialize_with = "present")]
    chat_group_link_joins_per_relay_per_min: Option<Option<i64>>,
    /// The whole-number settings listed in `site_settings::numeric_settings`,
    /// by field: a number sets one, `null` resets it; other fields are ignored.
    #[serde(flatten)]
    numeric: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(deserialize_with = "present")]
    chat_group_avatar_max_bytes: Option<Option<i64>>,
    #[serde(deserialize_with = "present")]
    chat_group_avatar_storage_per_group_bytes: Option<Option<i64>>,
    #[serde(deserialize_with = "present")]
    chat_group_avatar_pending_seconds: Option<Option<i64>>,
    pass_vault_max_bytes: Option<i64>,
}

/// A field that is present: `Some(None)` for `null`, so a missing field
/// (`None`, the default) and a reset differ.
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<i64>>, D::Error> {
    Option::<i64>::deserialize(deserializer).map(Some)
}

/// `PUT /api/admin/settings` — mirrors `UpdateSettings`.
#[utoipa::path(
    put,
    path = "/api/admin/settings",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = crate::models::UpdateAdminSettingsRequest,
    responses((status = 200, description = "Updated site settings", body = crate::models::AdminSettingsResponse))
)]
pub async fn update_settings(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> AppResult<Response> {
    if req.registration_mode.is_none()
        && req.default_storage_quota_bytes.is_none()
        && req.chat_mailbox_retention_days.is_none()
        && req.chat_media_delivery_retention_days.is_none()
        && req.name_hold_days.is_none()
        && req.old_address_receive_days.is_none()
        && req.chat_group_link_joins_per_relay_group_per_min.is_none()
        && req.chat_group_link_joins_per_relay_per_min.is_none()
        && !crate::site_settings::numeric_settings()
            .any(|setting| req.numeric.contains_key(setting.field))
        && req.chat_group_avatar_max_bytes.is_none()
        && req.chat_group_avatar_storage_per_group_bytes.is_none()
        && req.chat_group_avatar_pending_seconds.is_none()
        && req.pass_vault_max_bytes.is_none()
    {
        return Err(AppError::bad_request("at least one setting is required"));
    }
    if let Some(value) = req.pass_vault_max_bytes {
        crate::site_settings::validate_pass_vault_max_bytes(value)
            .map_err(AppError::bad_request)?;
    }
    if req
        .default_storage_quota_bytes
        .is_some_and(|quota| quota <= 0)
    {
        return Err(AppError::bad_request(
            "default storage quota must be positive",
        ));
    }
    for value in [
        req.chat_mailbox_retention_days,
        req.chat_media_delivery_retention_days,
    ]
    .into_iter()
    .flatten()
    {
        crate::site_settings::validate_chat_delivery_retention_days(value)
            .map_err(AppError::bad_request)?;
    }

    for value in [
        req.chat_group_link_joins_per_relay_group_per_min,
        req.chat_group_link_joins_per_relay_per_min,
    ]
    .into_iter()
    .flatten()
    .flatten()
    {
        crate::site_settings::validate_chat_group_link_joins(value)
            .map_err(AppError::bad_request)?;
    }
    // Each given whole-number setting: Some(value) to store, None to reset.
    let mut numeric = Vec::new();
    for setting in crate::site_settings::numeric_settings() {
        let Some(value) = req.numeric.get(setting.field) else {
            continue;
        };
        let value = match value {
            serde_json::Value::Null => None,
            value => Some(
                value
                    .as_i64()
                    .ok_or_else(|| {
                        AppError::bad_request(format!("{} takes a whole number", setting.field))
                    })
                    .and_then(|value| setting.validate(value).map_err(AppError::bad_request))?,
            ),
        };
        numeric.push((setting.key, value));
    }
    // The avatar limits are checked together, each new value (or reset to
    // its first value) beside the others as they stand.
    if req.chat_group_avatar_max_bytes.is_some()
        || req.chat_group_avatar_storage_per_group_bytes.is_some()
        || req.chat_group_avatar_pending_seconds.is_some()
    {
        use crate::site_settings::AvatarLimits;
        let current = crate::site_settings::chat_group_avatar_limits(&state.pool).await?;
        let pick = |new: Option<Option<i64>>, now: i64, first: i64| match new {
            Some(Some(value)) => value,
            Some(None) => first,
            None => now,
        };
        AvatarLimits {
            max_bytes: pick(
                req.chat_group_avatar_max_bytes,
                current.max_bytes,
                AvatarLimits::DEFAULT.max_bytes,
            ),
            storage_bytes: pick(
                req.chat_group_avatar_storage_per_group_bytes,
                current.storage_bytes,
                AvatarLimits::DEFAULT.storage_bytes,
            ),
            pending_seconds: pick(
                req.chat_group_avatar_pending_seconds,
                current.pending_seconds,
                AvatarLimits::DEFAULT.pending_seconds,
            ),
        }
        .validate()
        .map_err(AppError::bad_request)?;
    }
    // The two holds are checked together, each against the other's new or
    // current value.
    if req.name_hold_days.is_some() || req.old_address_receive_days.is_some() {
        let (hold, receive) = crate::site_settings::name_holds(&state.pool, &state.config).await?;
        crate::site_settings::validate_name_holds(
            req.name_hold_days.unwrap_or(hold),
            req.old_address_receive_days.unwrap_or(receive),
        )
        .map_err(AppError::bad_request)?;
    }
    let mut transaction = state.pool.begin().await?;
    if let Some(mode) = req.registration_mode {
        crate::registration::set_mode(&mut transaction, mode).await?;
    }
    for (key, value) in [
        (
            crate::storage_pool::DEFAULT_QUOTA_SETTING,
            req.default_storage_quota_bytes,
        ),
        (
            crate::site_settings::CHAT_MAILBOX_RETENTION_DAYS,
            req.chat_mailbox_retention_days,
        ),
        (
            crate::site_settings::CHAT_MEDIA_DELIVERY_RETENTION_DAYS,
            req.chat_media_delivery_retention_days,
        ),
        (crate::site_settings::NAME_HOLD_DAYS, req.name_hold_days),
        (
            crate::site_settings::PASS_VAULT_MAX_BYTES,
            req.pass_vault_max_bytes,
        ),
        (
            crate::site_settings::OLD_ADDRESS_RECEIVE_DAYS,
            req.old_address_receive_days,
        ),
    ] {
        let Some(value) = value else { continue };
        sqlx::query(
            "INSERT INTO site_settings (key, value) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::internal("internal error"))?;
    }
    for (key, value) in [
        (
            crate::site_settings::CHAT_GROUP_LINK_JOINS_PER_RELAY_GROUP,
            req.chat_group_link_joins_per_relay_group_per_min,
        ),
        (
            crate::site_settings::CHAT_GROUP_LINK_JOINS_PER_RELAY,
            req.chat_group_link_joins_per_relay_per_min,
        ),
        (
            crate::site_settings::CHAT_GROUP_AVATAR_MAX_BYTES,
            req.chat_group_avatar_max_bytes,
        ),
        (
            crate::site_settings::CHAT_GROUP_AVATAR_STORAGE_BYTES,
            req.chat_group_avatar_storage_per_group_bytes,
        ),
        (
            crate::site_settings::CHAT_GROUP_AVATAR_PENDING_SECONDS,
            req.chat_group_avatar_pending_seconds,
        ),
    ]
    .into_iter()
    .chain(numeric.iter().map(|(key, value)| (*key, Some(*value))))
    {
        match value {
            None => {}
            Some(Some(value)) => {
                sqlx::query(
                    "INSERT INTO site_settings (key, value) VALUES ($1, $2) \
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                )
                .bind(key)
                .bind(value.to_string())
                .execute(&mut *transaction)
                .await?;
            }
            Some(None) => {
                sqlx::query("DELETE FROM site_settings WHERE key = $1")
                    .bind(key)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
    }
    transaction.commit().await?;
    audit(
        &state.pool,
        &admin.user_id,
        "settings.update",
        None,
        json!({
            "registrationMode": req.registration_mode,
            "defaultStorageQuotaBytes": req.default_storage_quota_bytes,
            "chatMailboxRetentionDays": req.chat_mailbox_retention_days,
            "chatMediaDeliveryRetentionDays": req.chat_media_delivery_retention_days,
            "nameHoldDays": req.name_hold_days,
            "oldAddressReceiveDays": req.old_address_receive_days,
            "chatGroupLinkJoinsPerRelayGroupPerMin": req.chat_group_link_joins_per_relay_group_per_min,
            "chatGroupLinkJoinsPerRelayPerMin": req.chat_group_link_joins_per_relay_per_min,
            "numeric": crate::site_settings::numeric_settings()
                .filter_map(|setting| {
                    req.numeric
                        .get(setting.field)
                        .map(|value| (setting.field.to_owned(), value.clone()))
                })
                .collect::<serde_json::Map<_, _>>(),
            "chatGroupAvatarMaxBytes": req.chat_group_avatar_max_bytes,
            "chatGroupAvatarStoragePerGroupBytes": req.chat_group_avatar_storage_per_group_bytes,
            "chatGroupAvatarPendingSeconds": req.chat_group_avatar_pending_seconds,
            "passVaultMaxBytes": req.pass_vault_max_bytes,
        }),
    )
    .await;
    get_settings(State(state), admin).await
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
                "chat" => capabilities.push("chat.v2".to_owned()),
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
        kutup_federation_proto::FederationFeature::ChatV2,
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

// No Debug: it carries a one-time grant (or tokens).
#[derive(Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RotateTempPasswordRequest {
    /// An admin-reset grant for this account (`reset-grant`).
    grant: String,
    /// The new temporary password, registered by the administrator's client.
    #[serde(flatten)]
    setup: TempRegistration,
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
    let (key_binding, opaque_record, opaque_server_key_id) = req.setup.checked(&state)?;
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;

    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT COALESCE(username, ''), is_first_login FROM users WHERE id = $1")
            .bind(target)
            .fetch_optional(&state.pool)
            .await?;
    let Some((username, is_first_login)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if !is_first_login {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "user has completed setup; only the user can reset their password (recovery phrase), or wipe the account",
        ));
    }

    let mut tx = state.pool.begin().await?;
    take_reset_grant(&mut tx, &req.grant, &admin, target).await?;
    let rotated = sqlx::query(
        "UPDATE users SET key_binding = $2, opaque_record = $3, opaque_suite = $4,
                opaque_server_key_id = $5, updated_at = NOW()
          WHERE id = $1 AND is_first_login",
    )
    .bind(target)
    .bind(&key_binding)
    .bind(&opaque_record)
    .bind(kutup_crypto::opaque::SUITE as i16)
    .bind(opaque_server_key_id)
    .execute(&mut *tx)
    .await
    .map_err(map_insert_conflict)?;
    // Set up in between: nothing changes (the grant stays unused with the
    // rolled-back transaction).
    if rotated.rows_affected() != 1 {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "user has completed setup; only the user can reset their password (recovery phrase), or wipe the account",
        ));
    }
    crate::grants::end_all(&mut tx, target).await?;
    crate::sessions::revoke_all_for_user_in(&mut tx, target, None).await?;
    crate::security_events::record(
        &mut tx,
        target,
        crate::security_events::Kind::AdminReset,
        None,
        Uuid::parse_str(&admin.user_id).ok(),
    )
    .await?;
    tx.commit().await?;

    audit(
        &state.pool,
        &admin.user_id,
        "user.rotate_temp_password",
        Some(target),
        json!({"username": username}),
    )
    .await;
    Ok(Json(json!({"message": "temp password rotated"})).into_response())
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ResetGrantRequest {
    /// The admin's own grant from a reauth with `for: "adminReset"`.
    grant: String,
}

/// `POST /api/admin/users/{id}/reset-grant` — the admin's fresh password
/// proof (a reauth grant for `adminReset`), exchanged for one bound to this
/// account: what its temporary password's registration and the reset itself
/// take. Single use, five minutes, this admin session only.
#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/reset-grant",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Target user id")),
    request_body = ResetGrantRequest,
    responses(
        (status = 200, description = "A grant for this account", body = crate::handlers::opaque::GrantResponse),
        (status = 403, description = "grantInvalid")
    )
)]
pub async fn reset_grant(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(req): Json<ResetGrantRequest>,
) -> AppResult<Response> {
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let admin_id = Uuid::parse_str(&admin.user_id).map_err(|_| AppError::forbidden("forbidden"))?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(target)
        .fetch_one(&state.pool)
        .await?;
    if !exists {
        return Err(AppError::not_found("not found"));
    }
    let mut tx = state.pool.begin().await?;
    match crate::grants::take(&mut *tx, &req.grant, &[crate::grants::Purpose::AdminReset]).await? {
        // The admin's own, untargeted, from this session.
        Some((_, grant))
            if grant.user_id == admin_id
                && grant.target_user_id.is_none()
                && grant.session_id == Some(admin.session_id) => {}
        _ => return Err(crate::grants::invalid()),
    }
    let grant = crate::grants::issue(
        &mut *tx,
        crate::grants::Purpose::AdminReset,
        admin_id,
        Some(admin.session_id),
        Some(target),
        crate::grants::GRANT_MINUTES,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(crate::handlers::opaque::GrantResponse::new(grant)).into_response())
}

// No Debug: it carries a one-time grant (or tokens).
#[derive(Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct WipeUserRequest {
    /// An admin-reset grant for this account (`reset-grant`).
    grant: String,
    /// The temporary password it starts again with, registered by the
    /// administrator's client.
    #[serde(flatten)]
    setup: TempRegistration,
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
    let (key_binding, opaque_record, opaque_server_key_id) = req.setup.checked(&state)?;
    let target = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    // The admin's fresh proof, for this account, used before anything is
    // destroyed.
    let mut tx = state.pool.begin().await?;
    take_reset_grant(&mut tx, &req.grant, &admin, target).await?;
    tx.commit().await?;

    let row: Option<Option<String>> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(target)
            .fetch_optional(&state.pool)
            .await?;
    let Some(username) = row else {
        return Err(AppError::not_found("not found"));
    };
    if is_break_glass(&state, target).await? {
        return Err(AppError::forbidden("break-glass admin is protected"));
    }

    // 0. Nobody signed in to it watches the purges below, nor acts on a grant
    //    meanwhile: its sign-ins and grants end first (and again, with the
    //    reset, for any sign-in made in between).
    let mut tx = state.pool.begin().await?;
    crate::grants::end_all(&mut tx, target).await?;
    crate::sessions::revoke_all_for_user_in(&mut tx, target, None).await?;
    tx.commit().await?;

    // The replacement recovery setup must never inherit ciphertext encrypted
    // under the lost account master key.
    super::chat_backup::purge_for_account(&state, target).await?;
    purge_chat_media(&state, target).await?;

    // 1. Purge every owned folder and file, trashed ones too.
    purge_owned_drive(&state, target).await?;

    // 2. Everything keyed to the lost key material: incoming federated shares
    //    (their wrapped keys are unreachable), local shares received. (Collab
    //    devices go with the keys, below.)
    sqlx::query("DELETE FROM federated_incoming_shares WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM collection_shares WHERE recipient_user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM file_shares WHERE recipient_user_id = $1 OR sharer_user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;

    // A destructive wipe terminates the old account incarnation. Retain its
    // append-only signed manifest history for peers' reset evidence, but remove
    // the mutable head and every server-held delivery/device capability so the
    // next setup begins at manifest sequence 1 with a new authority.
    sqlx::query("DELETE FROM chat_device_manifests WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM chat_delivery_capabilities WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM chat_profiles WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM devices WHERE user_id = $1")
        .bind(target)
        .execute(&state.pool)
        .await?;
    // The account identity (docs/plans/account-identity-key.md) and what
    // hangs on it: the next device re-registers under a new one.
    for table in ["chat_account_identities", "chat_link_tokens"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1"))
            .bind(target)
            .execute(&state.pool)
            .await?;
    }

    // 3. Erase the key bundle + TOTP and reset to first-login with the new temp password,
    //    and with them the old incarnation's collab devices, in one step. Revoked
    //    devices stay, as tombstones: their keys never register again. Their
    //    revocations are not told to other servers any more (those take only the
    //    current incarnation's), nor need be: a server elsewhere stops taking the
    //    old incarnation's devices once the share is issued to the new one. Every
    //    grant and sign-in it ends ends with it, and the owner sees it happened
    //    (the event outlives the incarnation).
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM user_devices WHERE user_id = $1 AND revoked_at_ms IS NULL")
        .bind(target)
        .execute(&mut *tx)
        .await?;
    clear_account_values(&mut tx, target).await?;
    sqlx::query(
        r#"UPDATE users SET
               master_key_envelope = '', recovery_key_envelope = '',
               drive_private_key_envelope = '',
               public_key = '', account_authority_public_key = '',
               account_authority_key_id = '', account_incarnation_id = '',
               drive_signing_public_key = '',
               recovery_key_verifier = '', drive_key_binding = NULL,
               key_binding = $1, opaque_record = $3, opaque_suite = $4,
               opaque_server_key_id = $5,
               totp_secret = NULL, totp_enabled = false,
               is_first_login = true, updated_at = NOW()
           WHERE id = $2"#,
    )
    .bind(&key_binding)
    .bind(target)
    .bind(&opaque_record)
    .bind(kutup_crypto::opaque::SUITE as i16)
    .bind(opaque_server_key_id)
    .execute(&mut *tx)
    .await
    .map_err(map_insert_conflict)?;
    crate::grants::end_all(&mut tx, target).await?;
    crate::sessions::revoke_all_for_user_in(&mut tx, target, None).await?;
    crate::security_events::record(
        &mut tx,
        target,
        crate::security_events::Kind::AccountReset,
        None,
        Uuid::parse_str(&admin.user_id).ok(),
    )
    .await?;
    tx.commit().await?;

    // 4. Recompute quota: uploads into OTHER people's folders survive (they're the
    //    folder-owner's data view) and still count against this user.
    sqlx::query(
        r#"UPDATE users SET storage_used_bytes = (
               SELECT COALESCE((SELECT SUM((CASE WHEN original_pruned THEN 0 ELSE encrypted_size_bytes END)) FROM files WHERE uploader_user_id = $1), 0)
                    + COALESCE((SELECT SUM(size_bytes) FROM file_assets WHERE uploader_user_id = $1), 0)
                    + COALESCE((SELECT SUM(size_bytes) FROM file_thumbnails WHERE uploader_user_id = $1), 0)
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
        json!({"username": username.unwrap_or_default()}),
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
    /// The acting admin's live username — `null` once that account is deleted.
    admin_username: Option<String>,
    target_user_id: Option<Uuid>,
    /// The target's live username — `null` once deleted; the payload keeps
    /// the at-action-time snapshot.
    target_username: Option<String>,
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
        "id,occurred_at,action,admin_user_id,admin_username,target_user_id,target_username,payload\n",
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
            entry.admin_username.unwrap_or_default(),
            entry
                .target_user_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            entry.target_username.unwrap_or_default(),
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
        Option<Uuid>,
        Option<String>,
        serde_json::Value,
        OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"SELECT l.id, l.action, l.admin_user_id, a.username,
                  l.target_user_id, t.username, l.payload, l.occurred_at
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
            |(id, action, admin_id, a_username, target_id, t_username, payload, at)| {
                ActivityEntry {
                    id,
                    action,
                    admin_user_id: admin_id,
                    admin_username: a_username,
                    target_user_id: target_id,
                    target_username: t_username,
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
            return AppError::conflict("already registered");
        }
    }
    AppError::internal("internal error")
}

/// The account head chain starts again with the new incarnation, and no
/// listed value sealed under the old keys stays to be listed in it
/// (docs/plans/rollback-protection.md, "Account reset"): contacts, the
/// group list, the Chat contact list, calendars, labels, filters and Pass secrets go; custom folders keep
/// their mail and lose their names, until their owner names them again;
/// custom-domain addresses close until rekeyed. The
/// identity pins were sealed under the old master key too: nothing can open
/// them now.
async fn clear_account_values(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    target: Uuid,
) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM account_heads WHERE user_id = $1",
        "DELETE FROM identity_pins WHERE user_id = $1",
        "DELETE FROM contacts WHERE user_id = $1",
        "DELETE FROM chat_group_list WHERE user_id = $1",
        "DELETE FROM chat_contact_list WHERE user_id = $1",
        // Calendars' passphrases were sealed to the old address keys: the
        // account's own calendars go, and its places in others'.
        "DELETE FROM calendars WHERE owner_id = $1",
        "DELETE FROM calendar_members WHERE user_id = $1",
        // Forwardings both ways end with their proxy factors: they were
        // made for the old incarnation's keys (docs/plans/mail-forwarding.md).
        "DELETE FROM mail_forwardings WHERE user_id = $1
            OR forwardee_address_id IN (SELECT id FROM mail_addresses WHERE user_id = $1)",
        "DELETE FROM mail_labels WHERE user_id = $1",
        "DELETE FROM mail_filters WHERE user_id = $1",
        "DELETE FROM pass_vault_secrets WHERE user_id = $1",
        "UPDATE mail_folders SET name_sealed = NULL WHERE user_id = $1",
        // Old names held by the old incarnation stop receiving now: no one
        // holds the keys their mail would be sealed to. They are freed on
        // their own dates; the current name waits for the new incarnation,
        // which complete-setup records (docs/plans/username-renames.md).
        "UPDATE mail_addresses SET state = 'closed', receive_until = now()
          WHERE user_id = $1 AND state = 'receiving'",
        "UPDATE account_names SET receive_until = now() WHERE user_id = $1 AND state = 'held'",
        // Addresses on the account's custom domains stay its own but close
        // until rekeyed (docs/plans/mail-custom-domains.md §8): their keys
        // were sealed under the old master key, so their key lists (signed by
        // the old authority) go, their keys stop being primary, and mail to
        // them is refused until the owner makes each again with a new key.
        "DELETE FROM mail_key_lists WHERE address_id IN
            (SELECT id FROM mail_addresses
              WHERE user_id = $1 AND domain_id IS NOT NULL AND state = 'active')",
        // Obsolete as well (Proton's FLAG_NOT_OBSOLETE cleared): nobody can
        // open mail encrypted to them now.
        "UPDATE mail_address_keys SET is_primary = false, flags = flags & ~2 WHERE address_id IN
            (SELECT id FROM mail_addresses
              WHERE user_id = $1 AND domain_id IS NOT NULL AND state = 'active')",
        "UPDATE mail_addresses SET state = 'closed'
          WHERE user_id = $1 AND domain_id IS NOT NULL AND state = 'active'",
        "UPDATE account_names SET incarnation_id = NULL WHERE user_id = $1 AND state = 'current'",
    ] {
        sqlx::query(statement)
            .bind(target)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
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

    /// A reset leaves none of the old incarnation's group list or Chat
    /// contact list behind, and touches no other account's.
    #[tokio::test]
    async fn live_an_account_reset_clears_the_group_and_contact_lists() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let (reset, kept) = (Uuid::new_v4(), Uuid::new_v4());
        for user_id in [reset, kept] {
            sqlx::query(
                "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                    drive_private_key_envelope, public_key, account_authority_public_key,
                    account_authority_key_id, account_incarnation_id, drive_signing_public_key)
                 VALUES ($1, $2, '', '', '', '', '', '', '', '')",
            )
            .bind(user_id)
            .bind(format!("reset{}", &user_id.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO chat_group_list (user_id, id, revision, envelope) VALUES ($1, $2, 1, $3)",
            )
            .bind(user_id)
            .bind("A".repeat(43))
            .bind(vec![0u8; kutup_crypto::chat_group_list::SEALED_LEN])
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO chat_contact_list (user_id, id, revision, envelope) VALUES ($1, $2, 1, $3)",
            )
            .bind(user_id)
            .bind("A".repeat(43))
            .bind(vec![0u8; kutup_crypto::chat_contact_list::SEALED_LEN])
            .execute(&pool)
            .await
            .unwrap();
        }

        let mut tx = pool.begin().await.unwrap();
        clear_account_values(&mut tx, reset).await.unwrap();
        tx.commit().await.unwrap();

        for table in ["chat_group_list", "chat_contact_list"] {
            let query = format!("SELECT COUNT(*) FROM {table} WHERE user_id = $1");
            for (user_id, expected) in [(reset, 0), (kept, 1)] {
                let count: i64 = sqlx::query_scalar(&query)
                    .bind(user_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                assert_eq!(count, expected, "{table}");
            }
        }
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(vec![reset, kept])
            .execute(&pool)
            .await
            .unwrap();
    }
}
