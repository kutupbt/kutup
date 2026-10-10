//! Mail groups (docs/plans/mail-groups.md): what senders, members, owners,
//! managers and administrators see and change. Administrators create groups
//! and set their storage; owners and managers run their members and who may
//! post; anyone allowed to post fetches the members' keys to write to it end
//! to end.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::admin::audit;
use super::mail_keys::{lookup_address, MailKeyLookup};
use super::trusted_uuid;
use crate::error::{AppError, AppResult};
use crate::mail::group_keys::{self, NewGroupKey, ShareInput};
use crate::mail::groups::{self, Sender};
use crate::middleware::{AdminUser, AuthUser};
use crate::AppState;

/// Most members a group may have.
const MAX_MEMBERS: usize = 1000;
const POST_POLICIES: [&str; 4] = ["anyone", "local", "members", "managers"];
const ROLES: [&str; 3] = ["owner", "manager", "member"];

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct MailGroup {
    pub id: Uuid,
    pub address: String,
    pub display_name: String,
    pub description: String,
    /// `list` (each member their own copy) or `shared` (one mailbox).
    pub kind: String,
    /// `anyone`, `local` (Kutup users), `members` or `managers`.
    pub post_policy: String,
    /// The role address this system group answers for, if it is one.
    pub system_role: Option<String>,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
    pub member_count: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The caller's role in it, if a member.
    pub my_role: Option<String>,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct MailGroupMember {
    pub user_id: Uuid,
    pub username: String,
    /// The member's Kutup address.
    pub address: String,
    pub role: String,
    pub can_send_as: bool,
    /// An inactive account receives nothing.
    pub active: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailGroupDetail {
    pub group: MailGroup,
    pub members: Vec<MailGroupMember>,
    /// A system group without active members: its mail goes to every
    /// administrator.
    pub goes_to_administrators: bool,
}

const GROUP_COLUMNS: &str = "g.id, g.address, g.display_name, g.description, g.kind, g.post_policy,
    g.system_role, g.storage_quota_bytes, g.storage_used_bytes,
    (SELECT COUNT(*) FROM mail_group_members c WHERE c.group_id = g.id) AS member_count,
    g.created_at,
    (SELECT role FROM mail_group_members r WHERE r.group_id = g.id AND r.user_id = $1) AS my_role";

async fn group_row(state: &AppState, caller: Uuid, id: Uuid) -> AppResult<MailGroup> {
    sqlx::query_as(&format!(
        "SELECT {GROUP_COLUMNS} FROM mail_groups g WHERE g.id = $2"
    ))
    .bind(caller)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("not found"))
}

async fn members(state: &AppState, id: Uuid) -> AppResult<Vec<MailGroupMember>> {
    Ok(sqlx::query_as(
        "SELECT u.id AS user_id, COALESCE(u.username, '') AS username,
                COALESCE(u.username, '') || '@' || $2 AS address,
                m.role, m.can_send_as, u.is_active AS active
           FROM mail_group_members m JOIN users u ON u.id = m.user_id
          WHERE m.group_id = $1
          ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, u.username",
    )
    .bind(id)
    .bind(&state.config.chat_server_name)
    .fetch_all(&state.pool)
    .await?)
}

async fn detail(state: &AppState, caller: Uuid, id: Uuid) -> AppResult<MailGroupDetail> {
    let group = group_row(state, caller, id).await?;
    let members = members(state, id).await?;
    let goes_to_administrators =
        group.system_role.is_some() && !members.iter().any(|member| member.active);
    Ok(MailGroupDetail {
        group,
        members,
        goes_to_administrators,
    })
}

async fn is_admin(state: &AppState, user: Uuid) -> AppResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1 AND is_active")
            .bind(user)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or(false),
    )
}

/// The caller's standing on a group: administrator, owner, manager, member
/// or nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Standing {
    None,
    Member,
    Manager,
    Owner,
    Administrator,
}

async fn standing(state: &AppState, user: Uuid, group: &MailGroup) -> AppResult<Standing> {
    if is_admin(state, user).await? {
        return Ok(Standing::Administrator);
    }
    Ok(match group.my_role.as_deref() {
        Some("owner") => Standing::Owner,
        Some("manager") => Standing::Manager,
        Some(_) => Standing::Member,
        None => Standing::None,
    })
}

// --- Writing to a group -----------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RecipientsQuery {
    email: String,
}

/// A group's receivers with their keys, for a browser writing to it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailGroupRecipients {
    pub address: String,
    pub group_id: Uuid,
    pub kind: String,
    /// Each receiver as `GET /api/mail/keys` answers for them; their key
    /// lists are checked like any address's.
    pub members: Vec<MailKeyLookup>,
}

/// `GET /api/mail/groups/recipients?email=` — who receives a group's mail,
/// with their keys, when the caller may post to it.
#[utoipa::path(
    get,
    path = "/api/mail/groups/recipients",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("email" = String, Query, description = "The group's address")),
    responses(
        (status = 200, description = "The receivers and their keys", body = MailGroupRecipients),
        (status = 403, description = "The group does not take mail from you (code notAllowed)"),
        (status = 404, description = "No such group, or nobody to receive its mail"),
    )
)]
pub async fn recipients(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<RecipientsQuery>,
) -> AppResult<Json<MailGroupRecipients>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let address =
        kutup_crypto::mail_key::canonical_address(query.email.trim().to_lowercase().as_str())
            .map_err(|_| AppError::not_found("not found"))?;
    let group = groups::find(&state.pool, &address)
        .await?
        .ok_or_else(|| AppError::not_found("not found"))?;
    if !groups::may_post(&state.pool, &group, Sender::Local(user_id)).await? {
        return Err(
            AppError::forbidden("this group does not take mail from you")
                .with_details(json!({ "code": "notAllowed" })),
        );
    }
    let mut members = Vec::new();
    for receiver in groups::receivers(&state.pool, &group).await? {
        if let Some(lookup) = lookup_address(&state, &receiver.address).await? {
            members.push(lookup);
        }
    }
    if members.is_empty() {
        return Err(AppError::not_found("this group has nobody to receive mail"));
    }
    Ok(Json(MailGroupRecipients {
        address,
        group_id: group.id,
        kind: group.kind,
        members,
    }))
}

// --- Members, owners and managers -----------------------------------------

/// `GET /api/mail/groups` — the groups the caller belongs to.
#[utoipa::path(
    get,
    path = "/api/mail/groups",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Your groups", body = Vec<MailGroup>))
)]
pub async fn my_groups(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<MailGroup>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(
        sqlx::query_as(&format!(
            "SELECT {GROUP_COLUMNS} FROM mail_groups g
              WHERE EXISTS (SELECT 1 FROM mail_group_members m WHERE m.group_id = g.id AND m.user_id = $1)
              ORDER BY g.address"
        ))
        .bind(user_id)
        .fetch_all(&state.pool)
        .await?,
    ))
}

/// `GET /api/mail/groups/{id}` — a group and its members, for its members
/// and administrators.
#[utoipa::path(
    get,
    path = "/api/mail/groups/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    responses(
        (status = 200, description = "The group", body = MailGroupDetail),
        (status = 404, description = "No such group of yours"),
    )
)]
pub async fn group_detail(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<MailGroupDetail>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, user_id, id).await?;
    if standing(&state, user_id, &group).await? == Standing::None {
        return Err(AppError::not_found("not found"));
    }
    Ok(Json(detail(&state, user_id, id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailGroup {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub post_policy: Option<String>,
}

fn check_text(value: &Option<String>, max: usize, field: &str) -> AppResult<()> {
    match value {
        Some(text) if text.chars().count() > max || text.chars().any(char::is_control) => Err(
            AppError::bad_request(format!("{field} is too long or not plain text")),
        ),
        _ => Ok(()),
    }
}

async fn apply_update(
    state: &AppState,
    group: &MailGroup,
    change: &UpdateMailGroup,
) -> AppResult<()> {
    check_text(&change.display_name, 200, "displayName")?;
    check_text(&change.description, 1000, "description")?;
    if let Some(policy) = &change.post_policy {
        if !POST_POLICIES.contains(&policy.as_str()) {
            return Err(AppError::bad_request(
                "postPolicy must be anyone, local, members or managers",
            ));
        }
        if group.system_role.is_some() && policy != "anyone" {
            return Err(AppError::bad_request(
                "role addresses take mail from anyone",
            ));
        }
    }
    sqlx::query(
        "UPDATE mail_groups SET display_name = COALESCE($2, display_name),
                description = COALESCE($3, description), post_policy = COALESCE($4, post_policy)
          WHERE id = $1",
    )
    .bind(group.id)
    .bind(change.display_name.as_deref().map(str::trim))
    .bind(change.description.as_deref().map(str::trim))
    .bind(&change.post_policy)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// `PATCH /api/mail/groups/{id}` — the name, description and who may post,
/// for owners, managers and administrators.
#[utoipa::path(
    patch,
    path = "/api/mail/groups/{id}",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    request_body = UpdateMailGroup,
    responses(
        (status = 200, description = "The group", body = MailGroupDetail),
        (status = 403, description = "Not an owner or manager"),
    )
)]
pub async fn update_group(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(change): Json<UpdateMailGroup>,
) -> AppResult<Json<MailGroupDetail>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, user_id, id).await?;
    let standing = standing(&state, user_id, &group).await?;
    if standing == Standing::None {
        return Err(AppError::not_found("not found"));
    }
    if standing < Standing::Manager {
        return Err(AppError::forbidden(
            "only owners and managers change a group",
        ));
    }
    apply_update(&state, &group, &change).await?;
    audit(&state.pool, &user.user_id, "mail_group.update", None, json!({ "group": group.address, "change": {
        "displayName": change.display_name, "description": change.description, "postPolicy": change.post_policy,
    } })).await;
    Ok(Json(detail(&state, user_id, id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailGroupMemberInput {
    pub user_id: String,
    pub role: String,
    #[serde(default)]
    pub can_send_as: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetMailGroupMembers {
    pub members: Vec<MailGroupMemberInput>,
    /// Shared mailboxes: shares of the existing group keys for members
    /// joining (each needs one of every key, to read the whole mailbox).
    #[serde(default)]
    pub key_shares: Vec<GroupKeyShareInput>,
    /// Shared mailboxes: a new primary key with a share for every member
    /// after the change; required when anyone leaves, so they cannot read
    /// new mail.
    #[serde(default)]
    pub new_key: Option<NewGroupKey>,
}

/// A share of one existing group key for one member.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupKeyShareInput {
    /// The group key's fingerprint.
    pub group_fingerprint: String,
    #[serde(flatten)]
    pub share: ShareInput,
}

/// What a membership change does to a shared mailbox's keys, checked.
struct KeyChanges {
    /// Group key fingerprint → its new shares.
    shares: Vec<(String, Vec<group_keys::CheckedShare>)>,
    new_key: Option<(NewGroupKey, Vec<group_keys::CheckedShare>)>,
    removed: Vec<Uuid>,
}

async fn check_key_changes(
    state: &AppState,
    group: &MailGroup,
    current: &[MailGroupMember],
    after: &[Uuid],
    input: &SetMailGroupMembers,
) -> AppResult<KeyChanges> {
    let keys: Vec<String> =
        sqlx::query_scalar("SELECT fingerprint FROM mail_group_keys WHERE group_id = $1")
            .bind(group.id)
            .fetch_all(&state.pool)
            .await?;
    let added: Vec<Uuid> = after
        .iter()
        .filter(|id| !current.iter().any(|m| m.user_id == **id))
        .copied()
        .collect();
    let removed: Vec<Uuid> = current
        .iter()
        .filter(|m| !after.contains(&m.user_id))
        .map(|m| m.user_id)
        .collect();
    if !removed.is_empty() && input.new_key.is_none() {
        return Err(
            AppError::bad_request("removing a member needs a new group key")
                .with_details(json!({ "code": "newKeyNeeded" })),
        );
    }
    // Every joining member gets every existing key.
    let mut shares = Vec::new();
    for key in &keys {
        let for_key: Vec<ShareInput> = input
            .key_shares
            .iter()
            .filter(|s| s.group_fingerprint.eq_ignore_ascii_case(key))
            .map(|s| s.share.clone())
            .collect();
        let mut covered: Vec<Uuid> = for_key
            .iter()
            .filter_map(|s| Uuid::parse_str(&s.user_id).ok())
            .collect();
        covered.sort();
        let mut needed = added.clone();
        needed.sort();
        if covered != needed {
            return Err(AppError::bad_request(
                "each joining member needs a share of every group key",
            )
            .with_details(json!({ "code": "sharesNeeded" })));
        }
        if !for_key.is_empty() {
            shares.push((
                key.clone(),
                group_keys::check_shares(&state.pool, &for_key).await?,
            ));
        }
    }
    let new_key = match &input.new_key {
        Some(key) => {
            let mut covered: Vec<Uuid> = key
                .shares
                .iter()
                .filter_map(|s| Uuid::parse_str(&s.user_id).ok())
                .collect();
            covered.sort();
            covered.dedup();
            let mut needed = after.to_vec();
            needed.sort();
            if covered != needed || key.shares.len() != needed.len() {
                return Err(
                    AppError::bad_request("the new key needs a share for every member")
                        .with_details(json!({ "code": "sharesNeeded" })),
                );
            }
            Some((
                key.clone(),
                group_keys::check_shares(&state.pool, &key.shares).await?,
            ))
        }
        None => None,
    };
    Ok(KeyChanges {
        shares,
        new_key,
        removed,
    })
}

/// `PUT /api/mail/groups/{id}/members` — the whole member list. Owners and
/// administrators change anyone; managers change members and managers, but
/// neither add, remove nor change owners. A group other than a role address
/// keeps at least one owner.
#[utoipa::path(
    put,
    path = "/api/mail/groups/{id}/members",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    request_body = SetMailGroupMembers,
    responses(
        (status = 200, description = "The group", body = MailGroupDetail),
        (status = 400, description = "An unknown account, a bad role, or no owner left"),
        (status = 403, description = "Not allowed to make this change"),
    )
)]
pub async fn set_members(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<SetMailGroupMembers>,
) -> AppResult<Json<MailGroupDetail>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, user_id, id).await?;
    let standing = standing(&state, user_id, &group).await?;
    if standing == Standing::None {
        return Err(AppError::not_found("not found"));
    }
    if standing < Standing::Manager {
        return Err(AppError::forbidden(
            "only owners and managers change members",
        ));
    }
    if input.members.len() > MAX_MEMBERS {
        return Err(AppError::bad_request(format!(
            "a group has at most {MAX_MEMBERS} members"
        )));
    }
    let mut wanted: Vec<(Uuid, String, bool)> = Vec::with_capacity(input.members.len());
    for member in &input.members {
        let member_id = Uuid::parse_str(&member.user_id)
            .map_err(|_| AppError::bad_request("userId must be an account id"))?;
        if !ROLES.contains(&member.role.as_str()) {
            return Err(AppError::bad_request(
                "role must be owner, manager or member",
            ));
        }
        if wanted.iter().any(|(id, _, _)| *id == member_id) {
            return Err(AppError::bad_request("an account is listed twice"));
        }
        wanted.push((member_id, member.role.clone(), member.can_send_as));
    }
    let ids: Vec<Uuid> = wanted.iter().map(|(id, _, _)| *id).collect();
    let known: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE id = ANY($1) AND username IS NOT NULL",
    )
    .bind(&ids)
    .fetch_one(&state.pool)
    .await?;
    if known != ids.len() as i64 {
        return Err(AppError::bad_request(
            "an account does not exist or has no address",
        ));
    }
    if group.system_role.is_none() && !wanted.iter().any(|(_, role, _)| role == "owner") {
        return Err(AppError::bad_request("a group needs at least one owner"));
    }
    let current = members(&state, id).await?;
    if standing == Standing::Manager {
        // Owners stay exactly as they are, and nobody becomes one.
        let owners_before: Vec<Uuid> = current
            .iter()
            .filter(|m| m.role == "owner")
            .map(|m| m.user_id)
            .collect();
        let owners_after: Vec<Uuid> = wanted
            .iter()
            .filter(|(_, role, _)| role == "owner")
            .map(|(id, _, _)| *id)
            .collect();
        let mut before = owners_before.clone();
        let mut after = owners_after.clone();
        before.sort();
        after.sort();
        if before != after {
            return Err(AppError::forbidden(
                "only owners add, remove or change owners",
            ));
        }
    }

    let key_changes = if group.kind == "shared" {
        Some(check_key_changes(&state, &group, &current, &ids, &input).await?)
    } else {
        None
    };
    let authority = match key_changes.as_ref().and_then(|c| c.new_key.as_ref()) {
        Some(_) => Some(
            group_keys::authority(&state.pool)
                .await
                .map_err(|_| AppError::internal("mail-group authority"))?,
        ),
        None => None,
    };

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM mail_groups WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mail_group_members WHERE group_id = $1 AND NOT (user_id = ANY($2))")
        .bind(id)
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    for (member, role, can_send_as) in &wanted {
        sqlx::query(
            "INSERT INTO mail_group_members (group_id, user_id, role, can_send_as, added_by)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (group_id, user_id) DO UPDATE SET role = EXCLUDED.role, can_send_as = EXCLUDED.can_send_as",
        )
        .bind(id)
        .bind(member)
        .bind(role)
        .bind(can_send_as)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    if let Some(changes) = &key_changes {
        // Who left keeps nothing of the group keys; who joined gets them all.
        sqlx::query(
            "DELETE FROM mail_group_key_shares
              WHERE user_id = ANY($1)
                AND group_key_id IN (SELECT id FROM mail_group_keys WHERE group_id = $2)",
        )
        .bind(&changes.removed)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        for (fingerprint, shares) in &changes.shares {
            group_keys::add_shares(&mut tx, id, fingerprint, shares).await?;
        }
        if let (Some((key, shares)), Some(authority)) = (&changes.new_key, &authority) {
            group_keys::publish(&mut tx, authority, id, &group.address, key, shares).await?;
        }
    }
    tx.commit().await?;
    let removed: Vec<&str> = current
        .iter()
        .filter(|m| !ids.contains(&m.user_id))
        .map(|m| m.username.as_str())
        .collect();
    let added: Vec<Uuid> = ids
        .iter()
        .filter(|id| !current.iter().any(|m| m.user_id == **id))
        .copied()
        .collect();
    audit(
        &state.pool,
        &user.user_id,
        "mail_group.members",
        None,
        json!({
            "group": group.address, "added": added, "removed": removed, "count": ids.len(),
        }),
    )
    .await;
    Ok(Json(detail(&state, user_id, id).await?))
}

// --- Administrators ---------------------------------------------------------

/// `GET /api/admin/mail/groups` — every group, role addresses first.
#[utoipa::path(
    get,
    path = "/api/admin/mail/groups",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Every group", body = Vec<MailGroup>))
)]
pub async fn admin_list(
    State(state): State<AppState>,
    admin: AdminUser,
) -> AppResult<Json<Vec<MailGroup>>> {
    let admin_id = trusted_uuid(&admin.user_id)?;
    Ok(Json(
        sqlx::query_as(&format!(
            "SELECT {GROUP_COLUMNS} FROM mail_groups g
              ORDER BY (g.system_role IS NULL), g.address"
        ))
        .bind(admin_id)
        .fetch_all(&state.pool)
        .await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMailGroup {
    /// The part before the @: the username rules apply.
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    /// `list` (each member their own copy) or `shared` (one mailbox).
    pub kind: String,
    pub post_policy: String,
    pub storage_quota_bytes: i64,
    /// The first owners (at least one).
    pub owners: Vec<String>,
    /// A shared mailbox's first key, made in the creating browser, with a
    /// share for each owner.
    #[serde(default)]
    pub group_key: Option<NewGroupKey>,
}

/// Whether `name` may become a group's address: the username rules, no
/// reserved name, no account's username and no address in use.
pub(crate) async fn group_name_free(state: &AppState, name: &str) -> AppResult<String> {
    let valid = (3..=32).contains(&name.chars().count())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !valid {
        return Err(AppError::bad_request(
            "a group name has 3-32 lowercase letters, digits, _ and -",
        ));
    }
    if crate::mail::RESERVED_LOCAL_PARTS.contains(&name) {
        return Err(AppError::bad_request(
            "this name is reserved for the server",
        ));
    }
    let address = kutup_crypto::mail_key::canonical_address(&format!(
        "{name}@{}",
        state.config.chat_server_name
    ))
    .map_err(|_| AppError::bad_request("not a valid address"))?;
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)
             OR EXISTS (SELECT 1 FROM mail_addresses WHERE address = $2)
             OR EXISTS (SELECT 1 FROM mail_groups WHERE address = $2)",
    )
    .bind(name)
    .bind(&address)
    .fetch_one(&state.pool)
    .await?;
    if taken {
        return Err(AppError::conflict("this name is already taken")
            .with_details(json!({ "code": "nameTaken" })));
    }
    Ok(address)
}

/// `POST /api/admin/mail/groups` — creates a group.
#[utoipa::path(
    post,
    path = "/api/admin/mail/groups",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = CreateMailGroup,
    responses(
        (status = 200, description = "The group", body = MailGroupDetail),
        (status = 400, description = "A bad name, kind, policy, quota or owner"),
        (status = 409, description = "The name is taken (code nameTaken)"),
    )
)]
pub async fn admin_create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<CreateMailGroup>,
) -> AppResult<Json<MailGroupDetail>> {
    let admin_id = trusted_uuid(&admin.user_id)?;
    let name = input.name.trim().to_ascii_lowercase();
    let address = group_name_free(&state, &name).await?;
    if input.kind != "list" && input.kind != "shared" {
        return Err(AppError::bad_request("kind must be list or shared"));
    }
    if (input.kind == "shared") != input.group_key.is_some() {
        return Err(AppError::bad_request(
            "a shared mailbox, and only one, comes with its key",
        ));
    }
    if !POST_POLICIES.contains(&input.post_policy.as_str()) {
        return Err(AppError::bad_request(
            "postPolicy must be anyone, local, members or managers",
        ));
    }
    if input.storage_quota_bytes <= 0 {
        return Err(AppError::bad_request("storageQuotaBytes must be positive"));
    }
    check_text(&Some(input.display_name.clone()), 200, "displayName")?;
    check_text(&Some(input.description.clone()), 1000, "description")?;
    let owners = input
        .owners
        .iter()
        .map(|id| {
            Uuid::parse_str(id).map_err(|_| AppError::bad_request("owners must be account ids"))
        })
        .collect::<AppResult<Vec<Uuid>>>()?;
    if owners.is_empty() || owners.len() > MAX_MEMBERS {
        return Err(AppError::bad_request("a group needs at least one owner"));
    }
    let known: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT id) FROM users WHERE id = ANY($1) AND username IS NOT NULL",
    )
    .bind(&owners)
    .fetch_one(&state.pool)
    .await?;
    if known != owners.len() as i64 {
        return Err(AppError::bad_request(
            "an owner does not exist or has no address",
        ));
    }
    let shared_key = match &input.group_key {
        Some(key) => {
            let mut covered: Vec<Uuid> = key
                .shares
                .iter()
                .filter_map(|s| Uuid::parse_str(&s.user_id).ok())
                .collect();
            covered.sort();
            covered.dedup();
            let mut needed = owners.clone();
            needed.sort();
            needed.dedup();
            if covered != needed || key.shares.len() != needed.len() {
                return Err(
                    AppError::bad_request("the key needs a share for each owner")
                        .with_details(json!({ "code": "sharesNeeded" })),
                );
            }
            let shares = group_keys::check_shares(&state.pool, &key.shares).await?;
            let authority = group_keys::authority(&state.pool)
                .await
                .map_err(|_| AppError::internal("mail-group authority"))?;
            Some((shares, authority))
        }
        None => None,
    };

    let mut tx = state.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO mail_groups (address, display_name, description, kind, post_policy, storage_quota_bytes, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&address)
    .bind(input.display_name.trim())
    .bind(input.description.trim())
    .bind(&input.kind)
    .bind(&input.post_policy)
    .bind(input.storage_quota_bytes)
    .bind(admin_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| match error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("this name is already taken").with_details(json!({ "code": "nameTaken" }))
        }
        other => other.into(),
    })?;
    sqlx::query("INSERT INTO mail_addresses (group_id, address) VALUES ($1, $2)")
        .bind(id)
        .bind(&address)
        .execute(&mut *tx)
        .await
        .map_err(|error| match error {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AppError::conflict("this name is already taken")
                    .with_details(json!({ "code": "nameTaken" }))
            }
            other => other.into(),
        })?;
    for owner in &owners {
        sqlx::query(
            "INSERT INTO mail_group_members (group_id, user_id, role, can_send_as, added_by)
             VALUES ($1, $2, 'owner', true, $3)",
        )
        .bind(id)
        .bind(owner)
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    }
    if let (Some(key), Some((shares, authority))) = (&input.group_key, &shared_key) {
        group_keys::publish(&mut tx, authority, id, &address, key, shares).await?;
    }
    tx.commit().await?;
    audit(
        &state.pool,
        &admin.user_id,
        "mail_group.create",
        None,
        json!({
            "group": address, "kind": input.kind, "quota": input.storage_quota_bytes,
        }),
    )
    .await;
    Ok(Json(detail(&state, admin_id, id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminUpdateMailGroup {
    pub storage_quota_bytes: Option<i64>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub post_policy: Option<String>,
}

/// `PATCH /api/admin/mail/groups/{id}` — quota, name, description and who
/// may post.
#[utoipa::path(
    patch,
    path = "/api/admin/mail/groups/{id}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    request_body = AdminUpdateMailGroup,
    responses((status = 200, description = "The group", body = MailGroupDetail))
)]
pub async fn admin_update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
    Json(change): Json<AdminUpdateMailGroup>,
) -> AppResult<Json<MailGroupDetail>> {
    let admin_id = trusted_uuid(&admin.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, admin_id, id).await?;
    if let Some(quota) = change.storage_quota_bytes {
        if quota <= 0 {
            return Err(AppError::bad_request("storageQuotaBytes must be positive"));
        }
        sqlx::query("UPDATE mail_groups SET storage_quota_bytes = $2 WHERE id = $1")
            .bind(id)
            .bind(quota)
            .execute(&state.pool)
            .await?;
    }
    apply_update(
        &state,
        &group,
        &UpdateMailGroup {
            display_name: change.display_name.clone(),
            description: change.description.clone(),
            post_policy: change.post_policy.clone(),
        },
    )
    .await?;
    audit(&state.pool, &admin.user_id, "mail_group.update", None, json!({
        "group": group.address, "quota": change.storage_quota_bytes, "postPolicy": change.post_policy,
    }))
    .await;
    Ok(Json(detail(&state, admin_id, id).await?))
}

/// `DELETE /api/admin/mail/groups/{id}` — deletes a group (not a role
/// address). Members keep the copies they already received; its address
/// becomes free.
#[utoipa::path(
    delete,
    path = "/api/admin/mail/groups/{id}",
    tag = "admin",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "A role address cannot be deleted"),
    )
)]
pub async fn admin_delete(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    let admin_id = trusted_uuid(&admin.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, admin_id, id).await?;
    if group.system_role.is_some() {
        return Err(AppError::bad_request("a role address cannot be deleted"));
    }
    // A list's members keep their copies: their rows keep the shared objects
    // alive, and the orphan sweep removes each once its last row is gone. A
    // shared mailbox's own messages go with it.
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM mail_messages WHERE group_id = $1 AND user_id IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mail_groups WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if group.kind == "shared" {
        if let Err(error) = state
            .storage
            .delete_prefix(&format!("mail/groups/{id}/"))
            .await
        {
            tracing::warn!(error = %error, "mail: a deleted mailbox's objects left for the sweep");
        }
    }
    audit(
        &state.pool,
        &admin.user_id,
        "mail_group.delete",
        None,
        json!({ "group": group.address }),
    )
    .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `GET /.well-known/security.txt` (RFC 9116): where to report
/// vulnerabilities, the `security@` role group. Made per request, so its
/// `Expires` stays a year ahead.
pub async fn security_txt(State(state): State<AppState>) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let expires = (OffsetDateTime::now_utc() + time::Duration::days(365))
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        format!(
            "Contact: mailto:security@{}\nExpires: {expires}\nPreferred-Languages: en, tr\n",
            state.config.chat_server_name
        ),
    )
        .into_response()
}

/// A group key row with the caller's share: fingerprint, SHA-256 fingerprint,
/// public key, primary, flags, share, member fingerprint.
type KeyRow = (
    String,
    String,
    Vec<u8>,
    bool,
    i32,
    Option<Vec<u8>>,
    Option<String>,
);

/// One of a shared mailbox's keys, with the caller's share of it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailGroupKey {
    pub fingerprint: String,
    pub sha256_fingerprint: String,
    /// Binary OpenPGP public key, base64.
    pub public_key: String,
    pub primary: bool,
    pub flags: i32,
    /// The caller's share (the key's secret encrypted to their address key),
    /// base64; absent when they have none of this key.
    pub share: Option<String>,
    /// The address key the share is encrypted to.
    pub member_fingerprint: Option<String>,
}

/// `GET /api/mail/groups/{id}/keys` — a shared mailbox's keys, primary
/// first, with the caller's shares, for its members.
#[utoipa::path(
    get,
    path = "/api/mail/groups/{id}/keys",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    responses(
        (status = 200, description = "The keys", body = Vec<MailGroupKey>),
        (status = 404, description = "No such shared mailbox of yours"),
    )
)]
pub async fn group_keys(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<MailGroupKey>>> {
    use base64::Engine as _;
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, user_id, id).await?;
    if group.my_role.is_none() || group.kind != "shared" {
        return Err(AppError::not_found("not found"));
    }
    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT k.fingerprint, k.sha256_fingerprint, k.public_key, k.is_primary, k.flags,
                    s.share, s.member_fingerprint
               FROM mail_group_keys k
               LEFT JOIN mail_group_key_shares s ON s.group_key_id = k.id AND s.user_id = $2
              WHERE k.group_id = $1
              ORDER BY k.is_primary DESC, k.created_at DESC",
    )
    .bind(id)
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Json(
        rows.into_iter()
            .map(
                |(fingerprint, sha256, public_key, primary, flags, share, member)| MailGroupKey {
                    fingerprint,
                    sha256_fingerprint: sha256,
                    public_key: b64.encode(public_key),
                    primary,
                    flags,
                    share: share.map(|share| b64.encode(share)),
                    member_fingerprint: member,
                },
            )
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateGroupKey {
    pub key: NewGroupKey,
}

/// `POST /api/mail/groups/{id}/keys` — a new primary key for a shared
/// mailbox, with a share for every member (owners and managers): older keys
/// stay to open older mail.
#[utoipa::path(
    post,
    path = "/api/mail/groups/{id}/keys",
    tag = "mail",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "Group id")),
    request_body = RotateGroupKey,
    responses(
        (status = 200, description = "The new key's fingerprint", body = String),
        (status = 400, description = "A share is missing or the key is not for this address"),
        (status = 403, description = "Not an owner or manager"),
    )
)]
pub async fn rotate_group_key(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(input): Json<RotateGroupKey>,
) -> AppResult<Json<String>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let group = group_row(&state, user_id, id).await?;
    let standing = standing(&state, user_id, &group).await?;
    if standing == Standing::None || group.kind != "shared" {
        return Err(AppError::not_found("not found"));
    }
    if standing < Standing::Manager {
        return Err(AppError::forbidden(
            "only owners and managers change a mailbox's key",
        ));
    }
    let members: Vec<Uuid> = members(&state, id)
        .await?
        .iter()
        .map(|m| m.user_id)
        .collect();
    let mut covered: Vec<Uuid> = input
        .key
        .shares
        .iter()
        .filter_map(|s| Uuid::parse_str(&s.user_id).ok())
        .collect();
    covered.sort();
    covered.dedup();
    let mut needed = members.clone();
    needed.sort();
    if covered != needed || input.key.shares.len() != needed.len() {
        return Err(
            AppError::bad_request("the new key needs a share for every member")
                .with_details(json!({ "code": "sharesNeeded" })),
        );
    }
    let shares = group_keys::check_shares(&state.pool, &input.key.shares).await?;
    let authority = group_keys::authority(&state.pool)
        .await
        .map_err(|_| AppError::internal("mail-group authority"))?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM mail_groups WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let fingerprint =
        group_keys::publish(&mut tx, &authority, id, &group.address, &input.key, &shares).await?;
    tx.commit().await?;
    audit(
        &state.pool,
        &user.user_id,
        "mail_group.key",
        None,
        json!({ "group": group.address, "fingerprint": fingerprint }),
    )
    .await;
    Ok(Json(fingerprint))
}
