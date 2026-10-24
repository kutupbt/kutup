//! The home's gateway (docs/plans/pairwise-groups.md §3): opens a request
//! sealed to this server's gateway key, checks its home, clock, signature and
//! nonce, runs the group's acceptance checks (`kutup_chat_proto::group`, the
//! same functions every client runs) and seals the answer to that request.
//!
//! It learns the relay server a request came through, never the account
//! behind it. Nothing here logs a request, a group id or a pseudonym.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group::{
    check_change, check_genesis, AccessRequired, GroupActionV1, GroupChangeError, GroupChangeV1,
    GroupLimits, GroupStateV1,
};
use kutup_chat_proto::group_route::{
    pad_group_avatar, unpad_group_avatar, GroupHomePinV1, GroupJoinInfoV1, GroupLogEntryV1,
    GroupLogPageV1, GroupLogQueryV1, GroupNotaryV1, GroupOperationV1, GroupRequestAuthV1,
    GroupRequestStateV1, GroupRequestStatusV1, GroupRequestV1, GroupResponseStatusV1,
    GroupResponseV1, GroupStateAnswerV1, NONCE_MEMORY_SECS, PSEUDONYM_USED,
};
use kutup_crypto::oblivious::ResponseContext;
use kutup_crypto::primitives::{hash, Hasher, Suite};
use time::OffsetDateTime;

use super::keys;
use super::limits;
use crate::error::{AppError, AppResult};
use crate::federation::FederationStack;
use crate::AppState;

/// The most a log page carries, so it fits the 256 KiB padded size with its
/// envelope (base64 grows it by a third).
const LOG_PAGE_BYTES: usize = 180 * 1024;
const MAX_LOG_PAGE_CHANGES: i64 = 256;
const SEEN_PSEUDONYM_DOMAIN: &[u8] = b"kutup/chat-group/seen-pseudonym/v1\0";
/// A change or a read naming an avatar blob the home doesn't hold.
const AVATAR_MISSING: &str = "avatarMissing";

/// What became of a sealed request.
pub(crate) enum Opened {
    /// The sealed answer, for the relay to pass back.
    Answer(Vec<u8>),
    /// Not sealed to a key of this gateway: nothing can be sealed back.
    Unopenable,
}

/// One request through the gateway, from the relay server `relay`.
pub(crate) async fn handle(
    state: &AppState,
    federation: &FederationStack,
    relay: &str,
    sealed: &[u8],
) -> AppResult<Opened> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let identity = federation.local_identity();
    let mut opened = None;
    for key in keys::accepted_keys(identity.signing_key(), now)? {
        if let Ok(found) = key.open_request(sealed) {
            opened = Some(found);
            break;
        }
    }
    let Some((body, context)) = opened else {
        return Ok(Opened::Unopenable);
    };
    let answer = match GroupRequestV1::from_canonical_bytes(&body) {
        Ok(request) => answer(state, federation, relay, &request, now).await?,
        Err(_) => GroupResponseV1::refused("malformed", now),
    };
    Ok(Opened::Answer(seal(&context, &answer)?))
}

fn seal(context: &ResponseContext, answer: &GroupResponseV1) -> AppResult<Vec<u8>> {
    let bytes = answer.canonical_bytes().map_err(AppError::internal)?;
    context
        .seal_response(&bytes)
        .map_err(|error| AppError::internal(format!("seal group answer: {error}")))
}

fn status(status: GroupResponseStatusV1, now: i64) -> GroupResponseV1 {
    GroupResponseV1::new(status, now, b"")
}

fn ok(now: i64, body: Vec<u8>) -> GroupResponseV1 {
    GroupResponseV1::new(GroupResponseStatusV1::Ok, now, &body)
}

/// [`answer_checked`], under the relay's failure budget: a relay whose
/// requests keep failing (unknown groups, strangers, refused changes) is
/// throttled before any work, and only failures spend that budget.
async fn answer(
    state: &AppState,
    federation: &FederationStack,
    relay: &str,
    request: &GroupRequestV1,
    now: i64,
) -> AppResult<GroupResponseV1> {
    if !limits::may_fail(relay) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    let answer = answer_checked(state, federation, relay, request, now).await?;
    // A used pseudonym comes only after every proof passed: the client
    // retries at its next epoch, which mustn't throttle its whole server.
    let used = answer.code.as_deref() == Some(PSEUDONYM_USED);
    if !used
        && matches!(
            answer.status,
            GroupResponseStatusV1::NotFound | GroupResponseStatusV1::Refused
        )
    {
        limits::failed(relay);
    }
    Ok(answer)
}

async fn answer_checked(
    state: &AppState,
    federation: &FederationStack,
    relay: &str,
    request: &GroupRequestV1,
    now: i64,
) -> AppResult<GroupResponseV1> {
    // Another home's request is the same as an unknown group's.
    if request.home != federation.server_name() {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    if !request.is_timely(now) {
        return Ok(status(GroupResponseStatusV1::ClockSkew, now));
    }
    if !limits::relay(relay) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    let Ok(group_id) = request.group_id() else {
        return Ok(GroupResponseV1::refused("malformed", now));
    };
    let pseudonym = match &request.auth {
        GroupRequestAuthV1::Pseudonym { pseudonym, .. } => {
            // A bad signature, an unknown group and a stranger get one answer.
            if request.verify_pseudonym().is_err() {
                return Ok(status(GroupResponseStatusV1::NotFound, now));
            }
            pseudonym.clone()
        }
        // Only join info and the avatar take a link's password (the format
        // checks that).
        GroupRequestAuthV1::LinkPassword { .. } => {
            return link_request(state, request, &group_id, now).await;
        }
    };
    if !limits::pseudonym(&pseudonym) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    if !remember_nonce(state, request, now).await? {
        return Ok(status(GroupResponseStatusV1::Replayed, now));
    }
    let limits = group_limits(state);
    match request.operation {
        GroupOperationV1::Create => {
            create(
                state, federation, relay, request, &group_id, &pseudonym, &limits, now,
            )
            .await
        }
        GroupOperationV1::GetState => get_state(state, &group_id, &pseudonym, now).await,
        GroupOperationV1::GetLogs => get_logs(state, request, &group_id, &pseudonym, now).await,
        GroupOperationV1::SubmitChange => {
            submit(
                state, federation, relay, request, &group_id, &pseudonym, &limits, now,
            )
            .await
        }
        GroupOperationV1::GetJoinInfo => claim_join_info(state, &group_id, &pseudonym, now).await,
        GroupOperationV1::GetRequestStatus => {
            request_status(state, relay, &group_id, &pseudonym, now).await
        }
        GroupOperationV1::GetAvatar => get_avatar(state, &group_id, &pseudonym, now).await,
        GroupOperationV1::PutAvatar => put_avatar(state, request, &group_id, &pseudonym, now).await,
        // Calls come with slice 4.
        GroupOperationV1::CallToken => Ok(status(GroupResponseStatusV1::Unavailable, now)),
    }
}

fn join_info_answer(info: &GroupJoinInfoV1, now: i64) -> AppResult<GroupResponseV1> {
    Ok(ok(now, info.canonical_bytes().map_err(AppError::internal)?))
}

fn member_count(group: &GroupStateV1) -> AppResult<u16> {
    u16::try_from(group.members.len()).map_err(|_| AppError::internal("member count"))
}

/// A request with the link's password: join info, or the avatar a link
/// shows. A wrong password, a link that's off and an unknown group get one
/// answer.
async fn link_request(
    state: &AppState,
    request: &GroupRequestV1,
    group_id: &[u8; 32],
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some((group, head)) = load_state(&state.pool, group_id, false).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    let password = group
        .invite_link_password
        .as_deref()
        .and_then(|password| STANDARD.decode(password).ok());
    let link_on = group.access.add_from_invite_link != AccessRequired::Unsatisfiable;
    let proven = match &password {
        Some(password) => request.verify_link_password(password).unwrap_or(false),
        None => false,
    };
    if !(link_on && proven) {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    // Charged only for a proven link, so strangers can't spend the group's.
    if !limits::link(group_id) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    if !remember_nonce(state, request, now).await? {
        return Ok(status(GroupResponseStatusV1::Replayed, now));
    }
    match request.operation {
        GroupOperationV1::GetJoinInfo => link_join_info(&group, &head, now),
        // The current avatar only, which the link's join info names.
        GroupOperationV1::GetAvatar => current_avatar(state, &group, group_id, now).await,
        // The format lets a password authorise nothing else.
        _ => Ok(GroupResponseV1::refused("malformed", now)),
    }
}

/// Join info for a link's holder: what Signal's `GroupJoinInfo` shows, with
/// the revision and head to join at.
fn link_join_info(group: &GroupStateV1, head: &[u8; 32], now: i64) -> AppResult<GroupResponseV1> {
    join_info_answer(
        &GroupJoinInfoV1 {
            revision: group.revision,
            head: STANDARD.encode(head),
            member_count: member_count(group)?,
            title: group.attributes.title.clone(),
            description: group.attributes.description.clone(),
            avatar: group.attributes.avatar.clone(),
            requires_approval: Some(
                group.access.add_from_invite_link == AccessRequired::Administrator,
            ),
        },
        now,
    )
}

/// The group's current avatar blob, padded to one size, or `avatarMissing`
/// when it has none.
async fn current_avatar(
    state: &AppState,
    group: &GroupStateV1,
    group_id: &[u8; 32],
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some(hash) = group
        .attributes
        .avatar_hash
        .as_deref()
        .and_then(decode_exact::<32>)
    else {
        return Ok(GroupResponseV1::refused(AVATAR_MISSING, now));
    };
    let blob: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT blob FROM chat_group_avatars
         WHERE group_id = $1 AND hash = $2 AND expires_at IS NULL",
    )
    .bind(&group_id[..])
    .bind(&hash[..])
    .fetch_optional(&state.pool)
    .await?;
    let Some(blob) = blob else {
        return Ok(GroupResponseV1::refused(AVATAR_MISSING, now));
    };
    Ok(ok(
        now,
        pad_group_avatar(&blob).map_err(AppError::internal)?,
    ))
}

/// The avatar, to a member.
async fn get_avatar(
    state: &AppState,
    group_id: &[u8; 32],
    pseudonym: &str,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some((group, _)) = load_state(&state.pool, group_id, false).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    if group.member(pseudonym).is_none() {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    current_avatar(state, &group, group_id, now).await
}

/// A member's avatar upload, authorised as the avatar change is (a member
/// that `access.attributes` lets change it), checked against the state as it
/// arrives. It becomes the group's one pending upload, in place of any
/// earlier one, until a change names its hash or 24 hours pass. The home
/// counts it against its own limits (the largest blob, the storage per
/// group), never an account's pool: it doesn't know who uploaded.
async fn put_avatar(
    state: &AppState,
    request: &GroupRequestV1,
    group_id: &[u8; 32],
    pseudonym: &str,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some(blob) = request
        .body()
        .ok()
        .and_then(|body| unpad_group_avatar(&body).ok())
    else {
        return Ok(GroupResponseV1::refused("malformed", now));
    };
    let limits = crate::site_settings::chat_group_avatar_limits(&state.pool).await?;
    let (largest, storage) = (limits.max_bytes, limits.storage_bytes);
    let mut tx = state.pool.begin().await?;
    // Locked, so an upload and a change naming it don't cross.
    let Some((group, _)) = load_state(&mut *tx, group_id, true).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    if group.member(pseudonym).is_none() {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    if !group.may_modify_attributes(pseudonym) {
        return Ok(GroupResponseV1::refused(
            GroupChangeError::NotAllowed.code(),
            now,
        ));
    }
    let size = i64::try_from(blob.len()).map_err(|_| AppError::internal("avatar size"))?;
    if size > largest {
        return Ok(GroupResponseV1::refused("avatarTooLarge", now));
    }
    let hash: [u8; 32] = hash(Suite::V1, &blob).into();
    let current: Option<(Vec<u8>, i32)> = sqlx::query_as(
        "SELECT hash, octet_length(blob) FROM chat_group_avatars
         WHERE group_id = $1 AND expires_at IS NULL",
    )
    .bind(&group_id[..])
    .fetch_optional(&mut *tx)
    .await?;
    // The current blob again: nothing to store.
    if current
        .as_ref()
        .is_some_and(|(current, _)| current[..] == hash[..])
    {
        return Ok(ok(now, Vec::new()));
    }
    let current_size = current.map_or(0, |(_, size)| i64::from(size));
    if current_size + size > storage {
        return Ok(GroupResponseV1::refused("avatarStorageFull", now));
    }
    // Charged only for an upload that holds, as a change is.
    if !limits::change(pseudonym, group_id) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    let expires_at =
        OffsetDateTime::from_unix_timestamp(now.saturating_add(limits.pending_seconds))
            .map_err(|_| AppError::internal("avatar expiry"))?;
    sqlx::query("DELETE FROM chat_group_avatars WHERE group_id = $1 AND expires_at IS NOT NULL")
        .bind(&group_id[..])
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO chat_group_avatars (group_id, hash, blob, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&group_id[..])
    .bind(&hash[..])
    .bind(&blob)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ok(now, Vec::new()))
}

/// The avatar blob `next` names, when it differs from `current`'s:
/// `Some(Some(hash))` for a new one, `Some(None)` when it was removed.
fn avatar_change(
    current: &GroupStateV1,
    next: &GroupStateV1,
) -> AppResult<Option<Option<[u8; 32]>>> {
    if current.attributes.avatar_hash == next.attributes.avatar_hash {
        return Ok(None);
    }
    next.attributes
        .avatar_hash
        .as_deref()
        .map(|hash| decode_exact::<32>(hash).ok_or_else(|| AppError::internal("avatar hash")))
        .transpose()
        .map(Some)
}

/// Whether the group holds the blob `hash`: current, or pending and not yet
/// expired. Locked for the change's transaction, so the sweep can't take it
/// between this check and the swap.
async fn has_avatar(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &[u8; 32],
    hash: &[u8; 32],
) -> AppResult<bool> {
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat_group_avatars
          WHERE group_id = $1 AND hash = $2 AND (expires_at IS NULL OR expires_at > now())
          FOR UPDATE",
    )
    .bind(&group_id[..])
    .bind(&hash[..])
    .fetch_optional(&mut **tx)
    .await?;
    Ok(found.is_some())
}

/// Once a change naming a new avatar is accepted: its blob becomes the
/// current one and every other goes at once. A removed avatar's blob goes;
/// a pending upload waits out its day.
async fn swap_avatar(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &[u8; 32],
    avatar: Option<[u8; 32]>,
) -> AppResult<()> {
    match avatar {
        Some(hash) => {
            sqlx::query("DELETE FROM chat_group_avatars WHERE group_id = $1 AND hash <> $2")
                .bind(&group_id[..])
                .bind(&hash[..])
                .execute(&mut **tx)
                .await?;
            let made_current = sqlx::query(
                "UPDATE chat_group_avatars SET expires_at = NULL
                 WHERE group_id = $1 AND hash = $2",
            )
            .bind(&group_id[..])
            .bind(&hash[..])
            .execute(&mut **tx)
            .await?
            .rows_affected();
            // The blob was locked by `has_avatar`; never commit a state
            // naming a blob the home doesn't hold.
            if made_current != 1 {
                return Err(AppError::internal("the named avatar blob is gone"));
            }
        }
        None => {
            sqlx::query(
                "DELETE FROM chat_group_avatars WHERE group_id = $1 AND expires_at IS NULL",
            )
            .bind(&group_id[..])
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

/// Drops avatar uploads no change named within their day (the maintenance
/// loop calls this).
pub(crate) async fn sweep_avatars(pool: &sqlx::PgPool) -> AppResult<u64> {
    Ok(sqlx::query(
        "DELETE FROM chat_group_avatars WHERE expires_at IS NOT NULL AND expires_at < now()",
    )
    .execute(pool)
    .await?
    .rows_affected())
}

/// Join info for an invitee about to claim its slot: the revision and head
/// to claim at, and nothing sealed (the invitation carried the rest).
async fn claim_join_info(
    state: &AppState,
    group_id: &[u8; 32],
    claim_key: &str,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some((group, head)) = load_state(&state.pool, group_id, false).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    if !group.slots.iter().any(|slot| slot.claim_key == claim_key) {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    join_info_answer(
        &GroupJoinInfoV1 {
            revision: group.revision,
            head: STANDARD.encode(head),
            member_count: member_count(&group)?,
            title: None,
            description: None,
            avatar: None,
            requires_approval: None,
        },
        now,
    )
}

/// Where the signer's own request to join stands. Only its own pseudonym
/// asks (the signature proves it), so this tells nobody anything about
/// another; an unknown group and a pseudonym the group never saw get the
/// same `unknown`, never `NotFound`, so a requester whose change was lost
/// can tell it from a refusal. Every answer takes the same two reads, so
/// its timing doesn't tell a group that exists from one that doesn't, and
/// `unknown` spends the relay's failure budget, so probing for groups slows
/// as a stranger's requests do. The per-pseudonym budget was spent above.
async fn request_status(
    state: &AppState,
    relay: &str,
    group_id: &[u8; 32],
    pseudonym: &str,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let answer = |status, revision, head: Option<[u8; 32]>| -> AppResult<GroupResponseV1> {
        let body = GroupRequestStatusV1 {
            status,
            revision,
            head: head.map(|head| STANDARD.encode(head)),
        };
        Ok(ok(now, body.canonical_bytes().map_err(AppError::internal)?))
    };
    let found = load_state(&state.pool, group_id, false).await?;
    let seen = was_member(&state.pool, group_id, pseudonym).await?;
    let unknown = || {
        limits::failed(relay);
        answer(GroupRequestStateV1::Unknown, None, None)
    };
    let Some((group, head)) = found else {
        return unknown();
    };
    if group.member(pseudonym).is_some() {
        return answer(GroupRequestStateV1::Member, None, None);
    }
    if group.requesting.iter().any(|r| r.pseudonym == pseudonym) {
        return answer(
            GroupRequestStateV1::Pending,
            Some(group.revision),
            Some(head),
        );
    }
    if group.banned.iter().any(|banned| banned == pseudonym) {
        return answer(GroupRequestStateV1::Denied, None, None);
    }
    // Seen before (as a requester or a member) and neither now: denied, or
    // once in and out again.
    if seen {
        answer(GroupRequestStateV1::Denied, None, None)
    } else {
        unknown()
    }
}

pub(crate) fn group_limits(state: &AppState) -> GroupLimits {
    GroupLimits {
        max_members: state.config.chat_group_max_members,
        max_requesting: state.config.chat_group_max_members,
    }
}

/// Takes the request's nonce for the clock window; false if it was taken.
async fn remember_nonce(state: &AppState, request: &GroupRequestV1, now: i64) -> AppResult<bool> {
    let nonce = request.nonce().map_err(AppError::internal)?;
    let expires_at = OffsetDateTime::from_unix_timestamp(now.saturating_add(NONCE_MEMORY_SECS))
        .map_err(|_| AppError::internal("nonce expiry"))?;
    let taken = sqlx::query(
        "INSERT INTO chat_group_nonces (nonce, expires_at) VALUES ($1, $2)
         ON CONFLICT (nonce) DO NOTHING",
    )
    .bind(&nonce[..])
    .bind(expires_at)
    .execute(&state.pool)
    .await?
    .rows_affected();
    Ok(taken == 1)
}

/// Drops nonces past their window (the maintenance loop calls this).
pub(crate) async fn sweep_nonces(pool: &sqlx::PgPool) -> AppResult<u64> {
    Ok(
        sqlx::query("DELETE FROM chat_group_nonces WHERE expires_at < now()")
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

fn decode_change(request: &GroupRequestV1) -> Option<GroupChangeV1> {
    let body = request.body().ok()?;
    GroupChangeV1::from_canonical_bytes(&body).ok()
}

fn hash32(value: Result<[u8; 32], String>) -> AppResult<[u8; 32]> {
    value.map_err(AppError::internal)
}

/// The home's notary over an accepted change, naming the key config it serves.
fn notarise(
    federation: &FederationStack,
    group_id: &[u8; 32],
    change: &GroupChangeV1,
    next: &GroupStateV1,
    now: i64,
) -> AppResult<GroupNotaryV1> {
    let identity = federation.local_identity();
    let config = keys::current_config(identity.document(), identity.signing_key(), now)?;
    GroupNotaryV1::sign(
        identity.document(),
        identity.signing_key(),
        &config,
        group_id,
        next.revision,
        &hash32(change.hash())?,
        &hash32(next.hash())?,
    )
    .map_err(AppError::internal)
}

fn refused(error: &GroupChangeError, now: i64) -> GroupResponseV1 {
    match error {
        // Not the next revision, or not after the head: refetch and verify.
        GroupChangeError::WrongRevision | GroupChangeError::WrongPrevious => {
            status(GroupResponseStatusV1::Conflict, now)
        }
        other => GroupResponseV1::refused(other.code(), now),
    }
}

#[allow(clippy::too_many_arguments)]
async fn create(
    state: &AppState,
    federation: &FederationStack,
    relay: &str,
    request: &GroupRequestV1,
    group_id: &[u8; 32],
    pseudonym: &str,
    limits: &GroupLimits,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some(change) = decode_change(request) else {
        return Ok(GroupResponseV1::refused("malformed", now));
    };
    // The request's signer is the genesis's actor, and the group is the one
    // the request names.
    if change.actor != pseudonym || change.group_id != request.group_id {
        return Ok(GroupResponseV1::refused("wrongGroup", now));
    }
    // The pin must be this server's identity now: only the server knows it.
    let pin =
        GroupHomePinV1::of(federation.local_identity().document()).map_err(AppError::internal)?;
    let genesis = match check_genesis(&change, &pin, limits) {
        Ok(genesis) => genesis,
        Err(error) => return Ok(refused(&error, now)),
    };
    // An avatar is uploaded to a group that exists: a genesis can't name one.
    if genesis.attributes.avatar_hash.is_some() {
        return Ok(GroupResponseV1::refused(AVATAR_MISSING, now));
    }
    // New groups are limited per relaying server, and in all.
    if !limits::create(relay) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    let notary = notarise(federation, group_id, &change, &genesis, now)?;
    let state_bytes = genesis.canonical_bytes().map_err(AppError::internal)?;
    let change_bytes = change.canonical_bytes().map_err(AppError::internal)?;
    let notary_bytes =
        serde_json::to_vec(&notary).map_err(|e| AppError::internal(e.to_string()))?;
    let change_hash = hash32(change.hash())?;
    let state_hash = hash32(genesis.hash())?;
    let mut tx = state.pool.begin().await?;
    let hosted: i64 = sqlx::query_scalar("SELECT count(*) FROM chat_groups")
        .fetch_one(&mut *tx)
        .await?;
    if hosted >= state.config.chat_group_max_groups {
        return Ok(GroupResponseV1::refused("serverFull", now));
    }
    let created = sqlx::query(
        "INSERT INTO chat_groups (group_id, revision, head, state, state_hash)
         VALUES ($1, 0, $2, $3, $4) ON CONFLICT (group_id) DO NOTHING",
    )
    .bind(&group_id[..])
    .bind(&change_hash[..])
    .bind(&state_bytes)
    .bind(&state_hash[..])
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if created == 0 {
        // A group id is the hash of a fresh master key: a second genesis is
        // a replay or a mistake, never a new group.
        return Ok(status(GroupResponseStatusV1::Conflict, now));
    }
    insert_change(
        &mut tx,
        group_id,
        0,
        &change_bytes,
        &change_hash,
        &state_hash,
        &notary_bytes,
    )
    .await?;
    remember_newcomers(&mut tx, group_id, &genesis).await?;
    tx.commit().await?;
    let answer = GroupStateAnswerV1 {
        state: STANDARD.encode(&state_bytes),
        change: STANDARD.encode(&change_bytes),
        notary,
    };
    Ok(ok(
        now,
        answer.canonical_bytes().map_err(AppError::internal)?,
    ))
}

async fn insert_change(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &[u8; 32],
    revision: u64,
    change: &[u8],
    change_hash: &[u8; 32],
    state_hash: &[u8; 32],
    notary: &[u8],
) -> AppResult<()> {
    let revision = i64::try_from(revision).map_err(|_| AppError::internal("revision"))?;
    sqlx::query(
        "INSERT INTO chat_group_changes
             (group_id, revision, change, change_hash, state_hash, notary)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&group_id[..])
    .bind(revision)
    .bind(change)
    .bind(&change_hash[..])
    .bind(&state_hash[..])
    .bind(notary)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The group's state, or `None` for an unknown group.
async fn load_state(
    executor: impl sqlx::PgExecutor<'_>,
    group_id: &[u8; 32],
    lock: bool,
) -> AppResult<Option<(GroupStateV1, [u8; 32])>> {
    let query = if lock {
        "SELECT state, head FROM chat_groups WHERE group_id = $1 FOR UPDATE"
    } else {
        "SELECT state, head FROM chat_groups WHERE group_id = $1"
    };
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(query)
        .bind(&group_id[..])
        .fetch_optional(executor)
        .await?;
    row.map(|(state, head)| {
        let state = GroupStateV1::from_canonical_bytes(&state)
            .map_err(|e| AppError::internal(format!("stored group state: {e}")))?;
        let head: [u8; 32] = head
            .try_into()
            .map_err(|_| AppError::internal("stored group head"))?;
        Ok((state, head))
    })
    .transpose()
}

async fn get_state(
    state: &AppState,
    group_id: &[u8; 32],
    pseudonym: &str,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some((group, _)) = load_state(&state.pool, group_id, false).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    if group.member(pseudonym).is_none() {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    let revision = i64::try_from(group.revision).map_err(|_| AppError::internal("revision"))?;
    let (change, notary): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT change, notary FROM chat_group_changes WHERE group_id = $1 AND revision = $2",
    )
    .bind(&group_id[..])
    .bind(revision)
    .fetch_one(&state.pool)
    .await?;
    let answer = GroupStateAnswerV1 {
        state: STANDARD.encode(group.canonical_bytes().map_err(AppError::internal)?),
        change: STANDARD.encode(change),
        notary: serde_json::from_slice(&notary)
            .map_err(|e| AppError::internal(format!("stored notary: {e}")))?,
    };
    Ok(ok(
        now,
        answer.canonical_bytes().map_err(AppError::internal)?,
    ))
}

async fn get_logs(
    state: &AppState,
    request: &GroupRequestV1,
    group_id: &[u8; 32],
    pseudonym: &str,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some(query) = request
        .body()
        .ok()
        .and_then(|body| serde_json::from_slice::<GroupLogQueryV1>(&body).ok())
    else {
        return Ok(GroupResponseV1::refused("malformed", now));
    };
    let Some((group, _)) = load_state(&state.pool, group_id, false).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    let Some(member) = group.member(pseudonym) else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    // A member reads the log only from the revision it joined at.
    let from = query.from_revision.max(member.joined_at_revision);
    let from = i64::try_from(from).map_err(|_| AppError::bad_request("revision"))?;
    let limit = i64::from(query.limit.max(1)).min(MAX_LOG_PAGE_CHANGES);
    let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT change, notary FROM chat_group_changes
         WHERE group_id = $1 AND revision >= $2 ORDER BY revision LIMIT $3",
    )
    .bind(&group_id[..])
    .bind(from)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let mut entries = Vec::new();
    let mut size = 0usize;
    let mut more = rows.len() as i64 > limit;
    for (change, notary) in rows.into_iter().take(limit as usize) {
        size += change.len() + notary.len();
        if size > LOG_PAGE_BYTES && !entries.is_empty() {
            more = true;
            break;
        }
        entries.push(GroupLogEntryV1 {
            change: STANDARD.encode(change),
            notary: serde_json::from_slice(&notary)
                .map_err(|e| AppError::internal(format!("stored notary: {e}")))?,
        });
    }
    let page = GroupLogPageV1 { entries, more };
    Ok(ok(now, page.canonical_bytes().map_err(AppError::internal)?))
}

/// Whether `change`'s actor may act on the group: a member, or a newcomer
/// whose own action holds (a claim signed by its slot's key, the link's
/// password with the link on, or its own open request).
fn admitted(state: &GroupStateV1, group_id: &[u8; 32], change: &GroupChangeV1) -> bool {
    let actor = change.actor.as_str();
    if !change.is_newcomers_change() {
        return state.member(actor).is_some();
    }
    match change.actions.as_slice() {
        [GroupActionV1::Claim {
            slot_id,
            claim_signature,
            ..
        }] => claim_holds(state, group_id, actor, slot_id, claim_signature),
        [GroupActionV1::JoinFromLink { password, .. }]
        | [GroupActionV1::RequestToJoin { password, .. }] => link_password_holds(state, password),
        [GroupActionV1::CancelRequest] => state.requesting.iter().any(|r| r.pseudonym == actor),
        _ => false,
    }
}

fn decode_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    STANDARD.decode(value).ok()?.try_into().ok()
}

fn claim_holds(
    state: &GroupStateV1,
    group_id: &[u8; 32],
    actor: &str,
    slot_id: &str,
    signature: &str,
) -> bool {
    let Some(slot) = state.slots.iter().find(|slot| slot.slot_id == slot_id) else {
        return false;
    };
    let (Some(claim_key), Some(slot_bytes), Some(actor_key), Some(signature)) = (
        decode_exact::<32>(&slot.claim_key),
        decode_exact::<16>(slot_id),
        decode_exact::<32>(actor),
        decode_exact::<64>(signature),
    ) else {
        return false;
    };
    kutup_crypto::chat_group::verify_claim_signature(
        &claim_key,
        group_id,
        &slot_bytes,
        slot.created_at_revision,
        &actor_key,
        &signature,
    )
    .is_ok()
}

/// The link's password, compared in constant time, with the link on.
fn link_password_holds(state: &GroupStateV1, offered: &str) -> bool {
    if state.access.add_from_invite_link == AccessRequired::Unsatisfiable {
        return false;
    }
    let (Some(current), Some(offered)) = (
        state
            .invite_link_password
            .as_deref()
            .and_then(|p| STANDARD.decode(p).ok()),
        STANDARD.decode(offered).ok(),
    ) else {
        return false;
    };
    current.len() == offered.len()
        && std::hint::black_box(
            current
                .iter()
                .zip(&offered)
                .fold(0u8, |difference, (a, b)| difference | (a ^ b)),
        ) == 0
}

/// Whether `change` is a newcomer's way in: a claim, a join from the link or
/// a request to join (not the cancelling of its own request).
fn joins(change: &GroupChangeV1) -> bool {
    matches!(
        change.actions.as_slice(),
        [GroupActionV1::Claim { .. }
            | GroupActionV1::JoinFromLink { .. }
            | GroupActionV1::RequestToJoin { .. }]
    )
}

/// Whether `change` is a join from the link or a request to join.
fn from_link(change: &GroupChangeV1) -> bool {
    matches!(
        change.actions.as_slice(),
        [GroupActionV1::JoinFromLink { .. } | GroupActionV1::RequestToJoin { .. }]
    )
}

fn seen_hash(pseudonym: &str) -> AppResult<[u8; 32]> {
    let key = decode_exact::<32>(pseudonym).ok_or_else(|| AppError::internal("pseudonym"))?;
    Ok(Hasher::new(Suite::V1)
        .chain(SEEN_PSEUDONYM_DOMAIN)
        .chain(key)
        .finish()
        .into())
}

/// Whether the group has seen `pseudonym`: [`remember_newcomers`] recorded
/// it as a member or a requester.
async fn was_member(
    executor: impl sqlx::PgExecutor<'_>,
    group_id: &[u8; 32],
    pseudonym: &str,
) -> AppResult<bool> {
    let seen: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM chat_group_seen_pseudonyms
                        WHERE group_id = $1 AND pseudonym_hash = $2)",
    )
    .bind(&group_id[..])
    .bind(&seen_hash(pseudonym)?[..])
    .fetch_one(executor)
    .await?;
    Ok(seen)
}

/// Records the pseudonyms `next` brought in, for good: the members who
/// joined at its revision (the creator at genesis, a claim, a join from the
/// link, an approved request) and the requests made at it. The log is
/// pruned and the state forgets whoever left, so neither can answer later.
async fn remember_newcomers(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &[u8; 32],
    next: &GroupStateV1,
) -> AppResult<()> {
    let joined = next
        .members
        .iter()
        .filter(|member| member.joined_at_revision == next.revision)
        .map(|member| &member.pseudonym);
    let requested = next
        .requesting
        .iter()
        .filter(|request| request.requested_at_revision == next.revision)
        .map(|request| &request.pseudonym);
    let hashes = joined
        .chain(requested)
        .map(|pseudonym| seen_hash(pseudonym).map(|hash| hash.to_vec()))
        .collect::<AppResult<Vec<_>>>()?;
    if hashes.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO chat_group_seen_pseudonyms (group_id, pseudonym_hash)
         SELECT $1, hash FROM unnest($2::bytea[]) AS hash
         ON CONFLICT DO NOTHING",
    )
    .bind(&group_id[..])
    .bind(&hashes)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Drops the changes no current member can need: every member reads the log
/// only from the revision it joined at, so revisions before the earliest of
/// those are kept as the state alone. The latest change always stays (the
/// state's own notary rides on it).
async fn prune_log(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &[u8; 32],
    next: &GroupStateV1,
) -> AppResult<()> {
    let earliest = next
        .members
        .iter()
        .map(|member| member.joined_at_revision)
        .min()
        .unwrap_or(next.revision)
        .min(next.revision);
    let earliest = i64::try_from(earliest).map_err(|_| AppError::internal("revision"))?;
    sqlx::query("DELETE FROM chat_group_changes WHERE group_id = $1 AND revision < $2")
        .bind(&group_id[..])
        .bind(earliest)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit(
    state: &AppState,
    federation: &FederationStack,
    relay: &str,
    request: &GroupRequestV1,
    group_id: &[u8; 32],
    pseudonym: &str,
    limits: &GroupLimits,
    now: i64,
) -> AppResult<GroupResponseV1> {
    let Some(change) = decode_change(request) else {
        return Ok(GroupResponseV1::refused("malformed", now));
    };
    // The request's signer is the change's actor, so limits per pseudonym
    // count the right one.
    if change.actor != pseudonym {
        return Ok(GroupResponseV1::refused("wrongActor", now));
    }
    let link_budgets = if from_link(&change) {
        Some(crate::site_settings::chat_group_link_joins(&state.pool).await?)
    } else {
        None
    };
    let mut tx = state.pool.begin().await?;
    let Some((current, head)) = load_state(&mut *tx, group_id, true).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    // Whoever isn't admitted to the group (a stranger, a removed member, a
    // newcomer without a valid claim, link password or request) gets the
    // answer an unknown group gets, before anything else: no conflict, code
    // or "ended" tells them the group exists.
    if !admitted(&current, group_id, &change) {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    }
    // Newcomers from a link, once its password holds and before the change
    // is checked: per relay server and group, and per relay server, so junk
    // without the link spends nothing and one link's holders crowd only
    // that group.
    if let Some(budgets) = link_budgets {
        if !limits::link_join(relay, group_id, budgets) {
            return Ok(status(GroupResponseStatusV1::RateLimited, now));
        }
    }
    let next = match check_change(&current, &head, &change, limits) {
        Ok(next) => next,
        Err(error) => return Ok(refused(&error, now)),
    };
    // A change naming an avatar must find its blob, pending or current.
    let avatar = avatar_change(&current, &next)?;
    if let Some(Some(hash)) = &avatar {
        if !has_avatar(&mut tx, group_id, hash).await? {
            return Ok(GroupResponseV1::refused(AVATAR_MISSING, now));
        }
    }
    // A newcomer under a pseudonym the group has had before would let the
    // members link the two memberships; its signer is told so, and only
    // now, with its claim or link proof and the change itself accepted.
    if joins(&change) && was_member(&mut *tx, group_id, pseudonym).await? {
        return Ok(GroupResponseV1::refused(PSEUDONYM_USED, now));
    }
    // Charged only for a valid change, so nobody can spend a group's budget
    // with changes that would be refused.
    if !limits::change(pseudonym, group_id) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    let notary = notarise(federation, group_id, &change, &next, now)?;
    let state_bytes = next.canonical_bytes().map_err(AppError::internal)?;
    let change_bytes = change.canonical_bytes().map_err(AppError::internal)?;
    let notary_bytes =
        serde_json::to_vec(&notary).map_err(|e| AppError::internal(e.to_string()))?;
    let change_hash = hash32(change.hash())?;
    let state_hash = hash32(next.hash())?;
    let revision = i64::try_from(next.revision).map_err(|_| AppError::internal("revision"))?;
    sqlx::query(
        "UPDATE chat_groups SET revision = $2, head = $3, state = $4, state_hash = $5,
                updated_at = now()
         WHERE group_id = $1",
    )
    .bind(&group_id[..])
    .bind(revision)
    .bind(&change_hash[..])
    .bind(&state_bytes)
    .bind(&state_hash[..])
    .execute(&mut *tx)
    .await?;
    insert_change(
        &mut tx,
        group_id,
        next.revision,
        &change_bytes,
        &change_hash,
        &state_hash,
        &notary_bytes,
    )
    .await?;
    prune_log(&mut tx, group_id, &next).await?;
    remember_newcomers(&mut tx, group_id, &next).await?;
    if let Some(avatar) = avatar {
        swap_avatar(&mut tx, group_id, avatar).await?;
    }
    tx.commit().await?;
    // The change with its notary: a member applies it to the state it has;
    // a newcomer whose request awaits approval learns nothing more.
    let entry = GroupLogEntryV1 {
        change: STANDARD.encode(&change_bytes),
        notary,
    };
    Ok(ok(
        now,
        serde_json::to_vec(&entry).map_err(|e| AppError::internal(e.to_string()))?,
    ))
}
