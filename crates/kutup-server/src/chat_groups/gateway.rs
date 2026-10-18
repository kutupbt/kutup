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
    check_change, check_genesis, AccessRequired, GroupChangeError, GroupChangeV1, GroupLimits,
    GroupStateV1,
};
use kutup_chat_proto::group_route::{
    GroupHomePinV1, GroupJoinInfoV1, GroupLogEntryV1, GroupLogPageV1, GroupLogQueryV1,
    GroupNotaryV1, GroupOperationV1, GroupRequestAuthV1, GroupRequestV1, GroupResponseStatusV1,
    GroupResponseV1, GroupStateAnswerV1, NONCE_MEMORY_SECS,
};
use kutup_crypto::oblivious::ResponseContext;
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

async fn answer(
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
        // Only join info takes a link's password (the format checks that).
        GroupRequestAuthV1::LinkPassword { .. } => {
            return link_join_info(state, request, &group_id, now).await;
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
                state, federation, request, &group_id, &pseudonym, &limits, now,
            )
            .await
        }
        GroupOperationV1::GetState => get_state(state, &group_id, &pseudonym, now).await,
        GroupOperationV1::GetLogs => get_logs(state, request, &group_id, &pseudonym, now).await,
        GroupOperationV1::SubmitChange => {
            submit(
                state, federation, request, &group_id, &pseudonym, &limits, now,
            )
            .await
        }
        GroupOperationV1::GetJoinInfo => claim_join_info(state, &group_id, &pseudonym, now).await,
        // Calls and avatars come with slices 3 and 4.
        GroupOperationV1::CallToken | GroupOperationV1::GetAvatar | GroupOperationV1::PutAvatar => {
            Ok(status(GroupResponseStatusV1::Unavailable, now))
        }
    }
}

fn join_info_answer(info: &GroupJoinInfoV1, now: i64) -> AppResult<GroupResponseV1> {
    Ok(ok(now, info.canonical_bytes().map_err(AppError::internal)?))
}

fn member_count(group: &GroupStateV1) -> AppResult<u16> {
    u16::try_from(group.members.len()).map_err(|_| AppError::internal("member count"))
}

/// Join info for a link's holder: what Signal's `GroupJoinInfo` shows, with
/// the revision and head to join at. A wrong password, a link that's off and
/// an unknown group get one answer.
async fn link_join_info(
    state: &AppState,
    request: &GroupRequestV1,
    group_id: &[u8; 32],
    now: i64,
) -> AppResult<GroupResponseV1> {
    if !limits::link(group_id) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
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
    if !remember_nonce(state, request, now).await? {
        return Ok(status(GroupResponseStatusV1::Replayed, now));
    }
    join_info_answer(
        &GroupJoinInfoV1 {
            revision: group.revision,
            head: STANDARD.encode(head),
            member_count: member_count(&group)?,
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

async fn create(
    state: &AppState,
    federation: &FederationStack,
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
    let notary = notarise(federation, group_id, &change, &genesis, now)?;
    let state_bytes = genesis.canonical_bytes().map_err(AppError::internal)?;
    let change_bytes = change.canonical_bytes().map_err(AppError::internal)?;
    let notary_bytes =
        serde_json::to_vec(&notary).map_err(|e| AppError::internal(e.to_string()))?;
    let change_hash = hash32(change.hash())?;
    let state_hash = hash32(genesis.hash())?;
    let mut tx = state.pool.begin().await?;
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

async fn submit(
    state: &AppState,
    federation: &FederationStack,
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
    if !limits::change(pseudonym, group_id) {
        return Ok(status(GroupResponseStatusV1::RateLimited, now));
    }
    let mut tx = state.pool.begin().await?;
    let Some((current, head)) = load_state(&mut *tx, group_id, true).await? else {
        return Ok(status(GroupResponseStatusV1::NotFound, now));
    };
    let next = match check_change(&current, &head, &change, limits) {
        Ok(next) => next,
        Err(error) => return Ok(refused(&error, now)),
    };
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
