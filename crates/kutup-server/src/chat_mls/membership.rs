//! Destination-private MLS membership snapshots and control envelopes.
//!
//! Ordering authorities retain only `MlsMembershipTransitionV1`. An
//! authenticated group administrator stages one digest-bound delivery per
//! affected participant server before requesting finalization.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    roster_commitment, CommitMlsControlBlockV1, MlsControlActionTypeV1, MlsMembershipDeliveryV1,
    MlsMembershipEnvelopeKindV1, MlsMembershipTransitionV1,
};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::active_policy;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::telemetry;
use crate::AppState;

pub(super) struct MembershipFinalization {
    pub next_roster_commitment: String,
    pub next_member_count: u32,
    pub next_participant_domains: Vec<String>,
    pub deliveries: BTreeMap<String, MlsMembershipDeliveryV1>,
}

pub(crate) async fn stage_membership_delivery(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(delivery): Json<MlsMembershipDeliveryV1>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    delivery.validate().map_err(AppError::bad_request)?;
    let submitter = trusted_uuid(&auth.user_id)?;
    let is_admin: Option<bool> = sqlx::query_scalar(
        "SELECT is_admin
         FROM chat_mls_local_members
         WHERE conversation_id = $1 AND incarnation = $2
           AND user_id = $3 AND removed_epoch IS NULL
           AND membership_status = 'active'",
    )
    .bind(delivery.conversation_id)
    .bind(delivery.incarnation as i64)
    .bind(submitter)
    .fetch_optional(&state.pool)
    .await?;
    if is_admin != Some(true) {
        return Err(AppError::forbidden(
            "MLS membership delivery staging requires a local administrator",
        ));
    }
    let current_epoch: Option<i64> = sqlx::query_scalar(
        "SELECT last_finalized_epoch
         FROM chat_mls_incarnations
         WHERE conversation_id = $1 AND incarnation = $2 AND status = 'active'",
    )
    .bind(delivery.conversation_id)
    .bind(delivery.incarnation as i64)
    .fetch_optional(&state.pool)
    .await?;
    if current_epoch
        .and_then(|epoch| epoch.checked_add(1))
        .map(|epoch| epoch as u64)
        != Some(delivery.epoch_after)
    {
        return Err(AppError::conflict(
            "MLS membership delivery does not target the exact next epoch",
        ));
    }
    let digest = delivery.delivery_digest().map_err(AppError::bad_request)?;
    let value = serde_json::to_value(&delivery).map_err(|error| {
        AppError::internal(format!("serialize MLS membership delivery: {error}"))
    })?;
    let result = sqlx::query(
        "INSERT INTO chat_mls_membership_deliveries
             (conversation_id, incarnation, proposal_id, destination,
              delivery_digest, delivery, submitted_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (conversation_id, incarnation, proposal_id, destination)
         DO NOTHING",
    )
    .bind(delivery.conversation_id)
    .bind(delivery.incarnation as i64)
    .bind(delivery.proposal_id)
    .bind(&delivery.destination)
    .bind(&digest)
    .bind(value)
    .bind(submitter)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        let existing: Option<(String, String)> = sqlx::query_as(
            "SELECT delivery_digest, state
             FROM chat_mls_membership_deliveries
             WHERE conversation_id = $1 AND incarnation = $2
               AND proposal_id = $3 AND destination = $4",
        )
        .bind(delivery.conversation_id)
        .bind(delivery.incarnation as i64)
        .bind(delivery.proposal_id)
        .bind(&delivery.destination)
        .fetch_optional(&state.pool)
        .await?;
        if !existing.is_some_and(|(existing_digest, state)| {
            existing_digest == digest && matches!(state.as_str(), "staged" | "finalized")
        }) {
            return Err(AppError::conflict(
                "a different MLS membership delivery already exists",
            ));
        }
    }
    telemetry::mls_control_event("stage_membership_delivery", "accepted");
    Ok(Json(serde_json::json!({
        "proposalId": delivery.proposal_id,
        "destination": delivery.destination,
        "deliveryDigest": digest,
        "idempotent": result.rows_affected() == 0,
    }))
    .into_response())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_membership_finalization(
    tx: &mut Transaction<'_, Postgres>,
    local_domain: &str,
    local_submitter: Option<Uuid>,
    incoming_delivery: Option<&MlsMembershipDeliveryV1>,
    request: &CommitMlsControlBlockV1,
    conversation_kind: i16,
    current_roster_commitment: &str,
    current_member_count: u32,
    current_participant_domains: &[String],
    maximum_group_members: u16,
    verified_history_replay: bool,
) -> AppResult<Option<MembershipFinalization>> {
    let block = &request.finalized.block;
    let transition = request
        .membership_transition
        .as_ref()
        .or_else(|| {
            request
                .authority_change
                .as_ref()
                .map(|change| &change.delivery_transition)
        })
        .or_else(|| {
            request
                .owner_change
                .as_ref()
                .map(|change| &change.delivery_transition)
        });
    let Some(transition) = transition else {
        if incoming_delivery.is_some() {
            return Err(AppError::bad_request(
                "unrelated MLS control block carries a membership delivery",
            ));
        }
        return Ok(None);
    };
    if !matches!(
        block.proposal.action_type,
        MlsControlActionTypeV1::MembershipChange
            | MlsControlActionTypeV1::RoutineAdmin
            | MlsControlActionTypeV1::AuthoritySetChange
            | MlsControlActionTypeV1::OwnerSetChange
            | MlsControlActionTypeV1::AuthorizationPolicyChange
            | MlsControlActionTypeV1::CryptographicPolicyChange
            | MlsControlActionTypeV1::CloseConversation
    ) {
        return Err(AppError::bad_request(
            "unrelated MLS control action carries a roster transition",
        ));
    }
    validate_transition_against_state(
        transition,
        block.proposal.action_type,
        conversation_kind,
        current_roster_commitment,
        current_member_count,
        current_participant_domains,
        maximum_group_members,
    )?;

    let deliveries = if local_submitter.is_some() {
        if incoming_delivery.is_some() {
            return Err(AppError::bad_request(
                "local MLS finalization cannot supply a federation delivery",
            ));
        }
        load_staged_deliveries(tx, transition).await?
    } else {
        let local_affected = transition.delivery_commitment(local_domain).is_some();
        match (local_affected, incoming_delivery, verified_history_replay) {
            (true, Some(delivery), _) => {
                delivery
                    .verify_transition(transition)
                    .map_err(AppError::bad_request)?;
                if delivery.destination != local_domain {
                    return Err(AppError::forbidden(
                        "federated MLS membership delivery targets another server",
                    ));
                }
                BTreeMap::from([(local_domain.to_owned(), delivery.clone())])
            }
            (true, None, false) => {
                return Err(AppError::conflict(
                    "participant server requires its committed MLS membership delivery",
                ))
            }
            (true, None, true) | (false, None, _) => BTreeMap::new(),
            (false, Some(_), _) => {
                return Err(AppError::forbidden(
                    "ordering-only server received private MLS membership data",
                ))
            }
        }
    };

    if let (Some(change), true) = (&request.owner_change, local_submitter.is_some()) {
        let roster_owner_ids = deliveries
            .values()
            .flat_map(|delivery| delivery.local_members_after.iter())
            .filter_map(|member| member.owner_id.as_deref())
            .collect::<BTreeSet<_>>();
        let declared_owner_ids = change
            .next_owner_set
            .owners
            .iter()
            .map(|owner| owner.owner_id.as_str())
            .collect::<BTreeSet<_>>();
        if roster_owner_ids != declared_owner_ids {
            return Err(AppError::bad_request(
                "MLS owner set differs from the committed private roster snapshots",
            ));
        }
    }

    if let Some(delivery) = deliveries.get(local_domain) {
        apply_local_snapshot(
            tx,
            delivery,
            block.epoch_after,
            local_submitter,
            block.proposal.action_type,
        )
        .await?;
    }
    finalize_delivery_records(
        tx,
        local_submitter,
        transition,
        &deliveries,
        block.height,
        &block.block_hash().map_err(AppError::bad_request)?,
    )
    .await?;

    Ok(Some(MembershipFinalization {
        next_roster_commitment: transition.next_roster_commitment.clone(),
        next_member_count: transition.next_member_count,
        next_participant_domains: transition.next_participant_domains.clone(),
        deliveries,
    }))
}

fn validate_transition_against_state(
    transition: &MlsMembershipTransitionV1,
    action_type: MlsControlActionTypeV1,
    conversation_kind: i16,
    current_roster_commitment: &str,
    current_member_count: u32,
    current_participant_domains: &[String],
    maximum_group_members: u16,
) -> AppResult<()> {
    transition.validate().map_err(AppError::bad_request)?;
    if transition.previous_roster_commitment != current_roster_commitment
        || transition.previous_member_count != current_member_count
        || transition.previous_participant_domains != current_participant_domains
    {
        return Err(AppError::conflict(
            "MLS membership transition does not extend the current roster",
        ));
    }
    match action_type {
        MlsControlActionTypeV1::MembershipChange
            if transition.previous_member_count == transition.next_member_count =>
        {
            return Err(AppError::bad_request(
                "MLS membership change must add or remove an account",
            ))
        }
        MlsControlActionTypeV1::RoutineAdmin
            if transition.previous_member_count != transition.next_member_count
                || transition.previous_participant_domains
                    != transition.next_participant_domains =>
        {
            return Err(AppError::bad_request(
                "MLS routine administrator change cannot alter membership routing",
            ))
        }
        MlsControlActionTypeV1::AuthoritySetChange
            if transition.previous_member_count != transition.next_member_count
                || transition.previous_roster_commitment != transition.next_roster_commitment
                || transition.previous_participant_domains
                    != transition.next_participant_domains =>
        {
            return Err(AppError::bad_request(
                "MLS authority change cannot alter membership or routing",
            ))
        }
        MlsControlActionTypeV1::OwnerSetChange
            if transition.previous_member_count != transition.next_member_count
                || transition.previous_roster_commitment == transition.next_roster_commitment
                || transition.previous_participant_domains
                    != transition.next_participant_domains =>
        {
            return Err(AppError::bad_request(
                "MLS owner change must alter roles without changing membership routing",
            ))
        }
        MlsControlActionTypeV1::CloseConversation
        | MlsControlActionTypeV1::AuthorizationPolicyChange
        | MlsControlActionTypeV1::CryptographicPolicyChange
            if transition.previous_member_count != transition.next_member_count
                || transition.previous_roster_commitment != transition.next_roster_commitment
                || transition.previous_participant_domains
                    != transition.next_participant_domains =>
        {
            return Err(AppError::bad_request(
                "MLS close or policy change cannot alter membership, roles, or routing",
            ))
        }
        _ => {}
    }
    let valid_count = match conversation_kind {
        1 => transition.next_member_count == 1,
        2 => transition.next_member_count == 2,
        3 => {
            (2..=u32::from(maximum_group_members)).contains(&transition.next_member_count)
                && transition.next_member_count <= 1000
        }
        _ => false,
    };
    if !valid_count {
        return Err(AppError::bad_request(
            "MLS membership transition violates the conversation member limit",
        ));
    }
    Ok(())
}

async fn load_staged_deliveries(
    tx: &mut Transaction<'_, Postgres>,
    transition: &MlsMembershipTransitionV1,
) -> AppResult<BTreeMap<String, MlsMembershipDeliveryV1>> {
    let rows: Vec<(String, String, Value)> = sqlx::query_as(
        "SELECT destination, delivery_digest, delivery
         FROM chat_mls_membership_deliveries
         WHERE conversation_id = $1 AND incarnation = $2
           AND proposal_id = $3 AND state = 'staged' AND expires_at > now()
         ORDER BY destination
         FOR UPDATE",
    )
    .bind(transition.conversation_id)
    .bind(transition.incarnation as i64)
    .bind(transition.proposal_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() != transition.deliveries.len() {
        return Err(AppError::conflict(
            "not every committed MLS membership delivery has been staged",
        ));
    }
    let mut deliveries = BTreeMap::new();
    for (destination, stored_digest, value) in rows {
        let delivery: MlsMembershipDeliveryV1 = serde_json::from_value(value).map_err(|error| {
            AppError::internal(format!("stored MLS membership delivery invalid: {error}"))
        })?;
        delivery
            .verify_transition(transition)
            .map_err(AppError::bad_request)?;
        if delivery.destination != destination
            || delivery.delivery_digest().map_err(AppError::bad_request)? != stored_digest
        {
            return Err(AppError::internal(
                "stored MLS membership delivery commitment is inconsistent",
            ));
        }
        deliveries.insert(destination, delivery);
    }
    let expected: BTreeSet<&str> = transition
        .deliveries
        .iter()
        .map(|commitment| commitment.destination.as_str())
        .collect();
    if deliveries
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(AppError::conflict(
            "staged MLS membership delivery destinations do not match",
        ));
    }
    let mut complete_roster = deliveries
        .values()
        .flat_map(|delivery| delivery.local_members_after.iter().cloned())
        .collect::<Vec<_>>();
    complete_roster.sort_by_key(|member| member.address.canonical());
    if complete_roster.len() != transition.next_member_count as usize
        || roster_commitment(&complete_roster).map_err(AppError::bad_request)?
            != transition.next_roster_commitment
    {
        return Err(AppError::bad_request(
            "staged MLS membership snapshots do not reconstruct the committed roster",
        ));
    }
    Ok(deliveries)
}

async fn apply_local_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    delivery: &MlsMembershipDeliveryV1,
    epoch_after: u64,
    local_submitter: Option<Uuid>,
    action_type: MlsControlActionTypeV1,
) -> AppResult<()> {
    let active: Vec<(Uuid, String, bool, Option<String>, String)> = sqlx::query_as(
        "SELECT m.user_id, u.username, m.is_owner, m.owner_id, m.membership_status
         FROM chat_mls_local_members m
         JOIN users u ON u.id = m.user_id
         WHERE conversation_id = $1 AND incarnation = $2
           AND removed_epoch IS NULL
         ORDER BY m.user_id
         FOR UPDATE OF m",
    )
    .bind(delivery.conversation_id)
    .bind(delivery.incarnation as i64)
    .fetch_all(&mut **tx)
    .await?;
    let existing_owner_ids: BTreeSet<String> = active
        .iter()
        .filter_map(|(_, _, is_owner, owner_id, _)| is_owner.then(|| owner_id.clone()).flatten())
        .collect();
    let next_owner_ids: BTreeSet<String> = delivery
        .local_members_after
        .iter()
        .filter_map(|member| member.owner_id.clone())
        .collect();
    if action_type != MlsControlActionTypeV1::OwnerSetChange && existing_owner_ids != next_owner_ids
    {
        return Err(AppError::bad_request(
            "ordinary MLS membership change cannot add or remove owners",
        ));
    }

    let mut next_users = BTreeMap::new();
    for member in &delivery.local_members_after {
        let user_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
                .bind(&member.address.username)
                .fetch_optional(&mut **tx)
                .await?;
        let user_id = user_id.ok_or_else(|| {
            AppError::conflict("an added local MLS member account does not exist")
        })?;
        next_users.insert(user_id, member);
    }

    let active_ids: BTreeSet<Uuid> = active
        .iter()
        .map(|(user_id, _, _, _, _)| *user_id)
        .collect();
    let active_usernames: BTreeSet<&str> = active
        .iter()
        .map(|(_, username, _, _, _)| username.as_str())
        .collect();
    let rejected_ids: BTreeSet<Uuid> = active
        .iter()
        .filter_map(|(user_id, _, _, _, status)| (status == "rejected").then_some(*user_id))
        .collect();
    let rejected_usernames: BTreeSet<&str> = active
        .iter()
        .filter_map(|(_, username, _, _, status)| {
            (status == "rejected").then_some(username.as_str())
        })
        .collect();
    let mut required_envelopes = BTreeSet::new();
    for (user_id, member) in &next_users {
        // A rejected invitation stays in the cryptographic roster until an
        // administrator commits removal, but must never regain Welcome/Commit
        // material merely because another membership transition occurs.
        if rejected_ids.contains(user_id) {
            continue;
        }
        let device_ids: Vec<i32> = sqlx::query_scalar(
            "SELECT device_id
             FROM chat_mls_devices
             WHERE user_id = $1
             ORDER BY device_id",
        )
        .bind(user_id)
        .fetch_all(&mut **tx)
        .await?;
        if device_ids.is_empty() {
            return Err(AppError::conflict(
                "active MLS member has no manifest-bound MLS device",
            ));
        }
        let kind = if active_ids.contains(user_id) {
            MlsMembershipEnvelopeKindV1::Commit
        } else {
            MlsMembershipEnvelopeKindV1::Welcome
        };
        for device_id in device_ids {
            required_envelopes.insert((
                member.address.canonical(),
                device_id as u32,
                u16::from(kind),
            ));
        }
    }
    let supplied_after = delivery
        .envelopes
        .iter()
        .filter(|envelope| {
            next_users
                .values()
                .any(|member| member.address == envelope.recipient)
        })
        .map(|envelope| {
            (
                envelope.recipient.canonical(),
                envelope.device_id,
                u16::from(envelope.kind),
            )
        })
        .collect::<Vec<_>>();
    let supplied_set = supplied_after.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required_envelopes
        .difference(&supplied_set)
        .cloned()
        .collect::<Vec<_>>();
    let submitter_address = local_submitter
        .and_then(|user_id| next_users.get(&user_id))
        .map(|member| member.address.canonical());
    let initiator_omission = missing.len() == 1
        && submitter_address.as_deref() == Some(missing[0].0.as_str())
        && missing[0].2 == u16::from(MlsMembershipEnvelopeKindV1::Commit);
    if supplied_after.len() != supplied_set.len()
        || !supplied_set.is_subset(&required_envelopes)
        || !(missing.is_empty() || (local_submitter.is_some() && initiator_omission))
    {
        return Err(AppError::conflict(
            "MLS membership delivery does not cover every required local device exactly once",
        ));
    }

    for (user_id, _, _, _, _) in &active {
        if !next_users.contains_key(user_id) {
            sqlx::query(
                "UPDATE chat_mls_local_members
                 SET removed_epoch = $4
                 WHERE conversation_id = $1 AND incarnation = $2
                   AND user_id = $3 AND removed_epoch IS NULL",
            )
            .bind(delivery.conversation_id)
            .bind(delivery.incarnation as i64)
            .bind(user_id)
            .bind(epoch_after as i64)
            .execute(&mut **tx)
            .await?;
        }
    }
    for (user_id, member) in next_users {
        if active_ids.contains(&user_id) {
            sqlx::query(
                "UPDATE chat_mls_local_members
                 SET is_admin = $4, is_owner = $5, owner_id = $6
                 WHERE conversation_id = $1 AND incarnation = $2
                   AND user_id = $3 AND removed_epoch IS NULL",
            )
            .bind(delivery.conversation_id)
            .bind(delivery.incarnation as i64)
            .bind(user_id)
            .bind(member.is_admin)
            .bind(member.owner_id.is_some())
            .bind(&member.owner_id)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO chat_mls_local_members
                     (conversation_id, incarnation, user_id, is_admin, is_owner,
                      owner_id, membership_status, invitation_expires_at,
                      joined_epoch)
                 VALUES ($1,$2,$3,$4,$5,$6,'pending',
                         now() + interval '30 days',$7)",
            )
            .bind(delivery.conversation_id)
            .bind(delivery.incarnation as i64)
            .bind(user_id)
            .bind(member.is_admin)
            .bind(member.owner_id.is_some())
            .bind(&member.owner_id)
            .bind(epoch_after as i64)
            .execute(&mut **tx)
            .await?;
        }
    }

    for envelope in &delivery.envelopes {
        if rejected_usernames.contains(envelope.recipient.username.as_str()) {
            return Err(AppError::bad_request(
                "MLS membership envelope targets a rejected invitation",
            ));
        }
        let remains_member = delivery
            .local_members_after
            .iter()
            .any(|member| member.address == envelope.recipient);
        if !remains_member
            && (!active_usernames.contains(envelope.recipient.username.as_str())
                || envelope.kind != MlsMembershipEnvelopeKindV1::Commit)
        {
            return Err(AppError::bad_request(
                "MLS membership envelope targets neither an active nor a removed local member",
            ));
        }
        let recipient_user_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
                .bind(&envelope.recipient.username)
                .fetch_optional(&mut **tx)
                .await?;
        let recipient_user_id = recipient_user_id.ok_or_else(|| {
            AppError::conflict("MLS membership envelope recipient does not exist")
        })?;
        let device_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM chat_mls_devices
                WHERE user_id = $1 AND device_id = $2
             )",
        )
        .bind(recipient_user_id)
        .bind(envelope.device_id as i32)
        .fetch_one(&mut **tx)
        .await?;
        if !device_exists {
            return Err(AppError::conflict(
                "MLS membership envelope recipient device does not exist",
            ));
        }
        let opaque = STANDARD
            .decode(&envelope.opaque_message)
            .map_err(|_| AppError::bad_request("MLS membership envelope is invalid base64"))?;
        sqlx::query(
            "INSERT INTO chat_mls_mailbox
                 (recipient_user_id, recipient_device_id, delivery_kind,
                  conversation_id, incarnation, send_id, opaque_envelope)
             VALUES ($1,$2,'membership_control',$3,$4,$5,$6)
             ON CONFLICT (recipient_user_id, recipient_device_id, send_id)
             DO NOTHING",
        )
        .bind(recipient_user_id)
        .bind(envelope.device_id as i32)
        .bind(delivery.conversation_id)
        .bind(delivery.incarnation as i64)
        .bind(envelope.envelope_id)
        .bind(opaque)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn finalize_delivery_records(
    tx: &mut Transaction<'_, Postgres>,
    local_submitter: Option<Uuid>,
    transition: &MlsMembershipTransitionV1,
    deliveries: &BTreeMap<String, MlsMembershipDeliveryV1>,
    block_height: u64,
    block_hash: &str,
) -> AppResult<()> {
    let finalized_at = OffsetDateTime::now_utc();
    for (destination, delivery) in deliveries {
        let digest = delivery.delivery_digest().map_err(AppError::bad_request)?;
        if local_submitter.is_some() {
            let updated = sqlx::query(
                "UPDATE chat_mls_membership_deliveries
                 SET state = 'finalized', block_height = $5, block_hash = $6,
                     finalized_at = $7
                 WHERE conversation_id = $1 AND incarnation = $2
                   AND proposal_id = $3 AND destination = $4
                   AND delivery_digest = $8 AND state = 'staged'",
            )
            .bind(transition.conversation_id)
            .bind(transition.incarnation as i64)
            .bind(transition.proposal_id)
            .bind(destination)
            .bind(block_height as i64)
            .bind(block_hash)
            .bind(finalized_at)
            .bind(&digest)
            .execute(&mut **tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AppError::conflict(
                    "MLS membership delivery changed before finalization",
                ));
            }
        } else {
            let value = serde_json::to_value(delivery).map_err(|error| {
                AppError::internal(format!("serialize MLS membership delivery: {error}"))
            })?;
            let inserted = sqlx::query(
                "INSERT INTO chat_mls_membership_deliveries
                     (conversation_id, incarnation, proposal_id, destination,
                      delivery_digest, delivery, state, block_height, block_hash,
                      finalized_at)
                 VALUES ($1,$2,$3,$4,$5,$6,'finalized',$7,$8,$9)
                 ON CONFLICT (conversation_id, incarnation, proposal_id, destination)
                 DO NOTHING",
            )
            .bind(transition.conversation_id)
            .bind(transition.incarnation as i64)
            .bind(transition.proposal_id)
            .bind(destination)
            .bind(&digest)
            .bind(value)
            .bind(block_height as i64)
            .bind(block_hash)
            .bind(finalized_at)
            .execute(&mut **tx)
            .await?;
            if inserted.rows_affected() == 0 {
                let existing: Option<(String, Option<String>)> = sqlx::query_as(
                    "SELECT delivery_digest, block_hash
                     FROM chat_mls_membership_deliveries
                     WHERE conversation_id = $1 AND incarnation = $2
                       AND proposal_id = $3 AND destination = $4
                       AND state = 'finalized'",
                )
                .bind(transition.conversation_id)
                .bind(transition.incarnation as i64)
                .bind(transition.proposal_id)
                .bind(destination)
                .fetch_optional(&mut **tx)
                .await?;
                if existing.as_ref().map(|(stored_digest, stored_hash)| {
                    (stored_digest.as_str(), stored_hash.as_deref())
                }) != Some((digest.as_str(), Some(block_hash)))
                {
                    return Err(AppError::conflict(
                        "conflicting finalized MLS membership delivery exists",
                    ));
                }
            }
        }
    }
    Ok(())
}
