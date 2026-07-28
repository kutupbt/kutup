//! Atomic server materialization of an owner-approved MLS incarnation.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use kutup_chat_proto::{
    FederatedMlsRecoveryReplicaV1, MlsAuthoritySetV1, MlsConversationMemberV1,
    MlsIncarnationRecoveryV1, MlsMembershipDeliveryV1, MlsMembershipEnvelopeKindV1, MlsOwnerSetV1,
    RecoverMlsConversationResponseV1,
};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::MlsRepository;
use crate::error::{AppError, AppResult};

struct PreviousRecoveryState {
    incarnation: u64,
    genesis_hash: String,
    height: u64,
    epoch: u64,
    block_hash: Option<String>,
    roster_commitment: String,
    member_count: u32,
    participant_domains: Vec<String>,
    authority_set: MlsAuthoritySetV1,
    owner_set: MlsOwnerSetV1,
}

impl MlsRepository {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn recover_conversation(
        &self,
        local_domain: &str,
        local_submitter: Option<Uuid>,
        origin_domain: &str,
        recovery: &MlsIncarnationRecoveryV1,
        local_delivery: Option<&MlsMembershipDeliveryV1>,
        full_members: Option<&[MlsConversationMemberV1]>,
        all_deliveries: Option<&[MlsMembershipDeliveryV1]>,
        creator: Option<(&kutup_chat_proto::AccountAddress, u32)>,
        maximum_group_members: u16,
        maximum_authorities: u16,
    ) -> AppResult<RecoverMlsConversationResponseV1> {
        recovery.validate_shape().map_err(AppError::bad_request)?;
        let plan = &recovery.plan;
        if plan.new_genesis.member_count > u32::from(maximum_group_members)
            || plan.new_genesis.authority_set.authorities.len() > usize::from(maximum_authorities)
        {
            return Err(AppError::bad_request(
                "MLS recovery exceeds the local service policy",
            ));
        }
        match local_delivery {
            Some(delivery) => {
                plan.verify_delivery(delivery)
                    .map_err(AppError::bad_request)?;
                if delivery.destination != local_domain {
                    return Err(AppError::forbidden(
                        "MLS recovery delivery targets another server",
                    ));
                }
            }
            None => {}
        }
        let recovery_digest = plan.transition_digest().map_err(AppError::bad_request)?;
        let recovery_value = serde_json::to_value(recovery)
            .map_err(|error| AppError::internal(format!("serialize MLS recovery: {error}")))?;
        let mut tx = self.pool.begin().await?;

        if let Some((stored_digest, stored_new_incarnation)) = sqlx::query_as::<_, (String, i64)>(
            "SELECT recovery_digest, new_incarnation
             FROM chat_mls_incarnation_recoveries
             WHERE conversation_id = $1 AND previous_incarnation = $2",
        )
        .bind(plan.conversation_id)
        .bind(plan.previous_incarnation as i64)
        .fetch_optional(&mut *tx)
        .await?
        {
            if stored_digest != recovery_digest
                || stored_new_incarnation != plan.new_genesis.incarnation as i64
            {
                return Err(AppError::conflict(
                    "a different MLS recovery already extends this incarnation",
                ));
            }
            tx.commit().await?;
            return Ok(RecoverMlsConversationResponseV1 {
                conversation_id: plan.conversation_id,
                previous_incarnation: plan.previous_incarnation,
                incarnation: plan.new_genesis.incarnation,
                recovery_digest,
                status: "active".into(),
            });
        }

        let previous = load_previous_state(&mut tx, plan.conversation_id).await?;
        if previous.incarnation != plan.previous_incarnation {
            return Err(AppError::conflict(
                "MLS recovery does not extend the current incarnation",
            ));
        }
        if previous.genesis_hash != plan.previous_genesis_hash
            || previous.height != plan.previous_height
            || previous.epoch != plan.previous_epoch
            || previous.block_hash != plan.previous_block_hash
            || previous.roster_commitment != plan.previous_roster_commitment
            || previous.member_count != plan.new_genesis.member_count
            || previous.participant_domains != plan.participant_domains
        {
            return Err(AppError::conflict(
                "MLS recovery differs from the pinned previous public head",
            ));
        }
        recovery
            .verify(&previous.owner_set)
            .map_err(AppError::forbidden)?;
        let permitted_authorities = previous
            .participant_domains
            .iter()
            .cloned()
            .chain(
                previous
                    .authority_set
                    .authorities
                    .iter()
                    .map(|authority| authority.domain.clone()),
            )
            .collect::<BTreeSet<_>>();
        if plan
            .new_genesis
            .authority_set
            .authorities
            .iter()
            .any(|authority| !permitted_authorities.contains(&authority.domain))
        {
            return Err(AppError::forbidden(
                "V1 recovery authority lacks the previous public history",
            ));
        }

        if let Some(submitter) = local_submitter {
            let creator = creator.ok_or_else(|| {
                AppError::bad_request("local MLS recovery omits its creator binding")
            })?;
            if creator.0.server.as_deref() != Some(local_domain) {
                return Err(AppError::forbidden(
                    "local MLS recovery creator belongs to another server",
                ));
            }
            let submitted_username: String =
                sqlx::query_scalar("SELECT username FROM users WHERE id = $1 FOR UPDATE")
                    .bind(submitter)
                    .fetch_one(&mut *tx)
                    .await?;
            if creator.0.username != submitted_username {
                return Err(AppError::forbidden(
                    "authenticated MLS recovery owner differs from its creator",
                ));
            }
            let local_owner: Option<(bool, Option<String>)> = sqlx::query_as(
                "SELECT is_owner, owner_id
                 FROM chat_mls_local_members
                 WHERE conversation_id = $1 AND incarnation = $2
                   AND user_id = $3 AND removed_epoch IS NULL
                   AND membership_status = 'active'
                 FOR UPDATE",
            )
            .bind(plan.conversation_id)
            .bind(plan.previous_incarnation as i64)
            .bind(submitter)
            .fetch_optional(&mut *tx)
            .await?;
            if !local_owner.is_some_and(|(is_owner, owner_id)| {
                is_owner
                    && owner_id
                        .as_deref()
                        .is_some_and(|owner_id| previous.owner_set.owner(owner_id).is_some())
            }) {
                return Err(AppError::forbidden(
                    "MLS recovery requires a current local owner",
                ));
            }
            let creator_device_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1
                    FROM chat_mls_devices d
                    JOIN chat_device_manifests m ON m.user_id = d.user_id
                    WHERE d.user_id = $1 AND d.device_id = $2
                      AND d.manifest_version = m.version
                 )",
            )
            .bind(submitter)
            .bind(creator.1 as i32)
            .fetch_one(&mut *tx)
            .await?;
            if !creator_device_exists {
                return Err(AppError::conflict(
                    "MLS recovery creator device is not manifest-bound",
                ));
            }
            let members = full_members.ok_or_else(|| {
                AppError::bad_request("local MLS recovery omits its exact roster")
            })?;
            if members.len() != previous.member_count as usize
                || kutup_chat_proto::roster_commitment(members).map_err(AppError::bad_request)?
                    != previous.roster_commitment
            {
                return Err(AppError::bad_request(
                    "local MLS recovery roster differs from the previous commitment",
                ));
            }
        } else if !previous
            .participant_domains
            .iter()
            .any(|domain| domain == origin_domain)
        {
            return Err(AppError::forbidden(
                "MLS recovery origin did not participate in the previous incarnation",
            ));
        }

        let local_is_participant = plan
            .participant_domains
            .binary_search_by(|domain| domain.as_str().cmp(local_domain))
            .is_ok();
        let local_is_authority = plan
            .new_genesis
            .authority_set
            .authority(local_domain)
            .is_some();
        if !local_is_participant && !local_is_authority {
            return Err(AppError::forbidden(
                "server is not a destination of this MLS recovery",
            ));
        }
        if local_is_participant != local_delivery.is_some() {
            return Err(AppError::conflict(
                "participant recovery requires exactly its private delivery",
            ));
        }

        let genesis_hash = plan
            .new_genesis
            .genesis_hash()
            .map_err(AppError::bad_request)?;
        let group_id = super::decode_canonical_base64(
            "MLS recovery group id",
            &plan.new_genesis.mls_group_id,
        )?;
        sqlx::query(
            "INSERT INTO chat_mls_incarnations
                 (conversation_id, incarnation, mls_group_id, suite,
                  roster_commitment, member_count,
                  genesis_participant_domains, participant_domains,
                  authority_set_sequence, authority_set,
                  owner_set_sequence, owner_set, genesis, genesis_hash,
                  last_finalized_height, last_finalized_epoch,
                  last_block_hash, status)
             VALUES ($1,$2,$3,2,$4,$5,$6,$6,$7,$8,$9,$10,$11,$12,0,1,NULL,'active')",
        )
        .bind(plan.conversation_id)
        .bind(plan.new_genesis.incarnation as i64)
        .bind(group_id)
        .bind(&plan.new_genesis.roster_commitment)
        .bind(plan.new_genesis.member_count as i32)
        .bind(
            serde_json::to_value(&plan.participant_domains).map_err(|error| {
                AppError::internal(format!("serialize recovery participant domains: {error}"))
            })?,
        )
        .bind(plan.new_genesis.authority_set.sequence as i64)
        .bind(
            serde_json::to_value(&plan.new_genesis.authority_set).map_err(|error| {
                AppError::internal(format!("serialize recovery authorities: {error}"))
            })?,
        )
        .bind(previous.owner_set.sequence as i64)
        .bind(
            serde_json::to_value(&previous.owner_set).map_err(|error| {
                AppError::internal(format!("serialize recovery owners: {error}"))
            })?,
        )
        .bind(
            serde_json::to_value(&plan.new_genesis).map_err(|error| {
                AppError::internal(format!("serialize recovery genesis: {error}"))
            })?,
        )
        .bind(&genesis_hash)
        .execute(&mut *tx)
        .await?;

        if let Some(delivery) = local_delivery {
            apply_recovery_delivery(
                &mut tx,
                delivery,
                plan.previous_incarnation,
                local_submitter,
                creator,
            )
            .await?;
        }
        for approval in &recovery.owner_approval.approvals {
            sqlx::query(
                "INSERT INTO chat_mls_owner_approvals
                     (conversation_id, incarnation, owner_set_sequence,
                      proposal_hash, owner_id, approval)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT DO NOTHING",
            )
            .bind(plan.conversation_id)
            .bind(plan.previous_incarnation as i64)
            .bind(approval.owner_set_sequence as i64)
            .bind(&approval.proposal_hash)
            .bind(&approval.owner_id)
            .bind(serde_json::to_value(approval).map_err(|error| {
                AppError::internal(format!("serialize recovery owner approval: {error}"))
            })?)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "UPDATE chat_mls_incarnations
             SET status = 'read_only'
             WHERE conversation_id = $1 AND incarnation = $2 AND status = 'active'",
        )
        .bind(plan.conversation_id)
        .bind(plan.previous_incarnation as i64)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE chat_mls_conversations
             SET current_incarnation = $2, status = 'active', updated_at = now()
             WHERE conversation_id = $1 AND current_incarnation = $3",
        )
        .bind(plan.conversation_id)
        .bind(plan.new_genesis.incarnation as i64)
        .bind(plan.previous_incarnation as i64)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO chat_mls_incarnation_recoveries
                 (recovery_digest, conversation_id, previous_incarnation,
                  new_incarnation, proposal_id, origin_domain, initiated_by, recovery)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(&recovery_digest)
        .bind(plan.conversation_id)
        .bind(plan.previous_incarnation as i64)
        .bind(plan.new_genesis.incarnation as i64)
        .bind(plan.proposal_id)
        .bind(origin_domain)
        .bind(local_submitter)
        .bind(&recovery_value)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO chat_mls_admin_audit_events
                 (event_type, conversation_id, incarnation, evidence_digest, details)
             VALUES ('incarnation_recovery',$1,$2,$3,$4)",
        )
        .bind(plan.conversation_id)
        .bind(plan.new_genesis.incarnation as i64)
        .bind(&recovery_digest)
        .bind(serde_json::json!({
            "previousIncarnation": plan.previous_incarnation,
            "newIncarnation": plan.new_genesis.incarnation,
            "previousGenesisHash": plan.previous_genesis_hash,
            "authorityCount": plan.new_genesis.authority_set.authorities.len(),
            "memberCount": plan.new_genesis.member_count,
        }))
        .execute(&mut *tx)
        .await?;

        if local_submitter.is_some() {
            let all_deliveries = all_deliveries.ok_or_else(|| {
                AppError::bad_request("local MLS recovery omits its private deliveries")
            })?;
            enqueue_recovery_replicas(
                &mut tx,
                local_domain,
                &recovery_digest,
                recovery,
                all_deliveries,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(RecoverMlsConversationResponseV1 {
            conversation_id: plan.conversation_id,
            previous_incarnation: plan.previous_incarnation,
            incarnation: plan.new_genesis.incarnation,
            recovery_digest,
            status: "active".into(),
        })
    }
}

async fn load_previous_state(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> AppResult<PreviousRecoveryState> {
    let row: Option<(
        i64,
        String,
        i64,
        i64,
        Option<String>,
        String,
        i32,
        Value,
        Value,
        Value,
    )> = sqlx::query_as(
        "SELECT i.incarnation, i.genesis_hash, i.last_finalized_height,
                i.last_finalized_epoch, i.last_block_hash,
                i.roster_commitment, i.member_count, i.participant_domains,
                i.authority_set, i.owner_set
         FROM chat_mls_conversations c
         JOIN chat_mls_incarnations i
           ON i.conversation_id = c.conversation_id
          AND i.incarnation = c.current_incarnation
         WHERE c.conversation_id = $1 AND c.status = 'active'
           AND i.status = 'active'
         FOR UPDATE OF c, i",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((
        incarnation,
        genesis_hash,
        height,
        epoch,
        block_hash,
        roster_commitment,
        member_count,
        participant_domains,
        authority_set,
        owner_set,
    )) = row
    else {
        return Err(AppError::not_found(
            "active MLS conversation is unavailable",
        ));
    };
    Ok(PreviousRecoveryState {
        incarnation: incarnation as u64,
        genesis_hash,
        height: height as u64,
        epoch: epoch as u64,
        block_hash,
        roster_commitment,
        member_count: member_count as u32,
        participant_domains: serde_json::from_value(participant_domains).map_err(|error| {
            AppError::internal(format!(
                "stored MLS participant domains are invalid: {error}"
            ))
        })?,
        authority_set: serde_json::from_value(authority_set).map_err(|error| {
            AppError::internal(format!("stored MLS authority set is invalid: {error}"))
        })?,
        owner_set: serde_json::from_value(owner_set).map_err(|error| {
            AppError::internal(format!("stored MLS owner set is invalid: {error}"))
        })?,
    })
}

async fn apply_recovery_delivery(
    tx: &mut Transaction<'_, Postgres>,
    delivery: &MlsMembershipDeliveryV1,
    previous_incarnation: u64,
    local_submitter: Option<Uuid>,
    creator: Option<(&kutup_chat_proto::AccountAddress, u32)>,
) -> AppResult<()> {
    let mut users = BTreeMap::<String, Uuid>::new();
    let mut required = BTreeSet::new();
    for member in &delivery.local_members_after {
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT u.id
             FROM users u
             JOIN chat_mls_local_members m ON m.user_id = u.id
             WHERE u.username = $1 AND u.is_active = true
               AND m.conversation_id = $2 AND m.incarnation = $3
               AND m.removed_epoch IS NULL AND m.membership_status = 'active'",
        )
        .bind(&member.address.username)
        .bind(delivery.conversation_id)
        .bind(previous_incarnation as i64)
        .fetch_optional(&mut **tx)
        .await?;
        let user_id = user_id.ok_or_else(|| {
            AppError::conflict("recovered local member was not active in the prior incarnation")
        })?;
        let device_ids = delivery
            .local_devices_after
            .iter()
            .filter_map(|device| {
                (device.address == member.address).then_some(device.device_id as i32)
            })
            .collect::<Vec<_>>();
        if device_ids.is_empty() {
            return Err(AppError::conflict(
                "recovered local member has no manifest-bound MLS device",
            ));
        }
        for device_id in device_ids {
            let manifest_bound: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1
                    FROM chat_mls_devices d
                    JOIN chat_device_manifests m ON m.user_id = d.user_id
                    WHERE d.user_id = $1 AND d.device_id = $2
                      AND d.manifest_version = m.version
                 )",
            )
            .bind(user_id)
            .bind(device_id)
            .fetch_one(&mut **tx)
            .await?;
            if !manifest_bound {
                return Err(AppError::conflict(
                    "recovered MLS leaf is absent from the current signed manifest",
                ));
            }
            let omitted_creator = local_submitter == Some(user_id)
                && creator.is_some_and(|(address, creator_device)| {
                    address == &member.address && creator_device == device_id as u32
                });
            if !omitted_creator {
                required.insert((member.address.canonical(), device_id as u32));
            }
        }
        users.insert(member.address.canonical(), user_id);
    }
    let supplied = delivery
        .envelopes
        .iter()
        .map(|envelope| {
            if envelope.kind != MlsMembershipEnvelopeKindV1::Welcome {
                return Err(AppError::bad_request(
                    "MLS recovery delivery may contain only Welcome envelopes",
                ));
            }
            Ok((envelope.recipient.canonical(), envelope.device_id))
        })
        .collect::<AppResult<BTreeSet<_>>>()?;
    if supplied != required || supplied.len() != delivery.envelopes.len() {
        return Err(AppError::conflict(
            "MLS recovery delivery does not cover every local device exactly once",
        ));
    }

    for member in &delivery.local_members_after {
        let user_id = users[&member.address.canonical()];
        sqlx::query(
            "INSERT INTO chat_mls_local_members
                 (conversation_id, incarnation, user_id, is_admin, is_owner,
                  owner_id, membership_status, joined_epoch)
             VALUES ($1,$2,$3,$4,$5,$6,'active',1)",
        )
        .bind(delivery.conversation_id)
        .bind(delivery.incarnation as i64)
        .bind(user_id)
        .bind(member.is_admin)
        .bind(member.owner_id.is_some())
        .bind(&member.owner_id)
        .execute(&mut **tx)
        .await?;
    }
    for device in &delivery.local_devices_after {
        let user_id = users[&device.address.canonical()];
        sqlx::query(
            "INSERT INTO chat_mls_local_member_devices
                 (conversation_id, incarnation, user_id, device_id, joined_epoch)
             VALUES ($1,$2,$3,$4,1)",
        )
        .bind(delivery.conversation_id)
        .bind(delivery.incarnation as i64)
        .bind(user_id)
        .bind(device.device_id as i32)
        .execute(&mut **tx)
        .await?;
    }
    for envelope in &delivery.envelopes {
        let user_id = users[&envelope.recipient.canonical()];
        let opaque = base64::engine::general_purpose::STANDARD
            .decode(&envelope.opaque_message)
            .map_err(|_| AppError::bad_request("MLS recovery Welcome is invalid base64"))?;
        sqlx::query(
            "INSERT INTO chat_mls_mailbox
                 (id, recipient_user_id, recipient_device_id, delivery_kind,
                  conversation_id, incarnation, send_id, opaque_envelope)
             VALUES ($1,$2,$3,'membership_control',$4,$5,$1,$6)
             ON CONFLICT (recipient_user_id, recipient_device_id, send_id) DO NOTHING",
        )
        .bind(envelope.envelope_id)
        .bind(user_id)
        .bind(envelope.device_id as i32)
        .bind(delivery.conversation_id)
        .bind(delivery.incarnation as i64)
        .bind(opaque)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn enqueue_recovery_replicas(
    tx: &mut Transaction<'_, Postgres>,
    local_domain: &str,
    recovery_digest: &str,
    recovery: &MlsIncarnationRecoveryV1,
    deliveries: &[MlsMembershipDeliveryV1],
) -> AppResult<()> {
    let plan = &recovery.plan;
    let destinations = plan
        .participant_domains
        .iter()
        .cloned()
        .chain(
            plan.new_genesis
                .authority_set
                .authorities
                .iter()
                .map(|authority| authority.domain.clone()),
        )
        .collect::<BTreeSet<_>>();
    for destination in destinations {
        if destination == local_domain {
            continue;
        }
        let membership_delivery = deliveries
            .iter()
            .find(|delivery| delivery.destination == destination)
            .cloned();
        let replica = FederatedMlsRecoveryReplicaV1 {
            recovery: recovery.clone(),
            membership_delivery,
        };
        replica.validate_shape().map_err(AppError::internal)?;
        if plan.delivery_commitment(&destination).is_some() != replica.membership_delivery.is_some()
        {
            return Err(AppError::internal(
                "validated MLS recovery omitted a participant delivery",
            ));
        }
        sqlx::query(
            "INSERT INTO chat_mls_recovery_outbox
                 (destination, recovery_digest, conversation_id,
                  previous_incarnation, replica)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&destination)
        .bind(recovery_digest)
        .bind(plan.conversation_id)
        .bind(plan.previous_incarnation as i64)
        .bind(serde_json::to_value(replica).map_err(|error| {
            AppError::internal(format!("serialize MLS recovery replica: {error}"))
        })?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
