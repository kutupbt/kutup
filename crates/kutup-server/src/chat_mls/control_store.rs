//! Atomic finalized-control persistence and purpose-scoped ordering votes.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kutup_chat_proto::{
    CommitMlsControlBlockResponseV1, CommitMlsControlBlockV1, FederatedMlsControlReplicaV1,
    FederatedMlsOrderingVoteRequestV1, MlsAuthoritySetV1, MlsControlActionTypeV1,
    MlsMembershipDeliveryV1, MlsOrderingVoteTypeV1, MlsOrderingVoteV1, MlsOwnerSetV1,
};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    decode_canonical_base64, prepare_membership_finalization, MlsOrderingService, MlsRepository,
};
use crate::error::{AppError, AppResult};

impl MlsRepository {
    pub(super) async fn commit_control_block(
        &self,
        local_domain: &str,
        local_submitter: Option<Uuid>,
        federated_origin: Option<&str>,
        request: &CommitMlsControlBlockV1,
        incoming_membership_delivery: Option<&MlsMembershipDeliveryV1>,
        maximum_group_members: u16,
        verified_history_replay: bool,
    ) -> AppResult<CommitMlsControlBlockResponseV1> {
        request.validate_shape().map_err(AppError::bad_request)?;
        let block = &request.finalized.block;
        block.proposal.verify().map_err(AppError::bad_request)?;
        if block.proposal.action_type == MlsControlActionTypeV1::RecoverIncarnation {
            return Err(AppError::conflict(
                "MLS incarnation recovery must create a new append-only incarnation",
            ));
        }
        let block_hash = block.block_hash().map_err(AppError::bad_request)?;
        let mut tx = self.pool.begin().await?;
        if !verified_history_replay {
            let bootstrap_in_progress: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM chat_mls_authority_bootstraps
                    WHERE conversation_id = $1 AND incarnation = $2
                      AND state IN ('receiving', 'verified')
                 )",
            )
            .bind(block.conversation_id)
            .bind(block.incarnation as i64)
            .fetch_one(&mut *tx)
            .await?;
            if bootstrap_in_progress {
                return Err(AppError::conflict(
                    "MLS authority bootstrap must materialize completely before new control",
                ));
            }
        }
        let row: Option<(
            i16,
            Value,
            Option<Value>,
            Value,
            String,
            i32,
            i64,
            i64,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT c.kind, i.authority_set, i.owner_set, i.participant_domains,
                        i.roster_commitment, i.member_count,
                        i.last_finalized_height, i.last_finalized_epoch,
                        i.last_block_hash, i.status
                 FROM chat_mls_conversations c
                 JOIN chat_mls_incarnations i
                   ON i.conversation_id = c.conversation_id
                  AND i.incarnation = c.current_incarnation
                 WHERE c.conversation_id = $1 AND i.incarnation = $2
                 FOR UPDATE OF c, i",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .fetch_optional(&mut *tx)
        .await?;
        let (
            conversation_kind,
            authority_value,
            owner_value,
            participant_value,
            current_roster_commitment,
            current_member_count,
            last_height,
            last_epoch,
            last_hash,
            incarnation_status,
        ) = row.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
        let participant_domains: Vec<String> =
            serde_json::from_value(participant_value).map_err(|error| {
                AppError::internal(format!("stored MLS participant domains invalid: {error}"))
            })?;
        let current_member_count = u32::try_from(current_member_count)
            .map_err(|_| AppError::internal("stored MLS member count is invalid"))?;
        if block.height as i64 <= last_height {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT block_hash
                 FROM chat_mls_control_blocks
                 WHERE conversation_id = $1 AND incarnation = $2 AND height = $3",
            )
            .bind(block.conversation_id)
            .bind(block.incarnation as i64)
            .bind(block.height as i64)
            .fetch_optional(&mut *tx)
            .await?;
            if existing.as_deref() == Some(&block_hash) {
                tx.commit().await?;
                return Ok(CommitMlsControlBlockResponseV1 {
                    conversation_id: block.conversation_id,
                    incarnation: block.incarnation,
                    height: block.height,
                    epoch: block.epoch_after,
                    block_hash,
                    idempotent: true,
                });
            }
            return Err(AppError::conflict(
                "conflicting MLS control block exists at this height",
            ));
        }
        if let Some(origin) = federated_origin {
            if participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(origin))
                .is_err()
            {
                return Err(AppError::forbidden(
                    "federation origin is not a participant server",
                ));
            }
        }
        if let Some(local_submitter) = local_submitter {
            let local_member: Option<(bool, bool)> = sqlx::query_as(
                "SELECT is_admin, is_owner
                 FROM chat_mls_local_members
                 WHERE conversation_id = $1 AND incarnation = $2
                   AND user_id = $3 AND removed_epoch IS NULL
                   AND membership_status = 'active'",
            )
            .bind(block.conversation_id)
            .bind(block.incarnation as i64)
            .bind(local_submitter)
            .fetch_optional(&mut *tx)
            .await?;
            let (is_admin, is_owner) = local_member
                .ok_or_else(|| AppError::forbidden("not an active local MLS member"))?;
            if matches!(
                block.proposal.action_type,
                MlsControlActionTypeV1::RoutineAdmin
                    | MlsControlActionTypeV1::MembershipChange
                    | MlsControlActionTypeV1::AuthoritySetChange
            ) && !is_admin
            {
                return Err(AppError::forbidden(
                    "MLS routine, membership, and authority finalization requires a local administrator",
                ));
            }
            if block.proposal.action_type.requires_owner_quorum() && !is_owner {
                return Err(AppError::forbidden(
                    "MLS security-governance finalization requires a current local owner",
                ));
            }
        }
        if incarnation_status != "active" {
            return Err(AppError::conflict("MLS incarnation is not writable"));
        }

        if block.height as i64 != last_height + 1
            || block.epoch_before as i64 != last_epoch
            || block.previous_block_hash.as_deref() != last_hash.as_deref()
        {
            return Err(AppError::conflict(
                "MLS control block is not the exact next height and epoch",
            ));
        }

        let authorities: MlsAuthoritySetV1 =
            serde_json::from_value(authority_value).map_err(|error| {
                AppError::internal(format!("stored MLS authorities invalid: {error}"))
            })?;
        request
            .finalized
            .verify(&authorities)
            .map_err(AppError::bad_request)?;
        let owners: Option<MlsOwnerSetV1> = owner_value
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| AppError::internal(format!("stored MLS owners invalid: {error}")))?;
        if conversation_kind == 3 && block.proposal.action_type.requires_owner_quorum() {
            let owners = owners
                .as_ref()
                .ok_or_else(|| AppError::internal("group MLS owner set is absent"))?;
            block
                .owner_approval
                .as_ref()
                .ok_or_else(|| {
                    AppError::bad_request(
                        "security-sensitive group control requires owner approval",
                    )
                })?
                .verify(&block.proposal, block.transition_digest.as_deref(), owners)
                .map_err(AppError::bad_request)?;
        } else if let (Some(certificate), Some(owners)) = (&block.owner_approval, &owners) {
            certificate
                .verify(&block.proposal, block.transition_digest.as_deref(), owners)
                .map_err(AppError::bad_request)?;
        }

        let mut next_authorities = None;
        if block.proposal.action_type == MlsControlActionTypeV1::AuthoritySetChange {
            let next = request
                .authority_change
                .as_ref()
                .expect("validated authority transition shape")
                .next_authority_set
                .clone();
            request
                .authority_transition
                .as_ref()
                .expect("validated authority transition shape")
                .verify(&block_hash, &authorities, &next)
                .map_err(AppError::bad_request)?;
            next_authorities =
                Some(serde_json::to_value(&next).map_err(|error| {
                    AppError::internal(format!("serialize authorities: {error}"))
                })?);
        }

        let mut next_owners = None;
        if block.proposal.action_type == MlsControlActionTypeV1::OwnerSetChange {
            let current = owners
                .as_ref()
                .ok_or_else(|| AppError::internal("group MLS owner set is absent"))?;
            let next = request
                .owner_change
                .as_ref()
                .expect("validated owner transition shape")
                .next_owner_set
                .clone();
            next.validate().map_err(AppError::bad_request)?;
            if current.sequence.checked_add(1) != Some(next.sequence) {
                return Err(AppError::bad_request(
                    "MLS owner-set sequence must advance by exactly one",
                ));
            }
            next_owners = Some(
                serde_json::to_value(&next)
                    .map_err(|error| AppError::internal(format!("serialize owners: {error}")))?,
            );
        }

        let membership = prepare_membership_finalization(
            &mut tx,
            local_domain,
            local_submitter,
            incoming_membership_delivery,
            request,
            conversation_kind,
            &current_roster_commitment,
            current_member_count,
            &participant_domains,
            maximum_group_members,
            verified_history_replay,
        )
        .await?;

        for vote in &request.finalized.quorum_certificate.votes {
            insert_ordering_vote(&mut tx, vote).await?;
        }
        if let Some(transition) = &request.authority_transition {
            for vote in &transition.new_set_certificate.votes {
                insert_ordering_vote(&mut tx, vote).await?;
            }
        }
        if let Some(certificate) = &block.owner_approval {
            for approval in &certificate.approvals {
                sqlx::query(
                    "INSERT INTO chat_mls_owner_approvals
                         (conversation_id, incarnation, owner_set_sequence,
                          proposal_hash, owner_id, approval)
                     VALUES ($1,$2,$3,$4,$5,$6)",
                )
                .bind(approval.conversation_id)
                .bind(approval.incarnation as i64)
                .bind(approval.owner_set_sequence as i64)
                .bind(&approval.proposal_hash)
                .bind(&approval.owner_id)
                .bind(serde_json::to_value(approval).map_err(|error| {
                    AppError::internal(format!("serialize owner approval: {error}"))
                })?)
                .execute(&mut *tx)
                .await?;
            }
        }

        let finalized_at = OffsetDateTime::from_unix_timestamp(block.finalized_at)
            .map_err(|_| AppError::bad_request("MLS finalizedAt is outside supported time"))?;
        let commit_request_value = serde_json::to_value(request).map_err(|error| {
            AppError::internal(format!("serialize MLS commit request: {error}"))
        })?;
        sqlx::query(
            "INSERT INTO chat_mls_control_blocks
                 (conversation_id, incarnation, height, block_hash, previous_hash,
                  epoch_before, epoch_after, block, quorum_certificate,
                  commit_request, finalized_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .bind(block.height as i64)
        .bind(&block_hash)
        .bind(&block.previous_block_hash)
        .bind(block.epoch_before as i64)
        .bind(block.epoch_after as i64)
        .bind(
            serde_json::to_value(block).map_err(|error| {
                AppError::internal(format!("serialize MLS control block: {error}"))
            })?,
        )
        .bind(
            serde_json::to_value(&request.finalized.quorum_certificate).map_err(|error| {
                AppError::internal(format!("serialize MLS quorum certificate: {error}"))
            })?,
        )
        .bind(&commit_request_value)
        .bind(finalized_at)
        .execute(&mut *tx)
        .await?;

        let closed = block.proposal.action_type == MlsControlActionTypeV1::CloseConversation;
        sqlx::query(
            "UPDATE chat_mls_incarnations
             SET last_finalized_height = $3,
                 last_finalized_epoch = $4,
                 last_block_hash = $5,
                 authority_set_sequence =
                     COALESCE($6, authority_set_sequence),
                 authority_set = COALESCE($7, authority_set),
                 owner_set_sequence = COALESCE($8, owner_set_sequence),
                 owner_set = COALESCE($9, owner_set),
                 roster_commitment = COALESCE($10, roster_commitment),
                 member_count = COALESCE($11, member_count),
                 participant_domains = COALESCE($12, participant_domains),
                 status = CASE WHEN $13 THEN 'closed' ELSE status END
             WHERE conversation_id = $1 AND incarnation = $2",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .bind(block.height as i64)
        .bind(block.epoch_after as i64)
        .bind(&block_hash)
        .bind(
            request
                .authority_change
                .as_ref()
                .map(|change| change.next_authority_set.sequence as i64),
        )
        .bind(next_authorities)
        .bind(
            request
                .owner_change
                .as_ref()
                .map(|change| change.next_owner_set.sequence as i64),
        )
        .bind(next_owners)
        .bind(
            membership
                .as_ref()
                .map(|membership| membership.next_roster_commitment.as_str()),
        )
        .bind(
            membership
                .as_ref()
                .map(|membership| membership.next_member_count as i32),
        )
        .bind(
            membership
                .as_ref()
                .map(|membership| {
                    serde_json::to_value(&membership.next_participant_domains).map_err(|error| {
                        AppError::internal(format!("serialize MLS participant domains: {error}"))
                    })
                })
                .transpose()?,
        )
        .bind(closed)
        .execute(&mut *tx)
        .await?;
        if closed {
            sqlx::query(
                "UPDATE chat_mls_conversations
                 SET status = 'closed', updated_at = now()
                 WHERE conversation_id = $1",
            )
            .bind(block.conversation_id)
            .execute(&mut *tx)
            .await?;
        }
        if block.proposal.action_type.requires_owner_quorum() {
            let event_type = match block.proposal.action_type {
                MlsControlActionTypeV1::OwnerSetChange => "owner_change",
                MlsControlActionTypeV1::AuthoritySetChange => "authority_change",
                MlsControlActionTypeV1::CloseConversation => "conversation_close",
                MlsControlActionTypeV1::RecoverIncarnation => "incarnation_recovery",
                _ => "policy_change",
            };
            sqlx::query(
                "INSERT INTO chat_mls_admin_audit_events
                     (event_type, conversation_id, incarnation, details)
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(event_type)
            .bind(block.conversation_id)
            .bind(block.incarnation as i64)
            .bind(serde_json::json!({
                "height": block.height,
                "epoch": block.epoch_after,
                "blockHash": block_hash,
            }))
            .execute(&mut *tx)
            .await?;
        }
        if local_submitter.is_some() {
            let mut destinations = participant_domains.into_iter().collect::<BTreeSet<_>>();
            if let Some(membership) = &membership {
                destinations.extend(membership.next_participant_domains.iter().cloned());
            }
            destinations.extend(
                authorities
                    .authorities
                    .iter()
                    .map(|authority| authority.domain.clone()),
            );
            if let Some(next) = request
                .authority_change
                .as_ref()
                .map(|change| &change.next_authority_set)
            {
                destinations.extend(
                    next.authorities
                        .iter()
                        .map(|authority| authority.domain.clone()),
                );
            }
            for destination in destinations {
                if destination == local_domain {
                    continue;
                }
                let replica = FederatedMlsControlReplicaV1 {
                    commit: request.clone(),
                    membership_delivery: membership
                        .as_ref()
                        .and_then(|membership| membership.deliveries.get(&destination).cloned()),
                };
                replica.validate().map_err(AppError::internal)?;
                sqlx::query(
                    "INSERT INTO chat_mls_control_outbox
                         (destination, conversation_id, incarnation, height,
                          block_hash, commit_request)
                     VALUES ($1,$2,$3,$4,$5,$6)
                     ON CONFLICT (
                         destination, conversation_id, incarnation, height
                     ) DO NOTHING",
                )
                .bind(destination)
                .bind(block.conversation_id)
                .bind(block.incarnation as i64)
                .bind(block.height as i64)
                .bind(&block_hash)
                .bind(serde_json::to_value(replica).map_err(|error| {
                    AppError::internal(format!("serialize MLS control replica: {error}"))
                })?)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(CommitMlsControlBlockResponseV1 {
            conversation_id: block.conversation_id,
            incarnation: block.incarnation,
            height: block.height,
            epoch: block.epoch_after,
            block_hash,
            idempotent: false,
        })
    }

    pub(super) async fn cast_ordering_vote(
        &self,
        authenticated_origin: &str,
        local_domain: &str,
        ordering: &MlsOrderingService,
        request: &FederatedMlsOrderingVoteRequestV1,
    ) -> AppResult<MlsOrderingVoteV1> {
        request.validate().map_err(AppError::bad_request)?;
        if decode_canonical_base64(
            "encrypted MLS control payload",
            &request.block.proposal.encrypted_payload,
        )?
        .len()
            > ordering.policy().maximum_control_payload_bytes as usize
        {
            return Err(AppError::bad_request(
                "MLS control payload exceeds local ordering policy",
            ));
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if request.block.finalized_at > now + 5 * 60
            || request.block.proposal.created_at > now + 5 * 60
        {
            return Err(AppError::bad_request(
                "MLS control timestamps are too far in the future",
            ));
        }

        let block = &request.block;
        let block_hash = block.block_hash().map_err(AppError::bad_request)?;
        let mut tx = self.pool.begin().await?;
        let bootstrap_in_progress: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM chat_mls_authority_bootstraps
                WHERE conversation_id = $1 AND incarnation = $2
                  AND state IN ('receiving', 'verified')
             )",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .fetch_one(&mut *tx)
        .await?;
        if bootstrap_in_progress {
            return Err(AppError::conflict(
                "MLS authority bootstrap must materialize completely before voting",
            ));
        }
        let row: Option<(
            i16,
            Value,
            Option<Value>,
            Value,
            i64,
            i64,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT c.kind, i.authority_set, i.owner_set, i.participant_domains,
                        i.last_finalized_height, i.last_finalized_epoch,
                        i.last_block_hash, i.status
                 FROM chat_mls_conversations c
                 JOIN chat_mls_incarnations i
                   ON i.conversation_id = c.conversation_id
                  AND i.incarnation = c.current_incarnation
                 WHERE c.conversation_id = $1 AND i.incarnation = $2
                 FOR UPDATE OF c, i",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .fetch_optional(&mut *tx)
        .await?;
        let (
            conversation_kind,
            authority_value,
            owner_value,
            participant_value,
            last_height,
            last_epoch,
            last_hash,
            status,
        ) = row.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
        if status != "active" {
            return Err(AppError::conflict("MLS incarnation is not writable"));
        }
        let participant_domains: Vec<String> =
            serde_json::from_value(participant_value).map_err(|error| {
                AppError::internal(format!("stored MLS participant domains invalid: {error}"))
            })?;
        if participant_domains
            .binary_search_by(|domain| domain.as_str().cmp(authenticated_origin))
            .is_err()
        {
            return Err(AppError::forbidden(
                "federation origin is not a participant server",
            ));
        }
        if block.height as i64 != last_height + 1
            || block.epoch_before as i64 != last_epoch
            || block.previous_block_hash.as_deref() != last_hash.as_deref()
        {
            return Err(AppError::conflict(
                "MLS vote request is not for the exact next block",
            ));
        }

        let current_authorities: MlsAuthoritySetV1 = serde_json::from_value(authority_value)
            .map_err(|error| {
                AppError::internal(format!("stored MLS authorities invalid: {error}"))
            })?;
        if request.authority_set != current_authorities {
            let change = request
                .authority_change
                .as_ref()
                .ok_or_else(|| AppError::bad_request("MLS authority transition is absent"))?;
            let expected_transition_digest =
                change.transition_digest().map_err(AppError::bad_request)?;
            if block.proposal.action_type != MlsControlActionTypeV1::AuthoritySetChange
                || current_authorities.sequence.checked_add(1)
                    != Some(request.authority_set.sequence)
                || request.authority_set != change.next_authority_set
                || block.transition_digest.as_deref() != Some(expected_transition_digest.as_str())
            {
                return Err(AppError::bad_request(
                    "MLS vote requested under an unauthorized authority set",
                ));
            }
            request
                .previous_set_certificate
                .as_ref()
                .ok_or_else(|| {
                    AppError::bad_request(
                        "next-set MLS vote requires the current-set quorum certificate",
                    )
                })?
                .verify(&current_authorities)
                .map_err(AppError::bad_request)?;
        } else if request.previous_set_certificate.is_some() {
            return Err(AppError::bad_request(
                "current-set MLS vote must not carry a previous-set certificate",
            ));
        }
        let local_authority = request
            .authority_set
            .authority(local_domain)
            .ok_or_else(|| AppError::forbidden("this server is not an MLS authority"))?;
        if local_authority.key_id != ordering.signer().key_id()
            || local_authority.public_key != ordering.signer().public_key()
        {
            return Err(AppError::conflict(
                "authenticated MLS policy key does not match the authority set",
            ));
        }

        let owners: Option<MlsOwnerSetV1> = owner_value
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| AppError::internal(format!("stored MLS owners invalid: {error}")))?;
        if conversation_kind == 3 && block.proposal.action_type.requires_owner_quorum() {
            let owners = owners
                .as_ref()
                .ok_or_else(|| AppError::internal("group MLS owner set is absent"))?;
            block
                .owner_approval
                .as_ref()
                .ok_or_else(|| {
                    AppError::bad_request(
                        "security-sensitive group control requires owner approval",
                    )
                })?
                .verify(&block.proposal, block.transition_digest.as_deref(), owners)
                .map_err(AppError::bad_request)?;
        }

        let existing: Option<(String, Value)> = sqlx::query_as(
            "SELECT block_hash, vote
             FROM chat_mls_ordering_votes
             WHERE conversation_id = $1 AND incarnation = $2
               AND authority_set_sequence = $3 AND height = $4
               AND vote_type = 2 AND authority_domain = $5
             ORDER BY round
             LIMIT 1",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .bind(request.authority_set.sequence as i64)
        .bind(block.height as i64)
        .bind(local_domain)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((existing_hash, value)) = existing {
            if existing_hash != block_hash {
                return Err(AppError::conflict(
                    "MLS authority already voted for another block at this height",
                ));
            }
            let vote = serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored MLS ordering vote invalid: {error}"))
            })?;
            tx.commit().await?;
            return Ok(vote);
        }

        let mut vote = MlsOrderingVoteV1 {
            conversation_id: block.conversation_id,
            incarnation: block.incarnation,
            authority_set_sequence: request.authority_set.sequence,
            height: block.height,
            round: 0,
            vote_type: MlsOrderingVoteTypeV1::Precommit,
            block_hash,
            authority_domain: local_domain.to_owned(),
            authority_key_id: ordering.signer().key_id(),
            signature: String::new(),
        };
        vote.signature = STANDARD.encode(
            ordering
                .signer()
                .sign_mls_control(&vote.signing_bytes().map_err(AppError::bad_request)?)
                .map_err(AppError::internal)?,
        );
        vote.verify(&request.authority_set)
            .map_err(AppError::internal)?;
        insert_ordering_vote(&mut tx, &vote).await?;
        tx.commit().await?;
        Ok(vote)
    }
}

async fn insert_ordering_vote(
    tx: &mut Transaction<'_, Postgres>,
    vote: &kutup_chat_proto::MlsOrderingVoteV1,
) -> AppResult<()> {
    let vote_type = match vote.vote_type {
        MlsOrderingVoteTypeV1::Prevote => 1i16,
        MlsOrderingVoteTypeV1::Precommit => 2,
    };
    let encoded_vote = serde_json::to_value(vote)
        .map_err(|error| AppError::internal(format!("serialize MLS vote: {error}")))?;
    let result = sqlx::query(
        "INSERT INTO chat_mls_ordering_votes
             (conversation_id, incarnation, authority_set_sequence,
              height, round, vote_type, block_hash, authority_domain,
              authority_key_id, vote)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (
             conversation_id, incarnation, authority_set_sequence,
             height, round, vote_type, authority_domain
         ) DO NOTHING",
    )
    .bind(vote.conversation_id)
    .bind(vote.incarnation as i64)
    .bind(vote.authority_set_sequence as i64)
    .bind(vote.height as i64)
    .bind(vote.round as i32)
    .bind(vote_type)
    .bind(&vote.block_hash)
    .bind(&vote.authority_domain)
    .bind(&vote.authority_key_id)
    .bind(&encoded_vote)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() == 0 {
        let existing: Option<(String, String, Value)> = sqlx::query_as(
            "SELECT block_hash, authority_key_id, vote
             FROM chat_mls_ordering_votes
             WHERE conversation_id = $1 AND incarnation = $2
               AND authority_set_sequence = $3 AND height = $4
               AND round = $5 AND vote_type = $6 AND authority_domain = $7",
        )
        .bind(vote.conversation_id)
        .bind(vote.incarnation as i64)
        .bind(vote.authority_set_sequence as i64)
        .bind(vote.height as i64)
        .bind(vote.round as i32)
        .bind(vote_type)
        .bind(&vote.authority_domain)
        .fetch_optional(&mut **tx)
        .await?;
        let (block_hash, authority_key_id, stored_vote) = existing.ok_or_else(|| {
            AppError::internal("conflicting MLS vote disappeared during idempotency check")
        })?;
        if block_hash != vote.block_hash
            || authority_key_id != vote.authority_key_id
            || stored_vote != encoded_vote
        {
            return Err(AppError::conflict(
                "MLS authority equivocation detected for this height and round",
            ));
        }
    }
    Ok(())
}
