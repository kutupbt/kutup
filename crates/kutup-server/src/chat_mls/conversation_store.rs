//! Durable MLS conversation genesis and destination-local roster creation.

use kutup_chat_proto::{
    CreateMlsConversationRequestV1, CreateMlsConversationResponseV1, MlsConversationKindV1,
};
use serde_json::Value;
use uuid::Uuid;

use super::{decode_canonical_base64, validate_participant_domains, MlsRepository};
use crate::error::{AppError, AppResult};

impl MlsRepository {
    pub(super) async fn create_conversation(
        &self,
        creator_user_id: Option<Uuid>,
        server_name: &str,
        request: &CreateMlsConversationRequestV1,
        participant_domains: &[String],
        maximum_group_members: u16,
    ) -> AppResult<CreateMlsConversationResponseV1> {
        if creator_user_id.is_some() {
            request.validate().map_err(AppError::bad_request)?;
            validate_participant_domains(&request.members, participant_domains)?;
        } else {
            request.genesis.validate().map_err(AppError::bad_request)?;
            validate_participant_domains(&[], participant_domains)?;
            let mut previous = None;
            for member in &request.members {
                member.validate().map_err(AppError::bad_request)?;
                if member.address.server.as_deref() != Some(server_name) {
                    return Err(AppError::forbidden(
                        "replicated MLS genesis contains a non-local member",
                    ));
                }
                let address = member.address.canonical();
                if previous
                    .as_ref()
                    .is_some_and(|prior: &String| address <= *prior)
                {
                    return Err(AppError::bad_request(
                        "replicated MLS local members are not strictly ordered",
                    ));
                }
                previous = Some(address);
            }
        }
        if request.genesis.kind == MlsConversationKindV1::Group
            && request.genesis.member_count > u32::from(maximum_group_members)
        {
            return Err(AppError::bad_request(
                "MLS group exceeds the local service policy",
            ));
        }
        let genesis_hash = request
            .genesis
            .genesis_hash()
            .map_err(AppError::bad_request)?;
        let group_id = decode_canonical_base64("MLS group id", &request.genesis.mls_group_id)?;
        let genesis_value = serde_json::to_value(&request.genesis)
            .map_err(|error| AppError::internal(format!("serialize MLS genesis: {error}")))?;
        let authority_value = serde_json::to_value(&request.genesis.authority_set)
            .map_err(|error| AppError::internal(format!("serialize MLS authorities: {error}")))?;
        let owner_value = request
            .genesis
            .owner_set
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| AppError::internal(format!("serialize MLS owners: {error}")))?;
        let kind_code = match request.genesis.kind {
            MlsConversationKindV1::SelfSync => 1i16,
            MlsConversationKindV1::Direct => 2,
            MlsConversationKindV1::Group => 3,
        };

        let mut tx = self.pool.begin().await?;
        if let Some(creator_user_id) = creator_user_id {
            let creator_username: String =
                sqlx::query_scalar("SELECT username FROM users WHERE id = $1 FOR UPDATE")
                    .bind(creator_user_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let creator_address = format!("{creator_username}@{server_name}");
            if !request
                .members
                .iter()
                .any(|member| member.address.canonical() == creator_address)
            {
                return Err(AppError::forbidden(
                    "MLS conversation creator must be in the initial roster",
                ));
            }
        }

        let existing: Option<(i64, String, Value)> = sqlx::query_as(
            "SELECT current_incarnation, i.genesis_hash, i.genesis_participant_domains
             FROM chat_mls_conversations c
             JOIN chat_mls_incarnations i
               ON i.conversation_id = c.conversation_id
              AND i.incarnation = c.current_incarnation
             WHERE c.conversation_id = $1
             FOR UPDATE OF c, i",
        )
        .bind(request.genesis.conversation_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((incarnation, existing_hash, existing_domains)) = existing {
            let expected_domains = serde_json::to_value(participant_domains).map_err(|error| {
                AppError::internal(format!("serialize MLS participant domains: {error}"))
            })?;
            if incarnation != request.genesis.incarnation as i64
                || existing_hash != genesis_hash
                || existing_domains != expected_domains
            {
                return Err(AppError::conflict(
                    "MLS conversation id is already bound to another genesis",
                ));
            }
            tx.commit().await?;
            return Ok(CreateMlsConversationResponseV1 {
                conversation_id: request.genesis.conversation_id,
                incarnation: request.genesis.incarnation,
                genesis_hash,
                idempotent: true,
            });
        }

        sqlx::query(
            "INSERT INTO chat_mls_conversations
                 (conversation_id, kind, current_incarnation, status)
             VALUES ($1,$2,$3,'active')",
        )
        .bind(request.genesis.conversation_id)
        .bind(kind_code)
        .bind(request.genesis.incarnation as i64)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO chat_mls_incarnations
                 (conversation_id, incarnation, mls_group_id, suite,
                  roster_commitment, member_count,
                  genesis_participant_domains, participant_domains,
                  authority_set_sequence, authority_set,
                  owner_set_sequence, owner_set, genesis, genesis_hash,
                  last_finalized_epoch, status)
             VALUES ($1,$2,$3,2,$4,$5,$6,$6,$7,$8,$9,$10,$11,$12,$13,'active')",
        )
        .bind(request.genesis.conversation_id)
        .bind(request.genesis.incarnation as i64)
        .bind(group_id)
        .bind(&request.genesis.roster_commitment)
        .bind(request.genesis.member_count as i32)
        .bind(serde_json::to_value(participant_domains).map_err(|error| {
            AppError::internal(format!("serialize MLS participant domains: {error}"))
        })?)
        .bind(request.genesis.authority_set.sequence as i64)
        .bind(authority_value)
        .bind(
            request
                .genesis
                .owner_set
                .as_ref()
                .map(|owners| owners.sequence as i64),
        )
        .bind(owner_value)
        .bind(genesis_value)
        .bind(&genesis_hash)
        .bind(request.genesis.initial_epoch as i64)
        .execute(&mut *tx)
        .await?;

        for member in request
            .members
            .iter()
            .filter(|member| member.address.server.as_deref() == Some(server_name))
        {
            let local_user_id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND is_active = true")
                    .bind(&member.address.username)
                    .fetch_optional(&mut *tx)
                    .await?;
            let local_user_id = local_user_id.ok_or_else(|| {
                AppError::conflict("an initial local MLS member account does not exist")
            })?;
            sqlx::query(
                "INSERT INTO chat_mls_local_members
                     (conversation_id, incarnation, user_id, is_admin, is_owner,
                      owner_id, joined_epoch)
                 VALUES ($1,$2,$3,$4,$5,$6,0)",
            )
            .bind(request.genesis.conversation_id)
            .bind(request.genesis.incarnation as i64)
            .bind(local_user_id)
            .bind(member.is_admin)
            .bind(member.owner_id.is_some())
            .bind(&member.owner_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO chat_mls_admin_audit_events
                 (event_type, conversation_id, incarnation, details)
             VALUES ('genesis',$1,$2,$3)",
        )
        .bind(request.genesis.conversation_id)
        .bind(request.genesis.incarnation as i64)
        .bind(serde_json::json!({
            "kind": kind_code,
            "genesisHash": genesis_hash,
            "authorityCount": request.genesis.authority_set.authorities.len(),
            "memberCount": request.genesis.member_count,
        }))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(CreateMlsConversationResponseV1 {
            conversation_id: request.genesis.conversation_id,
            incarnation: request.genesis.incarnation,
            genesis_hash,
            idempotent: false,
        })
    }
}
