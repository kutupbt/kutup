//! Durable capability matching, anonymous KeyPackage claims, and mailbox writes.
//!
//! Raw capabilities are accepted only at this boundary and are never stored.
//! Destination mailbox rows structurally omit sender and conversation fields.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, constant_time_capability_hash_eq, AnonymousMlsDeliveryResponseV1,
    AnonymousMlsSubmissionV1, MlsAbuseLimitsV1, MlsCipherSuiteId, MlsKeyPackageV1,
};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{increment_counter, scoped_digest, unavailable, MlsRepository};
use crate::error::{AppError, AppResult};

#[derive(Debug)]
struct MatchedCapability {
    hash: [u8; 32],
    conversation_id: Uuid,
}

impl MlsRepository {
    async fn match_capability(
        tx: &mut Transaction<'_, Postgres>,
        recipient_user_id: Uuid,
        presented: &[u8; 32],
    ) -> AppResult<Option<MatchedCapability>> {
        let rows: Vec<(Vec<u8>, Uuid)> = sqlx::query_as(
            "SELECT d.capability_hash, d.conversation_id
             FROM chat_mls_delivery_capabilities d
             JOIN chat_mls_conversations c
               ON c.conversation_id = d.conversation_id
              AND c.current_incarnation = d.incarnation
             JOIN chat_mls_incarnations i
               ON i.conversation_id = d.conversation_id
              AND i.incarnation = d.incarnation
              AND i.last_finalized_epoch = d.epoch
             JOIN chat_mls_local_members m
               ON m.conversation_id = d.conversation_id
              AND m.incarnation = d.incarnation
              AND m.user_id = d.recipient_user_id
             WHERE d.recipient_user_id = $1
               AND c.status = 'active'
               AND i.status = 'active'
               AND m.removed_epoch IS NULL
               AND m.membership_status = 'active'
             ORDER BY d.conversation_id",
        )
        .bind(recipient_user_id)
        .fetch_all(&mut **tx)
        .await?;

        let mut matched = None;
        for (candidate, conversation_id) in rows {
            let Ok(candidate): Result<[u8; 32], _> = candidate.try_into() else {
                return Err(AppError::internal(
                    "stored MLS capability hash is malformed",
                ));
            };
            if constant_time_capability_hash_eq(&candidate, presented) {
                matched = Some(MatchedCapability {
                    hash: candidate,
                    conversation_id,
                });
            }
        }
        Ok(matched)
    }

    pub(super) async fn authorize_anonymous_key_package_claim(
        &self,
        username: &str,
        capability: &[u8; 16],
        limits: &MlsAbuseLimitsV1,
        now: OffsetDateTime,
    ) -> AppResult<(Uuid, u64)> {
        let presented_hash = capability_hash(capability);
        let mut tx = self.pool.begin().await?;
        let recipient: Option<(Uuid, i64)> = sqlx::query_as(
            "SELECT u.id, m.version
             FROM users u
             JOIN chat_device_manifests m ON m.user_id = u.id
             WHERE u.username = $1",
        )
        .bind(username)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((recipient_user_id, manifest_version)) = recipient else {
            constant_time_capability_hash_eq(&presented_hash, &[0; 32]);
            return Err(unavailable());
        };
        let matched = Self::match_capability(&mut tx, recipient_user_id, &presented_hash)
            .await?
            .ok_or_else(unavailable)?;

        increment_counter(
            &mut tx,
            "capability_bundle",
            scoped_digest(b"kutup/mls/rate/bundle/v1", &matched.hash),
            60,
            limits.capability_bundle_requests_per_minute.into(),
            now,
        )
        .await?;
        tx.commit().await?;
        let manifest_version =
            u64::try_from(manifest_version).map_err(|_| AppError::internal("manifest version"))?;
        Ok((recipient_user_id, manifest_version))
    }

    pub(super) async fn claim_anonymous_key_packages(
        &self,
        username: &str,
        capability: &[u8; 16],
        expected_user_id: Uuid,
        expected_manifest_version: u64,
        now: OffsetDateTime,
    ) -> AppResult<Vec<MlsKeyPackageV1>> {
        let presented_hash = capability_hash(capability);
        let mut tx = self.pool.begin().await?;
        let recipient: Option<(Uuid, i64)> = sqlx::query_as(
            "SELECT u.id, m.version
             FROM users u
             JOIN chat_device_manifests m ON m.user_id = u.id
             WHERE u.username = $1",
        )
        .bind(username)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((recipient_user_id, manifest_version)) = recipient else {
            constant_time_capability_hash_eq(&presented_hash, &[0; 32]);
            return Err(unavailable());
        };
        if recipient_user_id != expected_user_id
            || u64::try_from(manifest_version).ok() != Some(expected_manifest_version)
        {
            return Err(unavailable());
        }
        let matched = Self::match_capability(&mut tx, recipient_user_id, &presented_hash)
            .await?
            .ok_or_else(unavailable)?;

        let devices: Vec<i32> = sqlx::query_scalar(
            "SELECT device_id
             FROM chat_mls_devices
             WHERE user_id = $1 AND manifest_version = $2
             ORDER BY device_id",
        )
        .bind(recipient_user_id)
        .bind(manifest_version)
        .fetch_all(&mut *tx)
        .await?;
        if devices.is_empty() || devices.len() > 32 {
            return Err(unavailable());
        }

        let mut packages = Vec::with_capacity(devices.len());
        for device_id in devices {
            let row: Option<(String, Vec<u8>, OffsetDateTime)> = sqlx::query_as(
                "SELECT key_package_ref, key_package, expires_at
                 FROM chat_mls_key_packages
                 WHERE user_id = $1 AND device_id = $2
                   AND manifest_version = $3
                   AND claimed_at IS NULL AND expires_at > $4
                 ORDER BY created_at, key_package_ref
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED",
            )
            .bind(recipient_user_id)
            .bind(device_id)
            .bind(manifest_version)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((key_package_ref, key_package, expires_at)) = row else {
                return Err(unavailable());
            };
            sqlx::query(
                "UPDATE chat_mls_key_packages
                 SET claimed_at = $1, claimed_conversation = $2
                 WHERE user_id = $3 AND device_id = $4 AND key_package_ref = $5",
            )
            .bind(now)
            .bind(matched.conversation_id)
            .bind(recipient_user_id)
            .bind(device_id)
            .bind(&key_package_ref)
            .execute(&mut *tx)
            .await?;
            packages.push(MlsKeyPackageV1 {
                device_id: device_id as u32,
                manifest_version: manifest_version as u64,
                suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
                key_package_ref,
                key_package: STANDARD.encode(key_package),
                expires_at: expires_at.unix_timestamp(),
            });
        }
        tx.commit().await?;
        Ok(packages)
    }

    pub(super) async fn store_anonymous_submission(
        &self,
        username: &str,
        submission: &AnonymousMlsSubmissionV1,
        capability: &[u8; 16],
        limits: &MlsAbuseLimitsV1,
        now: OffsetDateTime,
    ) -> AppResult<AnonymousMlsDeliveryResponseV1> {
        let presented_hash = capability_hash(capability);
        let mut tx = self.pool.begin().await?;
        let recipient_user_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
                .bind(username)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(recipient_user_id) = recipient_user_id else {
            constant_time_capability_hash_eq(&presented_hash, &[0; 32]);
            return Err(unavailable());
        };
        let matched = Self::match_capability(&mut tx, recipient_user_id, &presented_hash)
            .await?
            .ok_or_else(unavailable)?;

        let lock_digest = scoped_digest(
            b"kutup/mls/send-id-lock/v1",
            &[presented_hash.as_slice(), submission.send_id.as_bytes()].concat(),
        );
        let advisory_key = i64::from_be_bytes(lock_digest[..8].try_into().expect("8-byte slice"));
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(advisory_key)
            .execute(&mut *tx)
            .await?;
        let previous: Option<i32> = sqlx::query_scalar(
            "SELECT stored_count
             FROM chat_mls_anonymous_send_ids
             WHERE recipient_user_id = $1 AND capability_hash = $2 AND send_id = $3",
        )
        .bind(recipient_user_id)
        .bind(&presented_hash[..])
        .bind(submission.send_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(stored_count) = previous {
            tx.commit().await?;
            return Ok(AnonymousMlsDeliveryResponseV1 {
                accepted: true,
                stored_devices: stored_count as u16,
                deduplicated: true,
            });
        }

        increment_counter(
            &mut tx,
            "capability_minute",
            scoped_digest(b"kutup/mls/rate/send-minute/v1", &matched.hash),
            60,
            limits.sealed_sends_per_capability_minute.into(),
            now,
        )
        .await?;
        increment_counter(
            &mut tx,
            "capability_day",
            scoped_digest(b"kutup/mls/rate/send-day/v1", &matched.hash),
            86_400,
            limits.sealed_sends_per_capability_day.into(),
            now,
        )
        .await?;
        increment_counter(
            &mut tx,
            "recipient",
            scoped_digest(b"kutup/mls/rate/recipient/v1", recipient_user_id.as_bytes()),
            60,
            limits.sealed_sends_per_capability_minute.into(),
            now,
        )
        .await?;

        let expected_devices: Vec<i32> = sqlx::query_scalar(
            "SELECT d.device_id
             FROM chat_mls_devices d
             JOIN chat_device_manifests m ON m.user_id = d.user_id
             WHERE d.user_id = $1 AND d.manifest_version = m.version
             ORDER BY d.device_id",
        )
        .bind(recipient_user_id)
        .fetch_all(&mut *tx)
        .await?;
        if expected_devices.len() != submission.envelopes.len()
            || !expected_devices
                .iter()
                .zip(&submission.envelopes)
                .all(|(expected, envelope)| *expected as u32 == envelope.device_id)
        {
            return Err(unavailable());
        }

        for envelope in &submission.envelopes {
            let opaque = serde_json::to_vec(envelope)
                .map_err(|error| AppError::internal(format!("serialize MLS envelope: {error}")))?;
            sqlx::query(
                "INSERT INTO chat_mls_mailbox
                     (recipient_user_id, recipient_device_id, delivery_kind,
                      request_id, conversation_id, send_id, opaque_envelope)
                 VALUES ($1,$2,'anonymous',NULL,NULL,$3,$4)",
            )
            .bind(recipient_user_id)
            .bind(envelope.device_id as i32)
            .bind(submission.send_id)
            .bind(opaque)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO chat_mls_anonymous_send_ids
                 (recipient_user_id, capability_hash, send_id, stored_count)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(recipient_user_id)
        .bind(&presented_hash[..])
        .bind(submission.send_id)
        .bind(submission.envelopes.len() as i32)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(AnonymousMlsDeliveryResponseV1 {
            accepted: true,
            stored_devices: submission.envelopes.len() as u16,
            deduplicated: false,
        })
    }
}
