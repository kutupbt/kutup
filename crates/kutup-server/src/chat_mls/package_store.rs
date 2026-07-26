//! Manifest-bound MLS KeyPackage and epoch-capability persistence.

use kutup_chat_proto::{
    DeviceManifest, MlsDeliveryCapabilityKindV1, PublishMlsDeliveryCapabilityV1,
    PublishMlsKeyPackagesRequestV1,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{decode_canonical_base64, MlsRepository, MAX_DEVICE_ID};
use crate::error::{AppError, AppResult};

impl MlsRepository {
    pub(super) async fn publish_key_packages(
        &self,
        user_id: Uuid,
        request: &PublishMlsKeyPackagesRequestV1,
        now: OffsetDateTime,
    ) -> AppResult<u32> {
        request
            .validate(now.unix_timestamp())
            .map_err(AppError::bad_request)?;
        if request.device_id > MAX_DEVICE_ID {
            return Err(AppError::bad_request(
                "MLS device id is outside the v1 range",
            ));
        }

        let mut tx = self.pool.begin().await?;
        let row: Option<(i64, Value)> = sqlx::query_as(
            "SELECT version, manifest
             FROM chat_device_manifests
             WHERE user_id = $1
             FOR SHARE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (manifest_version, manifest_value) =
            row.ok_or_else(|| AppError::conflict("publish a signed device manifest first"))?;
        if manifest_version != request.manifest_version as i64 {
            return Err(AppError::conflict(
                "MLS KeyPackages must use the current manifest version",
            ));
        }
        let manifest: DeviceManifest = serde_json::from_value(manifest_value)
            .map_err(|error| AppError::internal(format!("stored manifest is invalid: {error}")))?;
        manifest.verify().map_err(|error| {
            AppError::internal(format!("stored manifest failed verification: {error}"))
        })?;
        let declared = manifest
            .devices
            .iter()
            .find(|device| device.device_id == request.device_id)
            .ok_or_else(|| AppError::conflict("MLS device is absent from the current manifest"))?;
        let binding = declared.mls.as_ref().ok_or_else(|| {
            AppError::conflict("current manifest does not bind MLS keys for this device")
        })?;
        binding.validate().map_err(AppError::bad_request)?;
        let credential_key =
            decode_canonical_base64("MLS credential public key", &binding.credential_public_key)?;
        let anonymous_key = decode_canonical_base64(
            "MLS anonymous delivery public key",
            &binding.anonymous_delivery_public_key,
        )?;

        let existing: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT manifest_version, credential_public_key, anonymous_delivery_public_key
             FROM chat_mls_devices
             WHERE user_id = $1 AND device_id = $2
             FOR UPDATE",
        )
        .bind(user_id)
        .bind(request.device_id as i32)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((version, existing_credential, existing_anonymous)) = existing {
            if version != manifest_version
                || existing_credential != credential_key
                || existing_anonymous != anonymous_key
            {
                return Err(AppError::conflict(
                    "MLS device key replacement requires explicit device revocation",
                ));
            }
        } else {
            sqlx::query(
                "INSERT INTO chat_mls_devices
                     (user_id, device_id, manifest_version, suite,
                      credential_public_key, anonymous_delivery_public_key, name)
                 VALUES ($1,$2,$3,2,$4,$5,$6)",
            )
            .bind(user_id)
            .bind(request.device_id as i32)
            .bind(manifest_version)
            .bind(&credential_key)
            .bind(&anonymous_key)
            .bind("")
            .execute(&mut *tx)
            .await?;
        }

        for package in &request.key_packages {
            let package_bytes = decode_canonical_base64("MLS KeyPackage", &package.key_package)?;
            let expires_at = OffsetDateTime::from_unix_timestamp(package.expires_at)
                .map_err(|_| AppError::bad_request("MLS KeyPackage expiry is outside range"))?;
            let inserted = sqlx::query(
                "INSERT INTO chat_mls_key_packages
                     (user_id, device_id, key_package_ref, manifest_version,
                      suite, key_package, expires_at)
                 VALUES ($1,$2,$3,$4,2,$5,$6)
                 ON CONFLICT DO NOTHING",
            )
            .bind(user_id)
            .bind(request.device_id as i32)
            .bind(&package.key_package_ref)
            .bind(request.manifest_version as i64)
            .bind(&package_bytes)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 0 {
                let existing: Option<(i64, Vec<u8>, OffsetDateTime, Option<OffsetDateTime>)> =
                    sqlx::query_as(
                        "SELECT manifest_version, key_package, expires_at, claimed_at
                         FROM chat_mls_key_packages
                         WHERE user_id = $1 AND device_id = $2 AND key_package_ref = $3",
                    )
                    .bind(user_id)
                    .bind(request.device_id as i32)
                    .bind(&package.key_package_ref)
                    .fetch_optional(&mut *tx)
                    .await?;
                if !matches!(
                    existing,
                    Some((version, ref bytes, expiry, None))
                        if version == request.manifest_version as i64
                            && bytes == &package_bytes
                            && expiry == expires_at
                ) {
                    return Err(AppError::conflict(
                        "MLS KeyPackage reference was already used with different bytes",
                    ));
                }
            }
        }
        tx.commit().await?;
        self.available_key_package_count(user_id, request.device_id, now)
            .await
    }

    pub(super) async fn available_key_package_count(
        &self,
        user_id: Uuid,
        device_id: u32,
        now: OffsetDateTime,
    ) -> AppResult<u32> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM chat_mls_key_packages
             WHERE user_id = $1 AND device_id = $2
               AND claimed_at IS NULL AND expires_at > $3",
        )
        .bind(user_id)
        .bind(device_id as i32)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        u32::try_from(count).map_err(|_| AppError::internal("MLS KeyPackage count overflow"))
    }

    pub(super) async fn publish_delivery_capability(
        &self,
        user_id: Uuid,
        request: &PublishMlsDeliveryCapabilityV1,
    ) -> AppResult<()> {
        request.validate().map_err(AppError::bad_request)?;
        let capability_hash = hex::decode(&request.capability_hash)
            .map_err(|_| AppError::bad_request("capabilityHash must be SHA-256 hex"))?;
        let kind = match request.capability_kind {
            MlsDeliveryCapabilityKindV1::Direct => "direct",
            MlsDeliveryCapabilityKindV1::Group => "group",
        };

        let mut tx = self.pool.begin().await?;
        let state: Option<(i16, i64)> = sqlx::query_as(
            "SELECT c.kind, i.last_finalized_epoch
             FROM chat_mls_conversations c
             JOIN chat_mls_incarnations i
               ON i.conversation_id = c.conversation_id
              AND i.incarnation = c.current_incarnation
             JOIN chat_mls_local_members m
               ON m.conversation_id = i.conversation_id
              AND m.incarnation = i.incarnation
             WHERE c.conversation_id = $1
               AND c.current_incarnation = $2
               AND c.status = 'active'
               AND i.status = 'active'
               AND m.user_id = $3
               AND m.removed_epoch IS NULL
               AND m.membership_status = 'active'
             FOR UPDATE OF i",
        )
        .bind(request.conversation_id)
        .bind(request.incarnation as i64)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (conversation_kind, current_epoch) =
            state.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
        let expected_kind = if conversation_kind == 2 {
            "direct"
        } else if conversation_kind == 3 {
            "group"
        } else {
            return Err(AppError::conflict(
                "self-sync does not use anonymous delivery capabilities",
            ));
        };
        if kind != expected_kind || current_epoch != request.epoch as i64 {
            return Err(AppError::conflict(
                "MLS delivery capability does not match the active epoch",
            ));
        }

        let inserted = sqlx::query(
            "INSERT INTO chat_mls_delivery_capabilities
                 (recipient_user_id, conversation_id, incarnation, epoch,
                  capability_kind, capability_hash, policy_sequence)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(request.conversation_id)
        .bind(request.incarnation as i64)
        .bind(request.epoch as i64)
        .bind(kind)
        .bind(&capability_hash)
        .bind(request.policy_sequence as i64)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            let existing: (Vec<u8>, i64) = sqlx::query_as(
                "SELECT capability_hash, policy_sequence
                 FROM chat_mls_delivery_capabilities
                 WHERE recipient_user_id = $1 AND conversation_id = $2
                   AND incarnation = $3 AND epoch = $4
                 FOR UPDATE",
            )
            .bind(user_id)
            .bind(request.conversation_id)
            .bind(request.incarnation as i64)
            .bind(request.epoch as i64)
            .fetch_one(&mut *tx)
            .await?;
            if existing.0 != capability_hash || existing.1 != request.policy_sequence as i64 {
                return Err(AppError::conflict(
                    "an MLS capability verifier is already pinned for this epoch",
                ));
            }
        }
        tx.commit().await?;
        Ok(())
    }
}
