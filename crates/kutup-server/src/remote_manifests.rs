//! Other servers' accounts' manifests (docs/plans/one-device-list.md §8,
//! slice 2): the frame keys their devices sign collab frames with. A file's
//! home checks each frame an editor on another server sends against that
//! editor's account manifest, as fetched from the editor's own server and
//! kept in `remote_account_manifests`.
//!
//! A cached head only moves forward along its chain: a newer head is taken
//! once the history from the cached one to it verifies, link by link, under
//! the same authority. It is fetched the first time, again when a frame
//! names a newer manifest sequence or a device the cached head doesn't list
//! with that key, and again before a frame is taken on a head older than
//! `remoteManifestMaxAgeSeconds` (so a device removed there stops counting
//! here within that time), at most once a [`REFETCH_AFTER`] per account. A
//! failed first read is recorded too (`remote_manifest_failures`), so the
//! frames that follow wait it out instead of each starting a read.

use kutup_chat_proto::AccountManifestV3;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::envelope::{self, Frame};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::AppState;

/// The least time between two fetches of one account's manifest.
const REFETCH_AFTER: time::Duration = time::Duration::minutes(1);

/// The most history pages one catch-up reads (each holds up to 64).
const MAX_HISTORY_PAGES: usize = 16;

struct Cached {
    manifest: AccountManifestV3,
    fetched_at: OffsetDateTime,
}

async fn cached(pool: &PgPool, domain: &str, account_id: Uuid) -> AppResult<Option<Cached>> {
    let row: Option<(serde_json::Value, OffsetDateTime)> = sqlx::query_as(
        "SELECT manifest, fetched_at FROM remote_account_manifests
          WHERE domain = $1 AND account_id = $2",
    )
    .bind(domain)
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    let Some((value, fetched_at)) = row else {
        return Ok(None);
    };
    let manifest: AccountManifestV3 = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("cached manifest: {error}")))?;
    Ok(Some(Cached {
        manifest,
        fetched_at,
    }))
}

/// Stores `manifest` as the account's head, never over a later one.
async fn store(pool: &PgPool, manifest: &AccountManifestV3) -> AppResult<()> {
    let account_id = Uuid::parse_str(&manifest.account.account_id)
        .map_err(|_| AppError::internal("a manifest's account id is not a UUID"))?;
    let hash = manifest.manifest_hash().map_err(AppError::internal)?;
    let value = serde_json::to_value(manifest)
        .map_err(|error| AppError::internal(format!("encode manifest: {error}")))?;
    sqlx::query(
        "INSERT INTO remote_account_manifests
             (domain, account_id, sequence, manifest_hash, manifest, fetched_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (domain, account_id) DO UPDATE SET
             sequence = EXCLUDED.sequence,
             manifest_hash = EXCLUDED.manifest_hash,
             manifest = EXCLUDED.manifest,
             fetched_at = now()
         WHERE remote_account_manifests.sequence <= EXCLUDED.sequence",
    )
    .bind(&manifest.account.server)
    .bind(account_id)
    .bind(manifest.sequence as i64)
    .bind(hash)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks the account's head as just looked at (a fetch found nothing newer).
/// Whether a first read of the account's manifest failed within
/// [`REFETCH_AFTER`].
async fn failed_lately(pool: &PgPool, domain: &str, account_id: Uuid) -> AppResult<bool> {
    let failed_at: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT failed_at FROM remote_manifest_failures WHERE domain = $1 AND account_id = $2",
    )
    .bind(domain)
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(failed_at.is_some_and(|at| OffsetDateTime::now_utc() - at < REFETCH_AFTER))
}

/// Records a failed first read (`failed`), or clears it.
async fn mark_failed(pool: &PgPool, domain: &str, account_id: Uuid, failed: bool) -> AppResult<()> {
    let query = if failed {
        "INSERT INTO remote_manifest_failures (domain, account_id) VALUES ($1, $2)
         ON CONFLICT (domain, account_id) DO UPDATE SET failed_at = now()"
    } else {
        "DELETE FROM remote_manifest_failures WHERE domain = $1 AND account_id = $2"
    };
    sqlx::query(query)
        .bind(domain)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn touch(pool: &PgPool, domain: &str, account_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "UPDATE remote_account_manifests SET fetched_at = now()
          WHERE domain = $1 AND account_id = $2",
    )
    .bind(domain)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// The account's head from its own server, taken only if it follows `known`
/// (its chain verified from `known` to it) or, with nothing known, as the
/// first one seen of the account.
async fn fetch_following(
    state: &AppState,
    account: &AccountRef,
    known: Option<&AccountManifestV3>,
) -> AppResult<Option<AccountManifestV3>> {
    let head = crate::chat_federation::fetch_remote_manifest(state, account).await?;
    head.verify().map_err(AppError::bad_request)?;
    if head.account != *account {
        return Err(AppError::bad_request("a manifest names another account"));
    }
    let Some(known) = known else {
        return Ok(Some(head));
    };
    if head.sequence <= known.sequence {
        // The same head, or an older one: never back.
        return Ok(None);
    }
    if head.incarnation_id != known.incarnation_id
        || head.authority_key_id != known.authority_key_id
    {
        return Err(AppError::conflict("an account manifest changed authority"));
    }
    // The chain from the known head to the new one, link by link.
    let mut previous = known.clone();
    let mut page_from = known.sequence + 1;
    for _ in 0..MAX_HISTORY_PAGES {
        let page = crate::chat_federation::fetch_remote_manifest_history(
            state,
            account,
            &crate::handlers::chat::ManifestHistoryQuery {
                server: Some(account.server.clone()),
                from_sequence: known.sequence + 1,
                to_sequence: head.sequence,
                page_from_sequence: Some(page_from),
            },
        )
        .await?;
        for manifest in &page.manifests {
            manifest
                .verify_successor(Some(&previous))
                .map_err(AppError::conflict)?;
            previous = manifest.clone();
        }
        match page.next_sequence {
            Some(next) => page_from = next,
            None => break,
        }
    }
    if previous.manifest_hash().map_err(AppError::internal)?
        != head.manifest_hash().map_err(AppError::internal)?
    {
        return Err(AppError::conflict(
            "an account manifest's history doesn't reach its head",
        ));
    }
    Ok(Some(head))
}

/// Whether `frame` (packed as `raw`) is `sender`'s, a device of an account
/// of `domain` (the server that relayed it) under `incarnation` (the one the
/// share names): signed with the frame key that account's head lists for the
/// frame's device. Refreshes the cached head as the module says.
pub(crate) async fn frame_is_senders(
    state: &AppState,
    domain: &str,
    incarnation: &str,
    sender: &AccountRef,
    frame: &Frame,
    raw: &[u8],
) -> AppResult<bool> {
    // A server relays only its own accounts' frames.
    if sender.server != domain {
        return Ok(false);
    }
    let account_id = Uuid::parse_str(&sender.account_id)
        .map_err(|_| AppError::bad_request("an account id is not a UUID"))?;
    let known = cached(&state.pool, domain, account_id).await?;
    let holds = |manifest: &AccountManifestV3| {
        manifest.incarnation_id == incarnation
            && frame.manifest_sequence <= manifest.sequence
            && manifest
                .device(frame.device_id)
                .and_then(|device| device.frame_key.as_deref())
                .and_then(|key| kutup_chat_proto::decode_frame_key(key).ok())
                .is_some_and(|key| envelope::verify(raw, sender, &key).is_ok())
    };
    let max_age = time::Duration::seconds(
        crate::site_settings::REMOTE_MANIFEST_MAX_AGE_SECONDS
            .load(&state.pool)
            .await?,
    );
    if let Some(known) = &known {
        let age = OffsetDateTime::now_utc() - known.fetched_at;
        if holds(&known.manifest) && age < max_age {
            return Ok(true);
        }
        if age < REFETCH_AFTER {
            return Ok(holds(&known.manifest));
        }
    } else if failed_lately(&state.pool, domain, account_id).await? {
        return Ok(false);
    }
    let head = match fetch_following(state, sender, known.as_ref().map(|k| &k.manifest)).await {
        Ok(Some(head)) => {
            store(&state.pool, &head).await?;
            if known.is_none() {
                mark_failed(&state.pool, domain, account_id, false).await?;
            }
            head
        }
        Ok(None) => {
            // The server says the account has no manifest: none of its
            // frames count.
            match &known {
                Some(_) => touch(&state.pool, domain, account_id).await?,
                None => mark_failed(&state.pool, domain, account_id, true).await?,
            }
            return Ok(false);
        }
        Err(error) => {
            tracing::warn!(error = %error.message, domain, "collab: a sender's manifest could not be read");
            return match &known {
                // Unreachable for now: the cached head still decides, read
                // again after the refetch interval.
                Some(known) => {
                    touch(&state.pool, domain, account_id).await?;
                    Ok(holds(&known.manifest))
                }
                None => {
                    mark_failed(&state.pool, domain, account_id, true).await?;
                    Ok(false)
                }
            };
        }
    };
    Ok(holds(&head))
}

/// Drops the cached manifests no shared file needs any more (no live share
/// names an account of that server), and recorded failures an hour old
/// (long past the refetch interval): run with the uploads sweep.
pub(crate) async fn sweep(pool: &PgPool) -> AppResult<u64> {
    sqlx::query("DELETE FROM remote_manifest_failures WHERE failed_at < now() - interval '1 hour'")
        .execute(pool)
        .await?;
    let gone = sqlx::query(
        "DELETE FROM remote_account_manifests r
          WHERE NOT EXISTS (SELECT 1 FROM federated_outgoing_shares s
                             WHERE s.recipient_domain = r.domain)
            AND NOT EXISTS (SELECT 1 FROM federated_outgoing_file_shares s
                             WHERE s.recipient_domain = r.domain)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(gone)
}
