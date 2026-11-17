//! Auto-delete (docs/plans/mail-parity.md, P1): for accounts that turned it
//! on, mail that has been in Trash or Spam for more than 30 days is deleted
//! for good, its storage freed, as Proton's "Auto-delete unwanted messages".

use std::time::Duration;

use uuid::Uuid;

use crate::handlers::mail::Mailbox;
use crate::handlers::mail_settings::delete_all;
use crate::AppState;

const INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Runs once soon after start, then hourly.
pub fn spawn(state: AppState) {
    crate::job_health::register("mail.retention", INTERVAL);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(INTERVAL);
        loop {
            tick.tick().await;
            let mut ok = true;
            if let Err(error) = once(&state).await {
                tracing::warn!(error = %error, "mail: auto-delete failed");
                ok = false;
            }
            if let Err(error) = super::auto_reply::forget_old(&state.pool).await {
                tracing::warn!(error = %error, "mail: forgetting auto-reply senders failed");
                ok = false;
            }
            if let Err(error) = crate::handlers::mail::forget_old_tombstones(&state.pool).await {
                tracing::warn!(error = %error, "mail: forgetting body search tombstones failed");
                ok = false;
            }
            if ok {
                crate::job_health::beat(&state.pool, "mail.retention").await;
            }
        }
    });
}

/// One pass over the accounts with auto-delete on.
pub async fn once(state: &AppState) -> anyhow::Result<u64> {
    let accounts: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT s.account_id, s.auto_delete_days FROM mail_settings s
          WHERE s.auto_delete_days > 0
            AND NOT kutup_account_held(s.account_id)
            AND EXISTS (SELECT 1 FROM mail_messages m
                         WHERE m.mailbox_owner = s.account_id AND m.folder IN ('trash', 'spam')
                           AND m.folder_changed_at < now() - make_interval(days => s.auto_delete_days))",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut deleted = 0;
    for (user_id, days) in accounts {
        for folder in ["trash", "spam"] {
            match delete_all(state, Mailbox::Own(user_id), folder, Some(days)).await {
                Ok(count) => deleted += count,
                Err(error) => {
                    tracing::warn!(error = ?error, "mail: auto-delete for an account failed")
                }
            }
        }
    }
    if deleted > 0 {
        tracing::info!(deleted, "mail: auto-deleted old Trash and Spam");
    }
    Ok(deleted)
}
