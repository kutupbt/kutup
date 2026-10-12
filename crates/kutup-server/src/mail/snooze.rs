//! Snooze (docs/plans/mail-parity.md, P4), as Proton's: snoozed mail waits
//! in Snoozed; when its time comes, [`spawn`]'s loop brings it back to the
//! Inbox unread.

use std::time::Duration;

use crate::AppState;

const TICK: Duration = Duration::from_secs(20);

/// Wakes snoozed mail whose time has come, every 20 seconds.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = wake(&state).await {
                tracing::warn!(error = %error, "mail: waking snoozed mail failed");
            }
        }
    });
}

/// Brings due snoozed mail back to the Inbox, unread; how many.
pub async fn wake(state: &AppState) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "UPDATE mail_messages SET folder = 'inbox', seen = false, snoozed_until = NULL, notify_at = now()
          WHERE folder = 'snoozed' AND snoozed_until <= now()",
    )
    .execute(&state.pool)
    .await?
    .rows_affected())
}
