//! Expiring messages (docs/plans/mail-parity.md, P5), as Proton's: when a
//! message's time comes, every Kutup copy of it (the sender's and each
//! recipient's) is deleted for good and its storage freed.

use std::collections::BTreeMap;
use std::time::Duration;

use uuid::Uuid;

use crate::handlers::mail::{delete_for_good, Mailbox};
use crate::AppState;

const TICK: Duration = Duration::from_secs(30);

/// Every place a message can be in.
const ALL_FOLDERS: [&str; 9] = [
    "inbox",
    "drafts",
    "scheduled",
    "snoozed",
    "sent",
    "archive",
    "spam",
    "trash",
    "custom",
];

/// Deletes expired mail every 30 seconds.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = once(&state).await {
                tracing::warn!(error = %error, "mail: deleting expired mail failed");
            }
        }
    });
}

/// One pass: expired messages, a batch at a time, deleted per mailbox; how many.
pub async fn once(state: &AppState) -> anyhow::Result<u64> {
    let mut deleted = 0;
    loop {
        let due: Vec<(Uuid, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, user_id, group_id FROM mail_messages
              WHERE expires_at IS NOT NULL AND expires_at <= now()
              ORDER BY expires_at LIMIT 500",
        )
        .fetch_all(&state.pool)
        .await?;
        if due.is_empty() {
            return Ok(deleted);
        }
        let mut by_mailbox: BTreeMap<(bool, Uuid), Vec<Uuid>> = BTreeMap::new();
        for (id, user_id, group_id) in due {
            let key = match (user_id, group_id) {
                (Some(user), _) => (false, user),
                (None, Some(group)) => (true, group),
                (None, None) => continue,
            };
            by_mailbox.entry(key).or_default().push(id);
        }
        let before = deleted;
        for ((shared, owner), ids) in by_mailbox {
            let mailbox = if shared {
                Mailbox::Shared(owner)
            } else {
                Mailbox::Own(owner)
            };
            deleted += delete_for_good(state, mailbox, &ids, &ALL_FOLDERS)
                .await
                .map_err(|error| anyhow::anyhow!("{}", error.message))?;
        }
        if deleted == before {
            // Nothing could go this round: try again next tick, not in a loop.
            return Ok(deleted);
        }
    }
}
