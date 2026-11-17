//! One sync loop for the account records this engine keeps
//! (docs/plans/account-records.md): the group list, the Chat contact list and
//! the identity pin list, all in the account-records store under the account
//! head. One look reads them all when the last read is a while ago, then
//! writes whatever is due. When an entry is due is still each list's own
//! rule: a group entry waits a random delay (so the server can't time a
//! join), a block on the web goes at once, other contact changes wait theirs.

use rand::{CryptoRng, Rng};

use crate::engine::Engine;
use crate::error::Result;

/// How often a running device reads the account's lists again: one mark for
/// all of them.
pub(crate) const READ_EVERY_MS: i64 = 5 * 60 * 1000;

impl Engine {
    /// Reads the account's lists when the last read is a while ago (a running
    /// device's periodic look), then writes what is due, best effort: a read
    /// that fails is tried again at the next look, and its error is returned
    /// once the due writes have had their turn. Returns the groups the group
    /// list's read took up.
    pub async fn sync_account_records_if_due<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<String>> {
        let now = self.now_ms();
        let due = self.records_read_at_ms == 0 || now - self.records_read_at_ms >= READ_EVERY_MS;
        let mut taken_up = Vec::new();
        let mut failed = None;
        if due {
            match self.sync_group_list(rng).await {
                Ok(groups) => taken_up = groups,
                Err(error) => failed = Some(error),
            }
            if let Err(error) = self.sync_contact_list().await {
                failed.get_or_insert(error);
            }
            if failed.is_none() {
                self.records_read_at_ms = now;
            }
        }
        let _ = self.flush_group_list(false).await;
        let _ = self.flush_contact_list(false).await;
        // The pin list's first meetings go the same way.
        let _ = self.flush_identity_pins(false).await;
        // This account's group-send endorsement, once a day whatever its
        // groups (so the fetch says nothing about them); then each group gets
        // it, and the members' new ones are read, with this periodic look.
        let _ = self.refresh_own_group_send_endorsement().await;
        let _ = self.refresh_all_group_send_endorsements().await;
        match failed {
            Some(error) => Err(error),
            None => Ok(taken_up),
        }
    }
}
