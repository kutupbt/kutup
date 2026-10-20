//! The account's Chat contact list (docs/plans/chat-contacts-sync.md): who
//! it accepted, asked, rejected or blocked, sealed in the account head's
//! `chatContacts` scope, so a device that lost everything restores them, as
//! Signal's storage service keeps `ContactRecord`s.

use kutup_chat_proto::ContactState;

use crate::db::ContactRecord;

/// The one order of contact states, for the Note-to-Self contact control and
/// the list alike: the higher wins. At an equal revision a block wins,
/// whatever device wrote the other, so an older accept never undoes a block.
pub(crate) fn contact_order(
    revision: u64,
    state: ContactState,
    source_device_id: u32,
) -> (u64, bool, u32) {
    (revision, state == ContactState::Blocked, source_device_id)
}

/// A local record's place in [`contact_order`].
pub(crate) fn order_of(contact: &ContactRecord) -> (u64, bool, u32) {
    contact_order(contact.revision, contact.state, contact.source_device_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_wins_a_tie_whatever_device_wrote_the_other() {
        let accept = contact_order(5, ContactState::Accepted, 9);
        let block = contact_order(5, ContactState::Blocked, 1);
        assert!(block > accept);
        // A later revision still wins over a block.
        assert!(contact_order(6, ContactState::Accepted, 1) > block);
        // Between two of the same kind, the device id decides, as before.
        assert!(
            contact_order(5, ContactState::Accepted, 9)
                > contact_order(5, ContactState::Rejected, 1)
        );
    }
}
