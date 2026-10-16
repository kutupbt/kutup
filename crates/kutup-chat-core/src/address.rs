//! Chat addressing (`docs/chat-protocol.md` §2): a peer is an account,
//! `{server, accountId}` (Signal's ACI; docs/plans/account-ids.md), and a
//! device id. Its string form, `aci:<uuid>@<server>`, is the libsignal
//! `ProtocolAddress` name and every store's key, as Signal keys sessions by
//! ServiceId. An address (`username@server`) never reaches Chat core: the app
//! resolves it to an account first.

use kutup_chat_proto::{AccountRef, ConversationId};
use libsignal_protocol::{DeviceId, ProtocolAddress};

use crate::error::{ChatError, Result};

/// libsignal `DeviceId` is a `u8`; our wire ids are `u32` bounded to 1..=127.
pub(crate) fn device_id_u8(id: u32) -> Result<DeviceId> {
    let byte = u8::try_from(id).map_err(|_| ChatError::Invalid(format!("device id {id}")))?;
    DeviceId::new(byte).map_err(|_| ChatError::Invalid(format!("device id {id}")))
}

/// An account's string form, checked: `aci:<uuid>@<server>`, nothing else.
pub fn parse_account(value: &str) -> Result<AccountRef> {
    value
        .parse::<AccountRef>()
        .map_err(|error| ChatError::Invalid(format!("not an account: {error}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatAddress {
    pub account: AccountRef,
    pub device_id: u32,
}

impl ChatAddress {
    /// An account's string form (a delivered envelope's sender, a session's
    /// own account) plus a device id. An address is refused.
    pub fn from_sender(sender: &str, device_id: u32) -> Result<Self> {
        Ok(Self::from_account(parse_account(sender)?, device_id))
    }

    pub fn from_account(account: AccountRef, device_id: u32) -> Self {
        ChatAddress { account, device_id }
    }

    pub fn account(&self) -> AccountRef {
        self.account.clone()
    }

    pub fn conversation(&self) -> ConversationId {
        ConversationId::direct(self.account.clone())
    }

    /// The `aci:<uuid>@<server>` string libsignal keys sessions by.
    pub fn name(&self) -> String {
        self.account.to_string()
    }

    pub(crate) fn to_protocol(&self) -> Result<ProtocolAddress> {
        Ok(ProtocolAddress::new(
            self.name(),
            device_id_u8(self.device_id)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADA: &str = "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@kutup.dev";

    #[test]
    fn an_account_is_the_libsignal_name() {
        let address = ChatAddress::from_sender(ADA, 7).unwrap();
        assert_eq!(address.account.server, "kutup.dev");
        assert_eq!(address.name(), ADA);
        assert_eq!(
            address.conversation(),
            ConversationId::direct(ADA.parse().unwrap())
        );
        assert_eq!(address.to_protocol().unwrap().name(), ADA);
    }

    #[test]
    fn an_address_is_never_a_peer() {
        for refused in [
            "user@kutup.dev",
            "user",
            "user@@kutup.dev",
            "",
            "aci:user@kutup.dev",
        ] {
            assert!(ChatAddress::from_sender(refused, 1).is_err(), "{refused}");
        }
    }
}
