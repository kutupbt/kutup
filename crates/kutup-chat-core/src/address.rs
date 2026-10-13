//! Chat addressing (`docs/chat-protocol.md` §13): an address is `user`, its
//! home server `domain`, and a device id. There is no bare-username form.

use kutup_chat_proto::{AccountAddress, ConversationId};
use libsignal_protocol::{DeviceId, ProtocolAddress};

use crate::error::{ChatError, Result};

/// libsignal `DeviceId` is a `u8`; our wire ids are `u32` bounded to 1..=127.
pub(crate) fn device_id_u8(id: u32) -> Result<DeviceId> {
    let byte = u8::try_from(id).map_err(|_| ChatError::Invalid(format!("device id {id}")))?;
    DeviceId::new(byte).map_err(|_| ChatError::Invalid(format!("device id {id}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatAddress {
    pub user: String,
    /// The account's home server.
    pub domain: String,
    pub device_id: u32,
}

impl ChatAddress {
    /// Parse a canonical `user@domain` account (a delivered envelope's
    /// `sender`, a session's account) plus a device id into an address.
    pub fn from_sender(sender: &str, device_id: u32) -> Result<Self> {
        let account = sender
            .parse::<AccountAddress>()
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        Ok(Self::from_account(account, device_id))
    }

    pub fn from_account(account: AccountAddress, device_id: u32) -> Self {
        ChatAddress {
            user: account.username,
            domain: account.server,
            device_id,
        }
    }

    pub fn account(&self) -> AccountAddress {
        AccountAddress {
            username: self.user.clone(),
            server: self.domain.clone(),
        }
    }

    pub fn conversation(&self) -> ConversationId {
        ConversationId::direct(self.account())
    }

    /// The `user` / `user@domain` string libsignal keys sessions by.
    pub fn name(&self) -> String {
        self.account().canonical()
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

    #[test]
    fn federated_sender_becomes_the_libsignal_account_name() {
        let address = ChatAddress::from_sender("user@kutup.dev", 7).unwrap();
        assert_eq!(address.user, "user");
        assert_eq!(address.domain, "kutup.dev");
        assert_eq!(address.name(), "user@kutup.dev");
        assert_eq!(
            address.conversation(),
            ConversationId::direct(AccountAddress::federated("user", "kutup.dev").unwrap())
        );
    }

    #[test]
    fn malformed_federated_sender_fails_closed() {
        assert!(ChatAddress::from_sender("user@@kutup.dev", 1).is_err());
        assert!(ChatAddress::from_sender("user", 1).is_err());
    }
}
