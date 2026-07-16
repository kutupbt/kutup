//! Chat addressing. Federation-ready from day one (`docs/chat-protocol.md`
//! §13): an address is `user`, an optional `domain`, and a device id. Local v1
//! leaves `domain` unset; phase 3 populates it, changing routing, not types.

use libsignal_protocol::{DeviceId, ProtocolAddress};
use kutup_chat_proto::{AccountAddress, ConversationId};

use crate::error::{ChatError, Result};

/// libsignal `DeviceId` is a `u8`; our wire ids are `u32` bounded to 1..=127.
pub(crate) fn device_id_u8(id: u32) -> Result<DeviceId> {
    let byte = u8::try_from(id).map_err(|_| ChatError::Invalid(format!("device id {id}")))?;
    DeviceId::new(byte).map_err(|_| ChatError::Invalid(format!("device id {id}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatAddress {
    pub user: String,
    /// `None` for a local user; `Some(domain)` once federation lands.
    pub domain: Option<String>,
    pub device_id: u32,
}

impl ChatAddress {
    pub fn local(user: impl Into<String>, device_id: u32) -> Self {
        ChatAddress {
            user: user.into(),
            domain: None,
            device_id,
        }
    }

    /// Parse a delivered envelope's `sender` (`user`, or `user@domain` once
    /// federation lands) plus its device id into an address.
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
        let address = ChatAddress::from_sender("maya@chat.example", 7).unwrap();
        assert_eq!(address.user, "maya");
        assert_eq!(address.domain.as_deref(), Some("chat.example"));
        assert_eq!(address.name(), "maya@chat.example");
        assert_eq!(
            address.conversation(),
            ConversationId::direct(AccountAddress::federated("maya", "chat.example").unwrap())
        );
    }

    #[test]
    fn malformed_federated_sender_fails_closed() {
        assert!(ChatAddress::from_sender("maya@@chat.example", 1).is_err());
    }
}
