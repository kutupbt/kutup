//! Chat addressing. Federation-ready from day one (`docs/chat-protocol.md`
//! §13): an address is `user`, an optional `domain`, and a device id. Local v1
//! leaves `domain` unset; phase 3 populates it, changing routing, not types.

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

    /// The `user` / `user@domain` string libsignal keys sessions by.
    pub fn name(&self) -> String {
        match &self.domain {
            Some(d) => format!("{}@{}", self.user, d),
            None => self.user.clone(),
        }
    }

    pub(crate) fn to_protocol(&self) -> Result<ProtocolAddress> {
        Ok(ProtocolAddress::new(
            self.name(),
            device_id_u8(self.device_id)?,
        ))
    }
}
