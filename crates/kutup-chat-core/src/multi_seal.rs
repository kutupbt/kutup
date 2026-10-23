//! Multi-recipient sealed sender (libsignal's sealed sender v2) for group
//! sends on one destination server (docs/plans/pairwise-groups.md, "Slice
//! 2"). libsignal names each recipient by its service id (a bare account
//! UUID), while Kutup keys sessions and identities by the full account
//! (`aci:<uuid>@<server>`). One request goes to one server, where account
//! ids are unique, so the bare id names one account here: the destinations
//! are named by it, and identities are looked up under the full name again.

use std::collections::HashMap;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, ProtocolAddress,
    SignalProtocolError,
};

type SignalResult<T> = std::result::Result<T, SignalProtocolError>;

/// The identity store as libsignal's multi-recipient encrypt reads it: by a
/// destination's bare account id, answered from the store under the full
/// name. Only reads; nothing is saved through it.
pub(crate) struct NamedIdentities<'a, S: IdentityKeyStore> {
    inner: &'a S,
    /// Bare account id → the full name the store keys it by.
    full_names: HashMap<String, String>,
}

impl<'a, S: IdentityKeyStore> NamedIdentities<'a, S> {
    pub(crate) fn new(inner: &'a S, full_names: HashMap<String, String>) -> Self {
        Self { inner, full_names }
    }

    fn full(&self, address: &ProtocolAddress) -> SignalResult<ProtocolAddress> {
        let name = self.full_names.get(address.name()).ok_or_else(|| {
            SignalProtocolError::InvalidArgument(format!(
                "no account named {} in this send",
                address.name()
            ))
        })?;
        Ok(ProtocolAddress::new(name.clone(), address.device_id()))
    }
}

#[async_trait(?Send)]
impl<S: IdentityKeyStore> IdentityKeyStore for NamedIdentities<'_, S> {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        self.inner.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        self.inner.get_local_registration_id().await
    }

    async fn save_identity(
        &mut self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        Err(SignalProtocolError::InvalidState(
            "multi-recipient sealed sender",
            "identities are checked before a send, never saved during one".into(),
        ))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> SignalResult<bool> {
        self.inner
            .is_trusted_identity(&self.full(address)?, identity, direction)
            .await
    }

    /// The stored identity, only when the account's verified manifest still
    /// lists it: libsignal's multi-recipient encrypt reads identities here
    /// and never asks `is_trusted_identity`, so the check that a pairwise
    /// send makes is made here, failing closed.
    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        let full = self.full(address)?;
        let Some(identity) = self.inner.get_identity(&full).await? else {
            return Ok(None);
        };
        if !self
            .inner
            .is_trusted_identity(&full, &identity, Direction::Sending)
            .await?
        {
            return Err(SignalProtocolError::UntrustedIdentity(full));
        }
        Ok(Some(identity))
    }
}
