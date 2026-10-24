//! The zkgroup adapter: the only module that calls libsignal's zkgroup.
//! zkgroup names its own algorithms inside libsignal; nothing here names one
//! directly, and its randomness is drawn from kutup_crypto::primitives, so
//! the crypto lint holds here too.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use uuid::Uuid;
use zkgroup::groups::{
    GroupMasterKey, GroupSecretParams, GroupSendDerivedKeyPair, GroupSendEndorsement,
    GroupSendEndorsementsResponse, GroupSendFullToken,
};
use zkgroup::{EndorsementPublicKey, EndorsementServerRootKeyPair, ServerSecretParams, Timestamp};

use crate::{aci, check_expiration, params_master_key, randomness, Error, Result};

/// P0 (§3.1): the fixed public params every endorsement is issued and turned
/// into a token under. They hide nothing; libsignal's API needs a set.
fn params() -> &'static GroupSecretParams {
    static PARAMS: OnceLock<GroupSecretParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        GroupSecretParams::derive_from_master_key(GroupMasterKey::new(params_master_key()))
    })
}

/// P0's serialized bytes, for the vectors.
#[cfg(test)]
pub(crate) fn params_bytes() -> Vec<u8> {
    zkgroup::serialize(params())
}

pub(crate) fn default_expiration(now: u64) -> u64 {
    GroupSendEndorsementsResponse::default_expiration(Timestamp::from_epoch_seconds(now))
        .epoch_seconds()
}

/// A server's endorsement key (its secret): it issues endorsements for its
/// own accounts and verifies the tokens made from them. Only the
/// endorsement root of a `ServerSecretParams` is kept.
#[derive(Clone)]
pub struct ServerKey(EndorsementServerRootKeyPair);

impl ServerKey {
    pub fn generate() -> Self {
        Self::from_randomness(randomness())
    }

    pub(crate) fn from_randomness(randomness: [u8; 32]) -> Self {
        Self(ServerSecretParams::generate(randomness).get_endorsement_root_key_pair())
    }

    /// The key as stored (secret: seal it at rest).
    pub fn to_bytes(&self) -> Vec<u8> {
        zkgroup::serialize(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        zkgroup::deserialize(bytes)
            .map(Self)
            .map_err(|_| Error::Malformed("server key"))
    }

    /// The public key, as discovery publishes it.
    pub fn public_key(&self) -> EndorsementKey {
        EndorsementKey(self.0.public_key())
    }

    /// Today's endorsement of `account` at `now` (§3.2), expiring at
    /// [`crate::default_expiration`]: the full response, with its proof.
    pub fn issue(&self, account: Uuid, now: u64) -> Issued {
        self.issue_with(account, now, randomness())
    }

    pub(crate) fn issue_with(&self, account: Uuid, now: u64, randomness: [u8; 32]) -> Issued {
        let expiration = Timestamp::from_epoch_seconds(crate::default_expiration(now));
        let key_pair = GroupSendDerivedKeyPair::for_expiration(expiration, &self.0);
        let ciphertext = params().encrypt_service_id(aci(account));
        let response = GroupSendEndorsementsResponse::issue([ciphertext], &key_pair, randomness);
        Issued {
            expiration: expiration.epoch_seconds(),
            response: zkgroup::serialize(&response),
        }
    }

    /// A response expiring at `expiration`, whatever the schedule: what a
    /// misbehaving server could send.
    #[cfg(test)]
    pub(crate) fn issue_for_expiration(&self, account: Uuid, expiration: u64) -> Vec<u8> {
        let expiration =
            Timestamp::from_epoch_seconds(expiration - expiration % crate::SECONDS_PER_DAY);
        let key_pair = GroupSendDerivedKeyPair::for_expiration(expiration, &self.0);
        let ciphertext = params().encrypt_service_id(aci(account));
        zkgroup::serialize(&GroupSendEndorsementsResponse::issue(
            [ciphertext],
            &key_pair,
            randomness(),
        ))
    }

    fn verifies(&self, token: &GroupSendFullToken, recipients: &[Uuid], now: u64) -> bool {
        let key_pair = GroupSendDerivedKeyPair::for_expiration(token.expiration(), &self.0);
        token
            .verify(
                recipients.iter().map(|&account| aci(account)),
                Timestamp::from_epoch_seconds(now),
                &key_pair,
            )
            .is_ok()
    }
}

impl std::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerKey(..)")
    }
}

/// What [`ServerKey::issue`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub expiration: u64,
    /// The serialized `GroupSendEndorsementsResponse`.
    pub response: Vec<u8>,
}

/// A server's public endorsement key, as discovery publishes it: senders and
/// members check that server's endorsements with it.
#[derive(Clone)]
pub struct EndorsementKey(EndorsementPublicKey);

impl EndorsementKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        zkgroup::serialize(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        zkgroup::deserialize(bytes)
            .map(Self)
            .map_err(|_| Error::Malformed("endorsement key"))
    }
}

impl std::fmt::Debug for EndorsementKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EndorsementKey({})", hex_prefix(&self.to_bytes()))
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .skip(1)
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One account's checked endorsement, as a client keeps it: combinable with
/// others of the same server and expiration into a [`token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endorsement {
    pub expiration: u64,
    /// The compressed endorsement, serialized.
    bytes: Vec<u8>,
}

impl Endorsement {
    /// The endorsement as stored: expiration (u64 BE) · compressed endorsement.
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.expiration.to_be_bytes()[..], &self.bytes].concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const MALFORMED: Error = Error::Malformed("endorsement");
        if bytes.len() <= 8 {
            return Err(MALFORMED);
        }
        let (expiration, rest) = bytes.split_at(8);
        let endorsement = Self {
            expiration: u64::from_be_bytes(expiration.try_into().map_err(|_| MALFORMED)?),
            bytes: rest.to_vec(),
        };
        endorsement.point()?;
        Ok(endorsement)
    }

    fn point(&self) -> Result<GroupSendEndorsement> {
        zkgroup::deserialize(&self.bytes).map_err(|_| Error::Malformed("endorsement"))
    }
}

/// Checks `response`, issued for `account` by the server whose public key is
/// `key` (§3.3, §3.4): its proof, and its expiration (day-aligned, at least
/// two hours and at most [`crate::MAX_ENDORSEMENT_LIFETIME_SECS`] ahead).
/// The endorsement it holds, or why not.
pub fn receive(
    response: &[u8],
    account: Uuid,
    now: u64,
    key: &EndorsementKey,
) -> Result<Endorsement> {
    let response: GroupSendEndorsementsResponse =
        zkgroup::deserialize(response).map_err(|_| Error::Malformed("endorsement response"))?;
    let expiration = response.expiration().epoch_seconds();
    check_expiration(expiration, now)?;
    let received = response
        .receive_with_service_ids_single_threaded(
            [aci(account)],
            Timestamp::from_epoch_seconds(now),
            params(),
            &key.0,
        )
        .map_err(|_| Error::Invalid)?;
    let [endorsement] = received.as_slice() else {
        return Err(Error::Invalid);
    };
    Ok(Endorsement {
        expiration,
        bytes: zkgroup::serialize(&endorsement.compressed),
    })
}

/// The token for one multi-recipient request (§3.4): `endorsements`, one per
/// recipient, all of one server and one expiration, combined. The serialized
/// `GroupSendFullToken`.
pub fn token(endorsements: &[Endorsement]) -> Result<Vec<u8>> {
    let Some(first) = endorsements.first() else {
        return Err(Error::NoRecipients);
    };
    if endorsements
        .iter()
        .any(|endorsement| endorsement.expiration != first.expiration)
    {
        return Err(Error::MixedExpirations);
    }
    let points = endorsements
        .iter()
        .map(Endorsement::point)
        .collect::<Result<Vec<_>>>()?;
    let full = GroupSendEndorsement::combine(points)
        .to_token(params())
        .into_full_token(Timestamp::from_epoch_seconds(first.expiration));
    Ok(zkgroup::serialize(&full))
}

/// Verifies `token` for a request to `recipients` at `now` (§3.5) against
/// this server's keys, current first, then the previous one while it is in
/// its window. Duplicates are refused before anything is checked; every
/// other failure (malformed, expired, past the cap, a recipient added or
/// missing, another server's key) is [`Error::Invalid`].
pub fn verify_token(
    keys: &[&ServerKey],
    token: &[u8],
    recipients: &[Uuid],
    now: u64,
) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    let unique: BTreeSet<&Uuid> = recipients.iter().collect();
    if unique.len() != recipients.len() {
        return Err(Error::DuplicateRecipient);
    }
    let token: GroupSendFullToken = zkgroup::deserialize(token).map_err(|_| Error::Invalid)?;
    check_expiration(token.expiration().epoch_seconds(), now).map_err(|_| Error::Invalid)?;
    if keys.iter().any(|key| key.verifies(&token, recipients, now)) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}
