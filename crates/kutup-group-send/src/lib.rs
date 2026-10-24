//! Group send endorsements for Chat's multi-recipient route
//! (docs/plans/group-send-endorsements.md), on libsignal's zkgroup.
//!
//! Each account's own server endorses it once a day under the fixed public
//! params P0 ([`params_master_key`], §3.1; §3.2: [`ServerKey::issue`]). The member checks the
//! response ([`receive`]) and shares it, in an [`EndorsementBlob`] sealed
//! under each group's state key, with the group's home (§3.3). A sender
//! checks the blobs of the recipients on one server, combines their
//! endorsements into one token ([`token`], §3.4), and that server verifies
//! the token with its own key ([`ServerKey`]s in [`verify_token`], §3.5).
//!
//! Times are Unix seconds, as zkgroup's `Timestamp`. Randomness comes from
//! `kutup_crypto::primitives::random`, the one random source.

use kutup_crypto::primitives::{hash, random_array, Suite};
use uuid::Uuid;

mod zk;

pub use zk::{receive, token, verify_token, Endorsement, EndorsementKey, Issued, ServerKey};

/// Seconds in a day: expirations are day-aligned.
pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// The furthest ahead an expiration may be (§3.7): clients, homes and senders
/// refuse one later than this. The server issues libsignal's default (the end
/// of the next day UTC, 25 to 49 hours ahead).
pub const MAX_ENDORSEMENT_LIFETIME_SECS: u64 = 3 * SECONDS_PER_DAY;

/// A client fetches its next endorsement once its current one has less than
/// this left (§3.7), and uploads it to each group.
pub const REFRESH_BEFORE_SECS: u64 = 25 * 60 * 60;

/// A blob's length before sealing (every blob is padded to it, so all are
/// the same size, §3.3), and sealed under the group's state key, as the home
/// stores it: wire facts, defined with the wire types.
pub use kutup_chat_proto::group_send::{ENDORSEMENT_BLOB_BYTES, ENDORSEMENT_SEALED_BYTES};

/// The label P0's master key is the hash of (§3.1).
pub const PARAMS_LABEL: &[u8] = b"kutup/chat-group-send/params/v1";

/// The blob format's version byte.
const BLOB_VERSION: u8 = 1;

/// The longest server name a blob carries (a DNS name).
pub const MAX_SERVER_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not a well-formed value of its kind (bytes that don't decode, a blob
    /// that isn't one).
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// An expiration not day-aligned, past, or further ahead than the cap.
    #[error("expiration out of range")]
    Expiration,
    /// A response or token that doesn't verify.
    #[error("verification failed")]
    Invalid,
    /// Endorsements of different expirations combined into one token.
    #[error("endorsements of different expirations")]
    MixedExpirations,
    /// A token naming one recipient twice (`400` on the multi route).
    #[error("duplicate recipient")]
    DuplicateRecipient,
    /// A token over no recipients.
    #[error("no recipients")]
    NoRecipients,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Whether `expiration` is one a home or a sender takes at `now`: day-aligned,
/// in the future, and at most [`MAX_ENDORSEMENT_LIFETIME_SECS`] ahead.
/// ([`receive`] also refuses one under two hours away, as libsignal does.)
pub fn check_expiration(expiration: u64, now: u64) -> Result<()> {
    if !expiration.is_multiple_of(SECONDS_PER_DAY)
        || expiration <= now
        || expiration - now > MAX_ENDORSEMENT_LIFETIME_SECS
    {
        return Err(Error::Expiration);
    }
    Ok(())
}

/// The expiration the server issues at `now` (libsignal's default: the end of
/// the next day UTC, at least 25 hours ahead).
pub fn default_expiration(now: u64) -> u64 {
    zk::default_expiration(now)
}

/// P0's master key: the hash of [`PARAMS_LABEL`]. Public: anyone derives it.
pub fn params_master_key() -> [u8; 32] {
    hash(Suite::V1, PARAMS_LABEL).to_array()
}

/// What a member shares with each of its groups (§3.3): the response its
/// server issued, with the server and the key id to check it against. Padded
/// to [`ENDORSEMENT_BLOB_BYTES`] and sealed under the group's state key
/// (`SealedField::Endorsement`, the member's pseudonym as subject) by Chat
/// core.
///
/// Layout: version (1) · server length (1) · server · key id (u32 BE) ·
/// response length (u16 BE) · response · zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorsementBlob {
    pub server: String,
    pub key_id: u32,
    /// The `GroupSendEndorsementsResponse`, as issued (with its proof).
    pub response: Vec<u8>,
}

impl EndorsementBlob {
    pub fn encode(&self) -> Result<[u8; ENDORSEMENT_BLOB_BYTES]> {
        if !valid_server(&self.server) {
            return Err(Error::Malformed("endorsement blob server"));
        }
        let response_len =
            u16::try_from(self.response.len()).map_err(|_| Error::Malformed("endorsement blob"))?;
        let mut out = [0u8; ENDORSEMENT_BLOB_BYTES];
        let mut at = 0;
        let mut put = |bytes: &[u8]| -> Result<()> {
            let end = at + bytes.len();
            if end > ENDORSEMENT_BLOB_BYTES {
                return Err(Error::Malformed("endorsement blob"));
            }
            out[at..end].copy_from_slice(bytes);
            at = end;
            Ok(())
        };
        put(&[BLOB_VERSION, self.server.len() as u8])?;
        put(self.server.as_bytes())?;
        put(&self.key_id.to_be_bytes())?;
        put(&response_len.to_be_bytes())?;
        put(&self.response)?;
        Ok(out)
    }

    /// The blob in `bytes`: exactly [`ENDORSEMENT_BLOB_BYTES`] long, padded
    /// with zeros only.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        const MALFORMED: Error = Error::Malformed("endorsement blob");
        if bytes.len() != ENDORSEMENT_BLOB_BYTES || bytes[0] != BLOB_VERSION {
            return Err(MALFORMED);
        }
        let mut at = 1;
        let mut take = |len: usize| -> Result<&[u8]> {
            let end = at + len;
            let slice = bytes.get(at..end).ok_or(MALFORMED)?;
            at = end;
            Ok(slice)
        };
        let server_len = usize::from(take(1)?[0]);
        let server = std::str::from_utf8(take(server_len)?).map_err(|_| MALFORMED)?;
        if !valid_server(server) {
            return Err(MALFORMED);
        }
        let server = server.to_string();
        let key_id = u32::from_be_bytes(take(4)?.try_into().map_err(|_| MALFORMED)?);
        let response_len = u16::from_be_bytes(take(2)?.try_into().map_err(|_| MALFORMED)?);
        let response = take(usize::from(response_len))?.to_vec();
        if response.is_empty() || bytes[at..].iter().any(|&byte| byte != 0) {
            return Err(MALFORMED);
        }
        Ok(Self {
            server,
            key_id,
            response,
        })
    }
}

/// A server name as blobs carry it: 1 to 253 bytes of lowercase DNS
/// characters (and a port, for test stacks).
fn valid_server(server: &str) -> bool {
    !server.is_empty()
        && server.len() <= MAX_SERVER_LEN
        && server
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b':'))
}

/// Fresh randomness for one zkgroup operation.
fn randomness() -> [u8; 32] {
    random_array::<32>()
}

/// An account id as libsignal's service id.
fn aci(account: Uuid) -> libsignal_core::ServiceId {
    libsignal_core::Aci::from(account).into()
}

#[cfg(test)]
mod tests;
