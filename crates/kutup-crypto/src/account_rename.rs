//! Account renames (docs/plans/username-renames.md): the account authority
//! says "the account formerly `previous` is now `current`".
//!
//! Each rename is one statement, numbered from 1, and an account's renames form
//! a chain: statement n+1 starts where statement n ended. The chain is signed
//! by the authority whose hash is the incarnation id it names, so it moves
//! data (conversations, pins, shares) only *to* the account that signed it.
//! It cannot be used to claim the old name: a later holder of it is another
//! incarnation with another authority. It cannot claim the new name for anyone
//! else: the name must match the signer's current manifest. A client keeps the
//! longest chain it has verified for an incarnation and accepts only chains
//! that extend it, so a server cannot roll a rename back.
//!
//! Both addresses are on one server: moving an account between servers is a
//! different thing, not this.

use crate::primitives::{Hasher, Suite, VerifyingKey};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};
use crate::named_share::canonical_account;

const DOMAIN: &[u8] = b"kutup/account-rename/v1\0";
/// The most renames one chain holds.
pub const MAX_CHAIN: usize = 1000;
/// 2020-01-01T00:00:00Z and 2200-01-01T00:00:00Z, in milliseconds.
const MIN_ISSUED_AT_MS: i64 = 1_577_836_800_000;
const MAX_ISSUED_AT_MS: i64 = 7_258_118_400_000;

/// One signed rename, as stored and sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountRenameV1 {
    /// The signer's incarnation id (lowercase hex of the authority's hash).
    pub incarnation_id: String,
    /// 1 for the first rename, one more for each after it.
    pub sequence: u64,
    /// The address before, canonical `username@server`.
    pub previous: String,
    /// The address after, on the same server.
    pub current: String,
    /// When it was signed, in UTC milliseconds.
    pub issued_at_ms: i64,
    /// The authority's Ed25519 signature over [`signing_bytes`], canonical base64.
    pub signature: String,
}

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("account rename: {what}"))
}

fn server_of(account: &str) -> &str {
    account.split_once('@').map_or("", |(_, server)| server)
}

/// The bytes the authority signs.
pub fn signing_bytes(
    incarnation_id: &str,
    sequence: u64,
    previous: &str,
    current: &str,
    issued_at_ms: i64,
) -> Result<Vec<u8>> {
    let incarnation = hex::decode(incarnation_id)
        .ok()
        .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == incarnation_id)
        .ok_or_else(|| invalid("incarnation id"))?;
    let previous = canonical_account(previous).map_err(|_| invalid("previous address"))?;
    let current = canonical_account(current).map_err(|_| invalid("current address"))?;
    if sequence == 0 || sequence > MAX_CHAIN as u64 {
        return Err(invalid("sequence"));
    }
    if previous == current {
        return Err(invalid("previous and current are the same"));
    }
    if server_of(&previous) != server_of(&current) {
        return Err(invalid("previous and current are on different servers"));
    }
    if !(MIN_ISSUED_AT_MS..=MAX_ISSUED_AT_MS).contains(&issued_at_ms) {
        return Err(invalid("issuedAtMs"));
    }
    let mut out =
        Vec::with_capacity(DOMAIN.len() + 32 + 8 + 4 + previous.len() + current.len() + 8);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(&sequence.to_be_bytes());
    for address in [&previous, &current] {
        let len = u16::try_from(address.len()).map_err(|_| invalid("address is too long"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(address.as_bytes());
    }
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    Ok(out)
}

/// A rename signed by `identity`'s authority.
pub fn sign(
    identity: &AccountIdentityKeysV1,
    sequence: u64,
    previous: &str,
    current: &str,
    issued_at_ms: i64,
) -> Result<AccountRenameV1> {
    let incarnation_id = identity.incarnation_id();
    let bytes = signing_bytes(&incarnation_id, sequence, previous, current, issued_at_ms)?;
    Ok(AccountRenameV1 {
        incarnation_id,
        sequence,
        previous: previous.to_owned(),
        current: current.to_owned(),
        issued_at_ms,
        signature: STANDARD.encode(identity.authority_signing_key().sign(&bytes)),
    })
}

impl AccountRenameV1 {
    /// The statement's signing bytes, checked.
    fn bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(
            &self.incarnation_id,
            self.sequence,
            &self.previous,
            &self.current,
            self.issued_at_ms,
        )
    }

    /// Checks the statement alone against `authority_public`: its form, that
    /// it names this authority's incarnation, and the signature.
    pub fn verify(&self, authority_public: &[u8; 32]) -> Result<()> {
        let bytes = self.bytes()?;
        if self.incarnation_id != incarnation_id_from_authority_public(authority_public) {
            return Err(invalid("signed for another incarnation"));
        }
        let signature: [u8; 64] = STANDARD
            .decode(&self.signature)
            .ok()
            .filter(|raw| STANDARD.encode(raw) == self.signature)
            .and_then(|raw| raw.try_into().ok())
            .ok_or_else(|| invalid("signature"))?;
        VerifyingKey::from_bytes(Suite::V1, authority_public)
            .map_err(|_| invalid("authority key"))?
            .verify(&bytes, &signature)
            .map_err(|_| CryptoError::AuthFailed)
    }

    /// The statement's digest: what a client remembers of a chain it verified.
    fn digest(&self) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new(Suite::V1);
        hasher.update(self.bytes()?);
        hasher.update(self.signature.as_bytes());
        Ok(hasher.finish().to_array())
    }
}

/// What a verified chain says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameChainView {
    pub incarnation_id: String,
    /// The address the account had first.
    pub first: String,
    /// The address it has now.
    pub current: String,
    /// Every address it has had, oldest first (`first` … `current`).
    pub addresses: Vec<String>,
    /// The number of renames (the last statement's sequence).
    pub sequence: u64,
    /// One digest per statement, in order.
    pub digests: Vec<[u8; 32]>,
}

impl RenameChainView {
    /// Whether this chain is `earlier` with zero or more renames after it: the
    /// only kind of change a client accepts, so a server cannot roll a rename
    /// back or rewrite one.
    pub fn extends(&self, earlier: &RenameChainView) -> bool {
        self.incarnation_id == earlier.incarnation_id
            && self.digests.len() >= earlier.digests.len()
            && self.digests[..earlier.digests.len()] == earlier.digests[..]
    }

    /// Whether `address` is one this account has had.
    pub fn had(&self, address: &str) -> bool {
        self.addresses.iter().any(|known| known == address)
    }
}

/// Verifies an account's whole rename chain against its authority: every
/// statement signed by it and naming its incarnation, numbered 1, 2, …, each
/// starting at the address the one before ended at, in time order.
pub fn verify_chain(
    authority_public: &[u8; 32],
    chain: &[AccountRenameV1],
) -> Result<RenameChainView> {
    if chain.is_empty() {
        return Err(invalid("empty chain"));
    }
    if chain.len() > MAX_CHAIN {
        return Err(invalid("chain is too long"));
    }
    let mut addresses = vec![chain[0].previous.clone()];
    let mut digests = Vec::with_capacity(chain.len());
    let mut last_issued = i64::MIN;
    for (index, statement) in chain.iter().enumerate() {
        statement.verify(authority_public)?;
        if statement.sequence != index as u64 + 1 {
            return Err(invalid("sequence is not consecutive"));
        }
        if statement.previous != *addresses.last().expect("one address at least") {
            return Err(invalid(
                "a rename does not start where the one before ended",
            ));
        }
        if statement.issued_at_ms < last_issued {
            return Err(invalid("renames are out of time order"));
        }
        last_issued = statement.issued_at_ms;
        addresses.push(statement.current.clone());
        digests.push(statement.digest()?);
    }
    Ok(RenameChainView {
        incarnation_id: chain[0].incarnation_id.clone(),
        first: addresses[0].clone(),
        current: addresses.last().expect("one address at least").clone(),
        addresses,
        sequence: chain.len() as u64,
        digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_790_000_000_000;

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&[seed; 32]).unwrap()
    }

    fn chain(id: &AccountIdentityKeysV1) -> Vec<AccountRenameV1> {
        vec![
            sign(id, 1, "alice@kutup.dev", "alicia@kutup.dev", T).unwrap(),
            sign(id, 2, "alicia@kutup.dev", "ali@kutup.dev", T + 1).unwrap(),
        ]
    }

    #[test]
    fn a_chain_verifies_and_says_where_the_account_is() {
        let id = identity(1);
        let view = verify_chain(&id.authority_public_key(), &chain(&id)).unwrap();
        assert_eq!(view.first, "alice@kutup.dev");
        assert_eq!(view.current, "ali@kutup.dev");
        assert_eq!(view.sequence, 2);
        assert!(view.had("alicia@kutup.dev"));
        let shorter = verify_chain(&id.authority_public_key(), &chain(&id)[..1]).unwrap();
        assert!(view.extends(&shorter));
        assert!(
            !shorter.extends(&view),
            "a shorter chain rolls a rename back"
        );
    }

    #[test]
    fn another_authority_proves_nothing() {
        let (id, newcomer) = (identity(1), identity(2));
        // The old name's next holder cannot use the old owner's chain, nor
        // sign one that names the old owner's incarnation.
        assert!(verify_chain(&newcomer.authority_public_key(), &chain(&id)).is_err());
        let mut forged = chain(&id);
        forged[0] = sign(&newcomer, 1, "alice@kutup.dev", "alicia@kutup.dev", T).unwrap();
        forged[0].incarnation_id = id.incarnation_id();
        assert!(verify_chain(&id.authority_public_key(), &forged).is_err());
    }

    #[test]
    fn broken_chains_are_refused() {
        let id = identity(1);
        let key = id.authority_public_key();
        let gap = vec![sign(&id, 2, "alice@kutup.dev", "alicia@kutup.dev", T).unwrap()];
        assert!(verify_chain(&key, &gap).is_err());
        let unlinked = vec![
            sign(&id, 1, "alice@kutup.dev", "alicia@kutup.dev", T).unwrap(),
            sign(&id, 2, "bob@kutup.dev", "ali@kutup.dev", T + 1).unwrap(),
        ];
        assert!(verify_chain(&key, &unlinked).is_err());
        let backwards = vec![
            sign(&id, 1, "alice@kutup.dev", "alicia@kutup.dev", T).unwrap(),
            sign(&id, 2, "alicia@kutup.dev", "ali@kutup.dev", T - 1).unwrap(),
        ];
        assert!(verify_chain(&key, &backwards).is_err());
        assert!(sign(&id, 1, "alice@kutup.dev", "alice@other.dev", T).is_err());
        assert!(sign(&id, 1, "alice@kutup.dev", "alice@kutup.dev", T).is_err());
        assert!(sign(&id, 1, "Alice@kutup.dev", "bob@kutup.dev", T).is_err());
        let mut tampered = chain(&id);
        tampered[1].current = "mallory@kutup.dev".into();
        assert!(verify_chain(&key, &tampered).is_err());
        assert!(verify_chain(&key, &[]).is_err());
    }
}
