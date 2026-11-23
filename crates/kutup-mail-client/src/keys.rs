//! A Kutup address's public keys (docs/plans/mail-address-keys.md), checked
//! before anything is encrypted to them or a signature is trusted, as
//! `mail-core/keys.ts` checks them: every key list in the chain is signed by
//! the account's authority (or, for a shared mailbox, by its group signers)
//! and follows the one before, and only the keys the newest list names are
//! kept.
//!
//! [`verified`] is the check of one lookup. What the device remembers comes
//! after it, from the caller: [`rollback_id`] names the count a lookup's
//! sequence is held to (the revision guard), and [`apply_pin`] /
//! [`apply_group_pin`] apply the pin list's verdict.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::mail_key::{
    inspect_address_public_key, SignedMailKeyListV1, FLAG_EMAIL_NO_ENCRYPT, FLAG_NOT_COMPROMISED,
    FLAG_NOT_OBSOLETE,
};
use kutup_crypto::names::fold_address;
use serde::{Deserialize, Serialize};

/// What the revision guard calls an address's key list (`KEY_LIST_GUARD_SCOPE`
/// in `mail-core/keyList.ts`): one count for the account's own lists and its
/// recipients'.
pub const KEY_LIST_GUARD_SCOPE: &str = "mail-key-list";

/// One of an address's keys as `GET /api/v1/mail/keys` lists it (the server's
/// word: its flags count for nothing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRow {
    pub fingerprint: String,
    pub sha256_fingerprint: String,
    /// Base64, binary OpenPGP.
    pub public_key: String,
    pub primary: bool,
    pub flags: u32,
}

/// A signed key list as the lookup carries it (base64).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyListRow {
    pub data: String,
    pub signature: String,
}

/// A person's address: lists signed by their account authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonKeyLookup {
    pub address: String,
    /// The account's server (server-asserted).
    pub server: String,
    pub account_id: String,
    /// Base64, 32 bytes.
    pub account_authority_public_key: String,
    pub keys: Vec<PublicKeyRow>,
    pub key_lists: Vec<KeyListRow>,
}

/// A shared mailbox: lists signed by its own group signers
/// (docs/plans/mail-groups.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupKeyLookup {
    pub address: String,
    pub server: String,
    pub group_id: String,
    /// Base64: the chain's first signer.
    pub first_signer: String,
    pub keys: Vec<PublicKeyRow>,
    pub key_lists: Vec<KeyListRow>,
    /// Base64 handovers to each next signer.
    #[serde(default)]
    pub signer_handovers: Vec<String>,
}

/// What `GET /api/v1/mail/keys` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyLookup {
    Group(GroupKeyLookup),
    Person(PersonKeyLookup),
}

impl KeyLookup {
    pub fn address(&self) -> &str {
        match self {
            Self::Group(g) => &g.address,
            Self::Person(p) => &p.address,
        }
    }

    fn server(&self) -> &str {
        match self {
            Self::Group(g) => &g.server,
            Self::Person(p) => &p.server,
        }
    }

    fn keys(&self) -> &[PublicKeyRow] {
        match self {
            Self::Group(g) => &g.keys,
            Self::Person(p) => &p.keys,
        }
    }
}

/// The account an address belongs to, for good (docs/plans/account-ids.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRef {
    pub server: String,
    pub account_id: String,
}

/// A shared mailbox's verified chain, as the pin list checks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupChain {
    pub server: String,
    pub group_id: String,
    /// Base64, the first signer first.
    pub signers: Vec<String>,
    /// Each list's hash (hex), list 1's first.
    pub digests: Vec<String>,
}

/// An address's checked keys (`AddressKeys` in `mail-core/keys.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressKeys {
    /// As stored (the lookup's, whatever spelling was asked).
    pub address: String,
    /// The newest key list's sequence.
    pub sequence: u64,
    /// A person's account; absent for a shared mailbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<AccountRef>,
    /// The account's own name when the pin list knows it by another address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_as: Option<String>,
    /// A shared mailbox's chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupChain>,
    /// Base64: the newest list's signer (the account authority, or the
    /// group's signer now).
    pub authority_public_key: String,
    /// Base64: the key to encrypt to.
    pub primary: String,
    /// Base64: every key the newest list trusts for signatures (not marked
    /// compromised), primary first.
    pub all: Vec<String>,
    /// The newest list says not to encrypt to the address (it forwards
    /// outside): mail to it goes readable and is sealed when it arrives.
    pub encryption_disabled: bool,
    /// The newest list encrypts to nothing: the address is disabled.
    pub disabled: bool,
}

/// Why an address's keys are refused (`mail-core/keys.ts`'s errors).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeysError {
    /// The server's keys don't match what the owner signed (or a list is
    /// older than this device has seen).
    #[error("the keys of {0} do not match their signed key list")]
    Unverified(String),
    /// Not the person the pin list knows: another authority, or an address a
    /// known person holds now leading to another account (`now`: where that
    /// person is).
    #[error("the keys of {address} are not signed by the account met before")]
    IdentityChanged {
        address: String,
        now: Option<String>,
    },
    /// A shared mailbox's keys aren't signed by the signer met before;
    /// `chain` is what is published now, for the person to accept.
    #[error("the keys of the shared mailbox {address} are not signed by the signer met before")]
    GroupChanged {
        address: String,
        chain: Option<GroupChain>,
    },
    /// Its owner disabled the address: nothing is sent to it.
    #[error("{0} is disabled")]
    Disabled(String),
}

fn decode(value: &str) -> Option<Vec<u8>> {
    STANDARD.decode(value).ok()
}

fn authority_key(value: &str) -> Option<[u8; 32]> {
    decode(value)?.try_into().ok()
}

/// A lookup's keys, kept only where its signed key lists name them
/// (`verified` in `mail-core/keys.ts`). `own_server` is this account's
/// server (the domain of its Kutup address): an account lives on its
/// address's server, or on this one for an address on a domain it holds.
pub fn verified(
    address: &str,
    lookup: &KeyLookup,
    own_server: Option<&str>,
) -> Result<AddressKeys, KeysError> {
    let refused = || KeysError::Unverified(address.to_owned());
    let asked = fold_address(address).ok_or_else(refused)?;
    if Some(asked) != fold_address(lookup.address()) {
        return Err(refused());
    }
    let domain = lookup
        .address()
        .rsplit_once('@')
        .map(|(_, d)| d.to_lowercase())
        .ok_or_else(refused)?;
    let own = own_server.map(str::to_lowercase);
    if lookup.server() != domain && Some(lookup.server().to_owned()) != own {
        return Err(refused());
    }
    let (newest, signer, group) = match lookup {
        KeyLookup::Person(person) => {
            let authority =
                authority_key(&person.account_authority_public_key).ok_or_else(refused)?;
            let mut newest: Option<SignedMailKeyListV1> = None;
            for list in &person.key_lists {
                let data = decode(&list.data).ok_or_else(refused)?;
                let signature = decode(&list.signature).ok_or_else(refused)?;
                let signed = SignedMailKeyListV1::verify(&data, &signature, &authority)
                    .map_err(|_| refused())?;
                if let Some(previous) = &newest {
                    previous.check_successor(&signed).map_err(|_| refused())?;
                }
                newest = Some(signed);
            }
            (newest, person.account_authority_public_key.clone(), None)
        }
        KeyLookup::Group(group) => {
            let first = authority_key(&group.first_signer).ok_or_else(refused)?;
            let decoded = group
                .key_lists
                .iter()
                .map(|list| Some((decode(&list.data)?, decode(&list.signature)?)))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(refused)?;
            let pairs: Vec<(&[u8], &[u8])> = decoded
                .iter()
                .map(|(d, s)| (d.as_slice(), s.as_slice()))
                .collect();
            let handovers = group
                .signer_handovers
                .iter()
                .map(|h| {
                    decode(h).and_then(|bytes| {
                        kutup_crypto::mail_group::GroupSignerHandoverV1::decode(&bytes).ok()
                    })
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(refused)?;
            let chain = kutup_crypto::mail_group::verify_group_key_chain(
                &group.group_id,
                &first,
                &pairs,
                &handovers,
            )
            .map_err(|_| refused())?;
            let (data, signature) = decoded.last().ok_or_else(refused)?;
            let newest = SignedMailKeyListV1::verify(data, signature, &chain.signer)
                .map_err(|_| refused())?;
            let view = GroupChain {
                server: group.server.clone(),
                group_id: group.group_id.clone(),
                signers: chain.signers.iter().map(|s| STANDARD.encode(s)).collect(),
                digests: chain.digests.iter().map(hex::encode).collect(),
            };
            (Some(newest), STANDARD.encode(chain.signer), Some(view))
        }
    };
    let newest = newest.ok_or_else(refused)?;
    if newest.list.address != lookup.address() {
        return Err(refused());
    }
    // The server's rows, kept only where the newest list names the key; the
    // list's primary and flags, never the row's.
    let mut kept: Vec<(String, bool, u32)> = Vec::new();
    for row in lookup.keys() {
        let Some(public_key) = decode(&row.public_key) else {
            continue;
        };
        let Ok(info) = inspect_address_public_key(&public_key, lookup.address()) else {
            continue;
        };
        if let Some(listed) = newest.list.keys.iter().find(|k| {
            k.fingerprint.as_slice() == info.fingerprint.as_slice()
                && k.sha256_fingerprint == info.sha256_fingerprint
        }) {
            kept.push((row.public_key.clone(), listed.primary, listed.flags));
        }
    }
    let primary = kept
        .iter()
        .find(|(_, primary, _)| *primary)
        .cloned()
        .ok_or_else(refused)?;
    let all = std::iter::once(&primary)
        .chain(kept.iter().filter(|k| !k.1))
        .filter(|(_, _, flags)| flags & FLAG_NOT_COMPROMISED != 0)
        .map(|(key, _, _)| key.clone())
        .collect();
    Ok(AddressKeys {
        address: lookup.address().to_owned(),
        sequence: newest.list.sequence,
        account_ref: match lookup {
            KeyLookup::Person(p) => Some(AccountRef {
                server: p.server.clone(),
                account_id: p.account_id.clone(),
            }),
            KeyLookup::Group(_) => None,
        },
        known_as: None,
        group,
        authority_public_key: signer,
        primary: primary.0,
        all,
        encryption_disabled: primary.2 & FLAG_EMAIL_NO_ENCRYPT != 0,
        disabled: primary.2 & FLAG_NOT_OBSOLETE == 0,
    })
}

/// The id the revision guard counts `keys`' sequence under (scope
/// [`KEY_LIST_GUARD_SCOPE`]): a person's list per address and authority; a
/// shared mailbox's per address, mailbox and chain (its first signer), so a
/// handover stays one count and a new chain starts its own.
pub fn rollback_id(keys: &AddressKeys) -> String {
    let folded = fold_address(&keys.address).unwrap_or_else(|| keys.address.clone());
    match &keys.group {
        Some(group) => format!(
            "{folded}:group:{}:{}",
            group.group_id,
            group.signers.first().map_or("", String::as_str)
        ),
        None => format!("{folded}:{}", keys.authority_public_key),
    }
}

/// The revision guard's answer: `seen` is the highest sequence this device
/// has counted under [`rollback_id`] (None: never). A list older than that
/// is refused (a server handing back an earlier list).
pub fn not_rolled_back(keys: AddressKeys, seen: Option<u64>) -> Result<AddressKeys, KeysError> {
    if seen.is_some_and(|seen| keys.sequence < seen) {
        return Err(KeysError::Unverified(keys.address));
    }
    Ok(keys)
}

/// What the pin list says of a person's account at an address (drive-core's
/// `pinnedVerdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerdict {
    /// Never met: trusted on first use.
    Unknown,
    /// Pinned, with the account's own name when known by another address.
    Pinned { name: Option<String> },
    /// Another authority for a pinned account.
    Changed,
    /// An address a known person holds now leads to another account;
    /// `now`: where that person is.
    SomeoneElse { now: Option<String> },
}

/// `keys` held to the pin list's verdict for a person (`pinned` in
/// `mail-core/keys.ts`), then refused when disabled.
pub fn apply_pin(mut keys: AddressKeys, verdict: PinVerdict) -> Result<AddressKeys, KeysError> {
    match verdict {
        PinVerdict::Changed => {
            return Err(KeysError::IdentityChanged {
                address: keys.address,
                now: None,
            })
        }
        PinVerdict::SomeoneElse { now } => {
            return Err(KeysError::IdentityChanged {
                address: keys.address,
                now,
            })
        }
        PinVerdict::Pinned { name: Some(name) } => keys.known_as = Some(name),
        PinVerdict::Pinned { name: None } | PinVerdict::Unknown => {}
    }
    if keys.disabled {
        return Err(KeysError::Disabled(keys.address));
    }
    Ok(keys)
}

/// `keys` of a shared mailbox held to the pin list's verdict for its chain
/// (`checkGroup`): `changed` refuses, with the chain to accept.
pub fn apply_group_pin(keys: AddressKeys, changed: bool) -> Result<AddressKeys, KeysError> {
    if changed {
        return Err(KeysError::GroupChanged {
            address: keys.address,
            chain: keys.group,
        });
    }
    if keys.disabled {
        return Err(KeysError::Disabled(keys.address));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(disabled: bool) -> AddressKeys {
        AddressKeys {
            address: "ada_l@kutup.dev".into(),
            sequence: 3,
            account_ref: Some(AccountRef {
                server: "kutup.dev".into(),
                account_id: "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70".into(),
            }),
            known_as: None,
            group: None,
            authority_public_key: "AUTH".into(),
            primary: "KEY".into(),
            all: vec!["KEY".into()],
            encryption_disabled: false,
            disabled,
        }
    }

    #[test]
    fn a_list_older_than_seen_is_refused() {
        assert_eq!(rollback_id(&keys(false)), "adal@kutup.dev:AUTH");
        assert!(not_rolled_back(keys(false), None).is_ok());
        assert!(not_rolled_back(keys(false), Some(3)).is_ok());
        assert_eq!(
            not_rolled_back(keys(false), Some(4)),
            Err(KeysError::Unverified("ada_l@kutup.dev".into()))
        );
        let mut group = keys(false);
        group.group = Some(GroupChain {
            server: "kutup.dev".into(),
            group_id: "g1".into(),
            signers: vec!["FIRST".into(), "SECOND".into()],
            digests: vec![],
        });
        assert_eq!(rollback_id(&group), "adal@kutup.dev:group:g1:FIRST");
    }

    #[test]
    fn the_pin_list_decides_then_a_disabled_address_is_refused() {
        assert!(apply_pin(keys(false), PinVerdict::Unknown).is_ok());
        assert_eq!(
            apply_pin(
                keys(false),
                PinVerdict::Pinned {
                    name: Some("ada_lovelace@kutup.dev".into())
                }
            )
            .unwrap()
            .known_as
            .as_deref(),
            Some("ada_lovelace@kutup.dev")
        );
        assert!(matches!(
            apply_pin(keys(false), PinVerdict::Changed),
            Err(KeysError::IdentityChanged { now: None, .. })
        ));
        assert_eq!(
            apply_pin(
                keys(false),
                PinVerdict::SomeoneElse {
                    now: Some("ada_lovelace@kutup.dev".into())
                }
            ),
            Err(KeysError::IdentityChanged {
                address: "ada_l@kutup.dev".into(),
                now: Some("ada_lovelace@kutup.dev".into())
            })
        );
        assert_eq!(
            apply_pin(keys(true), PinVerdict::Unknown),
            Err(KeysError::Disabled("ada_l@kutup.dev".into()))
        );
        assert!(matches!(
            apply_group_pin(keys(false), true),
            Err(KeysError::GroupChanged { .. })
        ));
        assert!(apply_group_pin(keys(false), false).is_ok());
    }
}
