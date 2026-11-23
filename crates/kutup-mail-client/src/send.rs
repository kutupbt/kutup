//! Who gets which copy of a message (`sendDraft` in `mail-core/api.ts`,
//! its recipient rules in `sendPlan.ts`): Kutup recipients one end-to-end
//! copy, keyed per recipient; outside recipients with a key a PGP message
//! (To and Cc together per scheme, each Bcc on their own, so key IDs never
//! name them); everyone else the readable message.
//!
//! Three steps, the caller looking addresses up between them:
//! [`split_recipients`], [`pgp_groups`], [`kutup_targets`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::keys::AddressKeys;
use crate::protection::{KutupLookup, Protection};

/// Proton's PGP schemes for outside recipients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scheme {
    PgpMime,
    Inline,
}

/// Why a send can't go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "error", content = "address", rename_all = "camelCase")]
pub enum SendError {
    /// This server holds the address on another domain, while Contacts
    /// trust other keys for it.
    #[error("this server holds {0}, but the keys trusted for it are others")]
    PinnedKeyConflict(String),
    /// Its owner disabled the address.
    #[error("{0} is disabled")]
    RecipientDisabled(String),
    /// Every key the person trusts for it is unusable.
    #[error("the keys trusted for {0} can no longer be used")]
    PinnedKeyUnusable(String),
    /// Not a Kutup address after all (on this server's domain).
    #[error("{0} is not a Kutup address")]
    UnknownRecipient(String),
    /// A lookup failed: nothing is sent rather than sent another way.
    #[error("could not look up {0}")]
    LookupFailed(String),
}

/// Every recipient once, lowercased, in the order given (To, Cc, Bcc).
pub fn everyone(to: &[String], cc: &[String], bcc: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    to.iter()
        .chain(cc)
        .chain(bcc)
        .map(|a| a.to_lowercase())
        .filter(|a| seen.insert(a.clone()))
        .collect()
}

/// The recipients split into Kutup ones and outside ones. `on_server`:
/// the address is on this server's own domain; `lookup`: what the Kutup
/// lookup gave for any other; `pinned_keys`: whether Contacts trust keys
/// for it.
pub fn split_recipients(
    everyone: &[String],
    on_server: impl Fn(&str) -> bool,
    lookup: impl Fn(&str) -> KutupLookup,
    pinned_keys: impl Fn(&str) -> bool,
) -> Result<(Vec<String>, Vec<String>), SendError> {
    let (mut local, mut external) = (Vec::new(), Vec::new());
    for address in everyone {
        if on_server(address) {
            local.push(address.clone());
            continue;
        }
        match lookup(address) {
            // This server's word never outranks keys Contacts trust.
            KutupLookup::Keys { .. } if pinned_keys(address) => {
                return Err(SendError::PinnedKeyConflict(address.clone()))
            }
            KutupLookup::Keys { .. } => local.push(address.clone()),
            KutupLookup::Disabled => return Err(SendError::RecipientDisabled(address.clone())),
            KutupLookup::NotKutup => external.push(address.clone()),
            KutupLookup::Group | KutupLookup::Failed => {
                return Err(SendError::LookupFailed(address.clone()))
            }
        }
    }
    Ok((local, external))
}

/// One PGP message for outside recipients: their keys (and the sender's,
/// for the sent copy, added by the caller) and its scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PgpGroup {
    pub recipients: Vec<String>,
    /// Base64, each recipient's key in order.
    pub keys: Vec<String>,
    pub inline: bool,
}

/// The PGP messages for outside recipients and who gets the readable one.
/// `protections[i]` is `external[i]`'s; `scheme` the contact's choice for
/// an address, else `default_scheme`; with `encrypt` off nobody outside
/// gets a PGP message.
pub fn pgp_groups(
    external: &[String],
    protections: &[Protection],
    bcc: &[String],
    scheme: impl Fn(&str) -> Option<Scheme>,
    default_scheme: Scheme,
    encrypt: bool,
) -> Result<(Vec<PgpGroup>, Vec<String>), SendError> {
    if let Some((address, _)) = external
        .iter()
        .zip(protections)
        .find(|(_, p)| matches!(p, Protection::PinnedUnusable { .. }))
    {
        return Err(SendError::PinnedKeyUnusable(address.clone()));
    }
    let bcc: BTreeSet<String> = bcc.iter().map(|a| a.to_lowercase()).collect();
    let keyed: Vec<(String, String, bool)> = if encrypt {
        external
            .iter()
            .zip(protections)
            .filter_map(|(address, protection)| {
                let key = protection.pgp_key()?;
                let inline = scheme(address).unwrap_or(default_scheme) == Scheme::Inline;
                Some((address.clone(), key.to_owned(), inline))
            })
            .collect()
    } else {
        Vec::new()
    };
    let group = |members: Vec<&(String, String, bool)>| PgpGroup {
        recipients: members.iter().map(|m| m.0.clone()).collect(),
        keys: members.iter().map(|m| m.1.clone()).collect(),
        inline: members.first().is_some_and(|m| m.2),
    };
    let mut groups = vec![
        group(
            keyed
                .iter()
                .filter(|r| !bcc.contains(&r.0) && !r.2)
                .collect(),
        ),
        group(
            keyed
                .iter()
                .filter(|r| !bcc.contains(&r.0) && r.2)
                .collect(),
        ),
    ];
    groups.extend(
        keyed
            .iter()
            .filter(|r| bcc.contains(&r.0))
            .map(|r| group(vec![r])),
    );
    groups.retain(|g| !g.recipients.is_empty());
    let plain = external
        .iter()
        .filter(|a| !keyed.iter().any(|r| &r.0 == *a))
        .cloned()
        .collect();
    Ok((groups, plain))
}

/// What a Kutup recipient's lookup gave at send time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KutupRecipient {
    Keys(Box<AddressKeys>),
    /// A group's address: its members' checked keys (disabled ones left out).
    Group(Vec<AddressKeys>),
    NotKutup,
    Disabled,
}

/// The Kutup recipients' copies: each target's address and the key its
/// copy is sealed to, and who gets the message readable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Targets {
    /// `(address, primary key, base64)`, in order.
    pub keyed: Vec<(String, String)>,
    pub readable: Vec<String>,
}

/// The Kutup recipients' keys (each address, or each member of a group,
/// once, never the sender) and who gets the message readable: with
/// `encrypt` off, or an address that forwards outside.
pub fn kutup_targets(
    local: &[String],
    lookup: impl Fn(&str) -> KutupRecipient,
    sender: &str,
    encrypt: bool,
) -> Result<Targets, SendError> {
    let mut targets: Vec<(String, String)> = Vec::new();
    let mut readable: Vec<String> = Vec::new();
    let put = |keys: &AddressKeys,
               encrypt: bool,
               targets: &mut Vec<(String, String)>,
               readable: &mut Vec<String>| {
        if encrypt && !keys.encryption_disabled {
            targets.push((keys.address.clone(), keys.primary.clone()));
        } else {
            readable.push(keys.address.clone());
        }
    };
    for address in local {
        match lookup(address) {
            KutupRecipient::Keys(keys) => {
                // The address as asked: the server checks each copy by it.
                let keys = AddressKeys {
                    address: address.clone(),
                    ..*keys
                };
                put(&keys, encrypt, &mut targets, &mut readable);
            }
            KutupRecipient::Group(members) => {
                for member in members {
                    let known = member.address == sender
                        || targets.iter().any(|(a, _)| *a == member.address)
                        || readable.contains(&member.address);
                    // Lists and shared mailboxes stay end to end whatever
                    // Encrypt says; a member forwarding outside, readable.
                    if !known {
                        put(&member, true, &mut targets, &mut readable);
                    }
                }
            }
            KutupRecipient::NotKutup => return Err(SendError::UnknownRecipient(address.clone())),
            KutupRecipient::Disabled => return Err(SendError::RecipientDisabled(address.clone())),
        }
    }
    Ok(Targets {
        keyed: targets,
        readable,
    })
}
