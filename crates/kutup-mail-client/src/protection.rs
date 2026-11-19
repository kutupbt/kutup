//! How mail to one recipient is protected (docs/plans/mail.md, C3;
//! docs/plans/contact-keys.md), decided as `mail-core/protection.ts`
//! decides it, as Proton does:
//!
//! - a Kutup address: end to end, with its key list (readable when its owner
//!   turned encryption off: it forwards outside);
//! - an outside address with keys the person trusted in Contacts: encrypted
//!   to the first of them that can still encrypt;
//! - else with a key found through WKD, Proton or keys.openpgp.org, unless
//!   the person chose not to encrypt to the address;
//! - else readable on the way.
//!
//! The decision needs an outside key lookup only on some paths, so it comes
//! in two steps: [`protection_for`] answers, or asks for that lookup, and
//! [`with_outside_key`] finishes.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::mail_key::inspect_external_public_key;
use serde::{Deserialize, Serialize};

/// What looking the recipient up as a Kutup address gave
/// (`addressKeys` in `mail-core/keys.ts`, already checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KutupLookup {
    /// Its checked keys: whether its owner turned encryption off.
    Keys { encryption_disabled: bool },
    /// Its owner disabled it.
    Disabled,
    /// Not a Kutup address (no key), or a group's.
    NotKutup,
    /// The lookup failed (not: found nothing), or the keys were refused.
    Failed,
}

/// One key the person trusts for an address in Contacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactKey {
    /// Base64, binary OpenPGP.
    pub public_key: String,
    pub fingerprint: String,
}

/// What Contacts say about an outside address (`Pinned`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pinned {
    pub keys: Vec<ContactKey>,
    /// `false`: the person chose not to encrypt to this address.
    pub encrypt: Option<bool>,
}

/// Where a found outside key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeySource {
    Wkd,
    Proton,
    KeysOpenpgp,
}

/// An outside key the server found (`GET /api/mail/keys/outside`), not yet
/// checked here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKey {
    pub source: KeySource,
    /// Base64, binary OpenPGP.
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Protection {
    #[serde(rename_all = "camelCase")]
    Kutup {
        encryption_disabled: bool,
    },
    #[serde(rename_all = "camelCase")]
    Pinned {
        public_key: String,
        fingerprint: String,
    },
    #[serde(rename_all = "camelCase")]
    Found {
        public_key: String,
        fingerprint: String,
        source: KeySource,
    },
    /// Trusted keys, none usable any more: sending waits.
    PinnedUnusable {
        fingerprint: String,
    },
    /// Its owner disabled the address: nothing is sent to it.
    Disabled,
    /// This server holds an address on another domain while Contacts trust
    /// other keys for it: nothing is sent until the person settles it.
    PinnedConflict {
        fingerprint: String,
    },
    None,
}

impl Protection {
    /// The OpenPGP key mail to the recipient is encrypted to (`pgpKey`).
    pub fn pgp_key(&self) -> Option<&str> {
        match self {
            Self::Pinned { public_key, .. } | Self::Found { public_key, .. } => Some(public_key),
            _ => None,
        }
    }
}

/// The first step's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Done(Protection),
    /// Look the address up outside (`outsideKey`), then [`with_outside_key`].
    LookUpOutside,
}

/// The Kutup lookup failed for an address on another domain: whether it is
/// a Kutup user's can't be told (`KeyLookupFailed`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("could not look up a key for {0}")]
pub struct KeyLookupFailed(pub String);

/// The first key of `keys` that can still encrypt to `address` at `now_secs`
/// (expired or revoked ones are passed over), checked as any outside key.
fn first_usable(keys: &[ContactKey], address: &str, now_secs: u64) -> Option<(String, String)> {
    keys.iter().find_map(|key| {
        let bytes = STANDARD.decode(&key.public_key).ok()?;
        let info = inspect_external_public_key(&bytes, address, now_secs).ok()?;
        Some((STANDARD.encode(info.public_key), info.fingerprint))
    })
}

/// How mail to `address` is protected (`protectionFor`): `domain` is this
/// server's, `kutup` what the Kutup lookup gave, `pinned` what Contacts say.
pub fn protection_for(
    address: &str,
    domain: &str,
    kutup: &KutupLookup,
    pinned: Option<&Pinned>,
    now_secs: u64,
) -> Result<Step, KeyLookupFailed> {
    let lower = address.to_lowercase();
    if lower.ends_with(&format!("@{}", domain.to_lowercase())) {
        // This server's own domain: a lookup that fails is reported when
        // sending.
        return Ok(Step::Done(match kutup {
            KutupLookup::Disabled => Protection::Disabled,
            KutupLookup::Keys {
                encryption_disabled,
            } => Protection::Kutup {
                encryption_disabled: *encryption_disabled,
            },
            KutupLookup::NotKutup | KutupLookup::Failed => Protection::Kutup {
                encryption_disabled: false,
            },
        }));
    }
    let trusted = pinned.map_or(&[][..], |p| p.keys.as_slice());
    match kutup {
        // Another address this server holds (a custom domain): a Kutup
        // address too, unless Contacts trust other keys for it.
        KutupLookup::Keys {
            encryption_disabled,
        } => {
            return Ok(Step::Done(match trusted.first() {
                Some(key) => Protection::PinnedConflict {
                    fingerprint: key.fingerprint.clone(),
                },
                None => Protection::Kutup {
                    encryption_disabled: *encryption_disabled,
                },
            }))
        }
        KutupLookup::Disabled => return Ok(Step::Done(Protection::Disabled)),
        KutupLookup::Failed => return Err(KeyLookupFailed(lower)),
        KutupLookup::NotKutup => {}
    }
    if pinned.and_then(|p| p.encrypt) == Some(false) {
        return Ok(Step::Done(Protection::None));
    }
    if let Some(first) = trusted.first() {
        return Ok(Step::Done(match first_usable(trusted, &lower, now_secs) {
            Some((public_key, fingerprint)) => Protection::Pinned {
                public_key,
                fingerprint,
            },
            None => Protection::PinnedUnusable {
                fingerprint: first.fingerprint.clone(),
            },
        }));
    }
    Ok(Step::LookUpOutside)
}

/// The second step: the outside lookup's answer (`Ok(None)`: nothing found;
/// `Err`: the lookup failed), checked here too so a key is never used on the
/// server's word alone.
pub fn with_outside_key(
    address: &str,
    found: Result<Option<FoundKey>, ()>,
    now_secs: u64,
) -> Result<Protection, KeyLookupFailed> {
    let lower = address.to_lowercase();
    let Some(found) = found.map_err(|()| KeyLookupFailed(lower.clone()))? else {
        return Ok(Protection::None);
    };
    let usable = STANDARD
        .decode(&found.public_key)
        .ok()
        .and_then(|bytes| inspect_external_public_key(&bytes, &lower, now_secs).ok());
    // A key the server found that doesn't check here is a failed lookup,
    // never a reason to send readable silently.
    let info = usable.ok_or_else(|| KeyLookupFailed(lower.clone()))?;
    Ok(Protection::Found {
        public_key: STANDARD.encode(info.public_key),
        fingerprint: info.fingerprint,
        source: found.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_780_000_000;

    fn key_for(address: &str) -> ContactKey {
        let generated =
            kutup_crypto::mail_key::generate_address_key(address, 1_760_000_000).unwrap();
        ContactKey {
            public_key: STANDARD.encode(&generated.public_key),
            fingerprint: hex::encode(generated.fingerprint),
        }
    }

    fn broken(fingerprint: &str) -> ContactKey {
        ContactKey {
            public_key: STANDARD.encode(b"not a key"),
            fingerprint: fingerprint.into(),
        }
    }

    fn done(step: Result<Step, KeyLookupFailed>) -> Protection {
        match step.unwrap() {
            Step::Done(p) => p,
            Step::LookUpOutside => panic!("asked for an outside lookup"),
        }
    }

    #[test]
    fn kutup_addresses_follow_their_key_lists() {
        let on = KutupLookup::Keys {
            encryption_disabled: false,
        };
        let off = KutupLookup::Keys {
            encryption_disabled: true,
        };
        assert_eq!(
            done(protection_for("Ada@Kutup.dev", "kutup.dev", &on, None, NOW)),
            Protection::Kutup {
                encryption_disabled: false
            }
        );
        assert_eq!(
            done(protection_for(
                "ada@kutup.dev",
                "kutup.dev",
                &off,
                None,
                NOW
            )),
            Protection::Kutup {
                encryption_disabled: true
            }
        );
        assert_eq!(
            done(protection_for(
                "ada@kutup.dev",
                "kutup.dev",
                &KutupLookup::Disabled,
                None,
                NOW
            )),
            Protection::Disabled
        );
        // On this server's domain a failed lookup is reported when sending.
        assert_eq!(
            done(protection_for(
                "ada@kutup.dev",
                "kutup.dev",
                &KutupLookup::Failed,
                None,
                NOW
            )),
            Protection::Kutup {
                encryption_disabled: false
            }
        );
    }

    #[test]
    fn a_custom_domain_this_server_holds_never_outranks_contacts() {
        let keys = KutupLookup::Keys {
            encryption_disabled: false,
        };
        assert_eq!(
            done(protection_for(
                "ada@work.example",
                "kutup.dev",
                &keys,
                None,
                NOW
            )),
            Protection::Kutup {
                encryption_disabled: false
            }
        );
        let pinned = Pinned {
            keys: vec![key_for("ada@work.example")],
            encrypt: None,
        };
        let fingerprint = pinned.keys[0].fingerprint.clone();
        assert_eq!(
            done(protection_for(
                "ada@work.example",
                "kutup.dev",
                &keys,
                Some(&pinned),
                NOW
            )),
            Protection::PinnedConflict { fingerprint }
        );
        assert_eq!(
            done(protection_for(
                "ada@work.example",
                "kutup.dev",
                &KutupLookup::Disabled,
                None,
                NOW
            )),
            Protection::Disabled
        );
        assert_eq!(
            protection_for(
                "ada@work.example",
                "kutup.dev",
                &KutupLookup::Failed,
                None,
                NOW
            ),
            Err(KeyLookupFailed("ada@work.example".into()))
        );
    }

    #[test]
    fn trusted_keys_first_usable_one_and_never_a_found_one_instead() {
        let good = key_for("bob@outside.example");
        let pinned = Pinned {
            keys: vec![broken("aa"), good.clone()],
            encrypt: None,
        };
        match done(protection_for(
            "bob@outside.example",
            "kutup.dev",
            &KutupLookup::NotKutup,
            Some(&pinned),
            NOW,
        )) {
            Protection::Pinned { fingerprint, .. } => assert_eq!(fingerprint, good.fingerprint),
            other => panic!("{other:?}"),
        }
        let unusable = Pinned {
            keys: vec![broken("aa"), broken("bb")],
            encrypt: None,
        };
        assert_eq!(
            done(protection_for(
                "bob@outside.example",
                "kutup.dev",
                &KutupLookup::NotKutup,
                Some(&unusable),
                NOW
            )),
            Protection::PinnedUnusable {
                fingerprint: "aa".into()
            }
        );
        // The person chose not to encrypt: no lookup at all.
        let plain = Pinned {
            keys: vec![good],
            encrypt: Some(false),
        };
        assert_eq!(
            done(protection_for(
                "bob@outside.example",
                "kutup.dev",
                &KutupLookup::NotKutup,
                Some(&plain),
                NOW
            )),
            Protection::None
        );
    }

    #[test]
    fn otherwise_a_found_key_checked_here_or_readable() {
        assert_eq!(
            protection_for(
                "bob@outside.example",
                "kutup.dev",
                &KutupLookup::NotKutup,
                None,
                NOW
            ),
            Ok(Step::LookUpOutside)
        );
        let found = key_for("bob@outside.example");
        match with_outside_key(
            "bob@outside.example",
            Ok(Some(FoundKey {
                source: KeySource::Wkd,
                public_key: found.public_key.clone(),
            })),
            NOW,
        )
        .unwrap()
        {
            Protection::Found {
                fingerprint,
                source,
                ..
            } => {
                assert_eq!(fingerprint, found.fingerprint);
                assert_eq!(source, KeySource::Wkd);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            with_outside_key("bob@outside.example", Ok(None), NOW),
            Ok(Protection::None)
        );
        assert!(with_outside_key("bob@outside.example", Err(()), NOW).is_err());
        // A key that doesn't check here is a failed lookup, never readable mail.
        let bad = FoundKey {
            source: KeySource::Proton,
            public_key: STANDARD.encode(b"junk"),
        };
        assert!(with_outside_key("bob@outside.example", Ok(Some(bad)), NOW).is_err());
    }
}
