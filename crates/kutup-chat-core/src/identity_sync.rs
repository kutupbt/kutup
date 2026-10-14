//! Chat on the account's synced identity pins (docs/plans/drive-identity-pins.md).
//!
//! Chat keeps its own, stricter pins (the signed manifest chain, quarantine
//! until an in-person comparison). The account also keeps one list for all of
//! its apps (Drive, Office, Photos): the authority it met for every address,
//! and which were compared in person. Chat reads and writes that list so an
//! identity means the same everywhere:
//!
//! - a contact Chat meets for the first time whose address the list holds with
//!   another authority is quarantined, not trusted on first use;
//! - an authority the list holds as verified is verified in Chat too;
//! - an authority verified in Chat is verified in the list;
//! - a contact the list does not know yet is added to it.
//!
//! The list never lifts a Chat quarantine: only an in-person comparison does,
//! and that one (verified in Chat or in Drive) arrives as `verified`.
//!
//! The list is sealed to the account's key binding, never to its address
//! (docs/plans/account-identity.md).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::identity_pins::{self, IdentityPinsV1, PinMatch, PinState, PinUpdate};
use zeroize::Zeroizing;

use crate::db::{AuthorityTrust, ManifestTrust};
use crate::error::{ChatError, Result};
use crate::transport::{ChatTransport, IdentityPinsWrite};

/// The reason a contact is quarantined when the list says otherwise.
pub(crate) const DIFFERS_FROM_SYNCED: &str =
    "this account's identity differs from the one this account trusts in its other Kutup apps";

/// What Chat should do about one contact, given the list.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reconcile {
    Nothing,
    /// The list has this authority verified: verify it here too.
    MarkVerified,
    /// The list has another authority for the address: quarantine.
    Quarantine,
}

/// The account's key to the list, and the list as last read.
pub(crate) struct IdentityPinsSync {
    /// The account's key binding, which the list is sealed to.
    binding: String,
    key: Zeroizing<[u8; 32]>,
    cache: Option<(u64, IdentityPinsV1)>,
    /// The highest revision this engine has seen: an older list is refused
    /// (the server replaying one), as on the web.
    highest_seen: u64,
}

impl IdentityPinsSync {
    pub(crate) fn new(binding: &str, master_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            binding: kutup_crypto::key_binding::check(binding)
                .map_err(crypto)?
                .to_string(),
            key: identity_pins::derive_key(master_key).map_err(crypto)?,
            cache: None,
            highest_seen: 0,
        })
    }

    async fn load(&mut self, transport: &dyn ChatTransport) -> Result<(u64, IdentityPinsV1)> {
        if let Some(cached) = &self.cache {
            return Ok(cached.clone());
        }
        let loaded = match transport.fetch_identity_pins().await? {
            // None, though this engine has seen one: the server dropped it,
            // and writing from nothing would erase the pins it held.
            None if self.highest_seen > 0 => {
                return Err(ChatError::Trust(
                    "identity pins: the server answered no list after one was seen".into(),
                ))
            }
            None => (0, IdentityPinsV1::default()),
            Some(record) => {
                let sealed = STANDARD
                    .decode(&record.envelope)
                    .map_err(|_| ChatError::Invalid("identity pins are not base64".into()))?;
                let (list, revision) =
                    identity_pins::open(&self.key, &self.binding, &sealed).map_err(crypto)?;
                // The revision the server (and the account head the
                // transport checked it against) named is the sealed one.
                if revision != record.revision {
                    return Err(ChatError::Trust(
                        "identity pins: the list is not the revision the server named".into(),
                    ));
                }
                if revision < self.highest_seen {
                    return Err(ChatError::Trust(
                        "identity pins: the server answered an older list than seen".into(),
                    ));
                }
                self.highest_seen = revision;
                (revision, list)
            }
        };
        self.cache = Some(loaded.clone());
        Ok(loaded)
    }

    /// What to do about `trust`, a contact Chat has just accepted.
    pub(crate) async fn reconcile(
        &mut self,
        transport: &dyn ChatTransport,
        trust: &ManifestTrust,
    ) -> Result<Reconcile> {
        if trust.continuity_gap || trust.trust == AuthorityTrust::Quarantined {
            return Ok(Reconcile::Nothing);
        }
        let (_, list) = self.load(transport).await?;
        // The rules every app shares (identity_pins::lookup).
        let found = identity_pins::lookup(
            &list,
            &trust.account,
            Some(trust.self_authority_key.as_str()),
        );
        let verified_here = trust.trust == AuthorityTrust::Verified;
        Ok(match found {
            PinMatch::Pinned {
                pin,
                same_authority: false,
            } => {
                // Chat's own in-person verification outranks a pin that was
                // only seen elsewhere: it is written to the list instead.
                if verified_here && pin.state != PinState::Verified {
                    Reconcile::Nothing
                } else {
                    Reconcile::Quarantine
                }
            }
            // Someone the user knew had this address and is elsewhere now:
            // whoever is here is another person, unless verified here.
            PinMatch::Moved { .. } if !verified_here => Reconcile::Quarantine,
            // An identity the user replaced (its trust revoked), wherever it
            // turns up: never verified from the list, quarantined unless
            // verified here.
            PinMatch::Replaced { .. } if !verified_here => Reconcile::Quarantine,
            PinMatch::Replaced { .. } => Reconcile::Nothing,
            // The same account (pinned here, or under another of its names).
            PinMatch::Pinned { pin, .. }
            | PinMatch::Renamed { pin }
            | PinMatch::Returned { pin }
                if trust.trust == AuthorityTrust::Tofu && pin.state == PinState::Verified =>
            {
                Reconcile::MarkVerified
            }
            _ => Reconcile::Nothing,
        })
    }

    /// Writes Chat's view of `trust` to the list when it adds to it: a
    /// contact the list does not know, or one verified here.
    pub(crate) async fn record(
        &mut self,
        transport: &dyn ChatTransport,
        trust: &ManifestTrust,
        now_seconds: u64,
    ) -> Result<()> {
        if trust.continuity_gap || trust.trust == AuthorityTrust::Quarantined {
            return Ok(());
        }
        // The rules every app shares (identity_pins::record): a contact met
        // through a trusted manifest is pinned on first use, and one verified
        // in person replaces whatever was pinned.
        let update = if trust.trust == AuthorityTrust::Verified {
            PinUpdate::Verified
        } else {
            PinUpdate::FirstSeen
        };
        for _ in 0..5 {
            let (revision, mut list) = self.load(transport).await?;
            let before = list.clone();
            let since = identity_pins::since_from_unix(now_seconds);
            identity_pins::record(
                &mut list,
                &trust.account,
                &trust.self_authority_key,
                update,
                &since,
            )
            .map_err(crypto)?;
            if list == before {
                return Ok(());
            }
            // A time, above every revision seen (docs/plans/drive-identity-pins.md).
            let next = now_seconds
                .saturating_mul(1000)
                .max(revision + 1)
                .max(self.highest_seen + 1);
            let sealed =
                identity_pins::seal(&self.key, &self.binding, next, &list).map_err(crypto)?;
            let write = IdentityPinsWrite {
                base_revision: revision,
                envelope: STANDARD.encode(sealed),
                revision: next,
            };
            self.cache = None;
            if transport.store_identity_pins(&write).await? {
                self.highest_seen = next;
                self.cache = Some((next, list));
                return Ok(());
            }
        }
        Err(ChatError::Transport(
            "the identity pin list kept changing".into(),
        ))
    }
}

fn crypto(error: kutup_crypto::error::CryptoError) -> ChatError {
    ChatError::Trust(format!("identity pins: {error}"))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use async_trait::async_trait;
    use futures_executor::block_on;
    use kutup_chat_proto::{
        MailboxPage, RegisterChatDeviceRequest, SendMessagesRequest, UserPreKeyBundlesResponse,
    };

    use super::*;
    use crate::transport::IdentityPinsRecord;
    use crate::transport::SendOutcome;
    use kutup_crypto::identity_pins::IdentityPinV1;

    /// Only the identity pin calls; the server's list, revision by revision.
    #[derive(Default)]
    struct Server {
        stored: RefCell<Option<IdentityPinsRecord>>,
    }

    #[async_trait(?Send)]
    impl ChatTransport for Server {
        async fn register_device(&self, _: &RegisterChatDeviceRequest) -> Result<u32> {
            unimplemented!()
        }
        async fn fetch_bundles(&self, _: &str) -> Result<UserPreKeyBundlesResponse> {
            unimplemented!()
        }
        async fn send(&self, _: &str, _: &SendMessagesRequest) -> Result<SendOutcome> {
            unimplemented!()
        }
        async fn drain(&self, _: u32, _: Option<u64>, _: u32) -> Result<MailboxPage> {
            unimplemented!()
        }
        async fn ack(&self, _: u32, _: &[String]) -> Result<()> {
            unimplemented!()
        }
        async fn fetch_identity_pins(&self) -> Result<Option<IdentityPinsRecord>> {
            Ok(self.stored.borrow().clone())
        }
        async fn store_identity_pins(&self, write: &IdentityPinsWrite) -> Result<bool> {
            let current = self.stored.borrow().as_ref().map_or(0, |r| r.revision);
            let sealed = STANDARD.decode(&write.envelope).unwrap();
            let revision = identity_pins::inspect(&sealed).unwrap();
            if write.base_revision != current || revision <= current {
                return Ok(false);
            }
            *self.stored.borrow_mut() = Some(IdentityPinsRecord {
                revision,
                envelope: write.envelope.clone(),
            });
            Ok(true)
        }
    }

    const OWNER: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const MASTER: [u8; 32] = [4u8; 32];

    fn authority(seed: u8) -> String {
        STANDARD.encode(
            kutup_crypto::identity::AccountIdentityKeysV1::derive(&[seed; 32])
                .unwrap()
                .authority_public_key(),
        )
    }

    fn trust(account: &str, seed: u8, state: AuthorityTrust) -> ManifestTrust {
        ManifestTrust {
            peer: account.into(),
            account: account.into(),
            incarnation_id: String::new(),
            authority_key_id: String::new(),
            self_authority_key: authority(seed),
            drive_hpke_public_key: String::new(),
            drive_share_signing_public_key: String::new(),
            highest_sequence: 1,
            manifest_hash: String::new(),
            trust: state,
            continuity_gap: false,
            quarantine_reason: None,
            pending_reset: None,
        }
    }

    fn pins(server: &Server) -> Vec<IdentityPinV1> {
        let record = server.stored.borrow().clone().unwrap();
        let key = identity_pins::derive_key(&MASTER).unwrap();
        identity_pins::open(&key, OWNER, &STANDARD.decode(record.envelope).unwrap())
            .unwrap()
            .0
            .pins
    }

    fn sync() -> IdentityPinsSync {
        IdentityPinsSync::new(OWNER, &MASTER).unwrap()
    }

    #[test]
    fn a_new_contact_is_added_and_then_agreed_with() {
        let server = Server::default();
        let bob = trust("bob@kutup.dev", 2, AuthorityTrust::Tofu);
        assert_eq!(
            block_on(sync().reconcile(&server, &bob)).unwrap(),
            Reconcile::Nothing
        );
        block_on(sync().record(&server, &bob, 1_791_633_600)).unwrap();
        assert_eq!(pins(&server)[0].state, PinState::Seen);
        assert_eq!(pins(&server)[0].since, "2026-10-10T12:00:00Z");
        assert_eq!(
            block_on(sync().reconcile(&server, &bob)).unwrap(),
            Reconcile::Nothing
        );
    }

    #[test]
    fn another_authority_than_the_list_holds_is_quarantined() {
        let server = Server::default();
        block_on(sync().record(&server, &trust("bob@kutup.dev", 2, AuthorityTrust::Tofu), 0))
            .unwrap();
        // Chat meets "bob" with an authority the account never trusted elsewhere.
        let impostor = trust("bob@kutup.dev", 9, AuthorityTrust::Tofu);
        assert_eq!(
            block_on(sync().reconcile(&server, &impostor)).unwrap(),
            Reconcile::Quarantine
        );
        // A quarantined contact is left to Chat's own verification.
        let held = trust("bob@kutup.dev", 9, AuthorityTrust::Quarantined);
        assert_eq!(
            block_on(sync().reconcile(&server, &held)).unwrap(),
            Reconcile::Nothing
        );
    }

    #[test]
    fn verified_in_one_app_is_verified_in_the_other() {
        let server = Server::default();
        // Verified in Chat: verified in the list.
        block_on(sync().record(
            &server,
            &trust("bob@kutup.dev", 2, AuthorityTrust::Verified),
            0,
        ))
        .unwrap();
        assert_eq!(pins(&server)[0].state, PinState::Verified);
        // Another device of the account meets Bob: verified there too.
        let fresh = trust("bob@kutup.dev", 2, AuthorityTrust::Tofu);
        assert_eq!(
            block_on(sync().reconcile(&server, &fresh)).unwrap(),
            Reconcile::MarkVerified
        );
    }

    #[test]
    fn chats_in_person_check_outranks_an_identity_only_seen_elsewhere() {
        let server = Server::default();
        // Drive accepted a new identity for Bob without comparing it.
        block_on(sync().record(&server, &trust("bob@kutup.dev", 3, AuthorityTrust::Tofu), 0))
            .unwrap();
        // Chat compared Bob's old one in person: it is not quarantined, and it replaces the list's.
        let verified = trust("bob@kutup.dev", 2, AuthorityTrust::Verified);
        assert_eq!(
            block_on(sync().reconcile(&server, &verified)).unwrap(),
            Reconcile::Nothing
        );
        block_on(sync().record(&server, &verified, 0)).unwrap();
        let pin = &pins(&server)[0];
        assert_eq!(
            (pin.authority_public_key.as_str(), pin.state),
            (authority(2).as_str(), PinState::Verified)
        );
        assert_eq!(pin.replaced.len(), 1);
    }

    #[test]
    fn a_write_another_app_beat_is_merged() {
        let server = Server::default();
        let mut slow = sync();
        // This device read the empty list...
        assert_eq!(
            block_on(slow.reconcile(&server, &trust("bob@kutup.dev", 2, AuthorityTrust::Tofu)))
                .unwrap(),
            Reconcile::Nothing
        );
        // ...then another app pinned Carol.
        block_on(sync().record(
            &server,
            &trust("carol@kutup.dev", 5, AuthorityTrust::Tofu),
            0,
        ))
        .unwrap();
        block_on(slow.record(&server, &trust("bob@kutup.dev", 2, AuthorityTrust::Tofu), 0))
            .unwrap();
        let accounts: Vec<_> = pins(&server).into_iter().map(|p| p.account).collect();
        assert_eq!(accounts, ["bob@kutup.dev", "carol@kutup.dev"]);
    }

    #[test]
    fn a_list_the_server_drops_after_one_was_seen_is_refused() {
        let server = Server::default();
        let mut engine = sync();
        block_on(engine.record(&server, &trust("bob@kutup.dev", 2, AuthorityTrust::Tofu), 0))
            .unwrap();
        assert_eq!(pins(&server).len(), 1);
        // The server forgets the list: writing from nothing would erase Bob.
        *server.stored.borrow_mut() = None;
        engine.cache = None;
        assert!(matches!(
            block_on(engine.record(
                &server,
                &trust("carol@kutup.dev", 5, AuthorityTrust::Tofu),
                0
            )),
            Err(ChatError::Trust(_))
        ));
        assert!(server.stored.borrow().is_none());
        // A fresh engine (no history) trusts the empty answer, as documented.
        assert!(block_on(sync().record(
            &server,
            &trust("carol@kutup.dev", 5, AuthorityTrust::Tofu),
            0
        ))
        .is_ok());
    }

    #[test]
    fn a_released_name_is_not_the_person_who_had_it() {
        // The list knows Alice (verified) as alicia@, formerly alice@.
        let server = Server::default();
        let alice = kutup_crypto::identity::AccountIdentityKeysV1::derive(&[1; 32]).unwrap();
        let mut list = IdentityPinsV1::default();
        identity_pins::record(
            &mut list,
            "alice@kutup.dev",
            &authority(1),
            PinUpdate::Verified,
            "2026-10-10T12:00:00Z",
        )
        .unwrap();
        let chain = vec![kutup_crypto::account_rename::sign(
            &alice,
            1,
            "alice@kutup.dev",
            "alicia@kutup.dev",
            1_791_000_000_000,
        )
        .unwrap()];
        identity_pins::apply_rename(&mut list, &alice.authority_public_key(), &chain).unwrap();
        let key = identity_pins::derive_key(&MASTER).unwrap();
        *server.stored.borrow_mut() = Some(IdentityPinsRecord {
            revision: 1,
            envelope: STANDARD.encode(identity_pins::seal(&key, OWNER, 1, &list).unwrap()),
        });
        // Chat meets someone else at alice@: quarantined, and not pinned.
        let newcomer = trust("alice@kutup.dev", 6, AuthorityTrust::Tofu);
        assert_eq!(
            block_on(sync().reconcile(&server, &newcomer)).unwrap(),
            Reconcile::Quarantine
        );
        block_on(sync().record(&server, &newcomer, 0)).unwrap();
        assert_eq!(pins(&server).len(), 1);
        // Alice under a name this device has not followed yet: still verified.
        let renamed = trust("alicia2@kutup.dev", 1, AuthorityTrust::Tofu);
        assert_eq!(
            block_on(sync().reconcile(&server, &renamed)).unwrap(),
            Reconcile::MarkVerified
        );
    }

    #[test]
    fn an_identity_replaced_elsewhere_is_quarantined_wherever_it_turns_up() {
        // Bob verified, then replaced by a new identity the user accepted.
        let server = Server::default();
        block_on(sync().record(
            &server,
            &trust("bob@kutup.dev", 2, AuthorityTrust::Verified),
            0,
        ))
        .unwrap();
        let mut list = identity_pins::open(
            &identity_pins::derive_key(&MASTER).unwrap(),
            OWNER,
            &STANDARD
                .decode(server.stored.borrow().clone().unwrap().envelope)
                .unwrap(),
        )
        .unwrap()
        .0;
        identity_pins::record(
            &mut list,
            "bob@kutup.dev",
            &authority(3),
            PinUpdate::Accepted,
            "2026-10-11T12:00:00Z",
        )
        .unwrap();
        let key = identity_pins::derive_key(&MASTER).unwrap();
        *server.stored.borrow_mut() = Some(IdentityPinsRecord {
            revision: 2_000_000_000_000,
            envelope: STANDARD
                .encode(identity_pins::seal(&key, OWNER, 2_000_000_000_000, &list).unwrap()),
        });
        // The old identity shows up as carol@: never verified from the list.
        let old = trust("carol@kutup.dev", 2, AuthorityTrust::Tofu);
        assert_eq!(
            block_on(sync().reconcile(&server, &old)).unwrap(),
            Reconcile::Quarantine
        );
    }
}
