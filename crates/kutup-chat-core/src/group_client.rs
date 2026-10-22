//! The anonymous route to a group's home (docs/plans/pairwise-groups.md §3,
//! "The anonymous route"), from this device: a request signed by a
//! pseudonym (or a slot's claim key), sealed to the home's gateway key and
//! relayed by this account's own server, which learns only which home.
//!
//! The gateway key is taken only through the home's identity, pinned in the
//! group: the history is followed from the pin, the config verified against
//! it and kept only if it isn't older than one already seen. A relay that
//! hands over another key fails one of those checks; one that hides a newer
//! config is caught when a notary names a config this device doesn't hold
//! ([`GatewayCache::named_by`]).

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_chat_proto::group_route::{
    GroupGatewayKeyConfigV1, GroupHomePinV1, GroupNotaryV1, GroupOperationV1, GroupRequestV1,
    GroupResponseStatusV1, GroupResponseV1,
};
use kutup_federation_proto::FederationIdentityDocumentV1;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};

use crate::error::{ChatError, Result};
use crate::transport::{ChatTransport, GroupRelayOutcome};

/// A config is fetched again this long before it expires.
const REFRESH_MARGIN_SECS: i64 = 60 * 60;

/// What this device keeps of a home: the newest gateway key config it took,
/// and the identity history that config and the notaries are checked
/// against.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayCache {
    pub config: Option<GroupGatewayKeyConfigV1>,
    pub identity_history: Vec<FederationIdentityDocumentV1>,
    /// The hashes of every config this device took for the home, oldest
    /// first (at most [`MAX_ACCEPTED_CONFIGS`]): a change notarised before a
    /// rotation names one of them.
    pub accepted: Vec<String>,
}

/// How many accepted configs a home's cache remembers.
pub const MAX_ACCEPTED_CONFIGS: usize = 16;

/// What the config a notary names is, to this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigCheck {
    /// The config this device is served now.
    Current,
    /// One it took before (the change came before a rotation).
    Earlier,
    /// One it never held: either a rotation it slept through, or a relay
    /// showing it a config other members don't get.
    Unknown,
}

impl GatewayCache {
    /// What the config `notary` names is to this device. For a home's newest
    /// notary, `Unknown` is fetched again; if it stays unknown, the group is
    /// shown as not confirmed, without stopping it.
    pub fn check(&self, notary: &GroupNotaryV1) -> ConfigCheck {
        if self
            .config
            .as_ref()
            .is_some_and(|config| notary.names(config).unwrap_or(false))
        {
            return ConfigCheck::Current;
        }
        if self
            .accepted
            .iter()
            .any(|hash| hash == &notary.key_config_hash)
        {
            return ConfigCheck::Earlier;
        }
        ConfigCheck::Unknown
    }

    fn usable(&self, now: i64) -> Option<(u8, [u8; kutup_crypto::oblivious::PUBLIC_KEY_LEN])> {
        let config = self.config.as_ref()?;
        if now + REFRESH_MARGIN_SECS >= config.expires_at {
            return None;
        }
        config.verify(&self.identity_history, now).ok()
    }

    /// Fetches the home's config and history again, and takes them only
    /// through the pin.
    pub async fn refresh(
        &mut self,
        transport: &dyn ChatTransport,
        pin: &GroupHomePinV1,
        now: i64,
    ) -> Result<()> {
        let answer = transport
            .fetch_group_gateway(&pin.server, pin.identity_sequence)
            .await?;
        let current = pin
            .follow(&answer.identity_history)
            .map_err(|error| ChatError::Trust(format!("group home identity: {error}")))?;
        if current.server != pin.server {
            return Err(ChatError::Trust(
                "group home identity names another server".into(),
            ));
        }
        answer
            .config
            .verify(&answer.identity_history, now)
            .map_err(|error| ChatError::Trust(format!("group gateway key: {error}")))?;
        answer
            .config
            .accept_after(self.config.as_ref(), now)
            .map_err(|error| ChatError::Trust(format!("group gateway key: {error}")))?;
        let hash = base64::engine::general_purpose::STANDARD.encode(
            answer
                .config
                .hash()
                .map_err(|error| ChatError::Invalid(error.to_string()))?,
        );
        if !self.accepted.contains(&hash) {
            self.accepted.push(hash);
            if self.accepted.len() > MAX_ACCEPTED_CONFIGS {
                self.accepted.remove(0);
            }
        }
        self.config = Some(answer.config);
        self.identity_history = answer.identity_history;
        Ok(())
    }
}

/// Who signs a request: a member's pseudonym, or a slot's claim key (only
/// for the join info a claimant needs).
pub enum RequestSigner<'a> {
    /// A pseudonym's (or a slot's claim) key signs the request.
    Key(&'a [u8; 32]),
    /// The invite link's password proves it: only for join info, which a
    /// link holder reads before it has a pseudonym in the group.
    LinkPassword(&'a [u8; kutup_chat_proto::group::INVITE_LINK_PASSWORD_LEN]),
}

impl RequestSigner<'_> {
    /// The request for `operation`, signed or proven as this signer does it.
    fn request(
        &self,
        home: &str,
        group_id: &[u8; 32],
        operation: GroupOperationV1,
        timestamp: i64,
        nonce: &[u8; 16],
        body: &[u8],
    ) -> std::result::Result<GroupRequestV1, String> {
        match self {
            Self::Key(seed) => GroupRequestV1::sign_with_pseudonym(
                home,
                group_id,
                operation,
                timestamp,
                nonce,
                body,
                &SigningKey::from_bytes(seed),
            ),
            Self::LinkPassword(password) => {
                if !body.is_empty() {
                    return Err("a link-proven request carries no body".into());
                }
                GroupRequestV1::with_link_password(
                    home,
                    group_id,
                    operation,
                    timestamp,
                    nonce,
                    &password[..],
                )
            }
        }
    }
}

/// Why a route call didn't get an answer from the home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteFailure {
    /// This account's relay limit, or the home's.
    RateLimited,
    /// The home can't be reached now.
    Unreachable,
    /// Groups are off on this account's server.
    GroupsOff,
}

/// One request to the home: signed, sealed, relayed, opened. A key the home
/// no longer takes, or a clock the home finds off, is put right once.
#[allow(clippy::too_many_arguments)]
pub async fn call(
    transport: &dyn ChatTransport,
    cache: &mut GatewayCache,
    pin: &GroupHomePinV1,
    group_id: &[u8; 32],
    operation: GroupOperationV1,
    body: &[u8],
    signer: &RequestSigner<'_>,
    now: i64,
) -> Result<std::result::Result<GroupResponseV1, RouteFailure>> {
    // A key taken outside `refresh` (a new group's own server) is remembered too.
    if let Some(config) = &cache.config {
        if let Ok(hash) = config.hash() {
            let hash = base64::engine::general_purpose::STANDARD.encode(hash);
            if !cache.accepted.contains(&hash) {
                cache.accepted.push(hash);
            }
        }
    }
    let mut clock_offset = 0i64;
    let mut refreshed = false;
    for _ in 0..3 {
        let (key_id, public_key) = match cache.usable(now) {
            Some(key) => key,
            None if !refreshed => {
                cache.refresh(transport, pin, now).await?;
                refreshed = true;
                cache
                    .usable(now)
                    .ok_or_else(|| ChatError::Trust("group gateway key is not usable".into()))?
            }
            None => return Err(ChatError::Trust("group gateway key is not usable".into())),
        };
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let request = signer
            .request(
                &pin.server,
                group_id,
                operation,
                now + clock_offset,
                &nonce,
                body,
            )
            .map_err(ChatError::Invalid)?;
        let bytes = request.canonical_bytes().map_err(ChatError::Invalid)?;
        let (sealed, context) = kutup_crypto::oblivious::seal_request(key_id, &public_key, &bytes)
            .map_err(|error| ChatError::Invalid(error.to_string()))?;
        match transport.relay_group_request(&pin.server, &sealed).await? {
            GroupRelayOutcome::Answered(answer) => {
                let opened = context
                    .open_response(&answer)
                    .map_err(|_| ChatError::Trust("the group home's answer doesn't open".into()))?;
                let response =
                    GroupResponseV1::from_canonical_bytes(&opened).map_err(ChatError::Invalid)?;
                if response.status == GroupResponseStatusV1::ClockSkew && clock_offset == 0 {
                    clock_offset = response.server_time - now;
                    continue;
                }
                return Ok(Ok(response));
            }
            GroupRelayOutcome::Unopenable if !refreshed => {
                cache.refresh(transport, pin, now).await?;
                refreshed = true;
            }
            GroupRelayOutcome::Unopenable => {
                return Err(ChatError::Trust(
                    "the group home doesn't take the key it published".into(),
                ))
            }
            GroupRelayOutcome::RateLimited => return Ok(Err(RouteFailure::RateLimited)),
            GroupRelayOutcome::Unreachable => return Ok(Err(RouteFailure::Unreachable)),
            GroupRelayOutcome::GroupsOff => return Ok(Err(RouteFailure::GroupsOff)),
        }
    }
    Ok(Err(RouteFailure::Unreachable))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use futures_executor::block_on;
    use kutup_chat_proto::group_route::{GroupGatewayKeyConfigV1, GroupHomePinV1};
    use kutup_chat_proto::{
        AccountPreKeyBundlesResponse, MailboxPage, RegisterChatDeviceRequestV2, SendMessagesRequest,
    };
    use kutup_crypto::oblivious::GatewayKey;
    use kutup_federation_proto::FederationIdentityDocumentV1;

    use super::*;
    use crate::transport::{GroupGatewayAnswer, SendOutcome};

    const NOW: i64 = 1_000_000;

    /// This account's server and the group's home, in one: it answers the
    /// gateway-key fetch and relays to a gateway that opens what it gets.
    struct Home {
        identity: FederationIdentityDocumentV1,
        key: SigningKey,
        gateway: RefCell<GatewayKey>,
        /// What the fetch returns as the config (a relay may lie).
        served: RefCell<GroupGatewayKeyConfigV1>,
        /// The home's clock, to answer a skewed request.
        clock: i64,
        fetches: Cell<u32>,
        seen: RefCell<Vec<GroupRequestV1>>,
    }

    impl Home {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&[1u8; 32]);
            let identity = FederationIdentityDocumentV1::genesis("home.example", 10, &key).unwrap();
            let gateway = GatewayKey::generate(1).unwrap();
            let served = Self::config(&identity, &key, &gateway, NOW - 10);
            Self {
                identity,
                key,
                gateway: RefCell::new(gateway),
                served: RefCell::new(served),
                clock: NOW,
                fetches: Cell::new(0),
                seen: RefCell::new(Vec::new()),
            }
        }

        fn config(
            identity: &FederationIdentityDocumentV1,
            key: &SigningKey,
            gateway: &GatewayKey,
            issued_at: i64,
        ) -> GroupGatewayKeyConfigV1 {
            GroupGatewayKeyConfigV1::sign(
                identity,
                key,
                gateway.key_id(),
                &gateway.public_key(),
                issued_at,
                issued_at + 24 * 60 * 60,
            )
            .unwrap()
        }

        fn pin(&self) -> GroupHomePinV1 {
            GroupHomePinV1::of(&self.identity).unwrap()
        }

        /// The home moves to a new gateway key.
        fn rotate(&self) {
            let gateway = GatewayKey::generate(2).unwrap();
            *self.served.borrow_mut() = Self::config(&self.identity, &self.key, &gateway, NOW - 5);
            *self.gateway.borrow_mut() = gateway;
        }
    }

    #[async_trait(?Send)]
    impl ChatTransport for Home {
        async fn register_device(&self, _: &RegisterChatDeviceRequestV2) -> Result<u32> {
            unreachable!()
        }
        async fn fetch_bundles(&self, _: &str) -> Result<AccountPreKeyBundlesResponse> {
            unreachable!()
        }
        async fn send(&self, _: &str, _: &SendMessagesRequest) -> Result<SendOutcome> {
            unreachable!()
        }
        async fn drain(&self, _: u32, _: Option<u64>, _: u32) -> Result<MailboxPage> {
            unreachable!()
        }
        async fn ack(&self, _: u32, _: &[String]) -> Result<()> {
            unreachable!()
        }

        async fn fetch_group_gateway(&self, home: &str, from: u64) -> Result<GroupGatewayAnswer> {
            assert_eq!((home, from), ("home.example", self.identity.sequence));
            self.fetches.set(self.fetches.get() + 1);
            Ok(GroupGatewayAnswer {
                config: self.served.borrow().clone(),
                identity_history: vec![self.identity.clone()],
            })
        }

        async fn relay_group_request(
            &self,
            home: &str,
            sealed: &[u8],
        ) -> Result<GroupRelayOutcome> {
            assert_eq!(home, "home.example");
            let Ok((body, context)) = self.gateway.borrow().open_request(sealed) else {
                return Ok(GroupRelayOutcome::Unopenable);
            };
            let request = GroupRequestV1::from_canonical_bytes(&body).unwrap();
            request.verify_pseudonym().unwrap();
            let skewed = (request.timestamp - self.clock).abs() > 5 * 60;
            self.seen.borrow_mut().push(request);
            let response = if skewed {
                GroupResponseV1::new(GroupResponseStatusV1::ClockSkew, self.clock, b"")
            } else {
                GroupResponseV1::new(GroupResponseStatusV1::Ok, self.clock, b"state")
            };
            Ok(GroupRelayOutcome::Answered(
                context
                    .seal_response(&response.canonical_bytes().unwrap())
                    .unwrap(),
            ))
        }
    }

    fn get_state(home: &Home, cache: &mut GatewayCache, now: i64) -> Result<GroupResponseV1> {
        let pseudonym = [7u8; 32];
        block_on(call(
            home,
            cache,
            &home.pin(),
            &[5u8; 32],
            GroupOperationV1::GetState,
            b"",
            &RequestSigner::Key(&pseudonym),
            now,
        ))
        .map(|outcome| outcome.expect("an answer"))
    }

    #[test]
    fn a_request_reaches_the_home_sealed_to_its_pinned_key() {
        let home = Home::new();
        let mut cache = GatewayCache::default();
        let response = get_state(&home, &mut cache, NOW).unwrap();
        assert_eq!(response.status, GroupResponseStatusV1::Ok);
        assert_eq!(response.body().unwrap(), b"state");
        assert_eq!(home.fetches.get(), 1);
        // The key is kept: the next call fetches nothing.
        get_state(&home, &mut cache, NOW).unwrap();
        assert_eq!(home.fetches.get(), 1);
        let seen = home.seen.borrow();
        assert_eq!(seen[0].home, "home.example");
        assert_ne!(seen[0].nonce, seen[1].nonce, "a fresh nonce per request");
    }

    #[test]
    fn a_rotated_gateway_key_is_fetched_again_once() {
        let home = Home::new();
        let mut cache = GatewayCache::default();
        get_state(&home, &mut cache, NOW).unwrap();
        home.rotate();
        let response = get_state(&home, &mut cache, NOW).unwrap();
        assert_eq!(response.status, GroupResponseStatusV1::Ok);
        assert_eq!(home.fetches.get(), 2);
        assert_eq!(cache.config.as_ref().unwrap().key_id, 2);
    }

    #[test]
    fn a_key_not_signed_by_the_pinned_identity_is_refused() {
        let home = Home::new();
        // A relay hands over a config signed by its own identity.
        let relay_key = SigningKey::from_bytes(&[2u8; 32]);
        let relay = FederationIdentityDocumentV1::genesis("home.example", 10, &relay_key).unwrap();
        let gateway = GatewayKey::generate(1).unwrap();
        *home.served.borrow_mut() = Home::config(&relay, &relay_key, &gateway, NOW - 10);
        let mut cache = GatewayCache::default();
        assert!(matches!(
            get_state(&home, &mut cache, NOW),
            Err(ChatError::Trust(_))
        ));
        assert!(cache.config.is_none(), "nothing kept");
    }

    #[test]
    fn an_older_config_never_replaces_a_newer_one() {
        let home = Home::new();
        let mut cache = GatewayCache::default();
        home.rotate();
        get_state(&home, &mut cache, NOW).unwrap();
        // The relay now serves the older config again.
        let old = GatewayKey::generate(1).unwrap();
        *home.served.borrow_mut() = Home::config(&home.identity, &home.key, &old, NOW - 10);
        assert!(block_on(cache.refresh(&home, &home.pin(), NOW)).is_err());
        assert_eq!(cache.config.as_ref().unwrap().key_id, 2);
    }

    #[test]
    fn a_skewed_clock_is_corrected_from_the_homes_time() {
        let home = Home::new();
        let mut cache = GatewayCache::default();
        // Fetch the key first at the right time, then call with a clock an hour off.
        get_state(&home, &mut cache, NOW).unwrap();
        let response = get_state(&home, &mut cache, NOW + 60 * 60).unwrap();
        assert_eq!(response.status, GroupResponseStatusV1::Ok);
        let seen = home.seen.borrow();
        assert_eq!(seen.last().unwrap().timestamp, NOW);
    }
}
