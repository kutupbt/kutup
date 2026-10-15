//! A peer's username renames (docs/plans/username-renames.md).
//!
//! A rename keeps an account's authority and incarnation and changes only its
//! address. Each one is a statement signed by the account authority; the
//! chain of them is public, and a lookup of a name its account left answers
//! `409 renamed` with every chain that names it (a freed name reused by
//! someone else appears in several). Chat follows a chain only when:
//!
//! - its authority and incarnation are the ones pinned for the peer;
//! - it verifies (`kutup_crypto::account_rename::verify_chain`);
//! - it extends the chain seen before, digest for digest (a server cannot
//!   roll a rename back or rewrite one);
//! - it names the address the peer is pinned at, compared folded;
//! - the account still goes by it (`state` `current`).
//!
//! Anything else leaves the pin where it is: a reset or a freed name taken by
//! someone else is the usual "safety number changed" quarantine, never a
//! rename.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_rename::{self, AccountRenameV1};
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use crate::db::{ChatDb, ManifestTrust, Pending};
use crate::error::{ChatError, Result};

/// The only lookup format this client reads; another is unverifiable.
pub const RENAME_CHAINS_VERSION: u32 = 1;

/// Every rename chain naming an address, newest first, as `GET
/// /api/users/renames/:address` and a `409 renamed` (`renames`) carry them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameChainsV1 {
    pub version: u32,
    #[serde(default)]
    pub chains: Vec<RenameChainEntryV1>,
    /// The address's server could not be asked: nothing is known.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

/// One account's chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameChainEntryV1 {
    pub incarnation_id: String,
    pub authority_public_key: String,
    /// Where the account is now, as its server says (checked against the chain).
    pub current: String,
    /// `current`, `held` (the account is gone and its names held) or `gone`.
    pub state: String,
    pub chain: Vec<AccountRenameV1>,
}

/// What a client keeps of a peer's chain once followed: the newest sequence
/// and every statement's digest (a later chain must extend them), and every
/// address the peer has had, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownRenamesV1 {
    pub sequence: u64,
    /// Lowercase hex, one per statement.
    pub digests: Vec<String>,
    pub addresses: Vec<String>,
}

/// A chain to follow: the peer is `to` now, and was `from` where it is pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRename {
    pub from: String,
    pub to: String,
    pub known: KnownRenamesV1,
}

/// The folded form of an address (`kutup_crypto::names::fold_address`), or
/// the address itself when it is not one.
pub fn fold(address: &str) -> String {
    kutup_crypto::names::fold_address(address).unwrap_or_else(|| address.to_string())
}

/// Two addresses of one account: equal once folded.
pub fn same_address(a: &str, b: &str) -> bool {
    match (
        kutup_crypto::names::fold_address(a),
        kutup_crypto::names::fold_address(b),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

/// Whether `address` is one the peer is known to have had (its pinned
/// address, or any address of the chain followed for it).
pub fn known_address(trust: &ManifestTrust, address: &str) -> bool {
    same_address(&trust.peer, address)
        || same_address(&trust.account, address)
        || trust
            .renames
            .as_ref()
            .is_some_and(|known| known.addresses.iter().any(|a| same_address(a, address)))
}

/// The chain among `chains` that the peer pinned as `trust` has followed to
/// an address other than its pinned one, verified; `None` when there is
/// nothing to follow (no chain of its authority, still at the same address,
/// an account no longer current). Errors for a chain of its authority that
/// does not verify or rolls back the one followed before, and for an
/// unknown format.
pub fn select(trust: &ManifestTrust, chains: &RenameChainsV1) -> Result<Option<VerifiedRename>> {
    if chains.version != RENAME_CHAINS_VERSION {
        return Err(ChatError::Trust(format!(
            "rename lookup version {} is not one this client reads",
            chains.version
        )));
    }
    if chains.unavailable {
        return Ok(None);
    }
    let Some(entry) = chains.chains.iter().find(|entry| {
        entry.authority_public_key == trust.self_authority_key
            && entry.incarnation_id == trust.incarnation_id
    }) else {
        return Ok(None);
    };
    if entry.state != "current" {
        return Ok(None);
    }
    let authority: [u8; 32] = STANDARD
        .decode(&trust.self_authority_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ChatError::Trust("pinned authority key is malformed".into()))?;
    let view = account_rename::verify_chain(&authority, &entry.chain)
        .map_err(|error| ChatError::Trust(format!("rename chain: {error}")))?;
    if view.incarnation_id != trust.incarnation_id {
        return Err(ChatError::Trust(
            "rename chain names another incarnation".into(),
        ));
    }
    let digests: Vec<String> = view.digests.iter().map(hex::encode).collect();
    if let Some(known) = &trust.renames {
        if known.digests.len() > digests.len()
            || digests[..known.digests.len()] != known.digests[..]
        {
            return Err(ChatError::Trust(
                "rename chain does not extend the one followed before".into(),
            ));
        }
    }
    if !same_address(&entry.current, &view.current) {
        return Err(ChatError::Trust(
            "rename lookup names another current address than its chain".into(),
        ));
    }
    if !view.addresses.iter().any(|a| same_address(a, &trust.peer)) {
        return Ok(None);
    }
    if same_address(&view.current, &trust.peer) {
        return Ok(None);
    }
    Ok(Some(VerifiedRename {
        from: trust.peer.clone(),
        to: view.current.clone(),
        known: KnownRenamesV1 {
            sequence: view.sequence,
            digests,
            addresses: view.addresses,
        },
    }))
}

/// Where the rename alias log lives among the derived index records.
pub(crate) const ALIASES_KEY: &[u8] = b"renames/aliases";

/// The addresses peers left, and where each peer is now: history keeps the
/// address it was written under (messages, Note to Self controls, backups),
/// and the timeline, search and the app read it through this log, so a
/// thread follows its peer. Kept with the store; never sent.
///
/// A left name may later be someone else's (a freed name taken). From the
/// moment this device pins another incarnation there (`reused_at_ms`, set in
/// the same transaction), the alias no longer applies: what is written after
/// it is the newcomer's, and only what came before follows the old peer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameAliases {
    /// Folded old address → where the peer that left it is now.
    #[serde(default)]
    pub moved: BTreeMap<String, RenameAlias>,
}

/// One address a peer left.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameAlias {
    /// The peer's newest address.
    pub to: String,
    /// The peer's incarnation: someone else at the address is not it.
    pub incarnation_id: String,
    /// When this device followed the peer away (unix ms).
    pub moved_at_ms: i64,
    /// When this device met another incarnation at the address (unix ms):
    /// records from then on are the newcomer's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused_at_ms: Option<i64>,
}

impl RenameAliases {
    /// Where the peer last known at `address` is now, for what happens now
    /// (sessions, inbound senders, queued sends): `address` itself when it
    /// never moved, or when someone else holds it now.
    pub fn resolve(&self, address: &str) -> String {
        match self.moved.get(&fold(address)) {
            Some(alias) if alias.reused_at_ms.is_none() => alias.to.clone(),
            _ => address.to_string(),
        }
    }

    /// Where a record written under `address` at `at_ms` belongs: the peer
    /// that left the address, unless the record came once someone else had it.
    pub fn resolve_at(&self, address: &str, at_ms: i64) -> String {
        match self.moved.get(&fold(address)) {
            Some(alias) if alias.reused_at_ms.is_none_or(|reused| at_ms < reused) => {
                alias.to.clone()
            }
            _ => address.to_string(),
        }
    }

    /// Records that the peer (`incarnation_id`) at `from` is `to` now.
    /// Earlier addresses that led to `from` lead to `to`; `to` itself is no
    /// longer an alias (a peer that took a name back).
    pub fn record(&mut self, from: &str, to: &str, incarnation_id: &str, at_ms: i64) {
        let to_folded = fold(to);
        // The peer's earlier names follow it, a reused one too (for the
        // records from before someone else had it).
        for alias in self.moved.values_mut() {
            if alias.incarnation_id == incarnation_id && same_address(&alias.to, from) {
                alias.to = to.to_string();
            }
        }
        self.moved.remove(&to_folded);
        if fold(from) != to_folded {
            self.moved.insert(
                fold(from),
                RenameAlias {
                    to: to.to_string(),
                    incarnation_id: incarnation_id.to_string(),
                    moved_at_ms: at_ms,
                    reused_at_ms: None,
                },
            );
        }
    }

    /// Another incarnation (`incarnation_id`) is pinned at `address`: if a
    /// peer left it, the alias stops applying from `at_ms`. Whether it did.
    pub fn mark_reused(&mut self, address: &str, incarnation_id: &str, at_ms: i64) -> bool {
        match self.moved.get_mut(&fold(address)) {
            Some(alias)
                if alias.reused_at_ms.is_none() && alias.incarnation_id != incarnation_id =>
            {
                alias.reused_at_ms = Some(at_ms);
                true
            }
            _ => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.moved.is_empty()
    }
}

/// A direct conversation as of `at_ms`, where its peer is now (groups as
/// they are): see [`RenameAliases::resolve_at`].
pub fn current_conversation(
    aliases: &RenameAliases,
    conversation: &kutup_chat_proto::ConversationId,
    at_ms: i64,
) -> kutup_chat_proto::ConversationId {
    match conversation {
        kutup_chat_proto::ConversationId::Direct { address } if !aliases.is_empty() => aliases
            .resolve_at(&address.canonical(), at_ms)
            .parse::<kutup_chat_proto::AccountAddress>()
            .map(kutup_chat_proto::ConversationId::direct)
            .unwrap_or_else(|_| conversation.clone()),
        _ => conversation.clone(),
    }
}

/// The alias log as `pending` would leave it: its staged copy, else the
/// stored one.
pub(crate) async fn load_aliases(
    db: &dyn ChatDb,
    pending: Option<&Pending>,
) -> Result<RenameAliases> {
    if let Some(Some(bytes)) = pending.and_then(|pending| pending.index_values.get(ALIASES_KEY)) {
        return decode_aliases(bytes);
    }
    match db.load_index_value(ALIASES_KEY).await? {
        Some(bytes) => decode_aliases(&bytes),
        None => Ok(RenameAliases::default()),
    }
}

fn decode_aliases(bytes: &[u8]) -> Result<RenameAliases> {
    serde_json::from_slice(bytes).map_err(|error| ChatError::Db(format!("rename aliases: {error}")))
}

/// Stages `aliases` with the commit in `pending`.
pub(crate) fn stage_aliases(pending: &mut Pending, aliases: &RenameAliases) -> Result<()> {
    let bytes = serde_json::to_vec(aliases)
        .map_err(|error| ChatError::Db(format!("rename aliases: {error}")))?;
    pending
        .index_values
        .insert(ALIASES_KEY.to_vec(), Some(bytes));
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::AuthorityTrust;
    use kutup_crypto::identity::AccountIdentityKeysV1;

    pub(crate) const T: i64 = 1_790_000_000_000;

    pub(crate) fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&[seed; 32]).unwrap()
    }

    /// The chain of `identity`'s account through `addresses`, oldest first.
    pub(crate) fn chain(
        identity: &AccountIdentityKeysV1,
        addresses: &[&str],
    ) -> Vec<AccountRenameV1> {
        addresses
            .windows(2)
            .enumerate()
            .map(|(i, pair)| {
                account_rename::sign(identity, i as u64 + 1, pair[0], pair[1], T + i as i64)
                    .unwrap()
            })
            .collect()
    }

    pub(crate) fn chains(identity: &AccountIdentityKeysV1, addresses: &[&str]) -> RenameChainsV1 {
        RenameChainsV1 {
            version: RENAME_CHAINS_VERSION,
            chains: vec![RenameChainEntryV1 {
                incarnation_id: identity.incarnation_id(),
                authority_public_key: STANDARD.encode(identity.authority_public_key()),
                current: addresses.last().unwrap().to_string(),
                state: "current".into(),
                chain: chain(identity, addresses),
            }],
            unavailable: false,
        }
    }

    pub(crate) fn pinned(identity: &AccountIdentityKeysV1, peer: &str) -> ManifestTrust {
        ManifestTrust {
            peer: peer.into(),
            account: peer.into(),
            incarnation_id: identity.incarnation_id(),
            authority_key_id: "key".into(),
            self_authority_key: STANDARD.encode(identity.authority_public_key()),
            drive_hpke_public_key: STANDARD.encode([7u8; 32]),
            drive_share_signing_public_key: STANDARD.encode([8u8; 32]),
            highest_sequence: 1,
            manifest_hash: "11".repeat(32),
            trust: AuthorityTrust::Tofu,
            continuity_gap: false,
            quarantine_reason: None,
            pending_reset: None,
            renames: None,
        }
    }

    #[test]
    fn follows_the_pinned_authority_to_its_current_address() {
        let ada = identity(1);
        let trust = pinned(&ada, "ada_l@kutup.test");
        let found = select(
            &trust,
            &chains(&ada, &["ada_l@kutup.test", "ada_lovelace@kutup.test"]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(found.from, "ada_l@kutup.test");
        assert_eq!(found.to, "ada_lovelace@kutup.test");
        assert_eq!(found.known.sequence, 1);
        assert_eq!(
            found.known.addresses,
            ["ada_l@kutup.test", "ada_lovelace@kutup.test"]
        );
    }

    #[test]
    fn a_pin_in_another_spelling_is_followed_and_the_same_address_is_not_a_rename() {
        let ada = identity(1);
        let trust = pinned(&ada, "ada-l@kutup.test");
        let found = select(
            &trust,
            &chains(&ada, &["ada_l@kutup.test", "ada@kutup.test"]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(found.to, "ada@kutup.test");
        let trust = pinned(&ada, "a-da@kutup.test");
        assert_eq!(
            select(
                &trust,
                &chains(&ada, &["ada_l@kutup.test", "ada@kutup.test"])
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn another_authority_is_not_followed() {
        let ada = identity(1);
        let mallory = identity(2);
        let trust = pinned(&ada, "ada_l@kutup.test");
        // Mallory's own chain through the name: not Ada's.
        assert_eq!(
            select(
                &trust,
                &chains(&mallory, &["ada_l@kutup.test", "mallory@kutup.test"])
            )
            .unwrap(),
            None
        );
        // Ada's authority named, Mallory's signatures: refused.
        let mut forged = chains(&mallory, &["ada_l@kutup.test", "mallory@kutup.test"]);
        forged.chains[0].authority_public_key = trust.self_authority_key.clone();
        forged.chains[0].incarnation_id = trust.incarnation_id.clone();
        assert!(select(&trust, &forged).is_err());
    }

    #[test]
    fn a_rollback_or_rewrite_is_refused() {
        let ada = identity(1);
        let mut trust = pinned(&ada, "ada_lovelace@kutup.test");
        let two = select(
            &pinned(&ada, "ada_l@kutup.test"),
            &chains(
                &ada,
                &[
                    "ada_l@kutup.test",
                    "ada_lovelace@kutup.test",
                    "ada_king@kutup.test",
                ],
            ),
        )
        .unwrap()
        .unwrap();
        trust.peer = two.to.clone();
        trust.renames = Some(two.known);
        // The server answers the chain one statement short.
        let short = chains(&ada, &["ada_l@kutup.test", "ada_lovelace@kutup.test"]);
        assert!(select(&trust, &short).is_err());
        // A rewritten second rename.
        let rewritten = chains(
            &ada,
            &[
                "ada_l@kutup.test",
                "ada_lovelace@kutup.test",
                "ada_queen@kutup.test",
            ],
        );
        assert!(select(&trust, &rewritten).is_err());
    }

    #[test]
    fn an_unknown_format_is_refused_and_an_unavailable_answer_says_nothing() {
        let ada = identity(1);
        let trust = pinned(&ada, "ada_l@kutup.test");
        let mut later = chains(&ada, &["ada_l@kutup.test", "ada@kutup.test"]);
        later.version = 2;
        assert!(select(&trust, &later).is_err());
        let unavailable = RenameChainsV1 {
            version: 1,
            chains: vec![],
            unavailable: true,
        };
        assert_eq!(select(&trust, &unavailable).unwrap(), None);
    }

    #[test]
    fn an_account_no_longer_current_is_not_followed() {
        let ada = identity(1);
        let trust = pinned(&ada, "ada_l@kutup.test");
        let mut gone = chains(&ada, &["ada_l@kutup.test", "ada@kutup.test"]);
        gone.chains[0].state = "gone".into();
        assert_eq!(select(&trust, &gone).unwrap(), None);
    }

    #[test]
    fn aliases_follow_a_peer_through_every_rename_and_back() {
        let mut aliases = RenameAliases::default();
        aliases.record("ada_l@kutup.test", "ada_lovelace@kutup.test", "inc-ada", 1);
        assert_eq!(
            aliases.resolve("ada-l@kutup.test"),
            "ada_lovelace@kutup.test"
        );
        aliases.record(
            "ada_lovelace@kutup.test",
            "ada_king@kutup.test",
            "inc-ada",
            2,
        );
        assert_eq!(aliases.resolve("ada_l@kutup.test"), "ada_king@kutup.test");
        assert_eq!(
            aliases.resolve("ada_lovelace@kutup.test"),
            "ada_king@kutup.test"
        );
        // Back to the first name: it is the peer's address again, not an alias.
        aliases.record("ada_king@kutup.test", "ada_l@kutup.test", "inc-ada", 3);
        assert_eq!(aliases.resolve("ada_l@kutup.test"), "ada_l@kutup.test");
        assert_eq!(aliases.resolve("ada_king@kutup.test"), "ada_l@kutup.test");
        assert_eq!(aliases.resolve("grace@kutup.test"), "grace@kutup.test");
    }

    /// Every record a peer's address keys, classified for a rename
    /// (`Session::move_peer`): a field added to [`Pending`] does not compile
    /// here until someone decides whether it moves with the peer.
    #[test]
    fn every_store_is_classified_for_a_rename() {
        let Pending {
            // Moved to the new address in the same transaction.
            sessions: _,
            identities: _,
            manifest_trust: _,
            manifest_history: _,
            contacts: _,
            peer_profiles: _,
            delete_peer_records: _,
            // History: rewritten under the new address (received messages
            // through moved_messages, sent ones re-staged); Note to Self
            // controls and backups name conversations inside their content
            // and are read through the rename aliases, as of their time.
            moved_messages: _,
            messages: _,
            sent_messages: _,
            mls_messages: _,
            delete_messages_for_peers: _,
            delete_message_ids: _,
            delete_sent_message_ids: _,
            delete_mls_message_ids: _,
            // Derived from history, rebuilt after a move; holds the alias log.
            index_values: _,
            // Queued sends: resolved through the aliases when delivered.
            outbox: _,
            inbound: _,
            // MLS state is frozen (docs/plans/username-renames.md).
            mls_outbox: _,
            mls_state: _,
            // Reserved for groups, unused for 1:1.
            sender_keys: _,
            // This device's own keys and counters: no peer address.
            local_identity: _,
            pre_keys: _,
            signed_pre_keys: _,
            kyber_pre_keys: _,
            kyber_seen: _,
            local_profile: _,
            prekey_upload: _,
            prekey_rotation: _,
            repair_limits: _,
            delete_signed_pre_keys: _,
            delete_kyber_pre_keys: _,
            registration_upload: _,
            last_cursor: _,
            last_sent_seq: _,
        } = Pending::default();
    }

    /// The SQLite tables, classified as [`every_store_is_classified_for_a_rename`]
    /// does the staged fields: a new table fails here until it is.
    #[cfg(feature = "sqlite")]
    #[test]
    fn every_sqlite_table_is_classified_for_a_rename() {
        let classified = [
            // Moved.
            "sessions",
            "identities",
            "manifest_trust",
            "manifest_history",
            "contacts",
            "peer_profiles",
            // History: rewritten on a move, or read through the aliases; the
            // index holds the log.
            "messages",
            "sent_messages",
            "mls_messages",
            "index_values",
            "outbox",
            "inbound_envelopes",
            // Frozen MLS, reserved group keys.
            "mls_state",
            "mls_outbox",
            "sender_keys",
            // No peer address.
            "schema_migrations",
            "local_identity",
            "pre_keys",
            "signed_pre_keys",
            "kyber_pre_keys",
            "kyber_base_keys_seen",
            "pending_prekey_upload",
            "prekey_rotation",
            "repair_limits",
            "pending_chat_registration",
            "local_profile",
            "meta",
        ];
        let db = crate::SqliteChatDb::open_in_memory().unwrap();
        let mut tables = db.table_names();
        tables.sort();
        let mut expected: Vec<String> = classified.iter().map(|t| t.to_string()).collect();
        expected.sort();
        assert_eq!(tables, expected, "classify every new table for a rename");
    }

    #[test]
    fn a_name_someone_else_took_is_no_alias_from_then_on() {
        let mut aliases = RenameAliases::default();
        aliases.record(
            "ada_l@kutup.test",
            "ada_lovelace@kutup.test",
            "inc-ada",
            100,
        );
        // Ada herself pinned again at her old name is no reuse.
        assert!(!aliases.mark_reused("ada_l@kutup.test", "inc-ada", 150));
        // Mallory, another incarnation, pinned there at 200.
        assert!(aliases.mark_reused("ADA-L@kutup.test", "inc-mallory", 200));
        assert!(!aliases.mark_reused("ada_l@kutup.test", "inc-mallory", 300));
        assert_eq!(aliases.resolve("ada_l@kutup.test"), "ada_l@kutup.test");
        assert_eq!(
            aliases.resolve_at("ada_l@kutup.test", 199),
            "ada_lovelace@kutup.test"
        );
        assert_eq!(
            aliases.resolve_at("ada_l@kutup.test", 200),
            "ada_l@kutup.test"
        );
        // Ada renaming again takes her records from before the reuse along.
        aliases.record(
            "ada_lovelace@kutup.test",
            "ada_king@kutup.test",
            "inc-ada",
            400,
        );
        assert_eq!(
            aliases.resolve_at("ada_l@kutup.test", 199),
            "ada_king@kutup.test"
        );
        assert_eq!(aliases.resolve("ada_l@kutup.test"), "ada_l@kutup.test");
        assert_eq!(
            aliases.resolve("ada_lovelace@kutup.test"),
            "ada_king@kutup.test"
        );
    }
}
