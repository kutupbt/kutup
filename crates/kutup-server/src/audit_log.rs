//! The admin log (docs/plans/server-personal-data.md, A8): what administrators
//! did, append-only for the server and hash-chained.
//!
//! Each row stores the previous row's hash and its own:
//! `row_hash = SHA-256(domain ‖ previous_hash ‖ the row)`, the row being its
//! admin, action, target, time and payload (keys sorted, so the hash
//! recomputes from what Postgres stores). Changing, removing or reordering a
//! row breaks the chain from there, which [`verify`] finds. The retention job
//! deletes rows only from the oldest end and records, in
//! `admin_audit_anchor` (which only the owner role writes), the last row it
//! deleted and that row's hash: verification starts from there, so deleting
//! more of the oldest rows breaks it too. A row is timed after the chain's
//! lock is taken, so the chain's order is also its time order.

use kutup_crypto::primitives::{Hasher, Suite};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppResult;

/// Declares [`AdminAction`]: each action, its string (`area.verb`: two
/// camelCase segments, the verb imperative) and the payload keys it may
/// carry. Payloads name accounts by id only (the row's target account),
/// never by a username snapshot (A8).
macro_rules! admin_actions {
    ($($variant:ident = $name:literal [$($key:literal),* $(,)?]),* $(,)?) => {
        /// Every action the admin log records (docs/plans/w7-schema.md §3).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum AdminAction {
            $($variant),*
        }

        impl AdminAction {
            /// Every action, for the table's own test.
            #[cfg(test)]
            pub const ALL: &'static [AdminAction] = &[$(AdminAction::$variant),*];

            /// The action as the log stores it.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(AdminAction::$variant => $name),*
                }
            }

            /// The payload keys this action may carry (its top-level keys).
            pub const fn payload_keys(self) -> &'static [&'static str] {
                match self {
                    $(AdminAction::$variant => &[$($key),*]),*
                }
            }
        }
    };
}

admin_actions! {
    // Accounts (the account is the row's target).
    AccountView = "account.view" ["view"],
    AccountCreate = "account.create" ["storageQuotaBytes"],
    AccountSetFederation = "account.setFederation" ["federation"],
    AccountSetPublicSharing = "account.setPublicSharing" ["publicSharing"],
    AccountUpdate = "account.update" ["changes"],
    AccountDelete = "account.delete" [],
    AccountClose = "account.close" ["closesAt"],
    AccountSetLegalHold = "account.setLegalHold" ["reference"],
    AccountClearLegalHold = "account.clearLegalHold" ["reference"],
    AccountDisableTwoFactor = "account.disableTwoFactor" [],
    AccountRotateTempPassword = "account.rotateTempPassword" [],
    AccountResetKeys = "account.resetKeys" [],
    AccountSetEntitlement = "account.setEntitlement" ["key", "field", "section", "value", "previous"],
    AccountSetRateLimit = "account.setRateLimit" ["key", "value", "previous"],
    // Site settings and the other admin areas.
    SettingsUpdate = "settings.update" [
        "registrationMode", "publicSharing", "federationDefault", "defaultStorageQuotaBytes",
        "chatMailboxRetentionDays", "chatMediaDeliveryRetentionDays", "nameHoldDays",
        "oldAddressReceiveDays", "chatGroupLinkJoinsPerRelayGroupPerMin",
        "chatGroupLinkJoinsPerRelayPerMin", "numeric", "chatGroupAvatarMaxBytes",
        "chatGroupAvatarStoragePerGroupBytes", "chatGroupAvatarPendingSeconds", "passVaultMaxBytes",
    ],
    SettingsSetRateLimit = "settings.setRateLimit" ["key", "value", "previous"],
    // The oldest client of a type the server accepts (`null` value: the floor).
    ClientVersionSetMinimum = "clientVersion.setMinimum" ["clientType", "value"],
    MapsUpdateSettings = "maps.updateSettings" ["enabled", "providers", "proxy", "cacheMegabytes"],
    LegalPublish = "legal.publish" ["documentId", "kind", "version", "language", "requiredAtSignup"],
    MailUpdateSending = "mail.updateSending" ["perHour", "perDay", "paused", "clearFlag"],
    MailUpdateOutsideSending = "mail.updateOutsideSending" ["from", "to"],
    MailDomainUpdateSettings = "mailDomain.updateSettings" ["settings"],
    MailDomainApprove = "mailDomain.approve" ["domain"],
    MailDomainDeactivate = "mailDomain.deactivate" ["domain"],
    MailDomainUnblock = "mailDomain.unblock" ["domain"],
    MailDomainSetOverrides = "mailDomain.setOverrides" ["limits", "organization"],
    MailGroupCreate = "mailGroup.create" ["groupId", "address", "kind", "quota"],
    MailGroupUpdate = "mailGroup.update" ["groupId", "address", "change", "quota", "postPolicy"],
    MailGroupUpdateMembers = "mailGroup.updateMembers" ["groupId", "address", "added", "removed", "count"],
    MailGroupDelete = "mailGroup.delete" ["groupId", "address"],
    MailGroupSetKey = "mailGroup.setKey" ["groupId", "address", "fingerprint"],
    ReportDismiss = "report.dismiss" ["reportId", "shareId"],
    ShareRemove = "share.remove" ["reportId", "shareId"],
    ShareBlock = "share.block" ["shareId", "reason", "reference"],
    ShareUnblock = "share.unblock" ["shareId", "reason"],
    FeedbackResolve = "feedback.resolve" ["feedbackId", "resolution", "githubUrl"],
    FeedbackDelete = "feedback.delete" ["feedbackId"],
    RegistrationCodeCreate = "registrationCode.create" ["id", "hint", "note", "maxUses", "expiresAt"],
    RegistrationCodeRevoke = "registrationCode.revoke" ["id", "hint"],
    // The held name itself (what the action is about), not a snapshot.
    NameClose = "name.close" ["name"],
    NameFree = "name.free" ["name"],
    // Federation.
    FederationUpdatePolicy = "federation.updatePolicy" ["globalEnabled", "feature", "mode", "minimumTrust"],
    FederationSetRule = "federation.setRule" ["domain", "feature", "inbound", "outbound", "trustRequirement"],
    FederationDeleteRule = "federation.deleteRule" ["domain", "feature"],
    FederationRetryPeer = "federation.retryPeer" ["domain", "refreshed", "error"],
    FederationRetryPeers = "federation.retryPeers" ["results"],
    FederationCreateIdentity = "federation.createIdentity" ["actorType", "domain", "sequence", "fingerprint"],
    FederationRotateIdentity = "federation.rotateIdentity" [
        "actorType", "domain", "sequence", "oldFingerprint", "oldFingerprintDisplay",
        "newFingerprint", "newFingerprintDisplay",
    ],
    FederationPinPeer = "federation.pinPeer" ["actorType", "domain", "trust", "sequence", "fingerprint"],
    FederationVerifyPeer = "federation.verifyPeer" ["actorType", "domain", "sequence", "fingerprint", "fingerprintDisplay"],
    FederationRepinPeer = "federation.repinPeer" [
        "actorType", "domain", "oldFingerprint", "oldFingerprintDisplay", "newFingerprint",
        "newFingerprintDisplay", "newSequence",
    ],
    FederationAdvancePeer = "federation.advancePeer" [
        "actorType", "domain", "previousSequence", "sequence", "fingerprint", "trust",
    ],
    FederationQuarantinePeer = "federation.quarantinePeer" [
        "actorType", "domain", "reason", "retainedSequence", "retainedFingerprint",
        "candidateSequence", "candidateFingerprint",
    ],
    FederationCreateFeaturePolicy = "federation.createFeaturePolicy" [
        "actorType", "domain", "featureType", "sequence", "policyHash", "identityGeneration",
    ],
    FederationRotateFeaturePolicy = "federation.rotateFeaturePolicy" [
        "actorType", "domain", "featureType", "sequence", "policyHash", "identityGeneration",
    ],
}

impl std::fmt::Display for AdminAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// In debug builds and tests: the payload is an object whose keys are all in
/// `action`'s list, so a new key (or a username snapshot) can't slip in
/// without the table naming it.
fn debug_check_payload(action: AdminAction, payload: &Value) {
    if cfg!(debug_assertions) {
        let object = payload
            .as_object()
            .unwrap_or_else(|| panic!("the {action} payload is not an object"));
        for key in object.keys() {
            assert!(
                action.payload_keys().contains(&key.as_str()),
                "the {action} payload carries `{key}`, not in its list"
            );
        }
    }
}

const CHAIN_DOMAIN: &[u8] = kutup_crypto::labels::SERVER_ADMIN_AUDIT_CHAIN_V1;
/// The version [`row_hash`] is (`admin_audit_log.chain_version`): a row of
/// another version is one this server can't check, and reads as broken.
const CHAIN_VERSION: i16 = 1;
/// The advisory lock that orders the chain's inserts.
const CHAIN_LOCK: i64 = 0x6b75_7475_7061_7564; // "kutupaud"
/// Rows read per page when verifying.
const VERIFY_PAGE: i64 = 1000;

/// A JSON value with object keys sorted, recursively: the form the hash
/// covers.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", Value::String(key.clone()), canonical(&map[key])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

fn row_hash(
    previous: &[u8],
    admin: Uuid,
    action: &str,
    target: Option<Uuid>,
    at_micros: i128,
    payload: &Value,
) -> [u8; 32] {
    let mut hasher = Hasher::new(Suite::V1);
    hasher.update(CHAIN_DOMAIN);
    hasher.update((previous.len() as u32).to_be_bytes());
    hasher.update(previous);
    hasher.update(admin.as_bytes());
    hasher.update((action.len() as u32).to_be_bytes());
    hasher.update(action.as_bytes());
    if let Some(target) = target {
        hasher.update([1u8]);
        hasher.update(target.as_bytes());
    } else {
        hasher.update([0u8]);
    }
    hasher.update(at_micros.to_be_bytes());
    let payload = canonical(payload);
    hasher.update((payload.len() as u32).to_be_bytes());
    hasher.update(payload.as_bytes());
    hasher.finish().to_array()
}

/// The time to the microsecond, as Postgres keeps it.
fn micros(at: OffsetDateTime) -> i128 {
    at.unix_timestamp_nanos() / 1000
}

/// Whether `value` holds a number that is not an integer: Postgres's `jsonb`
/// may write such a number back otherwise than it came (`1e2` as `100`), so
/// the chain takes integers only.
fn has_fraction(value: &Value) -> bool {
    match value {
        Value::Number(number) => !(number.is_i64() || number.is_u64()),
        Value::Array(items) => items.iter().any(has_fraction),
        Value::Object(map) => map.values().any(has_fraction),
        _ => false,
    }
}

/// Appends one admin action, chained to the newest row.
pub async fn append(
    pool: &PgPool,
    admin: Uuid,
    action: AdminAction,
    target: Option<Uuid>,
    payload: &Value,
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    append_in(&mut tx, admin, action, target, payload).await?;
    tx.commit().await?;
    Ok(())
}

/// [`append`] in the caller's transaction, with the action it records: the
/// chain's lock is held until that commits.
pub async fn append_in(
    conn: &mut sqlx::PgConnection,
    admin: Uuid,
    action: AdminAction,
    target: Option<Uuid>,
    payload: &Value,
) -> sqlx::Result<()> {
    debug_check_payload(action, payload);
    let action = action.as_str();
    if has_fraction(payload) {
        return Err(sqlx::Error::Encode(
            "an admin log payload holds a number that is not an integer".into(),
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHAIN_LOCK)
        .execute(&mut *conn)
        .await?;
    // Timed under the lock: a row later in the chain is never earlier in time.
    let at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *conn)
        .await?;
    // The newest row's hash; when retention emptied the table, the anchor's
    // (the last row it deleted), which verification starts from; else none.
    let previous: Vec<u8> = sqlx::query_scalar(
        "SELECT h FROM (
             (SELECT row_hash AS h, 1 AS o FROM admin_audit_log ORDER BY id DESC LIMIT 1)
             UNION ALL
             (SELECT through_hash, 2 FROM admin_audit_anchor)
         ) chain ORDER BY o LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await?
    .flatten()
    .unwrap_or_default();
    let hash = row_hash(&previous, admin, action, target, micros(at), payload);
    sqlx::query(
        "INSERT INTO admin_audit_log
             (admin_account_id, action, target_account_id, payload, occurred_at, previous_hash, row_hash,
              chain_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(admin)
    .bind(action)
    .bind(target)
    .bind(payload)
    .bind(at)
    .bind((!previous.is_empty()).then_some(&previous))
    .bind(hash.as_slice())
    .bind(CHAIN_VERSION)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What [`verify`] found.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    /// Chained rows checked.
    pub checked: u64,
    /// The first row whose hash, or link to the row before, is wrong.
    pub broken_at: Option<i64>,
}

type ChainRow = (
    i64,
    Uuid,
    String,
    Option<Uuid>,
    Value,
    OffsetDateTime,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i16,
);

/// Walks the chain from where the retention job last cut it (its anchor), or
/// from the first row ever.
pub async fn verify(pool: &PgPool) -> AppResult<Verification> {
    let anchor: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT through_id, through_hash FROM admin_audit_anchor")
            .fetch_optional(pool)
            .await?;
    let (mut after, previous) = anchor.unwrap_or_default();
    let mut expected_previous = previous;
    let mut checked = 0u64;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(
            "SELECT id, admin_account_id, action, target_account_id, payload, occurred_at,
                    previous_hash, row_hash, chain_version
               FROM admin_audit_log
              WHERE id > $1
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(VERIFY_PAGE)
        .fetch_all(pool)
        .await?;
        if rows.is_empty() {
            return Ok(Verification {
                checked,
                broken_at: None,
            });
        }
        after = rows.last().map(|row| row.0).unwrap_or(after);
        if let Some(broken) = check(rows, &mut expected_previous, &mut checked) {
            return Ok(Verification {
                checked,
                broken_at: Some(broken),
            });
        }
    }
}

/// Checks `rows` (in order) against the chain so far (`expected_previous`:
/// the hash the next row must name, empty before the first row): the first
/// row whose link, or own hash, is wrong, or that has none.
fn check(rows: Vec<ChainRow>, expected_previous: &mut Vec<u8>, checked: &mut u64) -> Option<i64> {
    for (id, admin, action, target, payload, at, previous, stored, version) in rows {
        let previous = previous.unwrap_or_default();
        let (Some(stored), CHAIN_VERSION) = (stored, version) else {
            return Some(id);
        };
        let hash = row_hash(&previous, admin, &action, target, micros(at), &payload);
        if *expected_previous != previous || hash.as_slice() != stored.as_slice() {
            return Some(id);
        }
        *checked += 1;
        *expected_previous = stored;
    }
    None
}

/// The retention job's part: rows older than `days` go, from the oldest end
/// (by id, which is time order), and the anchor moves to the last one gone.
/// Returns how many. As the owner (only it writes the anchor).
pub async fn prune(pool: &PgPool, days: i64) -> AppResult<u64> {
    let mut tx = pool.begin().await?;
    // In the chain's order: no row is added while the anchor moves.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHAIN_LOCK)
        .execute(&mut *tx)
        .await?;
    let through: Option<(i64, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT id, row_hash FROM admin_audit_log
          WHERE id = (SELECT max(id) FROM admin_audit_log
                       WHERE occurred_at < now() - make_interval(days => $1::int)
                         -- A legal hold keeps its account's rows (A5), and the
                         -- chain stays whole: nothing from the oldest held row on.
                         AND id < COALESCE((SELECT min(a.id) FROM admin_audit_log a
                                              JOIN accounts u ON u.id = a.target_account_id
                                             WHERE u.legal_hold_reference IS NOT NULL),
                                           9223372036854775807))",
    )
    .bind(days)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((through_id, Some(through_hash))) = through else {
        return Ok(0);
    };
    let deleted = sqlx::query("DELETE FROM admin_audit_log WHERE id <= $1")
        .bind(through_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(
        "INSERT INTO admin_audit_anchor (through_id, through_hash) VALUES ($1, $2)
         ON CONFLICT (only_row) DO UPDATE SET through_id = $1, through_hash = $2",
    )
    .bind(through_id)
    .bind(&through_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Three chained rows, as `append` makes them.
    fn chain() -> Vec<ChainRow> {
        let admin = Uuid::from_u128(1);
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut previous = Vec::new();
        (1..=3)
            .map(|id| {
                let payload = json!({ "n": id });
                let hash = row_hash(
                    &previous,
                    admin,
                    "account.update",
                    None,
                    micros(at),
                    &payload,
                );
                let row = (
                    id,
                    admin,
                    "account.update".to_owned(),
                    None,
                    payload,
                    at,
                    (!previous.is_empty()).then(|| previous.clone()),
                    Some(hash.to_vec()),
                    CHAIN_VERSION,
                );
                previous = hash.to_vec();
                row
            })
            .collect()
    }

    #[test]
    fn a_changed_removed_or_unhashed_row_breaks_the_chain() {
        let (mut expected, mut checked) = (Vec::new(), 0);
        assert_eq!(check(chain(), &mut expected, &mut checked), None);
        assert_eq!(checked, 3);
        // The oldest row gone by retention, its hash the anchor: the rest holds.
        let rows = chain();
        let mut anchor = rows[0].7.clone().unwrap();
        assert_eq!(check(rows[1..].to_vec(), &mut anchor, &mut 0), None);
        // Gone beyond the anchor (two rows, the anchor naming one): broken.
        let mut anchor = rows[0].7.clone().unwrap();
        assert_eq!(check(rows[2..].to_vec(), &mut anchor, &mut 0), Some(3));
        // Without an anchor the first row must be the chain's first.
        assert_eq!(check(rows[1..].to_vec(), &mut Vec::new(), &mut 0), Some(2));
        // A payload changed in place.
        let mut changed = chain();
        changed[1].4 = json!({ "n": 9 });
        assert_eq!(check(changed, &mut Vec::new(), &mut 0), Some(2));
        // A row removed from the middle.
        let mut removed = chain();
        removed.remove(1);
        assert_eq!(check(removed, &mut Vec::new(), &mut 0), Some(3));
        // A row added without hashes.
        let mut unhashed = chain();
        unhashed[2].7 = None;
        assert_eq!(check(unhashed, &mut Vec::new(), &mut 0), Some(3));
        // A row of a version this server can't check.
        let mut unknown = chain();
        unknown[1].8 = 2;
        assert_eq!(check(unknown, &mut Vec::new(), &mut 0), Some(2));
    }

    /// Retention empties the log (a quiet spell longer than it keeps rows):
    /// the next action chains from the anchor, and the chain still holds.
    #[tokio::test]
    async fn live_an_emptied_log_chains_on_from_its_anchor() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let admin = Uuid::nil();
        append(
            &pool,
            admin,
            AdminAction::AccountUpdate,
            None,
            &json!({ "changes": 1 }),
        )
        .await
        .unwrap();
        // Everything older than now goes: the table is empty, the anchor set.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        prune(&pool, 0).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_audit_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
        append(
            &pool,
            admin,
            AdminAction::AccountUpdate,
            None,
            &json!({ "changes": 2 }),
        )
        .await
        .unwrap();
        let verified = verify(&pool).await.unwrap();
        assert_eq!(verified.broken_at, None);
        assert_eq!(verified.checked, 1);
    }

    /// One table names every action: each string unique and `area.verb`
    /// (two camelCase segments), each payload key camelCase, none a username.
    #[test]
    fn every_action_is_area_verb_with_camel_case_keys() {
        fn camel(segment: &str) -> bool {
            let mut bytes = segment.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_lowercase())
                && bytes.all(|b| b.is_ascii_alphabetic())
        }
        let mut seen = std::collections::BTreeSet::new();
        for action in AdminAction::ALL {
            let name = action.as_str();
            assert!(seen.insert(name), "{name} is listed twice");
            let (area, verb) = name.split_once('.').expect("area.verb");
            assert!(
                camel(area) && camel(verb),
                "{name} is not area.verb in camelCase"
            );
            let mut keys = std::collections::BTreeSet::new();
            for key in action.payload_keys() {
                assert!(camel(key), "{name}: payload key {key} is not camelCase");
                assert!(
                    keys.insert(key),
                    "{name}: payload key {key} is listed twice"
                );
                assert_ne!(*key, "username", "{name}: payloads name accounts by id");
            }
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "not in its list")]
    fn a_payload_key_outside_the_list_is_refused() {
        debug_check_payload(AdminAction::AccountDelete, &json!({ "username": "x" }));
    }

    #[test]
    fn a_payload_takes_integers_only() {
        assert!(!has_fraction(
            &json!({ "a": [1, -2, { "b": 3 }], "c": "1.5" })
        ));
        assert!(has_fraction(&json!({ "a": [1, { "b": 1.5 }] })));
        assert!(has_fraction(&json!(100.0)));
    }

    #[test]
    fn the_hash_covers_every_field_and_ignores_key_order() {
        let admin = Uuid::from_u128(1);
        let base = row_hash(
            &[],
            admin,
            "account.delete",
            None,
            10,
            &json!({ "a": 1, "b": [1, 2] }),
        );
        assert_eq!(
            base,
            row_hash(
                &[],
                admin,
                "account.delete",
                None,
                10,
                &json!({ "b": [1, 2], "a": 1 })
            )
        );
        for other in [
            row_hash(
                &[7],
                admin,
                "account.delete",
                None,
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                Uuid::from_u128(2),
                "account.delete",
                None,
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "account.resetKeys",
                None,
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "account.delete",
                Some(admin),
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "account.delete",
                None,
                11,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "account.delete",
                None,
                10,
                &json!({ "a": 2, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "account.delete",
                None,
                10,
                &json!({ "a": 1, "b": [2, 1] }),
            ),
        ] {
            assert_ne!(base, other);
        }
    }
}
