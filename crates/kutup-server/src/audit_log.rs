//! The admin log (docs/plans/server-personal-data.md, A8): what administrators
//! did, append-only for the server and hash-chained.
//!
//! The table has the same columns as `account_security_events`
//! (docs/plans/w7-schema.md §6): `kind` (an [`AdminAction`]), `actor_kind`
//! (`admin`, or `job` for the server's own steps) with `actor_account_id`
//! (the admin), `subject_account_id` (the account acted on), `at`, `payload`,
//! `count` (always 1 here) and the chain's `chain_version`, `previous_hash`
//! and `row_hash`.
//!
//! Each row stores the previous row's hash and its own:
//! `row_hash = SHA-256(domain ‖ previous_hash ‖ the row)`, the row being its
//! actor kind, actor, kind, subject, time, payload (keys sorted, so the hash
//! recomputes from what Postgres stores) and count. The first row's
//! `previous_hash` is 32 zero bytes (the genesis), so every row has both
//! hashes. Changing, removing or reordering a row breaks the chain from
//! there, which [`verify`] finds. The retention job
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

/// Who did an admin log row's action: an administrator, or the server itself
/// (a job or an operator's command on the server; the payload's `actorType`
/// says which).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// The administrator's account.
    Admin(Uuid),
    /// The server: no account.
    Job,
}

impl Actor {
    /// The row's `actor_kind`.
    pub const fn kind(self) -> &'static str {
        match self {
            Actor::Admin(_) => "admin",
            Actor::Job => "job",
        }
    }

    /// The row's `actor_account_id`.
    pub const fn account(self) -> Option<Uuid> {
        match self {
            Actor::Admin(account) => Some(account),
            Actor::Job => None,
        }
    }

    /// From the row's `actor_kind` and `actor_account_id`: none for a pair
    /// the table doesn't allow.
    fn from_row(kind: &str, account: Option<Uuid>) -> Option<Actor> {
        match (kind, account) {
            ("admin", Some(account)) => Some(Actor::Admin(account)),
            ("job", None) => Some(Actor::Job),
            _ => None,
        }
    }
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

const CHAIN_DOMAIN: &[u8] = kutup_crypto::labels::SERVER_ADMIN_AUDIT_CHAIN_V2;
/// The version [`row_hash`] is (`admin_audit_log.chain_version`): a row of
/// another version is one this server can't check, and reads as broken.
const CHAIN_VERSION: i16 = 1;
/// The first row's `previous_hash`.
const GENESIS: [u8; 32] = [0; 32];
/// An admin log row's `count`: each action is its own row.
const COUNT: i32 = 1;
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

/// Writes an optional account: a 0 byte for none, else 1 and its 16 bytes.
fn update_account(hasher: &mut Hasher, account: Option<Uuid>) {
    if let Some(account) = account {
        hasher.update([1u8]);
        hasher.update(account.as_bytes());
    } else {
        hasher.update([0u8]);
    }
}

/// Writes a string with its length (u32, big-endian) before it.
fn update_text(hasher: &mut Hasher, text: &str) {
    hasher.update((text.len() as u32).to_be_bytes());
    hasher.update(text.as_bytes());
}

/// `SHA-256(domain ‖ len ‖ previous ‖ len ‖ actor_kind ‖ actor ‖ len ‖ kind ‖
/// subject ‖ at (i128 µs) ‖ len ‖ canonical payload ‖ count (i32))`, every
/// length a big-endian u32 and every account 0, or 1 and its 16 bytes.
fn row_hash(
    previous: &[u8],
    actor: Actor,
    kind: &str,
    subject: Option<Uuid>,
    at_micros: i128,
    payload: &Value,
    count: i32,
) -> [u8; 32] {
    let mut hasher = Hasher::new(Suite::V1);
    hasher.update(CHAIN_DOMAIN);
    hasher.update((previous.len() as u32).to_be_bytes());
    hasher.update(previous);
    update_text(&mut hasher, actor.kind());
    update_account(&mut hasher, actor.account());
    update_text(&mut hasher, kind);
    update_account(&mut hasher, subject);
    hasher.update(at_micros.to_be_bytes());
    update_text(&mut hasher, &canonical(payload));
    hasher.update(count.to_be_bytes());
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

/// Appends one admin action, chained to the newest row; `subject` is the
/// account acted on.
pub async fn append(
    pool: &PgPool,
    actor: Actor,
    action: AdminAction,
    subject: Option<Uuid>,
    payload: &Value,
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    append_in(&mut tx, actor, action, subject, payload).await?;
    tx.commit().await?;
    Ok(())
}

/// [`append`] in the caller's transaction, with the action it records: the
/// chain's lock is held until that commits.
pub async fn append_in(
    conn: &mut sqlx::PgConnection,
    actor: Actor,
    action: AdminAction,
    subject: Option<Uuid>,
    payload: &Value,
) -> sqlx::Result<()> {
    debug_check_payload(action, payload);
    let kind = action.as_str();
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
    // (the last row it deleted), which verification starts from; else the
    // genesis.
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
    .unwrap_or_else(|| GENESIS.to_vec());
    let hash = row_hash(&previous, actor, kind, subject, micros(at), payload, COUNT);
    sqlx::query(
        "INSERT INTO admin_audit_log
             (kind, actor_kind, actor_account_id, subject_account_id, at, payload, count,
              chain_version, previous_hash, row_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(kind)
    .bind(actor.kind())
    .bind(actor.account())
    .bind(subject)
    .bind(at)
    .bind(payload)
    .bind(COUNT)
    .bind(CHAIN_VERSION)
    .bind(&previous)
    .bind(hash.as_slice())
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

/// One row as [`check`] reads it.
#[derive(Debug, Clone, sqlx::FromRow)]
struct ChainRow {
    id: i64,
    kind: String,
    actor_kind: String,
    actor_account_id: Option<Uuid>,
    subject_account_id: Option<Uuid>,
    at: OffsetDateTime,
    payload: Value,
    count: i32,
    chain_version: i16,
    previous_hash: Option<Vec<u8>>,
    row_hash: Option<Vec<u8>>,
}

/// Walks the chain from where the retention job last cut it (its anchor), or
/// from the first row ever.
pub async fn verify(pool: &PgPool) -> AppResult<Verification> {
    let anchor: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT through_id, through_hash FROM admin_audit_anchor")
            .fetch_optional(pool)
            .await?;
    let (mut after, mut expected_previous) = anchor.unwrap_or((0, GENESIS.to_vec()));
    let mut checked = 0u64;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(
            "SELECT id, kind, actor_kind, actor_account_id, subject_account_id, at, payload, count,
                    chain_version, previous_hash, row_hash
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
        after = rows.last().map(|row| row.id).unwrap_or(after);
        if let Some(broken) = check(rows, &mut expected_previous, &mut checked) {
            return Ok(Verification {
                checked,
                broken_at: Some(broken),
            });
        }
    }
}

/// Checks `rows` (in order) against the chain so far (`expected_previous`:
/// the hash the next row must name, the genesis before the first row): the
/// first row whose link, or own hash, is wrong, or that has none.
fn check(rows: Vec<ChainRow>, expected_previous: &mut Vec<u8>, checked: &mut u64) -> Option<i64> {
    for row in rows {
        let id = row.id;
        let (Some(previous), Some(stored), CHAIN_VERSION) =
            (row.previous_hash, row.row_hash, row.chain_version)
        else {
            return Some(id);
        };
        let Some(actor) = Actor::from_row(&row.actor_kind, row.actor_account_id) else {
            return Some(id);
        };
        let hash = row_hash(
            &previous,
            actor,
            &row.kind,
            row.subject_account_id,
            micros(row.at),
            &row.payload,
            row.count,
        );
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
                       WHERE at < now() - make_interval(days => $1::int)
                         -- A legal hold keeps its account's rows (A5), and the
                         -- chain stays whole: nothing from the oldest held row on.
                         AND id < COALESCE((SELECT min(a.id) FROM admin_audit_log a
                                              JOIN accounts u ON u.id = a.subject_account_id
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

    /// Three chained rows, as `append` makes them: an admin's, the server's,
    /// an admin's.
    fn chain() -> Vec<ChainRow> {
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut previous = GENESIS.to_vec();
        (1..=3)
            .map(|id| {
                let actor = if id == 2 {
                    Actor::Job
                } else {
                    Actor::Admin(Uuid::from_u128(1))
                };
                let subject = Some(Uuid::from_u128(5));
                let payload = json!({ "n": id });
                let hash = row_hash(
                    &previous,
                    actor,
                    "account.update",
                    subject,
                    micros(at),
                    &payload,
                    COUNT,
                );
                let row = ChainRow {
                    id,
                    kind: "account.update".to_owned(),
                    actor_kind: actor.kind().to_owned(),
                    actor_account_id: actor.account(),
                    subject_account_id: subject,
                    at,
                    payload,
                    count: COUNT,
                    chain_version: CHAIN_VERSION,
                    previous_hash: Some(previous.clone()),
                    row_hash: Some(hash.to_vec()),
                };
                previous = hash.to_vec();
                row
            })
            .collect()
    }

    fn genesis() -> Vec<u8> {
        GENESIS.to_vec()
    }

    #[test]
    fn a_changed_removed_or_unhashed_row_breaks_the_chain() {
        let (mut expected, mut checked) = (genesis(), 0);
        assert_eq!(check(chain(), &mut expected, &mut checked), None);
        assert_eq!(checked, 3);
        // The oldest row gone by retention, its hash the anchor: the rest holds.
        let rows = chain();
        let mut anchor = rows[0].row_hash.clone().unwrap();
        assert_eq!(check(rows[1..].to_vec(), &mut anchor, &mut 0), None);
        // Gone beyond the anchor (two rows, the anchor naming one): broken.
        let mut anchor = rows[0].row_hash.clone().unwrap();
        assert_eq!(check(rows[2..].to_vec(), &mut anchor, &mut 0), Some(3));
        // Without an anchor the first row must be the chain's first.
        assert_eq!(check(rows[1..].to_vec(), &mut genesis(), &mut 0), Some(2));
        // A payload changed in place.
        let mut changed = chain();
        changed[1].payload = json!({ "n": 9 });
        assert_eq!(check(changed, &mut genesis(), &mut 0), Some(2));
        // The actor changed: the server's row made an admin's.
        let mut changed = chain();
        changed[1].actor_kind = "admin".to_owned();
        changed[1].actor_account_id = Some(Uuid::from_u128(1));
        assert_eq!(check(changed, &mut genesis(), &mut 0), Some(2));
        // The subject dropped.
        let mut changed = chain();
        changed[2].subject_account_id = None;
        assert_eq!(check(changed, &mut genesis(), &mut 0), Some(3));
        // An actor pair the table doesn't allow.
        let mut changed = chain();
        changed[1].actor_kind = "peer".to_owned();
        assert_eq!(check(changed, &mut genesis(), &mut 0), Some(2));
        // A row removed from the middle.
        let mut removed = chain();
        removed.remove(1);
        assert_eq!(check(removed, &mut genesis(), &mut 0), Some(3));
        // A row added without hashes.
        let mut unhashed = chain();
        unhashed[2].row_hash = None;
        assert_eq!(check(unhashed, &mut genesis(), &mut 0), Some(3));
        let mut unlinked = chain();
        unlinked[0].previous_hash = None;
        assert_eq!(check(unlinked, &mut genesis(), &mut 0), Some(1));
        // A row of a version this server can't check.
        let mut unknown = chain();
        unknown[1].chain_version = 2;
        assert_eq!(check(unknown, &mut genesis(), &mut 0), Some(2));
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
        let admin = Actor::Job;
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
        let admin = Actor::Admin(Uuid::from_u128(1));
        let payload = json!({ "a": 1, "b": [1, 2] });
        let hash = |previous: &[u8], actor, kind, subject, at, payload: &Value, count| {
            row_hash(previous, actor, kind, subject, at, payload, count)
        };
        let base = hash(&GENESIS, admin, "account.delete", None, 10, &payload, 1);
        assert_eq!(
            base,
            hash(
                &GENESIS,
                admin,
                "account.delete",
                None,
                10,
                &json!({ "b": [1, 2], "a": 1 }),
                1
            )
        );
        for other in [
            hash(&[7; 32], admin, "account.delete", None, 10, &payload, 1),
            hash(
                &GENESIS,
                Actor::Admin(Uuid::from_u128(2)),
                "account.delete",
                None,
                10,
                &payload,
                1,
            ),
            hash(
                &GENESIS,
                Actor::Job,
                "account.delete",
                None,
                10,
                &payload,
                1,
            ),
            hash(&GENESIS, admin, "account.resetKeys", None, 10, &payload, 1),
            hash(
                &GENESIS,
                admin,
                "account.delete",
                Some(Uuid::from_u128(1)),
                10,
                &payload,
                1,
            ),
            hash(&GENESIS, admin, "account.delete", None, 11, &payload, 1),
            hash(
                &GENESIS,
                admin,
                "account.delete",
                None,
                10,
                &json!({ "a": 2, "b": [1, 2] }),
                1,
            ),
            hash(
                &GENESIS,
                admin,
                "account.delete",
                None,
                10,
                &json!({ "a": 1, "b": [2, 1] }),
                1,
            ),
            hash(&GENESIS, admin, "account.delete", None, 10, &payload, 2),
        ] {
            assert_ne!(base, other);
        }
    }

    /// The hashed bytes, fixed: a change to what a row hashes shows here
    /// (and needs a new `chain_version`, once rows exist).
    #[test]
    fn the_hash_matches_its_vector() {
        let first = row_hash(
            &GENESIS,
            Actor::Admin(Uuid::from_u128(1)),
            "account.setLegalHold",
            Some(Uuid::from_u128(2)),
            1_800_000_000_000_000,
            &json!({ "reference": "case-1" }),
            1,
        );
        let second = row_hash(
            &first,
            Actor::Job,
            "federation.rotateIdentity",
            None,
            1_800_000_000_000_001,
            &json!({ "actorType": "operatorCommand", "sequence": 2 }),
            1,
        );
        assert_eq!(
            hex::encode(first),
            "ca78d723002a88934f97571962fa1a469a9cec8ecbc3a44fd50302c969ce11f4"
        );
        assert_eq!(
            hex::encode(second),
            "e31a4e699f627786f63f8fd76f8f0e073d4a468d413966be06f3c50d4647c491"
        );
    }
}
