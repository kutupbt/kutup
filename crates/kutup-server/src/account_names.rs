//! Account names (docs/plans/username-renames.md): one account per folded
//! name (`kutup_crypto::names::fold`, and `kutup_fold` in SQL, byte for byte),
//! names held for an account after a rename or a deletion until they are
//! freed, and the rename chains that say where a name went.
//!
//! Lookups come in two kinds:
//! - **who a name is** (keys, manifests, profiles, identities): only a
//!   current name answers; a held one is [`renamed`], with the chains, never
//!   another account's keys;
//! - **where a delivery goes** (Chat and MLS traffic): a held name still
//!   reaches its account (the delivery queries select through
//!   `account_names` by the folded name, any state), so nothing in flight is
//!   lost.
//!
//! Both fold the name first, so every spelling resolves alike, and the
//! federated paths use the same functions as the local ones.

use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The account whose current name `name` is, in any spelling.
pub async fn current<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    name: &str,
) -> AppResult<Option<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT n.user_id FROM account_names n JOIN users u ON u.id = n.user_id
          WHERE n.folded = kutup_fold($1) AND n.state = 'current' AND u.is_active",
    )
    .bind(name)
    .fetch_optional(executor)
    .await?
    .flatten())
}

/// The chains that name `address` (`local@server`), as lookups answer them:
/// `{ "version": 1, "chains": [...] }`, newest first. A reused name appears
/// in more than one incarnation's chain; `incarnation` keeps one.
pub async fn chains(
    pool: &sqlx::PgPool,
    address: &str,
    incarnation: Option<&str>,
) -> AppResult<Value> {
    let (local, server) = address.rsplit_once('@').unwrap_or((address, ""));
    type Row = (String, String, i32, String, String, Value, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "WITH named AS (
             SELECT DISTINCT incarnation_id FROM account_renames
              WHERE (kutup_fold(split_part(previous, '@', 1)) = kutup_fold($1)
                     AND lower(split_part(previous, '@', 2)) = lower($2))
                 OR (kutup_fold(split_part(current, '@', 1)) = kutup_fold($1)
                     AND lower(split_part(current, '@', 2)) = lower($2)))
         SELECT r.incarnation_id, r.authority_public_key, r.sequence, r.current,
                to_char(max(r.accepted_at) OVER (PARTITION BY r.incarnation_id),
                        'YYYY-MM-DD\"T\"HH24:MI:SS.US') AS latest,
                r.statement,
                (SELECT n.state FROM account_names n
                  WHERE n.folded = kutup_fold(split_part(r.current, '@', 1))
                    AND n.incarnation_id = r.incarnation_id)
           FROM account_renames r JOIN named USING (incarnation_id)
          WHERE $3::text IS NULL OR r.incarnation_id = $3
          ORDER BY latest DESC, r.incarnation_id, r.sequence",
    )
    .bind(local)
    .bind(server)
    .bind(incarnation)
    .fetch_all(pool)
    .await?;
    let mut chains: Vec<Value> = Vec::new();
    let mut last: Option<String> = None;
    for (incarnation_id, authority, _sequence, current, _latest, statement, state) in rows {
        if last.as_deref() != Some(incarnation_id.as_str()) {
            chains.push(json!({
                "incarnationId": incarnation_id,
                "authorityPublicKey": authority,
                "current": current,
                "state": "gone",
                "chain": [],
            }));
            last = Some(incarnation_id.clone());
        }
        let entry = chains.last_mut().expect("pushed above");
        entry["current"] = json!(current);
        entry["state"] = json!(state.as_deref().unwrap_or("gone"));
        entry["chain"]
            .as_array_mut()
            .expect("an array")
            .push(statement);
    }
    Ok(json!({ "version": 1, "chains": chains }))
}

/// The answer to a lookup of a name an account no longer goes by (held, or
/// freed and not taken but named in a chain): `409 renamed` with the chains.
/// `None` when the name is no one's old name.
pub async fn renamed(
    pool: &sqlx::PgPool,
    server_name: &str,
    name: &str,
) -> AppResult<Option<AppError>> {
    let address = format!("{name}@{server_name}");
    let found = chains(pool, &address, None).await?;
    if found["chains"].as_array().is_none_or(|c| c.is_empty()) {
        return Ok(None);
    }
    Ok(Some(
        AppError::conflict("this account goes by another name now").with_details(json!({
            "code": "renamed",
            "renames": found,
        })),
    ))
}

/// Why a name cannot be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Not 3–32 of `a-z 0-9 _ -`, or nothing left once folded.
    Invalid,
    /// Kept for the server (postmaster, abuse, …, the break-glass account).
    Reserved,
    /// Another account's, or a group's, in some spelling.
    Taken,
    /// Held for an account that left it (a rename or a deletion), until freed.
    Held,
}

impl Unavailable {
    pub fn reason(self) -> &'static str {
        match self {
            Unavailable::Invalid => "invalid",
            Unavailable::Reserved => "reserved",
            Unavailable::Taken => "taken",
            Unavailable::Held => "held",
        }
    }

    /// The refusal a write answers with.
    pub fn error(self) -> AppError {
        match self {
            Unavailable::Invalid => AppError::bad_request("a name has 3-32 of a-z, 0-9, _ and -"),
            Unavailable::Reserved => AppError::conflict("this name is reserved")
                .with_details(json!({ "code": "nameReserved" })),
            Unavailable::Taken | Unavailable::Held => AppError::conflict("this name is taken")
                .with_details(json!({ "code": "nameTaken" })),
        }
    }
}

/// What a name may be had as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Available {
    /// Nobody's, in any spelling.
    Free,
    /// One the asking account itself holds (its own old name): taking it back.
    TakeBack,
}

/// Whether `name` can be had: by a new account or group (`asking` none), or
/// by `asking` (its user id and incarnation) in a rename. One function for
/// registration, groups and renames, comparing folded forms across account
/// names (current and held) and every live mail address of this server.
pub async fn available(
    conn: &mut sqlx::PgConnection,
    server_name: &str,
    break_glass: &str,
    name: &str,
    asking: Option<(Uuid, &str)>,
) -> AppResult<Result<Available, Unavailable>> {
    let valid = (3..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    let folded = kutup_crypto::names::fold(name);
    if !valid || folded.is_empty() {
        return Ok(Err(Unavailable::Invalid));
    }
    let reserved = crate::mail::RESERVED_LOCAL_PARTS
        .iter()
        .any(|r| kutup_crypto::names::fold(r) == folded)
        || (!break_glass.is_empty() && kutup_crypto::names::fold(break_glass) == folded);
    if reserved {
        return Ok(Err(Unavailable::Reserved));
    }
    let held: Option<(Option<Uuid>, Option<String>, String)> = sqlx::query_as(
        "SELECT user_id, incarnation_id, state FROM account_names WHERE folded = $1",
    )
    .bind(&folded)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((user_id, incarnation, state)) = held {
        let own = asking
            .is_some_and(|(id, inc)| user_id == Some(id) && incarnation.as_deref() == Some(inc));
        return Ok(match (state.as_str(), own) {
            ("held", true) => Ok(Available::TakeBack),
            ("held", false) => Err(Unavailable::Held),
            _ => Err(Unavailable::Taken),
        });
    }
    let address = format!("{folded}@{}", server_name.to_ascii_lowercase());
    let addressed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_addresses WHERE folded = $1 AND state <> 'freed')
             OR EXISTS (SELECT 1 FROM mail_groups WHERE kutup_fold(split_part(address, '@', 1))
                                                       || '@' || lower(split_part(address, '@', 2)) = $1)",
    )
    .bind(&address)
    .fetch_one(&mut *conn)
    .await?;
    Ok(if addressed {
        Err(Unavailable::Taken)
    } else {
        Ok(Available::Free)
    })
}

/// Records `name` as `user_id`'s current name (a new account), in the
/// transaction that makes the account; `incarnation` once it has keys.
pub async fn claim(
    conn: &mut sqlx::PgConnection,
    name: &str,
    user_id: Uuid,
    incarnation: Option<&str>,
) -> AppResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO account_names (folded, name, user_id, incarnation_id, state)
         VALUES (kutup_fold($1), $1, $2, NULLIF($3, ''), 'current')
         ON CONFLICT DO NOTHING",
    )
    .bind(name)
    .bind(user_id)
    .bind(incarnation)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(Unavailable::Taken.error());
    }
    Ok(())
}

/// Sets the incarnation of `user_id`'s current name, when its keys are made
/// (first setup) or made again (an account reset keeps the name).
pub async fn set_incarnation(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    incarnation: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE account_names SET incarnation_id = $2
          WHERE user_id = $1 AND state = 'current'",
    )
    .bind(user_id)
    .bind(incarnation)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The hourly sweep: old addresses whose receiving ended are closed (mail to
/// them bounces), and names whose hold ended are freed: the name is anyone's
/// again, and its last address row becomes `freed` (kept, with its keys, for
/// the mail it received; holding the address no more).
pub async fn sweep(pool: &sqlx::PgPool) -> AppResult<(u64, u64)> {
    let closed = sqlx::query(
        "UPDATE mail_addresses SET state = 'closed'
          WHERE state = 'receiving' AND receive_until <= now()",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let mut tx = pool.begin().await?;
    let freed: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "DELETE FROM account_names WHERE state = 'held' AND free_at <= now()
         RETURNING folded, user_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (folded, user_id) in &freed {
        sqlx::query(
            "UPDATE mail_addresses SET state = 'freed', receive_until = NULL
              WHERE split_part(folded, '@', 1) = $1 AND user_id IS NOT DISTINCT FROM $2
                AND state IN ('receiving', 'closed')",
        )
        .bind(folded)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok((closed, freed.len() as u64))
}

/// `otherwise` for a lookup that found no current account, unless the name
/// is someone's old name: then `409 renamed` with the chains.
pub async fn renamed_or(
    pool: &sqlx::PgPool,
    server_name: &str,
    name: &str,
    otherwise: AppError,
) -> AppError {
    match renamed(pool, server_name, name).await {
        Ok(Some(renamed)) => renamed,
        Ok(None) => otherwise,
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sweep: an old address past its receiving is closed, a name past
    /// its hold is freed (gone from the names, its address row freed and no
    /// longer holding the address), and a name still held stays.
    #[tokio::test]
    async fn live_the_sweep_closes_and_frees_on_their_dates() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let user_id = Uuid::new_v4();
        let tag = &user_id.simple().to_string()[..10];
        let (current, closing, freeing) = (
            format!("cur{tag}"),
            format!("old_{tag}"),
            format!("gone{tag}"),
        );
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                drive_private_key_envelope, public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '', '')",
        )
        .bind(user_id)
        .bind(&current)
        .execute(&pool)
        .await
        .unwrap();
        for (name, state, receive, free) in [
            (&current, "current", None, None),
            (&closing, "held", Some("-1 hour"), Some("+30 days")),
            (&freeing, "held", Some("-2 days"), Some("-1 hour")),
        ] {
            sqlx::query(
                "INSERT INTO account_names (folded, name, user_id, state, receive_until, free_at)
                 VALUES (kutup_fold($1), $1, $2, $3, now() + $4::interval, now() + $5::interval)",
            )
            .bind(name)
            .bind(user_id)
            .bind(state)
            .bind(receive)
            .bind(free)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO mail_addresses (user_id, address, folded, state, receive_until)
                 VALUES ($1, $2 || '@sweep.test', kutup_fold($2) || '@sweep.test', $3,
                         now() + $4::interval)",
            )
            .bind(user_id)
            .bind(name)
            .bind(if state == "current" {
                "active"
            } else {
                "receiving"
            })
            .bind(receive)
            .execute(&pool)
            .await
            .unwrap();
        }
        sweep(&pool).await.unwrap();
        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT split_part(address, '@', 1), state FROM mail_addresses
              WHERE user_id = $1 ORDER BY address",
        )
        .bind(user_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        let state = |name: &str| {
            states
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, s)| s.clone())
                .unwrap()
        };
        assert_eq!(state(&current), "active");
        assert_eq!(state(&closing), "closed");
        assert_eq!(state(&freeing), "freed");
        let names: Vec<String> =
            sqlx::query_scalar("SELECT name FROM account_names WHERE user_id = $1 ORDER BY name")
                .bind(user_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        let mut expected = vec![current.clone(), closing.clone()];
        expected.sort();
        assert_eq!(names, expected);
        // The freed address no longer holds its spelling: another row may.
        sqlx::query(
            "INSERT INTO mail_addresses (user_id, address, folded)
             VALUES ($1, $2 || '@sweep.test', kutup_fold($2) || '@sweep.test')",
        )
        .bind(user_id)
        .bind(&freeing)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM account_names WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
