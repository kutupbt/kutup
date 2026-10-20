//! The shared DKIM keys' rotation (docs/plans/mail-custom-domains.md §4).
//! Every custom domain's three CNAMEs point at `<id>.kutupN._dk.<server>`;
//! in v1 the operator serves one wildcard TXT per selector there, so a new
//! key signs only once its TXT is published:
//! - a new key is made `pending` on an idle selector, and the admin console
//!   shows the TXT to publish;
//! - once DNS has shown it for [`PUBLISHED_FOR`], it becomes `active` and
//!   the one before goes `retiring`;
//! - a retiring key stays published for [`RETIRING_FOR`] (mail in flight),
//!   then is `retired` and its selector idle again;
//! - an active key older than [`ROTATE_AFTER`] gets a successor.
//!
//! [`plan`] is pure; the sweep runs its steps.

use super::records::DKIM_SELECTORS;

pub const PUBLISHED_FOR: i64 = 24 * 3600;
pub const RETIRING_FOR: i64 = 7 * 24 * 3600;
pub const ROTATE_AFTER: i64 = 180 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Pending,
    Active,
    Retiring,
    Retired,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Pending => "pending",
            KeyState::Active => "active",
            KeyState::Retiring => "retiring",
            KeyState::Retired => "retired",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => KeyState::Pending,
            "active" => KeyState::Active,
            "retiring" => KeyState::Retiring,
            "retired" => KeyState::Retired,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub id: uuid::Uuid,
    pub selector: String,
    pub state: KeyState,
    /// Since when DNS has shown its TXT (pending keys).
    pub published_since: Option<i64>,
    pub activated_at: Option<i64>,
    pub retiring_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Make a key on this idle selector, pending.
    Create {
        selector: String,
    },
    Activate {
        id: uuid::Uuid,
    },
    Retire {
        id: uuid::Uuid,
    },
    Retired {
        id: uuid::Uuid,
    },
}

fn idle(keys: &[Key]) -> Option<String> {
    DKIM_SELECTORS
        .iter()
        .find(|selector| {
            !keys
                .iter()
                .any(|k| k.selector == **selector && k.state != KeyState::Retired)
        })
        .map(|s| s.to_string())
}

/// The steps due at `now`, in order.
pub fn plan(keys: &[Key], now: i64) -> Vec<Step> {
    let mut steps = Vec::new();
    let live = |state| keys.iter().filter(move |k| k.state == state);
    for key in live(KeyState::Retiring) {
        if key.retiring_at.is_some_and(|at| now - at >= RETIRING_FOR) {
            steps.push(Step::Retired { id: key.id });
        }
    }
    let pending = live(KeyState::Pending).next();
    let active = live(KeyState::Active).next();
    if let Some(pending) = pending {
        if pending
            .published_since
            .is_some_and(|since| now - since >= PUBLISHED_FOR)
        {
            steps.push(Step::Activate { id: pending.id });
            if let Some(active) = active {
                steps.push(Step::Retire { id: active.id });
            }
        }
        return steps;
    }
    let due = match active {
        None => true,
        Some(active) => active
            .activated_at
            .is_some_and(|at| now - at >= ROTATE_AFTER),
    };
    if due {
        // With every selector busy (a retiring key still published), the
        // successor waits for one to go idle.
        let retired_now: Vec<uuid::Uuid> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Retired { id } => Some(*id),
                _ => None,
            })
            .collect();
        let after: Vec<Key> = keys
            .iter()
            .cloned()
            .map(|mut k| {
                if retired_now.contains(&k.id) {
                    k.state = KeyState::Retired;
                }
                k
            })
            .collect();
        if let Some(selector) = idle(&after) {
            steps.push(Step::Create { selector });
        }
    }
    steps
}

/// The name a pending key's TXT is checked at: any name under the
/// selector's wildcard.
pub fn probe_name(selector: &str, server_name: &str) -> String {
    format!("check.{selector}._dk.{server_name}")
}

/// A key as stored.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredKey {
    pub id: uuid::Uuid,
    pub selector: String,
    pub state: String,
    pub server_key_id: i32,
    pub private_sealed: Vec<u8>,
    pub public_spki: Vec<u8>,
    pub published_since: Option<time::OffsetDateTime>,
    pub activated_at: Option<time::OffsetDateTime>,
    pub retiring_at: Option<time::OffsetDateTime>,
}

impl StoredKey {
    pub fn key(&self) -> Option<Key> {
        let secs = |at: Option<time::OffsetDateTime>| at.map(|at| at.unix_timestamp());
        Some(Key {
            id: self.id,
            selector: self.selector.clone(),
            state: KeyState::parse(&self.state)?,
            published_since: secs(self.published_since),
            activated_at: secs(self.activated_at),
            retiring_at: secs(self.retiring_at),
        })
    }

    /// The TXT the operator publishes for it.
    pub fn txt(&self) -> String {
        kutup_crypto::dkim_key::txt_record(&self.public_spki)
    }
}

pub async fn keys(pool: &sqlx::PgPool) -> Result<Vec<StoredKey>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, selector, state, server_key_id, private_sealed, public_spki,
                published_since, activated_at, retiring_at
           FROM mail_dkim_keys WHERE state <> 'retired' ORDER BY created_at",
    )
    .fetch_all(pool)
    .await
}

/// One rotation pass: pending keys' TXT checked in DNS, then [`plan`]'s
/// steps. A new key is made off the async threads (RSA generation).
pub async fn rotate(
    pool: &sqlx::PgPool,
    resolver: &dyn super::records::Resolver,
    server_name: &str,
    sealing: &crate::opaque_setup::OpaqueSetupKeys,
) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    for key in keys(pool).await? {
        if key.state != KeyState::Pending.as_str() {
            continue;
        }
        let published = match resolver.txt(&probe_name(&key.selector, server_name)).await {
            super::records::Lookup::Found(records) => Some(records.iter().any(|r| *r == key.txt())),
            super::records::Lookup::None => Some(false),
            super::records::Lookup::Unknown => None,
        };
        match published {
            Some(true) if key.published_since.is_none() => {
                sqlx::query("UPDATE mail_dkim_keys SET published_since = now() WHERE id = $1")
                    .bind(key.id)
                    .execute(pool)
                    .await?;
            }
            Some(false) if key.published_since.is_some() => {
                sqlx::query("UPDATE mail_dkim_keys SET published_since = NULL WHERE id = $1")
                    .bind(key.id)
                    .execute(pool)
                    .await?;
            }
            _ => {}
        }
    }
    let stored = keys(pool).await?;
    let current: Vec<Key> = stored.iter().filter_map(StoredKey::key).collect();
    for step in plan(&current, now.unix_timestamp()) {
        match step {
            Step::Create { selector } => {
                let (server_key_id, server_key) = sealing
                    .current()
                    .ok_or_else(|| anyhow::anyhow!("no MAIL_DKIM_KEYS"))?;
                let server_key = *server_key;
                let id = uuid::Uuid::new_v4();
                let for_selector = selector.clone();
                let (sealed, public) = tokio::task::spawn_blocking(move || {
                    let key = kutup_crypto::dkim_key::generate()?;
                    let sealed = kutup_crypto::dkim_key::seal(
                        &server_key,
                        server_key_id,
                        id.as_bytes(),
                        &for_selector,
                        &key.private_pkcs8,
                    )?;
                    Ok::<_, kutup_crypto::error::CryptoError>((sealed, key.public_spki))
                })
                .await??;
                sqlx::query(
                    "INSERT INTO mail_dkim_keys (id, selector, state, server_key_id, private_sealed, public_spki)
                     VALUES ($1, $2, 'pending', $3, $4, $5)",
                )
                .bind(id)
                .bind(&selector)
                .bind(i32::from(server_key_id))
                .bind(sealed)
                .bind(public)
                .execute(pool)
                .await?;
                tracing::info!(selector = %selector, "mail: a new DKIM key waits for its TXT to be published");
            }
            Step::Activate { id } => {
                // The active one retires in the same step (planned next);
                // done as one statement pair in a transaction.
                let mut tx = pool.begin().await?;
                sqlx::query(
                    "UPDATE mail_dkim_keys SET state = 'retiring', retiring_at = now() WHERE state = 'active'",
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "UPDATE mail_dkim_keys SET state = 'active', activated_at = now() WHERE id = $1",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
            }
            Step::Retire { .. } => {}
            Step::Retired { id } => {
                sqlx::query("UPDATE mail_dkim_keys SET state = 'retired' WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
        }
    }
    Ok(())
}

/// The active key's selector, PEM and id, opened.
pub async fn active(
    pool: &sqlx::PgPool,
    sealing: &crate::opaque_setup::OpaqueSetupKeys,
) -> anyhow::Result<Option<(String, zeroize::Zeroizing<String>, String)>> {
    let Some(key) = keys(pool)
        .await?
        .into_iter()
        .find(|k| k.state == KeyState::Active.as_str())
    else {
        return Ok(None);
    };
    let server_key_id = u16::try_from(key.server_key_id)?;
    let server_key = sealing
        .get(server_key_id)
        .ok_or_else(|| anyhow::anyhow!("MAIL_DKIM_KEYS lacks key {server_key_id}"))?;
    let private = kutup_crypto::dkim_key::open(
        server_key,
        server_key_id,
        key.id.as_bytes(),
        &key.selector,
        &key.private_sealed,
    )?;
    let pem = kutup_crypto::dkim_key::private_pem(&private)?;
    Ok(Some((key.selector, pem, key.id.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 3600;

    fn key(selector: &str, state: KeyState) -> Key {
        Key {
            id: uuid::Uuid::new_v4(),
            selector: selector.into(),
            state,
            published_since: None,
            activated_at: None,
            retiring_at: None,
        }
    }

    #[test]
    fn the_first_key_is_made_and_waits_for_dns() {
        assert_eq!(
            plan(&[], 0),
            vec![Step::Create {
                selector: "kutup1".into()
            }]
        );
        let pending = key("kutup1", KeyState::Pending);
        assert!(
            plan(std::slice::from_ref(&pending), 10 * DAY).is_empty(),
            "not published yet"
        );
        let seen = Key {
            published_since: Some(0),
            ..pending
        };
        assert!(
            plan(std::slice::from_ref(&seen), DAY - 1).is_empty(),
            "not a day yet"
        );
        assert_eq!(
            plan(std::slice::from_ref(&seen), DAY),
            vec![Step::Activate { id: seen.id }]
        );
    }

    #[test]
    fn a_key_rotates_through_the_selectors() {
        let active = Key {
            activated_at: Some(0),
            ..key("kutup1", KeyState::Active)
        };
        assert!(plan(std::slice::from_ref(&active), ROTATE_AFTER - 1).is_empty());
        assert_eq!(
            plan(std::slice::from_ref(&active), ROTATE_AFTER),
            vec![Step::Create {
                selector: "kutup2".into()
            }]
        );
        let next = Key {
            published_since: Some(ROTATE_AFTER),
            ..key("kutup2", KeyState::Pending)
        };
        assert_eq!(
            plan(&[active.clone(), next.clone()], ROTATE_AFTER + DAY),
            vec![
                Step::Activate { id: next.id },
                Step::Retire { id: active.id }
            ]
        );
        let retiring = Key {
            state: KeyState::Retiring,
            retiring_at: Some(0),
            ..active
        };
        assert_eq!(
            plan(std::slice::from_ref(&retiring), RETIRING_FOR - 1),
            vec![Step::Create {
                selector: "kutup2".into()
            }]
        );
        assert_eq!(
            plan(std::slice::from_ref(&retiring), RETIRING_FOR),
            vec![
                Step::Retired { id: retiring.id },
                Step::Create {
                    selector: "kutup1".into()
                }
            ]
        );
    }

    #[test]
    fn with_every_selector_busy_the_successor_waits() {
        let old = Key {
            activated_at: Some(0),
            ..key("kutup1", KeyState::Active)
        };
        let a = Key {
            retiring_at: Some(ROTATE_AFTER),
            ..key("kutup2", KeyState::Retiring)
        };
        let b = Key {
            retiring_at: Some(ROTATE_AFTER),
            ..key("kutup3", KeyState::Retiring)
        };
        assert!(plan(&[old.clone(), a.clone(), b.clone()], ROTATE_AFTER + 1).is_empty());
        assert_eq!(
            plan(&[old, a.clone(), b.clone()], ROTATE_AFTER + RETIRING_FOR),
            vec![
                Step::Retired { id: a.id },
                Step::Retired { id: b.id },
                Step::Create {
                    selector: "kutup2".into()
                }
            ]
        );
    }
}
