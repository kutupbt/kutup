//! Online signing keys a server makes for itself when its operator configures
//! none: its federation identity key, its MLS ordering control key, and the
//! key that signs shared mailboxes' key lists. Each
//! is a 32-byte Ed25519 seed, made once and kept in `server_generated_keys`;
//! every instance uses the stored copy. Configured keys take precedence and
//! never pass through here.

use rand::RngCore as _;
use sqlx::PgPool;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratedKey {
    FederationIdentity,
    MlsControl,
    /// Signs shared mailboxes' key lists (docs/plans/mail-groups.md).
    MailGroupAuthority,
}

impl GeneratedKey {
    fn purpose(self) -> &'static str {
        match self {
            Self::FederationIdentity => "federation-identity",
            Self::MlsControl => "mls-control",
            Self::MailGroupAuthority => "mail-group-authority",
        }
    }
}

/// The stored seed for `key`, made now if there is none yet.
pub(crate) async fn load_or_create(pool: &PgPool, key: GeneratedKey) -> anyhow::Result<[u8; 32]> {
    if let Some(seed) = load(pool, key).await? {
        return Ok(seed);
    }
    let mut created = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut created);
    sqlx::query("INSERT INTO server_generated_keys (purpose, private_key) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(key.purpose())
        .bind(created.to_vec())
        .execute(pool)
        .await?;
    created.fill(0);
    // Another instance may have won the race: use whatever is stored.
    load(pool, key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("generated {} key was not stored", key.purpose()))
}

async fn load(pool: &PgPool, key: GeneratedKey) -> anyhow::Result<Option<[u8; 32]>> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT private_key FROM server_generated_keys WHERE purpose = $1")
            .bind(key.purpose())
            .fetch_optional(pool)
            .await?;
    stored
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored {} key is not 32 bytes", key.purpose()))
        })
        .transpose()
}
