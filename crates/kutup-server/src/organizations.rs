//! Organizations, following Proton (docs/plans/organizations.md): a permanent
//! random id with members and roles, holding custom domains. O1 has the
//! organization of one (the first domain an account adds makes it its
//! owner) and the rule for who manages an organization's domains; members,
//! invitations and the organization key come with later slices.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// A member's role (`organization_members.role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "owner" => Role::Owner,
            "admin" => Role::Admin,
            "member" => Role::Member,
            _ => return None,
        })
    }

    /// Owners and admins manage the organization's domains and addresses.
    pub fn manages(self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }
}

/// An account's place in its organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership {
    pub organization_id: Uuid,
    pub role: Role,
    /// MEMBER_STATE: 0 disabled, 1 enabled, 2 invited.
    pub state: i16,
    /// The organization is active (not disabled by an administrator).
    pub active: bool,
}

impl Membership {
    /// The account may manage the organization's domains now.
    pub fn manages_domains(&self) -> bool {
        self.state == 1 && self.active && self.role.manages()
    }
}

/// The account's membership, whatever its state (one at most, the unique
/// index): a disabled member is still the organization's, refused
/// [`role_required`], never free to make an organization of its own.
pub async fn membership<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    account: Uuid,
) -> AppResult<Option<Membership>> {
    let row: Option<(Uuid, String, i16, i16)> = sqlx::query_as(
        "SELECT m.organization_id, m.role, m.state, o.state
           FROM organization_members m JOIN organizations o ON o.id = m.organization_id
          WHERE m.account_id = $1",
    )
    .bind(account)
    .fetch_optional(executor)
    .await?;
    row.map(|(organization_id, role, state, org_state)| {
        Ok(Membership {
            organization_id,
            role: Role::parse(&role)
                .ok_or_else(|| AppError::internal("unknown organization role"))?,
            state,
            active: org_state == 1,
        })
    })
    .transpose()
}

/// The organization whose domains the account manages, if any.
pub async fn managed_domains<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    account: Uuid,
) -> AppResult<Option<Uuid>> {
    Ok(membership(executor, account)
        .await?
        .filter(Membership::manages_domains)
        .map(|m| m.organization_id))
}

/// Refused: the account is in an organization whose domains it doesn't
/// manage (a member, invited, disabled, or the organization disabled).
pub fn role_required() -> AppError {
    AppError::forbidden("only an organization's owners and admins manage its domains")
        .with_details(serde_json::json!({ "code": "orgRoleRequired" }))
}

/// The organization the account manages domains for, or the refusal.
pub async fn require_managed_domains<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    account: Uuid,
) -> AppResult<Uuid> {
    match membership(executor, account).await? {
        Some(m) if m.manages_domains() => Ok(m.organization_id),
        Some(_) => Err(role_required()),
        None => Err(AppError::not_found("no such domain")),
    }
}

/// The organization a new domain of the account's goes to: the one it
/// manages, or a new organization of one with it as owner (Proton's domains
/// belong to the session's organization). The account's row must be locked
/// by the caller, so two first domains make one organization.
pub async fn for_new_domain(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> AppResult<Uuid> {
    match membership(&mut **tx, account).await? {
        Some(m) if m.manages_domains() => return Ok(m.organization_id),
        Some(_) => return Err(role_required()),
        None => {}
    }
    of_one(tx, account).await
}

/// The account's organization (any membership), or a new organization of
/// one with it as owner: where an administrator's domain limits for an
/// account go before it holds a domain. The account's row must be locked by
/// the caller.
pub async fn of_account(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> AppResult<Uuid> {
    match membership(&mut **tx, account).await? {
        Some(m) => Ok(m.organization_id),
        None => of_one(tx, account).await,
    }
}

async fn of_one(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> AppResult<Uuid> {
    let organization: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name)
         SELECT coalesce(nullif(username, ''), 'organization') FROM users WHERE id = $1
         RETURNING id",
    )
    .bind(account)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO organization_members (organization_id, account_id, role, state, joined_at)
         VALUES ($1, $2, 'owner', 1, now())",
    )
    .bind(organization)
    .bind(account)
    .execute(&mut **tx)
    .await?;
    Ok(organization)
}

/// The organization's enabled owners, who are told what happens to it.
pub async fn owners<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    organization: Uuid,
) -> AppResult<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT account_id FROM organization_members
          WHERE organization_id = $1 AND role = 'owner' AND state = 1
          ORDER BY joined_at NULLS LAST, account_id",
    )
    .bind(organization)
    .fetch_all(executor)
    .await?)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::mail::domains::settings::Settings;
    use crate::mail::domains::store::{self, AddRefusal};

    async fn account(pool: &sqlx::PgPool, tag: &str, name: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO users (username, master_key_envelope, recovery_key_envelope, public_key,
                                account_authority_public_key, account_authority_key_id,
                                account_incarnation_id, drive_signing_public_key)
             VALUES ($1, '', '', '', '', '', '', '') RETURNING id",
        )
        .bind(format!("{name}{}", &tag[..12]))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Live (`KUTUP_LIVE_DATABASE_URL`): an account's first domain makes it
    /// the owner of an organization of one; the domain limit is the
    /// organization's, raised by its own value; a member who doesn't manage
    /// the organization is refused; a deactivation tells every owner.
    #[tokio::test]
    async fn live_domains_belong_to_an_organization() {
        let Ok(database_url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset — skipping live organizations test");
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let tag = Uuid::new_v4().simple().to_string();
        let site = Settings {
            domains_per_organization: 1,
            ..Settings::default()
        };
        let alice = account(&pool, &tag, "orgalice").await;
        let bob = account(&pool, &tag, "orgbob").await;

        // The first domain: an organization of one, Alice its owner.
        assert_eq!(super::managed_domains(&pool, alice).await.unwrap(), None);
        let first = store::add(&pool, alice, &format!("one-{tag}.test"), &site)
            .await
            .unwrap()
            .unwrap();
        let organization = super::managed_domains(&pool, alice).await.unwrap().unwrap();
        assert_eq!(first.organization_id, organization);
        let membership = super::membership(&pool, alice).await.unwrap().unwrap();
        assert_eq!(membership.role, super::Role::Owner);
        assert_eq!(super::owners(&pool, organization).await.unwrap(), [alice]);

        // The limit counts the organization's domains, and its own value
        // raises it.
        assert_eq!(
            store::add(&pool, alice, &format!("two-{tag}.test"), &site)
                .await
                .unwrap()
                .unwrap_err(),
            AddRefusal::AccountLimit
        );
        sqlx::query(
            "INSERT INTO organization_setting_overrides (organization_id, key, value)
             VALUES ($1, 'mail_domains.per_organization', 2)",
        )
        .bind(organization)
        .execute(&pool)
        .await
        .unwrap();
        store::add(&pool, alice, &format!("two-{tag}.test"), &site)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(store::list(&pool, organization).await.unwrap().len(), 2);

        // Bob, a member who doesn't manage it: refused, and makes no
        // organization of his own.
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role, state, joined_at)
             VALUES ($1, $2, 'member', 1, now())",
        )
        .bind(organization)
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
        let refused = store::add(&pool, bob, &format!("bob-{tag}.test"), &site)
            .await
            .unwrap_err();
        assert_eq!(refused.status, axum::http::StatusCode::FORBIDDEN);
        assert!(super::require_managed_domains(&pool, bob).await.is_err());
        assert_eq!(super::managed_domains(&pool, bob).await.unwrap(), None);

        // An administrator deactivates the first domain: every owner told.
        sqlx::query("UPDATE organization_members SET role = 'owner' WHERE account_id = $1")
            .bind(bob)
            .execute(&pool)
            .await
            .unwrap();
        let (lost_by, _) = store::deactivate(&pool, first.id, alice).await.unwrap();
        assert_eq!(lost_by, organization);
        for owner in [alice, bob] {
            let told: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM account_security_events WHERE user_id = $1 AND kind = 'domainLost'",
            )
            .bind(owner)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(told, 1, "every owner sees the loss");
        }
        sqlx::query("DELETE FROM mail_domain_blocks WHERE name = $1")
            .bind(format!("one-{tag}.test"))
            .execute(&pool)
            .await
            .unwrap();

        // A disabled member is still the organization's: refused, and no
        // organization of one of its own.
        sqlx::query(
            "UPDATE organization_members SET role = 'member', state = 0 WHERE account_id = $1",
        )
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
        let refused = store::add(&pool, bob, &format!("bob2-{tag}.test"), &site)
            .await
            .unwrap_err();
        assert_eq!(refused.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(
            super::membership(&pool, bob)
                .await
                .unwrap()
                .map(|m| m.organization_id),
            Some(organization)
        );

        // An administrator's limit for an account with no domain: its
        // organization of one.
        let carol = account(&pool, &tag, "orgcarol").await;
        let mut tx = pool.begin().await.unwrap();
        let carols = super::of_account(&mut tx, carol).await.unwrap();
        tx.commit().await.unwrap();
        assert_ne!(carols, organization);
        assert_eq!(super::owners(&pool, carols).await.unwrap(), [carol]);

        // Its last owner's account deleted, an organization of one goes with
        // its domains, so the name is free again.
        let dave = account(&pool, &tag, "orgdave").await;
        let daves = store::add(&pool, dave, &format!("dave-{tag}.test"), &site)
            .await
            .unwrap()
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(dave)
            .execute(&pool)
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations WHERE id = $1")
            .bind(daves.organization_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0, "an organization nobody is left in goes");
        let domains: i64 = sqlx::query_scalar("SELECT count(*) FROM mail_domains WHERE id = $1")
            .bind(daves.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(domains, 0);

        // With people left in it, it passes to its longest-standing admin.
        sqlx::query(
            "UPDATE organization_members SET state = 1, role = 'admin' WHERE account_id = $1",
        )
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(alice)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(super::owners(&pool, organization).await.unwrap(), [bob]);
    }
}
