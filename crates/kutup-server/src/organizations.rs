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

/// The account's membership: enabled or invited (one at most, the partial
/// unique index), or none.
pub async fn membership<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    account: Uuid,
) -> AppResult<Option<Membership>> {
    let row: Option<(Uuid, String, i16, i16)> = sqlx::query_as(
        "SELECT m.organization_id, m.role, m.state, o.state
           FROM organization_members m JOIN organizations o ON o.id = m.organization_id
          WHERE m.account_id = $1 AND m.state IN (1, 2)",
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
    }
}
