//! One check of one domain: every record's state ([`super::records`]), the
//! DKIM warning's clock, and what the result does to the domain
//! ([`super::policy`]). It reads DNS and nothing else: whether another
//! account holds the name, and writing the row, are the store's.

use super::policy::{self, Change, Found, Grace, Status};
use super::records::{self, dkim, mx, verify, Resolver};

/// How long DKIM may stay broken, after it was good, before signing stops.
pub const DKIM_ERROR_AFTER: i64 = 7 * 24 * 3600;

/// What the server publishes and expects.
#[derive(Debug, Clone)]
pub struct Server {
    /// The accounts' domain, under which the DKIM targets and `_spf` live.
    pub name: String,
    /// The MX customers point at.
    pub mx_host: String,
    pub backup_mx: Option<String>,
}

impl Server {
    pub fn spf_include(&self) -> String {
        format!("_spf.{}", self.name)
    }
}

/// The parts of a domain a check reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub id: uuid::Uuid,
    pub name: String,
    pub verify_code: String,
    pub status: Status,
    pub verify_state: i16,
    pub mx_state: i16,
    pub spf_state: i16,
    pub dkim_state: i16,
    pub dmarc_state: i16,
    pub dkim_good_once: bool,
    pub dkim_warning_since: Option<i64>,
}

/// The domain after a check at `now`, and what changed in its standing.
pub async fn check(
    resolver: &dyn Resolver,
    server: &Server,
    domain: &Domain,
    grace: Grace,
    now: i64,
) -> (Domain, Change) {
    let mut next = domain.clone();
    let name = &domain.name;

    let verify = records::verify_state(&resolver.txt(name).await, &domain.verify_code);
    if let Some(state) = verify {
        next.verify_state = state;
    }
    let mx_answer = resolver.mx(name).await;
    let mx = records::mx_state(&mx_answer, &server.mx_host, server.backup_mx.as_deref());
    if let Some(state) = mx {
        next.mx_state = state;
    }
    if let Some(state) = records::spf_state(resolver, name, &server.spf_include()).await {
        next.spf_state = state;
    }
    if let Some(state) = records::dmarc_state(&resolver.txt(&format!("_dmarc.{name}")).await) {
        next.dmarc_state = state;
    }
    if let Some(state) = records::dkim_state(
        resolver,
        name,
        &domain.id,
        &server.name,
        domain.dkim_good_once,
    )
    .await
    {
        apply_dkim(&mut next, state, now);
    }

    let found = Found {
        owned: verify.map(|state| state == verify::GOOD),
        // Ours as first, or as a backup the operator runs: mail reaches us.
        mx_ours: mx.map(|state| matches!(state, mx::GOOD | mx::BACKUP | mx::INC_US)),
    };
    let (status, change) = policy::next(domain.status, found, now, grace);
    next.status = status;
    (next, change)
}

/// DKIM's state, with its warning clock: `WARNING` turns into `ERROR` after
/// [`DKIM_ERROR_AFTER`], and `GOOD` once makes the domain signable.
fn apply_dkim(domain: &mut Domain, state: i16, now: i64) {
    match state {
        dkim::GOOD => {
            domain.dkim_good_once = true;
            domain.dkim_warning_since = None;
            domain.dkim_state = dkim::GOOD;
        }
        dkim::WARNING => {
            let since = *domain.dkim_warning_since.get_or_insert(now);
            domain.dkim_state = if now - since >= super::scaled(DKIM_ERROR_AFTER) {
                dkim::ERROR
            } else {
                dkim::WARNING
            };
        }
        other => {
            domain.dkim_warning_since = None;
            domain.dkim_state = other;
        }
    }
}

/// Whether Stalwart should sign for the domain now.
pub fn signs(domain: &Domain) -> bool {
    domain.status.usable()
        && domain.dkim_good_once
        && matches!(domain.dkim_state, dkim::GOOD | dkim::WARNING)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::domains::records::fake::FakeResolver;
    use crate::mail::domains::records::{dkim_target, Lookup, DKIM_SELECTORS};

    fn server() -> Server {
        Server {
            name: "kutup.dev".into(),
            mx_host: "mail.kutup.dev".into(),
            backup_mx: None,
        }
    }

    fn domain() -> Domain {
        Domain {
            id: uuid::Uuid::new_v4(),
            name: "example.com".into(),
            verify_code: "kutup-verification=abcdefghijklmnopqrstuvwxyz".into(),
            status: Status::default(),
            verify_state: 0,
            mx_state: 0,
            spf_state: 0,
            dkim_state: 0,
            dmarc_state: 0,
            dkim_good_once: false,
            dkim_warning_since: None,
        }
    }

    /// Every record as asked.
    fn all_set(domain: &Domain) -> FakeResolver {
        let mut dns = FakeResolver::default();
        dns.txt.insert(
            domain.name.clone(),
            Lookup::Found(vec![
                domain.verify_code.clone(),
                "v=spf1 include:_spf.kutup.dev ~all".into(),
            ]),
        );
        dns.mx.insert(
            domain.name.clone(),
            Lookup::Found(vec![(10, "mail.kutup.dev".into())]),
        );
        dns.txt.insert(
            format!("_dmarc.{}", domain.name),
            Lookup::Found(vec!["v=DMARC1; p=quarantine".into()]),
        );
        for selector in DKIM_SELECTORS {
            dns.cname.insert(
                format!("{selector}._domainkey.{}", domain.name),
                Lookup::Found(dkim_target(&domain.id, selector, "kutup.dev")),
            );
        }
        dns
    }

    #[tokio::test]
    async fn a_domain_set_up_as_asked_is_verified_and_signs() {
        let domain = domain();
        let (checked, change) =
            check(&all_set(&domain), &server(), &domain, Grace::default(), 100).await;
        assert_eq!(change, Change::Verified);
        assert_eq!(
            (
                checked.verify_state,
                checked.mx_state,
                checked.spf_state,
                checked.dkim_state,
                checked.dmarc_state
            ),
            (
                verify::GOOD,
                mx::GOOD,
                records::spf::GOOD,
                dkim::GOOD,
                records::dmarc::RELAXED
            )
        );
        assert!(signs(&checked));
    }

    #[tokio::test]
    async fn broken_dkim_warns_then_stops_signing_after_a_week() {
        let domain = domain();
        let (good, _) = check(&all_set(&domain), &server(), &domain, Grace::default(), 0).await;
        let mut dns = all_set(&domain);
        dns.cname
            .remove(&format!("kutup2._domainkey.{}", domain.name));
        let (warned, _) = check(&dns, &server(), &good, Grace::default(), 10).await;
        assert_eq!(warned.dkim_state, dkim::WARNING);
        assert!(signs(&warned));
        let (later, _) = check(
            &dns,
            &server(),
            &warned,
            Grace::default(),
            10 + DKIM_ERROR_AFTER,
        )
        .await;
        assert_eq!(later.dkim_state, dkim::ERROR);
        assert!(!signs(&later));
        // Fixed again: good, the clock cleared.
        let (fixed, _) = check(
            &all_set(&domain),
            &server(),
            &later,
            Grace::default(),
            20 + DKIM_ERROR_AFTER,
        )
        .await;
        assert_eq!(
            (fixed.dkim_state, fixed.dkim_warning_since),
            (dkim::GOOD, None)
        );
    }

    #[tokio::test]
    async fn an_unknown_answer_keeps_every_state() {
        let domain = domain();
        let (good, _) = check(&all_set(&domain), &server(), &domain, Grace::default(), 0).await;
        let mut dns = FakeResolver::default();
        dns.txt.insert(domain.name.clone(), Lookup::Unknown);
        dns.mx.insert(domain.name.clone(), Lookup::Unknown);
        dns.txt
            .insert(format!("_dmarc.{}", domain.name), Lookup::Unknown);
        for selector in DKIM_SELECTORS {
            dns.cname.insert(
                format!("{selector}._domainkey.{}", domain.name),
                Lookup::Unknown,
            );
        }
        let (after, change) = check(&dns, &server(), &good, Grace::default(), 99).await;
        assert_eq!(change, Change::None);
        assert_eq!(after, good);
    }

    #[tokio::test]
    async fn txt_and_mx_gone_stop_the_domain_after_the_confirming_check() {
        let domain = domain();
        let grace = Grace::default();
        let (good, _) = check(&all_set(&domain), &server(), &domain, grace, 0).await;
        let empty = FakeResolver::default();
        let (first, change) = check(&empty, &server(), &good, grace, 100).await;
        assert_eq!(change, Change::None);
        assert!(first.status.usable());
        let (second, change) =
            check(&empty, &server(), &first, grace, 100 + grace.confirm_after).await;
        assert_eq!(change, Change::Stopped);
        assert!(!second.status.usable() && !signs(&second));
    }
}
