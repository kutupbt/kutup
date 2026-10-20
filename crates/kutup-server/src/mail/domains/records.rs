//! A custom domain's DNS records and their states (docs/plans/mail-custom-
//! domains.md §3–4), in Proton's numbers (WebClients `Domain.ts`), so the web
//! UI shows Proton's badges and texts one to one.
//!
//! A lookup that fails (SERVFAIL, a timeout) is [`Lookup::Unknown`]: a check
//! built on it answers `None`, and the stored state stays as it was.

use axum::async_trait;

/// What a DNS lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    Found(T),
    /// The name or the record type doesn't exist (NXDOMAIN, NODATA).
    None,
    /// The lookup failed: nothing can be said.
    Unknown,
}

/// The lookups the checks need, uncached for verification.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Every TXT record at `name`, each with its strings joined.
    async fn txt(&self, name: &str) -> Lookup<Vec<String>>;
    /// Every MX record at `name`: (preference, exchange without the dot).
    async fn mx(&self, name: &str) -> Lookup<Vec<(u16, String)>>;
    /// The CNAME at `name`, without the trailing dot.
    async fn cname(&self, name: &str) -> Lookup<String>;
}

/// The ownership code's prefix: `kutup-verification=<26 base32>`.
pub const VERIFY_PREFIX: &str = "kutup-verification=";

pub mod verify {
    pub const DEFAULT: i16 = 0;
    /// A code of ours that doesn't match.
    pub const EXIST: i16 = 1;
    pub const GOOD: i16 = 2;
}

pub mod mx {
    pub const DEFAULT: i16 = 0;
    pub const NO_US: i16 = 1;
    /// Ours, but another has priority over it.
    pub const INC_US: i16 = 2;
    pub const GOOD: i16 = 3;
    /// Our backup MX first: works, with a warning.
    pub const BACKUP: i16 = 4;
}

pub mod spf {
    pub const DEFAULT: i16 = 0;
    /// One record, without us.
    pub const ONE: i16 = 1;
    pub const MULT: i16 = 2;
    pub const GOOD: i16 = 3;
}

pub mod dkim {
    pub const DEFAULT: i16 = 0;
    /// A record found, pointing elsewhere.
    pub const WRONG: i16 = 1;
    pub const ERROR: i16 = 3;
    pub const GOOD: i16 = 4;
    /// The owner signs elsewhere (their own keys at our selector names).
    pub const DELEGATED: i16 = 5;
    pub const WARNING: i16 = 6;
}

pub mod dmarc {
    pub const DEFAULT: i16 = 0;
    /// One record, not in DMARC's form.
    pub const ONE: i16 = 1;
    pub const MULT: i16 = 2;
    /// Good, with strict DKIM alignment.
    pub const GOOD: i16 = 3;
    /// Good, with relaxed DKIM alignment (DMARC's default).
    pub const RELAXED: i16 = 4;
}

/// The DKIM selectors every custom domain points at us.
pub const DKIM_SELECTORS: [&str; 3] = ["kutup1", "kutup2", "kutup3"];

/// Where `selector` of the domain with row id `domain_id` points: a name
/// under the server's `_dk` zone, keyed by the random row id (lowercase
/// base32, no padding), so a target names no domain and never changes.
pub fn dkim_target(domain_id: &uuid::Uuid, selector: &str, server_name: &str) -> String {
    let id = base32(domain_id.as_bytes());
    format!("{id}.{selector}._dk.{server_name}")
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A fresh ownership code: 16 random bytes in base32.
pub fn new_verify_code() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{VERIFY_PREFIX}{}", base32(&bytes))
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.').eq_ignore_ascii_case(b.trim_end_matches('.'))
}

pub fn verify_state(txt: &Lookup<Vec<String>>, code: &str) -> Option<i16> {
    match txt {
        Lookup::Unknown => None,
        Lookup::None => Some(verify::DEFAULT),
        Lookup::Found(records) => Some(if records.iter().any(|r| r.trim() == code) {
            verify::GOOD
        } else if records.iter().any(|r| r.trim().starts_with(VERIFY_PREFIX)) {
            verify::EXIST
        } else {
            verify::DEFAULT
        }),
    }
}

/// `ours` is the server's MX host; `backup` its backup MX, when it has one.
pub fn mx_state(records: &Lookup<Vec<(u16, String)>>, ours: &str, backup: Option<&str>) -> Option<i16> {
    let records = match records {
        Lookup::Unknown => return None,
        Lookup::None => return Some(mx::DEFAULT),
        Lookup::Found(records) if records.is_empty() => return Some(mx::DEFAULT),
        Lookup::Found(records) => records,
    };
    let best = records.iter().map(|(preference, _)| *preference).min()?;
    let first: Vec<&str> = records
        .iter()
        .filter(|(preference, _)| *preference == best)
        .map(|(_, host)| host.as_str())
        .collect();
    let has = |host: &str| records.iter().any(|(_, h)| same_name(h, host));
    Some(if first.iter().any(|h| same_name(h, ours)) {
        mx::GOOD
    } else if backup.is_some_and(|b| first.iter().any(|h| same_name(h, b))) {
        mx::BACKUP
    } else if has(ours) {
        mx::INC_US
    } else {
        mx::NO_US
    })
}

/// SPF lookups a check may make, as SPF itself allows.
const SPF_LOOKUPS: usize = 10;

/// Whether the domain's one SPF record reaches `include` (the server's
/// `_spf.<server>`), following `include:` and `redirect=` within SPF's
/// lookup limit.
pub async fn spf_state(resolver: &dyn Resolver, domain: &str, include: &str) -> Option<i16> {
    let records = match resolver.txt(domain).await {
        Lookup::Unknown => return None,
        Lookup::None => Vec::new(),
        Lookup::Found(records) => records,
    };
    let spf: Vec<&String> = records.iter().filter(|r| is_spf(r)).collect();
    match spf.as_slice() {
        [] => Some(spf::DEFAULT),
        [_, _, ..] => Some(spf::MULT),
        [record] => {
            let mut budget = SPF_LOOKUPS;
            match reaches(resolver, record, include, &mut budget).await {
                Some(true) => Some(spf::GOOD),
                Some(false) => Some(spf::ONE),
                None => None,
            }
        }
    }
}

fn is_spf(record: &str) -> bool {
    let record = record.trim();
    record.eq_ignore_ascii_case("v=spf1") || record.to_ascii_lowercase().starts_with("v=spf1 ")
}

/// Whether `record` includes `target`, directly or through the records it
/// names. `None` when a lookup on the way failed.
fn reaches<'a>(
    resolver: &'a dyn Resolver,
    record: &'a str,
    target: &'a str,
    budget: &'a mut usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<bool>> + Send + 'a>> {
    Box::pin(async move {
        let mut unknown = false;
        for term in record.split_whitespace().skip(1) {
            let term = term.trim_start_matches(['+', '?', '~']);
            let name = if let Some(name) = term.strip_prefix("include:") {
                name
            } else if let Some(name) = term.strip_prefix("redirect=") {
                name
            } else {
                continue;
            };
            if same_name(name, target) {
                return Some(true);
            }
            if *budget == 0 {
                return Some(false);
            }
            *budget -= 1;
            match resolver.txt(name).await {
                Lookup::Found(records) => {
                    if let Some(next) = records.iter().find(|r| is_spf(r)) {
                        match reaches(resolver, next, target, budget).await {
                            Some(true) => return Some(true),
                            None => unknown = true,
                            Some(false) => {}
                        }
                    }
                }
                Lookup::None => {}
                Lookup::Unknown => unknown = true,
            }
        }
        if unknown {
            None
        } else {
            Some(false)
        }
    })
}

/// The three selectors' state. `good_once`: the domain's DKIM was `GOOD`
/// before, so a broken record now is a `WARNING` (signing goes on), not a
/// setup still in progress.
pub async fn dkim_state(
    resolver: &dyn Resolver,
    domain: &str,
    domain_id: &uuid::Uuid,
    server_name: &str,
    good_once: bool,
) -> Option<i16> {
    let mut matching = 0;
    let mut wrong = false;
    let mut own_keys = 0;
    for selector in DKIM_SELECTORS {
        let name = format!("{selector}._domainkey.{domain}");
        match resolver.cname(&name).await {
            Lookup::Unknown => return None,
            Lookup::Found(target) if same_name(&target, &dkim_target(domain_id, selector, server_name)) => {
                matching += 1
            }
            Lookup::Found(_) => wrong = true,
            Lookup::None => match resolver.txt(&name).await {
                Lookup::Unknown => return None,
                Lookup::Found(records) if records.iter().any(|r| r.contains("v=DKIM1") || r.contains("p=")) => {
                    own_keys += 1
                }
                _ => {}
            },
        }
    }
    Some(if matching == DKIM_SELECTORS.len() {
        dkim::GOOD
    } else if own_keys == DKIM_SELECTORS.len() {
        dkim::DELEGATED
    } else if good_once {
        dkim::WARNING
    } else if wrong || matching > 0 {
        dkim::WRONG
    } else {
        dkim::DEFAULT
    })
}

pub fn dmarc_state(txt: &Lookup<Vec<String>>) -> Option<i16> {
    let records = match txt {
        Lookup::Unknown => return None,
        Lookup::None => return Some(dmarc::DEFAULT),
        Lookup::Found(records) => records,
    };
    let dmarc: Vec<&String> = records
        .iter()
        .filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();
    let record = match dmarc.as_slice() {
        [] => return Some(dmarc::DEFAULT),
        [_, _, ..] => return Some(dmarc::MULT),
        [record] => record.to_ascii_lowercase(),
    };
    let tag = |name: &str| {
        record
            .split(';')
            .map(str::trim)
            .find_map(|part| part.strip_prefix(name)?.trim_start().strip_prefix('=').map(str::trim))
            .map(str::to_owned)
    };
    match tag("p").as_deref() {
        Some("none" | "quarantine" | "reject") => {}
        _ => return Some(dmarc::ONE),
    }
    Some(if tag("adkim").as_deref() == Some("s") {
        dmarc::GOOD
    } else {
        dmarc::RELAXED
    })
}

#[cfg(test)]
pub mod fake {
    use std::collections::HashMap;

    use super::*;

    /// Answers from a table; a name it lacks has no records.
    #[derive(Default)]
    pub struct FakeResolver {
        pub txt: HashMap<String, Lookup<Vec<String>>>,
        pub mx: HashMap<String, Lookup<Vec<(u16, String)>>>,
        pub cname: HashMap<String, Lookup<String>>,
    }

    #[async_trait]
    impl Resolver for FakeResolver {
        async fn txt(&self, name: &str) -> Lookup<Vec<String>> {
            self.txt.get(name).cloned().unwrap_or(Lookup::None)
        }
        async fn mx(&self, name: &str) -> Lookup<Vec<(u16, String)>> {
            self.mx.get(name).cloned().unwrap_or(Lookup::None)
        }
        async fn cname(&self, name: &str) -> Lookup<String> {
            self.cname.get(name).cloned().unwrap_or(Lookup::None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeResolver;
    use super::*;

    fn found(values: &[&str]) -> Lookup<Vec<String>> {
        Lookup::Found(values.iter().map(|v| v.to_string()).collect())
    }

    #[test]
    fn codes_and_targets_have_their_shapes() {
        let code = new_verify_code();
        assert!(code.starts_with(VERIFY_PREFIX));
        assert_eq!(code.len(), VERIFY_PREFIX.len() + 26);
        assert_ne!(code, new_verify_code());
        let id = uuid::Uuid::from_bytes([0xff; 16]);
        assert_eq!(
            dkim_target(&id, "kutup1", "kutup.dev"),
            format!("{}4.kutup1._dk.kutup.dev", "7".repeat(25))
        );
    }

    #[test]
    fn ownership() {
        let code = "kutup-verification=abc";
        assert_eq!(verify_state(&found(&["v=spf1 -all", code]), code), Some(verify::GOOD));
        assert_eq!(verify_state(&found(&["kutup-verification=other"]), code), Some(verify::EXIST));
        assert_eq!(verify_state(&found(&["google-site-verification=x"]), code), Some(verify::DEFAULT));
        assert_eq!(verify_state(&Lookup::None, code), Some(verify::DEFAULT));
        assert_eq!(verify_state(&Lookup::Unknown, code), None);
    }

    #[test]
    fn mail_exchangers() {
        let ours = "mail.kutup.dev";
        let mx = |records: &[(u16, &str)]| {
            Lookup::Found(records.iter().map(|(p, h)| (*p, h.to_string())).collect())
        };
        assert_eq!(mx_state(&mx(&[(10, "mail.kutup.dev")]), ours, None), Some(mx::GOOD));
        assert_eq!(mx_state(&mx(&[(10, "MAIL.kutup.dev."), (20, "b.example")]), ours, None), Some(mx::GOOD));
        assert_eq!(mx_state(&mx(&[(5, "a.example"), (10, "mail.kutup.dev")]), ours, None), Some(mx::INC_US));
        assert_eq!(mx_state(&mx(&[(10, "a.example")]), ours, None), Some(mx::NO_US));
        assert_eq!(
            mx_state(&mx(&[(5, "mx2.kutup.dev"), (10, "mail.kutup.dev")]), ours, Some("mx2.kutup.dev")),
            Some(mx::BACKUP)
        );
        assert_eq!(mx_state(&Lookup::None, ours, None), Some(mx::DEFAULT));
        assert_eq!(mx_state(&Lookup::Unknown, ours, None), None);
    }

    #[tokio::test]
    async fn spf_follows_includes_within_the_limit() {
        let ours = "_spf.kutup.dev";
        let mut dns = FakeResolver::default();
        dns.txt.insert("a.example".into(), found(&["v=spf1 include:_spf.kutup.dev ~all"]));
        dns.txt.insert("b.example".into(), found(&["v=spf1 include:_spf.other.example -all"]));
        dns.txt.insert("c.example".into(), found(&["v=spf1 a", "v=spf1 mx"]));
        dns.txt.insert("d.example".into(), found(&["v=spf1 include:chain.example ~all"]));
        dns.txt.insert("chain.example".into(), found(&["v=spf1 redirect=_spf.kutup.dev"]));
        dns.txt.insert("e.example".into(), found(&["v=spf1 include:broken.example ~all"]));
        dns.txt.insert("broken.example".into(), Lookup::Unknown);
        dns.txt.insert("loop.example".into(), found(&["v=spf1 include:loop.example ~all"]));
        assert_eq!(spf_state(&dns, "a.example", ours).await, Some(spf::GOOD));
        assert_eq!(spf_state(&dns, "b.example", ours).await, Some(spf::ONE));
        assert_eq!(spf_state(&dns, "c.example", ours).await, Some(spf::MULT));
        assert_eq!(spf_state(&dns, "d.example", ours).await, Some(spf::GOOD));
        assert_eq!(spf_state(&dns, "e.example", ours).await, None);
        assert_eq!(spf_state(&dns, "none.example", ours).await, Some(spf::DEFAULT));
        assert_eq!(spf_state(&dns, "loop.example", ours).await, Some(spf::ONE));
    }

    #[tokio::test]
    async fn dkim_needs_all_three_cnames() {
        let id = uuid::Uuid::new_v4();
        let server = "kutup.dev";
        let mut dns = FakeResolver::default();
        let name = |s: &str| format!("{s}._domainkey.example.com");
        for selector in DKIM_SELECTORS {
            dns.cname.insert(name(selector), Lookup::Found(dkim_target(&id, selector, server)));
        }
        assert_eq!(dkim_state(&dns, "example.com", &id, server, false).await, Some(dkim::GOOD));
        dns.cname.remove(&name("kutup3"));
        assert_eq!(dkim_state(&dns, "example.com", &id, server, false).await, Some(dkim::WRONG));
        assert_eq!(dkim_state(&dns, "example.com", &id, server, true).await, Some(dkim::WARNING));
        dns.cname.insert(name("kutup3"), Lookup::Unknown);
        assert_eq!(dkim_state(&dns, "example.com", &id, server, true).await, None);

        let mut own = FakeResolver::default();
        for selector in DKIM_SELECTORS {
            own.txt.insert(name(selector), found(&["v=DKIM1; k=rsa; p=MIIB"]));
        }
        assert_eq!(dkim_state(&own, "example.com", &id, server, true).await, Some(dkim::DELEGATED));
        assert_eq!(
            dkim_state(&FakeResolver::default(), "example.com", &id, server, false).await,
            Some(dkim::DEFAULT)
        );
    }

    #[test]
    fn dmarc() {
        assert_eq!(dmarc_state(&found(&["v=DMARC1; p=quarantine; adkim=s"])), Some(dmarc::GOOD));
        assert_eq!(dmarc_state(&found(&["v=DMARC1; p=quarantine"])), Some(dmarc::RELAXED));
        assert_eq!(dmarc_state(&found(&["v=DMARC1; rua=mailto:x@y"])), Some(dmarc::ONE));
        assert_eq!(dmarc_state(&found(&["v=DMARC1; p=none", "v=DMARC1; p=reject"])), Some(dmarc::MULT));
        assert_eq!(dmarc_state(&found(&["something else"])), Some(dmarc::DEFAULT));
        assert_eq!(dmarc_state(&Lookup::Unknown), None);
    }
}
