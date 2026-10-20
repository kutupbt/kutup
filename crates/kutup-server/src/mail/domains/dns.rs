//! The [`Resolver`] the checks use in production: hickory, uncached, asking
//! the configured nameserver (`MAIL_DNS_RESOLVER`, else the system's) and
//! validating DNSSEC itself, so a forged answer for a signed zone is
//! refused rather than trusted (docs/plans/mail-custom-domains.md §3). A
//! bogus answer, a timeout or SERVFAIL is [`Lookup::Unknown`].

use std::net::SocketAddr;
use std::time::Duration;

use axum::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use super::records::{Lookup, Resolver};

pub struct DnsResolver {
    inner: TokioResolver,
}

impl DnsResolver {
    /// `nameserver`: the resolver to ask; the system's when `None`.
    pub fn new(nameserver: Option<SocketAddr>) -> anyhow::Result<Self> {
        let mut builder = match nameserver {
            Some(address) => {
                let mut server = NameServerConfig::udp_and_tcp(address.ip());
                for connection in &mut server.connections {
                    connection.port = address.port();
                }
                TokioResolver::builder_with_config(
                    ResolverConfig::from_parts(None, Vec::new(), vec![server]),
                    TokioRuntimeProvider::default(),
                )
            }
            None => TokioResolver::builder_tokio()?,
        };
        let options = builder.options_mut();
        // Every check sees the record as it is now.
        options.cache_size = 0;
        options.validate = true;
        options.timeout = Duration::from_secs(5);
        options.attempts = 2;
        Ok(DnsResolver {
            inner: builder.build()?,
        })
    }

    async fn records(&self, name: &str, kind: RecordType) -> Lookup<Vec<RData>> {
        match self.inner.lookup(name, kind).await {
            Ok(lookup) => {
                let found: Vec<RData> = lookup
                    .answers()
                    .iter()
                    .filter(|record| record.record_type() == kind)
                    .map(|record| record.data.clone())
                    .collect();
                if found.is_empty() {
                    Lookup::None
                } else {
                    Lookup::Found(found)
                }
            }
            Err(error) if no_records(&error) => Lookup::None,
            Err(_) => Lookup::Unknown,
        }
    }
}

fn no_records(error: &NetError) -> bool {
    error.is_no_records_found()
}

fn host(name: &impl ToString) -> String {
    name.to_string().trim_end_matches('.').to_ascii_lowercase()
}

#[async_trait]
impl Resolver for DnsResolver {
    async fn txt(&self, name: &str) -> Lookup<Vec<String>> {
        match self.records(name, RecordType::TXT).await {
            Lookup::Found(records) => Lookup::Found(
                records
                    .into_iter()
                    .filter_map(|record| match record {
                        RData::TXT(txt) => Some(
                            txt.txt_data
                                .iter()
                                .map(|part| String::from_utf8_lossy(part).into_owned())
                                .collect::<String>(),
                        ),
                        _ => None,
                    })
                    .collect(),
            ),
            Lookup::None => Lookup::None,
            Lookup::Unknown => Lookup::Unknown,
        }
    }

    async fn mx(&self, name: &str) -> Lookup<Vec<(u16, String)>> {
        match self.records(name, RecordType::MX).await {
            Lookup::Found(records) => Lookup::Found(
                records
                    .into_iter()
                    .filter_map(|record| match record {
                        RData::MX(mx) => Some((mx.preference, host(&mx.exchange))),
                        _ => None,
                    })
                    .collect(),
            ),
            Lookup::None => Lookup::None,
            Lookup::Unknown => Lookup::Unknown,
        }
    }

    async fn cname(&self, name: &str) -> Lookup<String> {
        match self.records(name, RecordType::CNAME).await {
            Lookup::Found(records) => records
                .into_iter()
                .find_map(|record| match record {
                    RData::CNAME(cname) => Some(Lookup::Found(host(&cname.0))),
                    _ => None,
                })
                .unwrap_or(Lookup::None),
            Lookup::None => Lookup::None,
            Lookup::Unknown => Lookup::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against the public DNS, by hand: `cargo test -p kutup-server --bins
    /// mail::domains::dns -- --ignored`.
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn the_system_resolver_answers() {
        let dns = DnsResolver::new(None).unwrap();
        assert!(matches!(dns.mx("gmail.com").await, Lookup::Found(mx) if !mx.is_empty()));
        assert!(
            matches!(dns.txt("gmail.com").await, Lookup::Found(txt) if txt.iter().any(|t| t.starts_with("v=spf1")))
        );
        assert_eq!(dns.mx("nonexistent-kutup-check.example").await, Lookup::None);
    }
}
