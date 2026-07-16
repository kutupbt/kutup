//! Outbound-federation URL guard — mirrors `backend/utils/ssrf.go`.
//!
//! Blocks requests to private/internal address ranges (SSRF defense) and requires
//! HTTPS (unless `allow_http` for local/dev). When the host is a name it is resolved
//! and *every* returned address is checked, matching the Go `net.LookupHost` loop.
//!
//! Consumed by the federation/fed-proxy handlers (server slice 6); ported now with its
//! own unit tests, so `dead_code` is allowed until those call sites land.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

/// The blocked CIDRs from `ssrf.go`'s `privateCIDRs` list, as `(network, prefix_bits)`.
const PRIVATE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16), // link-local / AWS metadata
    (Ipv4Addr::new(100, 64, 0, 0), 10),  // shared address space (CGNAT)
];

const PRIVATE_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128), // ::1/128 loopback
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // fc00::/7 unique-local
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // fe80::/10 link-local
];

fn v4_in(ip: Ipv4Addr, net: Ipv4Addr, bits: u8) -> bool {
    let ip = u32::from(ip);
    let net = u32::from(net);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (ip & mask) == (net & mask)
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, bits: u8) -> bool {
    let ip = u128::from(ip);
    let net = u128::from(net);
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    (ip & mask) == (net & mask)
}

/// Reports whether `ip` falls in any blocked range — mirrors `isPrivateIP`.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => PRIVATE_V4.iter().any(|&(net, bits)| v4_in(v4, net, bits)),
        IpAddr::V6(v6) => PRIVATE_V6.iter().any(|&(net, bits)| v6_in(v6, net, bits)),
    }
}

/// Validates a federation URL — mirrors `ValidateFederationURL`. `Err(msg)` carries the
/// same human-readable reasons the Go function returns.
pub async fn validate_federation_url(raw_url: &str, allow_http: bool) -> Result<(), String> {
    validate_url(raw_url, allow_http, false).await
}

/// Chat-only validation entry point for the local two-server harness. Callers
/// must enforce that `allow_private_test_network` can only be enabled under an
/// explicit test environment. Other federation features always use
/// [`validate_federation_url`] and therefore cannot opt out of private-address
/// blocking.
pub async fn validate_chat_federation_url(
    raw_url: &str,
    allow_http: bool,
    allow_private_test_network: bool,
) -> Result<(), String> {
    validate_url(raw_url, allow_http, allow_private_test_network).await
}

async fn validate_url(
    raw_url: &str,
    allow_http: bool,
    allow_private_test_network: bool,
) -> Result<(), String> {
    let u = Url::parse(raw_url).map_err(|e| format!("invalid URL: {e}"))?;

    let scheme = u.scheme();
    if scheme != "https" && !(allow_http && scheme == "http") {
        return Err("federation URLs must use HTTPS".to_string());
    }

    let host = u.host_str().unwrap_or("");
    if host.is_empty() {
        return Err("invalid URL: missing host".to_string());
    }

    // Host is already a literal IP — check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) && !allow_private_test_network {
            return Err("federation to private/internal addresses is not allowed".to_string());
        }
        return Ok(());
    }

    // Resolve and check every returned address (port is irrelevant to the IP check).
    let addrs: Vec<_> = tokio::net::lookup_host((host, 0u16))
        .await
        .map_err(|e| format!("cannot resolve host {host:?}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("host {host:?} resolved to no addresses"));
    }
    for addr in addrs {
        if is_private_ip(addr.ip()) && !allow_private_test_network {
            return Err("federation to private/internal addresses is not allowed".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_detected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
        ] {
            assert!(is_private_ip(ip.parse().unwrap()), "{ip} should be private");
        }
    }

    #[test]
    fn public_ranges_allowed() {
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700:4700::1111"] {
            assert!(!is_private_ip(ip.parse().unwrap()), "{ip} should be public");
        }
    }

    #[tokio::test]
    async fn rejects_non_https() {
        let err = validate_federation_url("http://example.com/x", false)
            .await
            .unwrap_err();
        assert!(err.contains("HTTPS"));
        // …but http is allowed in dev mode.
        // (uses an IP literal so the test never hits real DNS)
        assert!(validate_federation_url("http://8.8.8.8/x", true)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn rejects_private_ip_literal() {
        let err = validate_federation_url("https://127.0.0.1/x", false)
            .await
            .unwrap_err();
        assert!(err.contains("private/internal"));
        let err = validate_federation_url("https://169.254.169.254/latest/meta-data", false)
            .await
            .unwrap_err();
        assert!(err.contains("private/internal"));
    }

    #[tokio::test]
    async fn allows_public_ip_literal() {
        assert!(validate_federation_url("https://8.8.8.8/x", false)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn chat_test_policy_can_explicitly_allow_private_networks() {
        assert!(
            validate_chat_federation_url("http://127.0.0.1/x", true, true)
                .await
                .is_ok()
        );
        assert!(
            validate_chat_federation_url("http://127.0.0.1/x", true, false)
                .await
                .is_err()
        );
        assert!(validate_federation_url("http://127.0.0.1/x", true)
            .await
            .is_err());
    }
}
