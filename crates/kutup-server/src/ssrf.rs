//! IP classification shared by the unified federation resolver and the
//! narrow public fetchers (Chat link previews, mail key lookup). Feature
//! adapters never validate or dereference caller-supplied URLs themselves.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Globally routable unicast: not loopback, private, link-local, shared
/// (CGNAT), multicast, broadcast, documentation, benchmarking, reserved,
/// unique-local, or an IPv4 address wrapped in IPv6.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            let segments = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                // fc00::/7 unique local, fe80::/10 link-local
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                // 2001:db8::/32 documentation
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                // 64:ff9b::/96 NAT64 and ::/96 IPv4-compatible can reach IPv4 space
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || segments[..6] == [0, 0, 0, 0, 0, 0])
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        // 100.64.0.0/10 shared address space
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 protocol assignments
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15 benchmarking
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4 reserved
        || a >= 240)
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
}
