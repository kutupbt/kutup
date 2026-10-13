//! The one address list for every outbound connection to an address a user
//! or a peer named: the narrow fetcher (`public_fetch`: Chat link previews,
//! Pass site icons, Mail's image proxy, outside keys, unsubscribe) and the
//! federation transport. Feature adapters never validate or dereference
//! caller-supplied URLs themselves.

use std::net::{IpAddr, Ipv4Addr};

/// Globally routable unicast: not loopback, private, link-local, shared
/// (CGNAT), multicast, broadcast, documentation, benchmarking, reserved,
/// unique-local, discard-only, or IPv6 that carries or reaches IPv4 space
/// (mapped, compatible, NAT64, 6to4, Teredo).
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
                // Prefixes that carry or reach IPv4 space: 64:ff9b::/96 NAT64,
                // 64:ff9b:1::/48 local-use NAT64, 2002::/16 6to4, 2001::/32
                // Teredo, and ::/96 IPv4-compatible
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || segments[0] == 0x2002
                || (segments[0] == 0x2001 && segments[1] == 0)
                || segments[..6] == [0, 0, 0, 0, 0, 0]
                // 100::/64 discard-only
                || segments[..4] == [0x0100, 0, 0, 0])
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
            assert!(!is_public(ip.parse().unwrap()), "{ip} should not be public");
        }
    }

    #[test]
    fn ipv6_that_reaches_ipv4_space_is_not_public() {
        for ip in [
            "::ffff:127.0.0.1",
            "::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::808:808",
            "64:ff9b:1::a00:1",
            "64:ff9b:1:ffff::1",
            "2002:7f00:1::",
            "2002:a00:1::1",
            "2002:808:808::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "100::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} should not be public");
        }
        for ip in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450:4001::1",
            "64:ff9c::1",
            "2003::1",
            "101::1",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn public_ranges_allowed() {
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip} should be public");
        }
    }
}
