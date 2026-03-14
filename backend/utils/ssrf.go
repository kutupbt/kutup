package utils

import (
	"fmt"
	"net"
	"net/url"
)

var privateNets []*net.IPNet

func init() {
	privateCIDRs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // link-local / AWS metadata
		"100.64.0.0/10",  // shared address space
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, ipNet)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, ipNet := range privateNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateFederationURL validates that a URL is safe for outbound federation requests.
// Blocks private/internal IP ranges (SSRF protection) and requires a valid host.
// Scheme must be https unless allowHTTP is true (for local/dev setups).
func ValidateFederationURL(rawURL string, allowHTTP bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return fmt.Errorf("federation URLs must use HTTPS")
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("invalid URL: missing host")
	}

	// If the host is already an IP address, check it directly
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("federation to private/internal addresses is not allowed")
		}
		return nil
	}

	// Resolve hostname and check all returned IPs
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host %q resolved to no addresses", host)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return fmt.Errorf("federation to private/internal addresses is not allowed")
		}
	}

	return nil
}
