package utils

import (
	"net"
	"strings"
	"testing"
)

func TestValidateFederationURL_RequiresHTTPS(t *testing.T) {
	if err := ValidateFederationURL("http://example.com", false); err == nil {
		t.Error("http:// without allowHTTP must be rejected")
	}
	if err := ValidateFederationURL("ftp://example.com", false); err == nil {
		t.Error("non-http(s) scheme must be rejected")
	}
	if err := ValidateFederationURL("javascript:alert(1)", false); err == nil {
		t.Error("javascript: scheme must be rejected")
	}
}

func TestValidateFederationURL_AllowHTTPInDev(t *testing.T) {
	// allowHTTP=true is for local/test setups (e.g. http://kutup-other.local).
	if err := ValidateFederationURL("http://example.com", true); err != nil {
		t.Errorf("allowHTTP=true should accept http://example.com, got %v", err)
	}
	// Even with allowHTTP, private addresses are still blocked.
	if err := ValidateFederationURL("http://127.0.0.1", true); err == nil {
		t.Error("allowHTTP=true must still block 127.0.0.1")
	}
}

func TestValidateFederationURL_BlocksLiteralPrivateIPs(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/",
		"https://10.0.0.1/",
		"https://172.16.0.1/",
		"https://192.168.1.1/",
		"https://169.254.169.254/", // AWS metadata
		"https://100.64.0.1/",      // shared (CGN)
		"https://[::1]/",
		"https://[fc00::1]/",
		"https://[fe80::1]/",
	}
	for _, raw := range cases {
		err := ValidateFederationURL(raw, false)
		if err == nil {
			t.Errorf("%s: expected SSRF rejection, got nil", raw)
		} else if !strings.Contains(err.Error(), "private") {
			t.Errorf("%s: error should mention 'private', got %v", raw, err)
		}
	}
}

func TestValidateFederationURL_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"not a url",
		"https://",
	}
	for _, raw := range cases {
		if err := ValidateFederationURL(raw, false); err == nil {
			t.Errorf("%q: expected error, got nil", raw)
		}
	}
}

func TestValidateFederationURL_RejectsUnresolvableHost(t *testing.T) {
	// invalid TLD that no resolver should ever return an answer for.
	err := ValidateFederationURL("https://this-host-must-not-exist.kutup-test.invalid", false)
	if err == nil {
		t.Fatal("unresolvable host must be rejected")
	}
}

func TestIsPrivateIP_Helper(t *testing.T) {
	// Sanity check the helper's table coverage.
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false}, // outside 172.16.0.0/12
		{"192.168.0.5", true},
		{"192.169.0.5", false},
		{"169.254.169.254", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"2001:db8::1", false},
		{"fe80::1", true},
		{"fc00::1", true},
	}
	for _, tc := range cases {
		got := isPrivateIP(net.ParseIP(tc.ip))
		if got != tc.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}
