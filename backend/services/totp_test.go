package services

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTP_ProducesValidProvisioningURI(t *testing.T) {
	secret, uri, err := GenerateTOTP("user@example.com", "Kutup")
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if secret == "" {
		t.Fatal("empty secret")
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI does not start with otpauth://totp/, got %q", uri)
	}
	if !strings.Contains(uri, "issuer=Kutup") {
		t.Errorf("URI missing issuer, got %q", uri)
	}
	if !strings.Contains(uri, "user%40example.com") && !strings.Contains(uri, "user@example.com") {
		t.Errorf("URI missing account, got %q", uri)
	}
}

func TestGenerateTOTP_DifferentIssuersAndUsers(t *testing.T) {
	s1, _, _ := GenerateTOTP("a@x.com", "Kutup")
	s2, _, _ := GenerateTOTP("b@x.com", "Kutup")
	// Secrets are randomly generated; collisions are astronomically unlikely.
	if s1 == s2 {
		t.Error("two GenerateTOTP calls must yield different secrets")
	}
}

func TestValidateTOTP_AcceptsCorrectCode(t *testing.T) {
	secret, _, err := GenerateTOTP("user@example.com", "Kutup")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateTOTP(secret, code) {
		t.Error("ValidateTOTP rejected the code we just generated for now")
	}
}

func TestValidateTOTP_RejectsWrongCode(t *testing.T) {
	secret, _, _ := GenerateTOTP("user@example.com", "Kutup")
	if ValidateTOTP(secret, "000000") {
		t.Error("000000 must not be a valid code (negligible probability)")
	}
	if ValidateTOTP(secret, "123456") {
		// Could occasionally hit a real code by coincidence; if it does,
		// re-rolling the secret in this test makes that vanishingly rare.
		t.Error("123456 happened to match the current code — rerun the test")
	}
}

func TestValidateTOTP_RejectsCodeForDifferentSecret(t *testing.T) {
	s1, _, _ := GenerateTOTP("a@x.com", "Kutup")
	s2, _, _ := GenerateTOTP("b@x.com", "Kutup")
	code1, err := totp.GenerateCode(s1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ValidateTOTP(s2, code1) {
		t.Error("code generated for s1 must not validate against s2")
	}
}

func TestValidateTOTP_RejectsMalformed(t *testing.T) {
	secret, _, _ := GenerateTOTP("user@example.com", "Kutup")
	cases := []string{"", "abc", "abcdef", "12345"} // wrong length / non-digit
	for _, c := range cases {
		if ValidateTOTP(secret, c) {
			t.Errorf("malformed code %q must be rejected", c)
		}
	}
}
