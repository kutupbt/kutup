package utils

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-do-not-use-in-prod-9b8a7c6d"

func TestGenerateAccessTokenRoundTrip(t *testing.T) {
	tok, err := GenerateAccessToken("user-123", true, testSecret)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	claims, err := ValidateToken(tok, testSecret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Errorf("userID = %q, want %q", claims.UserID, "user-123")
	}
	if !claims.IsAdmin {
		t.Error("IsAdmin = false, want true")
	}
	if claims.Subject != "" {
		t.Errorf("access token Subject = %q, want empty", claims.Subject)
	}
}

func TestGenerateRefreshToken_NoIsAdmin(t *testing.T) {
	tok, err := GenerateRefreshToken("user-456", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateToken(tok, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "user-456" {
		t.Errorf("userID = %q", claims.UserID)
	}
	// Refresh tokens should NOT carry isAdmin (caller re-checks DB).
	if claims.IsAdmin {
		t.Error("refresh token IsAdmin should be false")
	}
}

func TestValidateToken_RejectsWrongSecret(t *testing.T) {
	tok, _ := GenerateAccessToken("u", false, testSecret)
	_, err := ValidateToken(tok, "different-secret")
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestValidateToken_RejectsAlgNone(t *testing.T) {
	// Build a token with alg:none — a classic JWT confusion attack. ValidateToken
	// must reject any non-HMAC signing method.
	claims := Claims{UserID: "evil"}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	str, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	_, err = ValidateToken(str, testSecret)
	if err == nil {
		t.Fatal("alg:none token must be rejected")
	}
}

func TestValidateToken_RejectsExpired(t *testing.T) {
	// Build a manually-expired token.
	claims := Claims{
		UserID: "expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := tok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateToken(str, testSecret)
	if err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestValidateToken_RejectsGarbage(t *testing.T) {
	if _, err := ValidateToken("not.a.token", testSecret); err == nil {
		t.Error("garbage token must be rejected")
	}
	if _, err := ValidateToken("", testSecret); err == nil {
		t.Error("empty token must be rejected")
	}
}

func TestSetupToken_RoundTrip(t *testing.T) {
	tok, err := GenerateSetupToken("setup-user", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := ValidateSetupToken(tok, testSecret)
	if err != nil {
		t.Fatalf("ValidateSetupToken: %v", err)
	}
	if uid != "setup-user" {
		t.Errorf("uid = %q, want %q", uid, "setup-user")
	}
}

func TestSetupToken_RejectsWrongSubject(t *testing.T) {
	// Access tokens have empty Subject; ValidateSetupToken must refuse them
	// to prevent token-confusion (e.g. an access token used to bypass first-
	// login completion).
	access, _ := GenerateAccessToken("u", false, testSecret)
	_, err := ValidateSetupToken(access, testSecret)
	if err == nil {
		t.Fatal("access token must not validate as setup token")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Errorf("error should mention setup, got: %v", err)
	}
}

func TestPreAuthToken_RoundTrip(t *testing.T) {
	tok, err := GeneratePreAuthToken("totp-user", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := ValidatePreAuthToken(tok, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if uid != "totp-user" {
		t.Errorf("uid = %q", uid)
	}
}

func TestPreAuthToken_RejectsAccessToken(t *testing.T) {
	access, _ := GenerateAccessToken("u", false, testSecret)
	_, err := ValidatePreAuthToken(access, testSecret)
	if err == nil {
		t.Fatal("access token must not validate as pre-auth token")
	}
}

func TestPreAuthToken_RejectsSetupToken(t *testing.T) {
	setup, _ := GenerateSetupToken("u", testSecret)
	_, err := ValidatePreAuthToken(setup, testSecret)
	if err == nil {
		t.Fatal("setup token must not validate as pre-auth token")
	}
}

func TestSetupToken_RejectsPreAuthToken(t *testing.T) {
	preAuth, _ := GeneratePreAuthToken("u", testSecret)
	_, err := ValidateSetupToken(preAuth, testSecret)
	if err == nil {
		t.Fatal("pre-auth token must not validate as setup token")
	}
}
