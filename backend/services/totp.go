package services

import (
	"github.com/pquerna/otp/totp"
)

// GenerateTOTP creates a new TOTP secret for a user.
func GenerateTOTP(email, issuer string) (secret, qrURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP checks a TOTP code against the stored secret.
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
