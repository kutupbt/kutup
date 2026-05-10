package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SetupTOTPResponse is what POST /user/2fa/setup returns.
type SetupTOTPResponse struct {
	Secret string `json:"secret"`
	QrURI  string `json:"qrUri"`
}

// SetupTOTP starts the TOTP enrollment flow. The returned QrURI is an
// otpauth://totp/... URI that authenticator apps consume directly. The
// returned Secret is the base32 form for manual entry.
//
// The setup is "pending" until VerifyTOTP succeeds — totp_enabled stays
// false until verify, so a setup-without-verify is a no-op for login.
func (c *Client) SetupTOTP() (*SetupTOTPResponse, error) {
	resp, err := c.postJSON("/user/2fa/setup", struct{}{})
	if err != nil {
		return nil, err
	}
	var r SetupTOTPResponse
	return &r, decodeJSON(resp, &r)
}

// VerifyTOTP completes the enrollment by submitting a 6-digit code from
// the user's authenticator. Flips totp_enabled to true on success.
func (c *Client) VerifyTOTP(code string) error {
	resp, err := c.postJSON("/user/2fa/verify", map[string]string{"code": code})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// DisableTOTP turns off 2FA. The backend requires a valid TOTP code in
// the request body to prevent a stolen session from silently disabling
// 2FA.
//
// DELETE-with-body is unusual but matches the backend handler at
// auth.go:DisableTOTP.
func (c *Client) DisableTOTP(code string) error {
	body, _ := json.Marshal(map[string]string{"code": code})
	req, err := http.NewRequest(http.MethodDelete, c.base+"/api/user/2fa", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(errBody))
	}
	return nil
}
