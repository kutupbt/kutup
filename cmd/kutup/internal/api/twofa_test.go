package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSetupTOTP_ReturnsSecretAndURI(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/2fa/setup" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(SetupTOTPResponse{
			Secret: "ABCDEFGHIJKLMNOP",
			QrURI:  "otpauth://totp/Kutup:test@example.com?secret=ABCDEFGHIJKLMNOP&issuer=Kutup",
		})
	})
	defer cleanup()

	res, err := client.SetupTOTP()
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret == "" || !strings.HasPrefix(res.QrURI, "otpauth://totp/") {
		t.Errorf("bad response: %+v", res)
	}
}

func TestVerifyTOTP_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/2fa/verify" {
			t.Errorf("path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]string
		_ = json.Unmarshal(body, &got)
		if got["code"] != "123456" {
			t.Errorf("code not propagated: %v", got)
		}
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	})
	defer cleanup()

	if err := client.VerifyTOTP("123456"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid code"}`, 400)
	})
	defer cleanup()

	if err := client.VerifyTOTP("000000"); err == nil {
		t.Error("expected error on 400")
	}
}

func TestDisableTOTP_OK_DELETEWithBody(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]string
		_ = json.Unmarshal(body, &got)
		if got["code"] != "654321" {
			t.Errorf("body wrong: %v", got)
		}
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	})
	defer cleanup()

	if err := client.DisableTOTP("654321"); err != nil {
		t.Fatal(err)
	}
}
