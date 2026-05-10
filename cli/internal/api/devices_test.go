package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestListUserDevices_TwoRows(t *testing.T) {
	last := time.Now()
	rows := []UserDevice{
		{DeviceID: 1, Label: "web/firefox", IsActive: true, CreatedAt: time.Now(), LastSeenAt: &last},
		{DeviceID: 2, Label: "cli", IsActive: true, CreatedAt: time.Now()},
	}
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/devices" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(rows)
	})
	defer cleanup()

	got, err := client.ListUserDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].DeviceID != 1 || got[1].Label != "cli" {
		t.Errorf("decode wrong: %+v", got)
	}
}

func TestRevokeUserDevice_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/devices/42") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(204)
	})
	defer cleanup()

	if err := client.RevokeUserDevice(42); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeUserDevice_NotFound(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	defer cleanup()

	if err := client.RevokeUserDevice(99); err == nil {
		t.Error("expected error on 404")
	}
}
