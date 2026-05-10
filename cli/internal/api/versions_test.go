package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newMockClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c := New(srv.URL, "test-token")
	return c, srv.Close
}

func TestListVersions_Empty(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/files/F1/versions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing auth header")
		}
		_, _ = w.Write([]byte("[]"))
	})
	defer cleanup()

	versions, err := client.ListVersions("F1")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 0 {
		t.Errorf("got %d versions, want 0", len(versions))
	}
}

func TestListVersions_TwoRows(t *testing.T) {
	rows := []VersionRow{
		{ID: "v1", S3VersionID: "s1", StoragePath: "p1", SizeBytes: 100, CreatedAt: time.Now()},
		{ID: "v2", S3VersionID: "s2", StoragePath: "p2", SizeBytes: 200, CreatedAt: time.Now()},
	}
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	defer cleanup()

	got, err := client.ListVersions("F1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "v1" || got[1].SizeBytes != 200 {
		t.Errorf("decode failure: %+v", got)
	}
}

func TestDownloadVersion_OK(t *testing.T) {
	expected := []byte("encrypted-bytes")
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/versions/V1/download") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write(expected)
	})
	defer cleanup()

	got, err := client.DownloadVersion("F1", "V1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(expected) {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestDownloadVersion_NotFound(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	defer cleanup()

	if _, err := client.DownloadVersion("F1", "missing"); err == nil {
		t.Error("expected error on 404")
	}
}

func TestRecordSnapshot_413QuotaExceeded(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"storage quota exceeded"}`, 413)
	})
	defer cleanup()

	_, err := client.RecordSnapshot("F1", RecordSnapshotRequest{
		S3VersionID: "v", StoragePath: "p", SizeBytes: 100,
	})
	if err == nil {
		t.Error("expected error on 413")
	}
}

func TestPatchVersion_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var got PatchVersionRequest
		_ = json.Unmarshal(body, &got)
		if got.Label == nil || *got.Label != "test-label" {
			t.Errorf("label not propagated: %+v", got)
		}
		_ = json.NewEncoder(w).Encode(VersionRow{ID: "V1", Label: got.Label})
	})
	defer cleanup()

	label := "test-label"
	row, err := client.PatchVersion("F1", "V1", PatchVersionRequest{Label: &label})
	if err != nil {
		t.Fatal(err)
	}
	if row.Label == nil || *row.Label != "test-label" {
		t.Errorf("response decode wrong: %+v", row)
	}
}

func TestLatestEncryptedBytes_PrefersVersion(t *testing.T) {
	versionBytes := []byte("from-version")
	mainBytes := []byte("from-main")
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			_ = json.NewEncoder(w).Encode([]VersionRow{{ID: "V1"}})
		case strings.Contains(r.URL.Path, "/versions/V1/download"):
			_, _ = w.Write(versionBytes)
		case strings.HasSuffix(r.URL.Path, "/download"):
			_, _ = w.Write(mainBytes)
		}
	})
	defer cleanup()

	got, fromVersion, err := client.LatestEncryptedBytes("F1")
	if err != nil {
		t.Fatal(err)
	}
	if !fromVersion {
		t.Error("expected fromVersion=true when versions list non-empty")
	}
	if string(got) != string(versionBytes) {
		t.Errorf("got %q, want %q", got, versionBytes)
	}
}

func TestLatestEncryptedBytes_FallsBackToMain(t *testing.T) {
	mainBytes := []byte("cold-start")
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			_, _ = w.Write([]byte("[]"))
		case strings.HasSuffix(r.URL.Path, "/download"):
			_, _ = w.Write(mainBytes)
		}
	})
	defer cleanup()

	got, fromVersion, err := client.LatestEncryptedBytes("F1")
	if err != nil {
		t.Fatal(err)
	}
	if fromVersion {
		t.Error("expected fromVersion=false when versions list empty")
	}
	if string(got) != string(mainBytes) {
		t.Errorf("got %q, want %q", got, mainBytes)
	}
}
