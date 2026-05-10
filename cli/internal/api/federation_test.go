package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestListIncomingShares_TwoRows(t *testing.T) {
	shares := []IncomingShare{
		{ID: "s1", RemoteServer: "https://a.example", CreatedAt: time.Now()},
		{ID: "s2", RemoteServer: "https://b.example", CanUpload: true, CreatedAt: time.Now()},
	}
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fed-proxy/incoming" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(shares)
	})
	defer cleanup()

	got, err := client.ListIncomingShares()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].ID != "s2" || !got[1].CanUpload {
		t.Errorf("decode wrong: %+v", got)
	}
}

func TestAddIncomingShare_PostsInviteURL(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var got AddIncomingShareRequest
		_ = json.Unmarshal(body, &got)
		if got.InviteURL != "https://server.example/invite/abc" {
			t.Errorf("inviteUrl not propagated: %v", got)
		}
		_ = json.NewEncoder(w).Encode(IncomingShare{ID: "new-share", RemoteServer: "https://server.example"})
	})
	defer cleanup()

	got, err := client.AddIncomingShare("https://server.example/invite/abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "new-share" {
		t.Errorf("response id = %q", got.ID)
	}
}

func TestRemoveIncomingShare_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/fed-proxy/incoming/s1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(204)
	})
	defer cleanup()

	if err := client.RemoveIncomingShare("s1"); err != nil {
		t.Fatal(err)
	}
}

func TestProxyListFiles_OK(t *testing.T) {
	files := []File{
		{ID: "f1"}, {ID: "f2"},
	}
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/fed-proxy/s1/files") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(files)
	})
	defer cleanup()

	got, err := client.ProxyListFiles("s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d files, want 2", len(got))
	}
}

func TestProxyDownload_OK(t *testing.T) {
	expected := []byte("encrypted-bytes-from-remote")
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/fed-proxy/s1/files/f1/download") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write(expected)
	})
	defer cleanup()

	got, err := client.ProxyDownload("s1", "f1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(expected) {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestProxyDeleteFile_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(204)
	})
	defer cleanup()

	if err := client.ProxyDeleteFile("s1", "f1"); err != nil {
		t.Fatal(err)
	}
}
