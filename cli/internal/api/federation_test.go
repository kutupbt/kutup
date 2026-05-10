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

func TestProxyUploadFile_PostsCorrectMultipart(t *testing.T) {
	gotFields := map[string]string{}
	gotFile := []byte(nil)
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/fed-proxy/share-1/upload") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			t.Fatal(err)
		}
		for k, v := range r.MultipartForm.Value {
			if len(v) > 0 {
				gotFields[k] = v[0]
			}
		}
		// Reject the local-upload-style "collectionId" field — fed-proxy
		// must NOT receive it (the remote infers from the share token).
		if _, exists := gotFields["collectionId"]; exists {
			t.Error("collectionId must NOT be sent on a federated upload")
		}
		fhs, ok := r.MultipartForm.File["file"]
		if !ok || len(fhs) == 0 {
			t.Fatal("missing file field")
		}
		f, _ := fhs[0].Open()
		gotFile, _ = io.ReadAll(f)
		_ = json.NewEncoder(w).Encode(ProxyUploadResponse{ID: "new-file-id"})
	})
	defer cleanup()

	resp, err := client.ProxyUploadFile("share-1",
		"meta-b64", "meta-nonce-b64",
		"key-b64", "key-nonce-b64",
		[]byte("ciphertext-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != "new-file-id" {
		t.Errorf("response id = %q", resp.ID)
	}
	if gotFields["encryptedMetadata"] != "meta-b64" ||
		gotFields["encryptedFileKey"] != "key-b64" ||
		gotFields["fileKeyNonce"] != "key-nonce-b64" ||
		gotFields["metadataNonce"] != "meta-nonce-b64" {
		t.Errorf("multipart fields wrong: %v", gotFields)
	}
	if string(gotFile) != "ciphertext-bytes" {
		t.Errorf("file body wrong: %q", gotFile)
	}
}

func TestProxyUploadFile_403WhenForbidden(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"upload not permitted"}`, 403)
	})
	defer cleanup()
	_, err := client.ProxyUploadFile("share-1", "", "", "", "", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("expected HTTP 403 error, got %v", err)
	}
}

func TestProxyUploadFile_413WhenQuotaExceeded(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"share quota exceeded"}`, 413)
	})
	defer cleanup()
	_, err := client.ProxyUploadFile("share-1", "", "", "", "", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 413") {
		t.Errorf("expected HTTP 413 error, got %v", err)
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
