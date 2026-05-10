package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestGetPublicShare_OK(t *testing.T) {
	want := PublicShare{
		ID: "S1", ShareType: "collection", TargetID: "C1",
	}
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/share/tok123") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(want)
	})
	defer cleanup()

	got, err := client.GetPublicShare("tok123")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "S1" || got.ShareType != "collection" {
		t.Errorf("decode wrong: %+v", got)
	}
}

func TestGetPublicShare_404(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	defer cleanup()
	if _, err := client.GetPublicShare("missing"); err == nil {
		t.Error("expected 404 error")
	}
}

func TestListPublicShareFiles_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/share/tok/files") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]File{{ID: "F1"}, {ID: "F2"}})
	})
	defer cleanup()

	got, err := client.ListPublicShareFiles("tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d files, want 2", len(got))
	}
}

func TestPublicShareDownloadURL_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DownloadURLResponse{URL: "https://s3/presigned/abc"})
	})
	defer cleanup()
	res, err := client.PublicShareDownloadURL("tok", "F1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.URL, "https://") {
		t.Errorf("bad URL: %q", res.URL)
	}
}

func TestUpdateFileMetadata_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	})
	defer cleanup()
	if err := client.UpdateFileMetadata("F1", UpdateFileMetadataRequest{
		EncryptedMetadata: "abc", MetadataNonce: "def",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateCollectionColor_OK(t *testing.T) {
	client, cleanup := newMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(204)
	})
	defer cleanup()
	if err := client.UpdateCollectionColor("C1", "#ef4444"); err != nil {
		t.Fatal(err)
	}
}
