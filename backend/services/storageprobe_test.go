package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// volumeServer serves a SeaweedFS-style GET /status with the given
// DiskStatuses JSON array.
func volumeServer(t *testing.T, disksJSON string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Version":"test","DiskStatuses":%s}`, disksJSON)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// masterServer serves a SeaweedFS-style GET /dir/status whose topology
// lists the given volume-server URLs as DataNodes. hits counts requests.
func masterServer(t *testing.T, dataNodeURLs []string, hits *int32) *httptest.Server {
	t.Helper()
	nodes := make([]string, len(dataNodeURLs))
	for i, u := range dataNodeURLs {
		nodes[i] = fmt.Sprintf(`{"Url":%q}`, u)
	}
	body := fmt.Sprintf(
		`{"Topology":{"DataCenters":[{"Racks":[{"DataNodes":[%s]}]}]},"Version":"test"}`,
		strings.Join(nodes, ","),
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		if r.URL.Path != "/dir/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNewStorageProbe_EmptyURLDisablesProbe(t *testing.T) {
	if NewStorageProbe("") != nil {
		t.Error("NewStorageProbe(\"\") should return nil (probe disabled)")
	}
	if NewStorageProbe("   ") != nil {
		t.Error("NewStorageProbe(whitespace) should return nil")
	}
}

func TestStorageProbe_SumsDisksAcrossOneVolume(t *testing.T) {
	vol := volumeServer(t, `[
		{"dir":"/data","all":300,"used":120,"free":180},
		{"dir":"/data2","all":200,"used":80,"free":120}
	]`)
	master := masterServer(t, []string{vol.URL}, nil)

	probe := NewStorageProbe(master.URL)
	stats, ok := probe.Probe(context.Background())
	if !ok {
		t.Fatal("Probe returned ok=false against a healthy fixture")
	}
	if stats.TotalBytes != 500 || stats.UsedBytes != 200 || stats.FreeBytes != 300 {
		t.Errorf("stats = %+v, want {Total:500 Used:200 Free:300}", stats)
	}
}

func TestStorageProbe_SumsAcrossMultipleVolumes(t *testing.T) {
	v1 := volumeServer(t, `[{"dir":"/d","all":1000,"used":400,"free":600}]`)
	v2 := volumeServer(t, `[{"dir":"/d","all":500,"used":100,"free":400}]`)
	master := masterServer(t, []string{v1.URL, v2.URL}, nil)

	stats, ok := NewStorageProbe(master.URL).Probe(context.Background())
	if !ok {
		t.Fatal("Probe ok=false")
	}
	if stats.TotalBytes != 1500 || stats.UsedBytes != 500 || stats.FreeBytes != 1000 {
		t.Errorf("stats = %+v, want {Total:1500 Used:500 Free:1000}", stats)
	}
}

func TestStorageProbe_UnreachableMasterReportsNotOK(t *testing.T) {
	// Port 1 is reserved/unused — the dial fails fast.
	probe := NewStorageProbe("http://127.0.0.1:1")
	if _, ok := probe.Probe(context.Background()); ok {
		t.Error("Probe should report ok=false when the master is unreachable")
	}
}

func TestStorageProbe_CachesWithinTTL(t *testing.T) {
	var hits int32
	vol := volumeServer(t, `[{"dir":"/d","all":100,"used":40,"free":60}]`)
	master := masterServer(t, []string{vol.URL}, &hits)

	probe := NewStorageProbe(master.URL)
	for i := 0; i < 3; i++ {
		if _, ok := probe.Probe(context.Background()); !ok {
			t.Fatalf("probe %d: ok=false", i)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("master hit %d times, want 1 (subsequent calls should be cached)", got)
	}
}
