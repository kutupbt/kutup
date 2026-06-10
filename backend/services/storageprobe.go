package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// StorageStats is the result of a SeaweedFS capacity probe — real disk
// numbers aggregated across every volume server in the cluster.
type StorageStats struct {
	TotalBytes int64
	UsedBytes  int64
	FreeBytes  int64
}

// StorageProbe queries the SeaweedFS master for the cluster topology, then
// each volume server's /status for real disk capacity + usage. Results are
// cached (storageProbeCacheTTL) so /admin/stats doesn't hammer SeaweedFS on
// every request — capacity barely moves second-to-second.
//
// Reaching SeaweedFS is best-effort: on any failure Probe reports ok=false
// and the caller falls back to the STORAGE_TOTAL_BYTES env var. A
// previously-cached value is preferred over a hard failure.
type StorageProbe struct {
	masterURL string
	client    *http.Client

	mu       sync.Mutex
	cached   StorageStats
	cachedOK bool
	cachedAt time.Time
}

const (
	storageProbeCacheTTL = 60 * time.Second
	storageProbeTimeout  = 5 * time.Second
	// Cap probe response bodies — SeaweedFS status payloads are small;
	// anything larger is almost certainly not what we expect.
	storageProbeMaxBody = 4 << 20 // 4 MiB
)

// NewStorageProbe builds a probe against the given SeaweedFS master URL.
// Returns nil when masterURL is empty — the caller treats nil as "probe
// disabled" and falls back to the configured capacity.
func NewStorageProbe(masterURL string) *StorageProbe {
	masterURL = strings.TrimRight(strings.TrimSpace(masterURL), "/")
	if masterURL == "" {
		return nil
	}
	return &StorageProbe{
		masterURL: masterURL,
		client: &http.Client{
			Timeout: storageProbeTimeout,
			// Block redirects — we only ever hit known internal URLs;
			// refusing to follow is basic SSRF hygiene.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Probe returns aggregated storage stats, refreshing the cache when stale.
// ok is false only when SeaweedFS could not be reached and there is no
// usable cached value.
func (p *StorageProbe) Probe(ctx context.Context) (stats StorageStats, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cachedOK && time.Since(p.cachedAt) < storageProbeCacheTTL {
		return p.cached, true
	}

	fresh, err := p.query(ctx)
	if err != nil {
		// Prefer a stale-but-real value over reporting failure.
		if p.cachedOK {
			return p.cached, true
		}
		return StorageStats{}, false
	}

	p.cached = fresh
	p.cachedOK = true
	p.cachedAt = time.Now()
	return fresh, true
}

// query does the live two-hop probe: master topology → each volume /status.
func (p *StorageProbe) query(ctx context.Context) (StorageStats, error) {
	nodes, err := p.dataNodeURLs(ctx)
	if err != nil {
		return StorageStats{}, err
	}
	if len(nodes) == 0 {
		return StorageStats{}, fmt.Errorf("seaweedfs: master reported no volume servers")
	}

	var stats StorageStats
	for _, node := range nodes {
		disks, err := p.diskStatuses(ctx, node)
		if err != nil {
			return StorageStats{}, err
		}
		for _, d := range disks {
			stats.TotalBytes += d.All
			stats.UsedBytes += d.Used
			stats.FreeBytes += d.Free
		}
	}
	return stats, nil
}

// masterStatus is the subset of SeaweedFS's GET /dir/status we care about.
type masterStatus struct {
	Topology struct {
		DataCenters []struct {
			Racks []struct {
				DataNodes []struct {
					URL       string `json:"Url"`
					PublicURL string `json:"PublicUrl"`
				} `json:"DataNodes"`
			} `json:"Racks"`
		} `json:"DataCenters"`
	} `json:"Topology"`
}

// dataNodeURLs walks the master topology and returns each volume server's
// base URL (scheme-qualified, ready to append /status).
func (p *StorageProbe) dataNodeURLs(ctx context.Context) ([]string, error) {
	var ms masterStatus
	if err := p.getJSON(ctx, p.masterURL+"/dir/status", &ms); err != nil {
		return nil, fmt.Errorf("seaweedfs master probe: %w", err)
	}
	var urls []string
	seen := map[string]bool{}
	for _, dc := range ms.Topology.DataCenters {
		for _, rack := range dc.Racks {
			for _, node := range rack.DataNodes {
				raw := node.URL
				if raw == "" {
					raw = node.PublicURL
				}
				raw = strings.TrimSpace(raw)
				if raw == "" {
					continue
				}
				if !strings.Contains(raw, "://") {
					raw = "http://" + raw
				}
				raw = strings.TrimRight(raw, "/")
				if !seen[raw] {
					seen[raw] = true
					urls = append(urls, raw)
				}
			}
		}
	}
	return urls, nil
}

// diskStatus is one disk's byte counts from a volume server's /status.
type diskStatus struct {
	Dir  string `json:"dir"`
	All  int64  `json:"all"`
	Used int64  `json:"used"`
	Free int64  `json:"free"`
}

// volumeStatus is the subset of a volume server's GET /status we care about.
type volumeStatus struct {
	DiskStatuses []diskStatus `json:"DiskStatuses"`
}

func (p *StorageProbe) diskStatuses(ctx context.Context, nodeURL string) ([]diskStatus, error) {
	var vs volumeStatus
	if err := p.getJSON(ctx, nodeURL+"/status", &vs); err != nil {
		return nil, fmt.Errorf("seaweedfs volume probe (%s): %w", nodeURL, err)
	}
	return vs.DiskStatuses, nil
}

// getJSON fetches url and decodes the JSON body into dst.
func (p *StorageProbe) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, storageProbeMaxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}
