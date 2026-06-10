//! Live SeaweedFS capacity probe — mirrors `backend/services/storageprobe.go`.
//!
//! Queries the SeaweedFS master for the cluster topology (`/dir/status`), then each volume
//! server's `/status` for real on-disk capacity + usage, and sums across the cluster. Results
//! are cached (60 s) so `/admin/stats` doesn't hammer SeaweedFS on every request. Reaching
//! SeaweedFS is best-effort: on failure `probe()` returns `None` and the caller falls back to
//! the `STORAGE_TOTAL_BYTES` env var; a previously-cached value is preferred over a hard fail.

use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(60);
const TIMEOUT: Duration = Duration::from_secs(5);

/// Aggregated real storage numbers across every volume server — mirrors `StorageStats`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StorageStats {
    pub total_bytes: i64,
    pub used_bytes: i64,
    pub free_bytes: i64,
}

/// Probes the SeaweedFS master + volume servers — mirrors `StorageProbe`.
pub struct StorageProbe {
    master_url: String,
    client: reqwest::Client,
    cache: Mutex<Option<(StorageStats, Instant)>>,
}

impl StorageProbe {
    /// Builds a probe against `master_url`; returns `None` when it's empty (probe disabled —
    /// the caller then falls back to the configured capacity). Mirrors `NewStorageProbe`.
    pub fn new(master_url: &str) -> Option<StorageProbe> {
        let master_url = master_url.trim().trim_end_matches('/').to_string();
        if master_url.is_empty() {
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(StorageProbe {
            master_url,
            client,
            cache: Mutex::new(None),
        })
    }

    /// Returns aggregated stats, refreshing the cache when stale — mirrors `Probe`. `None` only
    /// when SeaweedFS could not be reached and there is no usable cached value.
    pub async fn probe(&self) -> Option<StorageStats> {
        let mut cache = self.cache.lock().await;
        if let Some((stats, at)) = cache.as_ref() {
            if at.elapsed() < CACHE_TTL {
                return Some(*stats);
            }
        }
        match self.query().await {
            Ok(fresh) => {
                *cache = Some((fresh, Instant::now()));
                Some(fresh)
            }
            // Prefer a stale-but-real value over reporting failure.
            Err(e) => {
                tracing::warn!("storage probe failed: {e}");
                cache.as_ref().map(|(stats, _)| *stats)
            }
        }
    }

    /// The live two-hop probe: master topology → each volume `/status` — mirrors `query`.
    async fn query(&self) -> anyhow::Result<StorageStats> {
        let nodes = self.data_node_urls().await?;
        if nodes.is_empty() {
            anyhow::bail!("seaweedfs: master reported no volume servers");
        }
        let mut stats = StorageStats::default();
        for node in nodes {
            let vs: VolumeStatus = self.get_json(&format!("{node}/status")).await?;
            for d in vs.disk_statuses {
                stats.total_bytes += d.all;
                stats.used_bytes += d.used;
                stats.free_bytes += d.free;
            }
        }
        Ok(stats)
    }

    /// Walks the master topology and returns each volume server's base URL — mirrors
    /// `dataNodeURLs`.
    async fn data_node_urls(&self) -> anyhow::Result<Vec<String>> {
        let ms: MasterStatus = self
            .get_json(&format!("{}/dir/status", self.master_url))
            .await?;
        let mut urls = Vec::new();
        for dc in ms.topology.data_centers {
            for rack in dc.racks {
                for node in rack.data_nodes {
                    let mut raw = node.url.trim().to_string();
                    if raw.is_empty() {
                        raw = node.public_url.trim().to_string();
                    }
                    if raw.is_empty() {
                        continue;
                    }
                    if !raw.contains("://") {
                        raw = format!("http://{raw}");
                    }
                    let raw = raw.trim_end_matches('/').to_string();
                    if !urls.contains(&raw) {
                        urls.push(raw);
                    }
                }
            }
        }
        Ok(urls)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let resp = self.client.get(url).send().await?;
        if resp.status().as_u16() != 200 {
            anyhow::bail!("unexpected status {}", resp.status().as_u16());
        }
        Ok(resp.json().await?)
    }
}

// --- the subset of the SeaweedFS JSON we care about (exact field names) ---

#[derive(Deserialize)]
struct MasterStatus {
    #[serde(rename = "Topology", default)]
    topology: Topology,
}
#[derive(Deserialize, Default)]
struct Topology {
    #[serde(rename = "DataCenters", default)]
    data_centers: Vec<DataCenter>,
}
#[derive(Deserialize)]
struct DataCenter {
    #[serde(rename = "Racks", default)]
    racks: Vec<Rack>,
}
#[derive(Deserialize)]
struct Rack {
    #[serde(rename = "DataNodes", default)]
    data_nodes: Vec<DataNode>,
}
#[derive(Deserialize)]
struct DataNode {
    #[serde(rename = "Url", default)]
    url: String,
    #[serde(rename = "PublicUrl", default)]
    public_url: String,
}

#[derive(Deserialize)]
struct VolumeStatus {
    #[serde(rename = "DiskStatuses", default)]
    disk_statuses: Vec<DiskStatus>,
}
#[derive(Deserialize)]
struct DiskStatus {
    #[serde(default)]
    all: i64,
    #[serde(default)]
    used: i64,
    #[serde(default)]
    free: i64,
}
