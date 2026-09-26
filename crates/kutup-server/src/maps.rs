//! Maps (docs/plans/maps.md): which map providers the administrator offers,
//! each person's choice among them, and the relay that fetches map tiles for
//! people who would rather not reveal their address to a provider.
//!
//! Kutup stores no map data. Providers need no API key (OpenFreeMap,
//! OpenStreetMap) or are the server's own tile server. Only the administrator
//! sets upstream addresses; people only pick from that list, so the relay
//! never fetches an address a user chose. The relay keeps one shared cache,
//! sized by the administrator, which keeps it within OpenStreetMap's tile
//! usage policy (no repeated fetches) and means a provider sees occasional
//! fetches from the server rather than every view.

use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::{AdminUser, AuthUser};
use crate::ratelimit::RateLimiter;
use crate::AppState;

const SETTING_KEY: &str = "maps";
const PROXY_PREFIX: &str = "/api/maps/proxy";
const MAX_UPSTREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_PATH_CHARS: usize = 512;
const MAX_CACHE_MEGABYTES: u32 = 102_400;
/// How long a cached tile is served before asking the provider again, when
/// the provider does not say: a week, within [1 hour, 30 days].
const DEFAULT_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const MIN_TTL: Duration = Duration::from_secs(3600);
const MAX_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
const SETTINGS_REFRESH: Duration = Duration::from_secs(60);

/// A map view loads dozens of tiles at once; this bounds a runaway client.
static PROXY_LIMIT: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(1200, Duration::from_secs(60)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Openfreemap,
    Openstreetmap,
    Custom,
}

impl ProviderId {
    fn as_str(self) -> &'static str {
        match self {
            Self::Openfreemap => "openfreemap",
            Self::Openstreetmap => "openstreetmap",
            Self::Custom => "custom",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "openfreemap" => Some(Self::Openfreemap),
            "openstreetmap" => Some(Self::Openstreetmap),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TileKind {
    /// A style document (MapLibre style JSON) with vector tiles.
    Vector,
    /// Image tiles from a `{z}/{x}/{y}` template.
    Raster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Browsers always load tiles from the provider.
    Off,
    /// Each person chooses.
    Available,
    /// Browsers always load tiles through this server.
    Enforced,
}

/// The server's own tile server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomProvider {
    pub name: String,
    pub kind: TileKind,
    /// A style URL (vector) or a tile template with `{z}`, `{x}` and `{y}`
    /// (raster). May be on a private network when the relay is enforced.
    pub url: String,
    pub attribution: String,
}

/// The administrator's map settings (`site_settings.maps`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MapSettings {
    /// False turns every map feature off: nothing goes to any provider.
    pub enabled: bool,
    /// The providers people may choose, in the order offered.
    pub providers: Vec<ProviderId>,
    pub custom: Option<CustomProvider>,
    pub proxy: ProxyMode,
    /// The relay's shared tile cache; 0 turns it off.
    pub cache_megabytes: u32,
}

impl Default for MapSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            providers: vec![ProviderId::Openfreemap, ProviderId::Openstreetmap],
            custom: None,
            proxy: ProxyMode::Available,
            cache_megabytes: 2048,
        }
    }
}

impl MapSettings {
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = Vec::new();
        for provider in &self.providers {
            if seen.contains(provider) {
                return Err("a provider is listed twice".into());
            }
            seen.push(*provider);
        }
        if self.enabled && self.providers.is_empty() {
            return Err("offer at least one provider, or turn maps off".into());
        }
        if self.providers.contains(&ProviderId::Custom) != self.custom.is_some() {
            return Err("the custom provider must be both configured and offered".into());
        }
        if self.cache_megabytes > MAX_CACHE_MEGABYTES {
            return Err(format!("the cache is at most {MAX_CACHE_MEGABYTES} MB"));
        }
        if let Some(custom) = &self.custom {
            let name = custom.name.trim();
            if name.is_empty() || name.chars().count() > 60 {
                return Err("the tile server needs a name of at most 60 characters".into());
            }
            if custom.attribution.chars().count() > 200 {
                return Err("the attribution is at most 200 characters".into());
            }
            let url = url::Url::parse(&custom.url)
                .map_err(|_| "the tile server address is not a URL".to_string())?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || custom.url.len() > 500
            {
                return Err("the tile server address must be a plain http(s) URL".into());
            }
            if custom.kind == TileKind::Raster
                && !["{z}", "{x}", "{y}"]
                    .iter()
                    .all(|part| custom.url.contains(part))
            {
                return Err("a raster tile template needs {z}, {x} and {y}".into());
            }
        }
        Ok(())
    }
}

/// One provider as the relay and the browser see it.
#[derive(Debug, Clone)]
struct Upstream {
    id: ProviderId,
    name: String,
    kind: TileKind,
    /// `scheme://host[:port]`, the only address the relay fetches from.
    origin: String,
    /// The style URL or tile template, on `origin`.
    entry: String,
    attribution: String,
}

impl Upstream {
    fn resolve(id: ProviderId, settings: &MapSettings) -> Option<Self> {
        match id {
            ProviderId::Openfreemap => Some(Self {
                id,
                name: "OpenFreeMap".into(),
                kind: TileKind::Vector,
                origin: "https://tiles.openfreemap.org".into(),
                entry: "https://tiles.openfreemap.org/styles/liberty".into(),
                attribution: "OpenFreeMap © OpenMapTiles Data from OpenStreetMap".into(),
            }),
            ProviderId::Openstreetmap => Some(Self {
                id,
                name: "OpenStreetMap".into(),
                kind: TileKind::Raster,
                origin: "https://tile.openstreetmap.org".into(),
                entry: "https://tile.openstreetmap.org/{z}/{x}/{y}.png".into(),
                attribution: "© OpenStreetMap contributors".into(),
            }),
            ProviderId::Custom => {
                let custom = settings.custom.as_ref()?;
                let url = url::Url::parse(&custom.url).ok()?;
                Some(Self {
                    id,
                    name: custom.name.trim().to_owned(),
                    kind: custom.kind,
                    origin: url.origin().ascii_serialization(),
                    entry: custom.url.clone(),
                    attribution: custom.attribution.clone(),
                })
            }
        }
    }

    /// The entry point through the relay: the same path under this server.
    fn proxied_entry(&self) -> String {
        format!(
            "{PROXY_PREFIX}/{}{}",
            self.id.as_str(),
            &self.entry[self.origin.len()..]
        )
    }
}

// ----- the service -----

pub struct MapService {
    client: reqwest::Client,
    cache_dir: PathBuf,
    settings: RwLock<(MapSettings, Instant)>,
    cache: Mutex<CacheIndex>,
}

#[derive(Default)]
struct CacheIndex {
    /// key → (bytes on disk, last used)
    entries: HashMap<String, (u64, SystemTime)>,
    total: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheMeta {
    content_type: String,
    /// Seconds since the Unix epoch.
    expires_at: u64,
}

impl MapService {
    pub async fn start(pool: &PgPool, cache_dir: &str, server_url: &str) -> anyhow::Result<Self> {
        let cache_dir = if cache_dir.is_empty() {
            std::env::temp_dir().join("kutup-maps-cache")
        } else {
            PathBuf::from(cache_dir)
        };
        tokio::fs::create_dir_all(&cache_dir).await?;
        let client = reqwest::Client::builder()
            // OpenStreetMap's tile usage policy asks for an identifying agent.
            .user_agent(format!(
                "Kutup/{} (+{server_url})",
                env!("CARGO_PKG_VERSION")
            ))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()?;
        let settings = load_settings(pool).await?;
        let index = scan_cache(&cache_dir).await;
        tracing::info!(
            dir = %cache_dir.display(),
            cached = index.entries.len(),
            "map relay ready"
        );
        Ok(Self {
            client,
            cache_dir,
            settings: RwLock::new((settings, Instant::now())),
            cache: Mutex::new(index),
        })
    }

    /// The current settings, re-read from the database at most once a minute
    /// (another server process may have changed them).
    async fn settings(&self, pool: &PgPool) -> AppResult<MapSettings> {
        {
            let guard = self.settings.read().unwrap();
            if guard.1.elapsed() < SETTINGS_REFRESH {
                return Ok(guard.0.clone());
            }
        }
        let fresh = load_settings(pool)
            .await
            .map_err(|error| AppError::internal(format!("map settings: {error}")))?;
        *self.settings.write().unwrap() = (fresh.clone(), Instant::now());
        Ok(fresh)
    }

    fn replace_settings(&self, settings: MapSettings) {
        let cap = u64::from(settings.cache_megabytes) * 1024 * 1024;
        *self.settings.write().unwrap() = (settings, Instant::now());
        self.evict_to(cap);
    }

    fn entry_path(&self, key: &str, extension: &str) -> PathBuf {
        self.cache_dir.join(format!("{key}.{extension}"))
    }

    async fn cached(&self, key: &str) -> Option<(Vec<u8>, CacheMeta)> {
        let meta: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(self.entry_path(key, "meta")).await.ok()?)
                .ok()?;
        let body = tokio::fs::read(self.entry_path(key, "bin")).await.ok()?;
        if let Some(entry) = self.cache.lock().unwrap().entries.get_mut(key) {
            entry.1 = SystemTime::now();
        }
        Some((body, meta))
    }

    async fn store(&self, key: &str, body: &[u8], meta: &CacheMeta, cap: u64) {
        let size = body.len() as u64;
        if cap == 0 || size > cap {
            return;
        }
        let write = async {
            let tmp = self.entry_path(key, "tmp");
            tokio::fs::write(&tmp, body).await?;
            tokio::fs::rename(&tmp, self.entry_path(key, "bin")).await?;
            tokio::fs::write(
                self.entry_path(key, "meta"),
                serde_json::to_vec(meta).unwrap_or_default(),
            )
            .await
        };
        if let Err(error) = write.await {
            tracing::warn!(%error, "map cache write failed");
            return;
        }
        {
            let mut index = self.cache.lock().unwrap();
            if let Some((old, _)) = index
                .entries
                .insert(key.to_owned(), (size, SystemTime::now()))
            {
                index.total -= old;
            }
            index.total += size;
        }
        self.evict_to(cap);
    }

    /// Remove the least recently used tiles until the cache fits `cap`.
    fn evict_to(&self, cap: u64) {
        let victims: Vec<String> = {
            let mut index = self.cache.lock().unwrap();
            if index.total <= cap {
                return;
            }
            let mut order: Vec<(String, u64, SystemTime)> = index
                .entries
                .iter()
                .map(|(key, (size, used))| (key.clone(), *size, *used))
                .collect();
            order.sort_by_key(|entry| entry.2);
            let mut victims = Vec::new();
            for (key, size, _) in order {
                if index.total <= cap {
                    break;
                }
                index.entries.remove(&key);
                index.total -= size;
                victims.push(key);
            }
            victims
        };
        for key in victims {
            let _ = std::fs::remove_file(self.entry_path(&key, "bin"));
            let _ = std::fs::remove_file(self.entry_path(&key, "meta"));
        }
    }
}

async fn load_settings(pool: &PgPool) -> Result<MapSettings, sqlx::Error> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(SETTING_KEY)
            .fetch_optional(pool)
            .await?;
    Ok(stored
        .and_then(|value| serde_json::from_str::<MapSettings>(&value).ok())
        .filter(|settings| settings.validate().is_ok())
        .unwrap_or_default())
}

async fn scan_cache(dir: &FsPath) -> CacheIndex {
    let mut index = CacheIndex::default();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return index;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(key) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".bin"))
            .map(str::to_owned)
        else {
            continue;
        };
        if let Ok(meta) = entry.metadata().await {
            let used = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            index.total += meta.len();
            index.entries.insert(key, (meta.len(), used));
        }
    }
    index
}

// ----- what people see -----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapProviderView {
    pub id: ProviderId,
    pub name: String,
    pub kind: TileKind,
    /// Style URL (vector) or tile template (raster) at the provider.
    pub url: String,
    /// The same through this server's relay; absent when the relay is off.
    pub proxy_url: Option<String>,
    pub attribution: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MapPreferences {
    pub enabled: bool,
    pub provider: Option<ProviderId>,
    pub via_proxy: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapConfigResponse {
    /// False: the administrator turned maps off.
    pub enabled: bool,
    pub proxy: ProxyMode,
    pub providers: Vec<MapProviderView>,
    pub preferences: MapPreferences,
}

async fn preferences_of(pool: &PgPool, user_id: uuid::Uuid) -> AppResult<MapPreferences> {
    let row: Option<(bool, Option<String>, bool)> = sqlx::query_as(
        "SELECT enabled, provider, via_proxy FROM user_map_preferences WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((enabled, provider, via_proxy)) => MapPreferences {
            enabled,
            provider: provider.as_deref().and_then(ProviderId::parse),
            via_proxy,
        },
        None => MapPreferences {
            enabled: false,
            provider: None,
            via_proxy: true,
        },
    })
}

fn config_response(settings: &MapSettings, preferences: MapPreferences) -> MapConfigResponse {
    let providers = if settings.enabled {
        settings
            .providers
            .iter()
            .filter_map(|id| Upstream::resolve(*id, settings))
            .map(|upstream| MapProviderView {
                proxy_url: (settings.proxy != ProxyMode::Off).then(|| upstream.proxied_entry()),
                id: upstream.id,
                name: upstream.name,
                kind: upstream.kind,
                url: upstream.entry,
                attribution: upstream.attribution,
            })
            .collect()
    } else {
        Vec::new()
    };
    MapConfigResponse {
        enabled: settings.enabled,
        proxy: settings.proxy,
        providers,
        preferences,
    }
}

/// `GET /api/maps` — the providers on offer and your own choices.
#[utoipa::path(
    get,
    path = "/api/maps",
    tag = "maps",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Map providers and your choices", body = MapConfigResponse))
)]
pub async fn get_config(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<MapConfigResponse>> {
    let settings = state.maps.settings(&state.pool).await?;
    let preferences = preferences_of(&state.pool, trusted_uuid(&user.user_id)?).await?;
    Ok(Json(config_response(&settings, preferences)))
}

/// `PUT /api/maps/preferences` — turn maps on or off for yourself and choose
/// among the administrator's providers.
#[utoipa::path(
    put,
    path = "/api/maps/preferences",
    tag = "maps",
    security(("BearerAuth" = [])),
    request_body = MapPreferences,
    responses((status = 200, description = "Saved", body = MapConfigResponse))
)]
pub async fn put_preferences(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<MapPreferences>,
) -> AppResult<Json<MapConfigResponse>> {
    let settings = state.maps.settings(&state.pool).await?;
    if let Some(provider) = request.provider {
        if !settings.providers.contains(&provider) {
            return Err(AppError::bad_request("that map provider is not offered"));
        }
    }
    let user_id = trusted_uuid(&user.user_id)?;
    sqlx::query(
        "INSERT INTO user_map_preferences (user_id, enabled, provider, via_proxy)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE SET
             enabled = EXCLUDED.enabled,
             provider = EXCLUDED.provider,
             via_proxy = EXCLUDED.via_proxy,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(request.enabled)
    .bind(request.provider.map(ProviderId::as_str))
    .bind(request.via_proxy)
    .execute(&state.pool)
    .await?;
    Ok(Json(config_response(&settings, request)))
}

/// `GET /api/admin/maps` — the administrator's map settings.
#[utoipa::path(
    get,
    path = "/api/admin/maps",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Map settings", body = MapSettings))
)]
pub async fn admin_get(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Json<MapSettings>> {
    let settings = load_settings(&state.pool).await?;
    state.maps.replace_settings(settings.clone());
    Ok(Json(settings))
}

/// `PUT /api/admin/maps` — replace the map settings.
#[utoipa::path(
    put,
    path = "/api/admin/maps",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = MapSettings,
    responses((status = 200, description = "Saved", body = MapSettings))
)]
pub async fn admin_put(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(settings): Json<MapSettings>,
) -> AppResult<Json<MapSettings>> {
    settings.validate().map_err(AppError::bad_request)?;
    let value = serde_json::to_string(&settings)
        .map_err(|error| AppError::internal(format!("map settings: {error}")))?;
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(SETTING_KEY)
    .bind(value)
    .execute(&state.pool)
    .await?;
    crate::handlers::admin::audit(
        &state.pool,
        &admin.user_id,
        "maps.settings.update",
        None,
        serde_json::json!({
            "enabled": settings.enabled,
            "providers": settings.providers,
            "proxy": settings.proxy,
            "cacheMegabytes": settings.cache_megabytes,
        }),
    )
    .await;
    state.maps.replace_settings(settings.clone());
    Ok(Json(settings))
}

// ----- the relay -----

/// A relayed path (already percent-decoded by the router): plain segments
/// only, no `..`, no query. Font stacks have spaces ("Noto Sans Regular").
fn valid_relay_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_CHARS
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'_' | b'-' | b'@' | b',' | b'+' | b' ')
                })
        })
}

/// The provider's address for a relayed path, each segment percent-encoded.
fn upstream_url(origin: &str, path: &str) -> AppResult<url::Url> {
    let mut url = url::Url::parse(origin)
        .map_err(|_| AppError::internal("map provider origin is not a URL"))?;
    url.path_segments_mut()
        .map_err(|_| AppError::internal("map provider origin cannot take a path"))?
        .extend(path.split('/'));
    Ok(url)
}

fn allowed_content_type(value: &str) -> bool {
    let value = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        value.as_str(),
        "image/png"
            | "image/jpeg"
            | "image/webp"
            | "application/json"
            | "application/x-protobuf"
            | "application/vnd.mapbox-vector-tile"
            | "application/octet-stream"
            | "application/x-font-pbf"
    )
}

fn is_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

/// Point every URL on the provider at the relay instead, so a style's tiles,
/// glyphs and sprites are fetched through it too.
fn rewrite_json(body: &[u8], upstream: &Upstream) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    text.replace(
        &upstream.origin,
        &format!("{PROXY_PREFIX}/{}", upstream.id.as_str()),
    )
    .into_bytes()
}

fn ttl_of(cache_control: Option<&str>) -> Duration {
    cache_control
        .and_then(|value| {
            value.split(',').find_map(|directive| {
                directive
                    .trim()
                    .strip_prefix("max-age=")
                    .and_then(|seconds| seconds.parse::<u64>().ok())
            })
        })
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_TTL)
        .clamp(MIN_TTL, MAX_TTL)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn relay_response(body: Vec<u8>, content_type: &str, upstream: &Upstream) -> Response {
    let body = if is_json(content_type) {
        rewrite_json(&body, upstream)
    } else {
        body
    };
    let mut response = Response::new(Body::from(body));
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=86400"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// `GET /api/maps/proxy/{provider}/{path}` — a map resource (style, tile,
/// glyphs, sprite) fetched from the provider by this server and cached, so
/// the provider never sees the person's address.
#[utoipa::path(
    get,
    path = "/api/maps/proxy/{provider}/{path}",
    tag = "maps",
    security(("BearerAuth" = [])),
    params(
        ("provider" = String, Path, description = "openfreemap, openstreetmap or custom"),
        ("path" = String, Path, description = "The resource's path at the provider")
    ),
    responses(
        (status = 200, description = "The resource"),
        (status = 404, description = "Not offered, or not found at the provider"),
        (status = 429, description = "Too many requests")
    )
)]
pub async fn proxy(
    State(state): State<AppState>,
    user: AuthUser,
    Path((provider, path)): Path<(String, String)>,
) -> AppResult<Response> {
    if !PROXY_LIMIT.allow(&user.user_id) {
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many map requests",
        ));
    }
    let settings = state.maps.settings(&state.pool).await?;
    let not_offered = || AppError::not_found("map provider not offered");
    let id = ProviderId::parse(&provider).ok_or_else(not_offered)?;
    if !settings.enabled || settings.proxy == ProxyMode::Off || !settings.providers.contains(&id) {
        return Err(not_offered());
    }
    let upstream = Upstream::resolve(id, &settings).ok_or_else(not_offered)?;
    if !valid_relay_path(&path) {
        return Err(AppError::bad_request("invalid map path"));
    }
    let key = hex::encode(Sha256::digest(
        format!("{}\0{}\0{path}", id.as_str(), upstream.origin).as_bytes(),
    ));
    let cap = u64::from(settings.cache_megabytes) * 1024 * 1024;
    let cached = if cap > 0 {
        state.maps.cached(&key).await
    } else {
        None
    };
    if let Some((body, meta)) = &cached {
        if meta.expires_at > now_secs() {
            return Ok(relay_response(body.clone(), &meta.content_type, &upstream));
        }
    }

    let fetched = async {
        let response = state
            .maps
            .client
            .get(upstream_url(&upstream.origin, &path)?)
            .send()
            .await
            .map_err(|error| {
                AppError::new(StatusCode::BAD_GATEWAY, format!("map provider: {error}"))
            })?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::NO_CONTENT {
            return Err(AppError::not_found("not found at the map provider"));
        }
        if !status.is_success() {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("map provider answered {status}"),
            ));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        if !allowed_content_type(&content_type) {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "map provider sent an unexpected kind of file",
            ));
        }
        let ttl = ttl_of(
            response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
        );
        if response
            .content_length()
            .is_some_and(|length| length as usize > MAX_UPSTREAM_BYTES)
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "map resource is too large",
            ));
        }
        let mut body = Vec::new();
        let mut stream = response;
        while let Some(chunk) = stream.chunk().await.map_err(|error| {
            AppError::new(StatusCode::BAD_GATEWAY, format!("map provider: {error}"))
        })? {
            if body.len() + chunk.len() > MAX_UPSTREAM_BYTES {
                return Err(AppError::new(
                    StatusCode::BAD_GATEWAY,
                    "map resource is too large",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((body, content_type, ttl))
    }
    .await;

    match fetched {
        Ok((body, content_type, ttl)) => {
            let meta = CacheMeta {
                content_type: content_type.clone(),
                expires_at: now_secs() + ttl.as_secs(),
            };
            state.maps.store(&key, &body, &meta, cap).await;
            Ok(relay_response(body, &content_type, &upstream))
        }
        // An expired copy beats no map while the provider is unreachable.
        Err(error) if error.status == StatusCode::BAD_GATEWAY => match cached {
            Some((body, meta)) => Ok(relay_response(body, &meta.content_type, &upstream)),
            None => Err(error),
        },
        Err(error) => Err(error),
    }
    .map(IntoResponse::into_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_valid() {
        assert!(MapSettings::default().validate().is_ok());
    }

    #[test]
    fn settings_are_checked() {
        let mut settings = MapSettings {
            providers: vec![ProviderId::Openfreemap, ProviderId::Openfreemap],
            ..MapSettings::default()
        };
        assert!(settings.validate().is_err(), "duplicate provider");
        settings.providers = vec![];
        assert!(settings.validate().is_err(), "maps on with nothing offered");
        settings.enabled = false;
        assert!(settings.validate().is_ok(), "maps off may offer nothing");
        settings.enabled = true;
        settings.providers = vec![ProviderId::Custom];
        assert!(
            settings.validate().is_err(),
            "custom offered but not configured"
        );
        settings.custom = Some(CustomProvider {
            name: "Our tiles".into(),
            kind: TileKind::Raster,
            url: "http://tiles.internal:8080/tile/{z}/{x}/{y}.png".into(),
            attribution: "© OpenStreetMap contributors".into(),
        });
        assert!(settings.validate().is_ok());
        settings.custom.as_mut().unwrap().url = "http://tiles.internal:8080/tile.png".into();
        assert!(
            settings.validate().is_err(),
            "raster template without z/x/y"
        );
        settings.custom.as_mut().unwrap().url = "ftp://tiles.internal/{z}/{x}/{y}".into();
        assert!(settings.validate().is_err(), "not http(s)");
        settings.custom.as_mut().unwrap().url = "http://user:pw@tiles/{z}/{x}/{y}".into();
        assert!(settings.validate().is_err(), "credentials in the URL");
        settings.custom = None;
        settings.providers = vec![ProviderId::Openstreetmap];
        settings.cache_megabytes = MAX_CACHE_MEGABYTES + 1;
        assert!(settings.validate().is_err(), "cache too large");
    }

    #[test]
    fn relay_paths_stay_on_the_provider() {
        for good in [
            "styles/liberty",
            "planet/20250101_001001_pt/14/8800/5373.pbf",
            "fonts/Noto Sans Regular,Noto Sans Bold/0-255.pbf",
            "sprites/ofm_f384/ofm@2x.png",
            "14/8800/5373.png",
        ] {
            assert!(valid_relay_path(good), "{good}");
        }
        for bad in [
            "",
            "../etc/passwd",
            "a/../b",
            "a//b",
            "/abs",
            "a/./b",
            "tile?x=1",
            "evil.com:80/x",
            "a\\b",
            "a%2fb",
        ] {
            assert!(!valid_relay_path(bad), "{bad}");
        }
    }

    #[test]
    fn upstream_addresses_are_encoded() {
        assert_eq!(
            upstream_url(
                "https://tiles.openfreemap.org",
                "fonts/Noto Sans Regular/0-255.pbf"
            )
            .unwrap()
            .as_str(),
            "https://tiles.openfreemap.org/fonts/Noto%20Sans%20Regular/0-255.pbf"
        );
    }

    #[test]
    fn styles_are_pointed_at_the_relay() {
        let settings = MapSettings::default();
        let upstream = Upstream::resolve(ProviderId::Openfreemap, &settings).unwrap();
        let style = br#"{"sources":{"openmaptiles":{"url":"https://tiles.openfreemap.org/planet"}},"glyphs":"https://tiles.openfreemap.org/fonts/{fontstack}/{range}.pbf"}"#;
        let rewritten = String::from_utf8(rewrite_json(style, &upstream)).unwrap();
        assert!(!rewritten.contains("tiles.openfreemap.org"));
        assert!(rewritten.contains(r#""url":"/api/maps/proxy/openfreemap/planet""#));
        assert_eq!(
            upstream.proxied_entry(),
            "/api/maps/proxy/openfreemap/styles/liberty"
        );
        let osm = Upstream::resolve(ProviderId::Openstreetmap, &settings).unwrap();
        assert_eq!(
            osm.proxied_entry(),
            "/api/maps/proxy/openstreetmap/{z}/{x}/{y}.png"
        );
    }

    #[test]
    fn cache_lifetimes_are_bounded() {
        assert_eq!(ttl_of(None), DEFAULT_TTL);
        assert_eq!(ttl_of(Some("public, max-age=60")), MIN_TTL);
        assert_eq!(ttl_of(Some("max-age=604800")), Duration::from_secs(604_800));
        assert_eq!(ttl_of(Some("max-age=99999999")), MAX_TTL);
    }

    #[test]
    fn only_map_resources_are_relayed() {
        assert!(allowed_content_type("image/png"));
        assert!(allowed_content_type("application/json; charset=utf-8"));
        assert!(allowed_content_type("application/x-protobuf"));
        assert!(!allowed_content_type("text/html"));
        assert!(!allowed_content_type("application/javascript"));
    }
}
