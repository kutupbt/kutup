//! `GET /api/health/ready` (docs/plans/restore-drill-and-alerting.md, Part 2
//! A): whether the server can do its work, not only whether it answers. The
//! database answers, a small object is written, read back and deleted, the
//! mail server takes a connection (where mail is on), each background job
//! succeeded within its window, and the newest backups are recent enough.
//! One JSON with a status per check; 503 when any fails.
//!
//! Only an administrator's session, or a request from this machine or the
//! internal network (and, through the proxy, from a client there too), may
//! ask: the answer names jobs and backups, and each request writes to the
//! object store.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::middleware::AdminAccount;
use crate::site_settings::{
    HEALTH_BACKUP_MAX_AGE_SECONDS, HEALTH_JOB_GRACE_SECONDS, HEALTH_PROBE_TIMEOUT_SECONDS,
};
use crate::AppState;

/// A check's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum CheckStatus {
    /// It passed.
    Ok,
    /// Not failed yet: a job this server started recently that hasn't had
    /// its first success.
    Starting,
    /// Not checked here (mail off, or the backup check turned off).
    Off,
    /// It failed: a person should look.
    Fail,
}

impl CheckStatus {
    fn failed(self) -> bool {
        self == CheckStatus::Fail
    }
}

/// One probe: its outcome, how long it took and, when it failed, why.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProbeCheck {
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One background job.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobCheck {
    pub name: String,
    pub status: CheckStatus,
    pub interval_seconds: u64,
    /// The last successful pass, by this server or an earlier run of it.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_success_at: Option<OffsetDateTime>,
}

/// The background jobs this server runs.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobsCheck {
    pub status: CheckStatus,
    pub jobs: Vec<JobCheck>,
}

/// The newest backup of one kind, as its script recorded it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupCheck {
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub finished_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<i64>,
}

/// The newest database and mail backups.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupsCheck {
    pub status: CheckStatus,
    /// The oldest the newest backup may be, in seconds (0: not checked).
    pub max_age_seconds: i64,
    pub database: BackupCheck,
    pub mail: BackupCheck,
}

/// Every check.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessChecks {
    pub database: ProbeCheck,
    pub storage: ProbeCheck,
    pub mail: ProbeCheck,
    pub jobs: JobsCheck,
    pub backups: BackupsCheck,
}

/// `GET /api/health/ready`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessResponse {
    /// `ok`, or `fail` when any check failed.
    pub status: CheckStatus,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub checked_at: OffsetDateTime,
    pub checks: ReadinessChecks,
}

/// Whether an address is this machine's or the internal network's:
/// loopback, private (RFC 1918), unique local (fc00::/7) or link-local.
pub fn internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return internal_ip(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Whether a request comes from the internal network: the socket's peer is
/// internal, and so is every client the proxy names (`X-Real-IP`, each
/// `X-Forwarded-For` hop). A `Forwarded` header, or a hop that isn't an
/// address, counts as outside.
pub fn from_internal_network(peer: Option<SocketAddr>, headers: &HeaderMap) -> bool {
    let Some(peer) = peer else {
        return false;
    };
    if !internal_ip(peer.ip()) || headers.contains_key("forwarded") {
        return false;
    }
    for name in ["x-real-ip", "x-forwarded-for"] {
        for value in headers.get_all(name) {
            let Ok(value) = value.to_str() else {
                return false;
            };
            for hop in value
                .split(',')
                .map(str::trim)
                .filter(|hop| !hop.is_empty())
            {
                match hop.parse::<IpAddr>() {
                    Ok(ip) if internal_ip(ip) => {}
                    _ => return false,
                }
            }
        }
    }
    true
}

/// `GET /api/health/ready` — readiness: the database, the object store,
/// the mail server, the background jobs and the backups, each with its own
/// status. 200 when none failed, 503 otherwise.
#[utoipa::path(
    get,
    path = "/api/health/ready",
    tag = "health",
    security((), ("BearerAuth" = [])),
    responses(
        (status = 200, description = "Every check passed (or is off, or starting)", body = ReadinessResponse),
        (status = 503, description = "At least one check failed", body = ReadinessResponse),
        (status = 401, description = "Not from the internal network, and no session"),
        (status = 403, description = "Not from the internal network, and not an administrator"),
    )
)]
pub async fn ready(State(state): State<AppState>, request: Request) -> Response {
    let (mut parts, _) = request.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    if !from_internal_network(peer, &parts.headers) {
        if let Err(rejection) = AdminAccount::from_request_parts(&mut parts, &state).await {
            return rejection.into_response();
        }
    }
    let report = check(&state).await;
    let code = if report.status.failed() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, Json(report)).into_response()
}

/// Runs every check.
pub async fn check(state: &AppState) -> ReadinessResponse {
    let timeout = Duration::from_secs(
        HEALTH_PROBE_TIMEOUT_SECONDS
            .load(&state.pool)
            .await
            .unwrap_or(HEALTH_PROBE_TIMEOUT_SECONDS.default)
            .max(1) as u64,
    );
    let (database, storage, mail) = tokio::join!(
        probe(timeout, database(state)),
        probe(timeout, storage(state)),
        mail(state, timeout),
    );
    let jobs = jobs(state).await;
    let backups = backups(state).await;
    let failed = [&database, &storage, &mail]
        .iter()
        .any(|check| check.status.failed())
        || jobs.status.failed()
        || backups.status.failed();
    ReadinessResponse {
        status: if failed {
            CheckStatus::Fail
        } else {
            CheckStatus::Ok
        },
        checked_at: OffsetDateTime::now_utc(),
        checks: ReadinessChecks {
            database,
            storage,
            mail,
            jobs,
            backups,
        },
    }
}

/// Runs one probe within `timeout`, timed.
async fn probe(
    timeout: Duration,
    work: impl std::future::Future<Output = anyhow::Result<()>>,
) -> ProbeCheck {
    let started = Instant::now();
    let outcome = match tokio::time::timeout(timeout, work).await {
        Ok(outcome) => outcome,
        Err(_) => Err(anyhow::anyhow!("no answer within {} s", timeout.as_secs())),
    };
    let millis = Some(started.elapsed().as_millis() as u64);
    match outcome {
        Ok(()) => ProbeCheck {
            status: CheckStatus::Ok,
            millis,
            error: None,
        },
        Err(error) => ProbeCheck {
            status: CheckStatus::Fail,
            millis,
            error: Some(format!("{error:#}")),
        },
    }
}

async fn database(state: &AppState) -> anyhow::Result<()> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await?;
    Ok(())
}

/// Where the storage probe writes (one object per check, removed at once).
pub const PROBE_PREFIX: &str = "kutup-health/";

async fn storage(state: &AppState) -> anyhow::Result<()> {
    // The probe's own object: written, read and removed at once, never
    // queued (no database row ever names it).
    let storage = state.storage.immediate();
    let key = format!("{PROBE_PREFIX}{}", uuid::Uuid::new_v4());
    let body = format!("kutup readiness {key}").into_bytes();
    storage
        .upload(
            &key,
            aws_sdk_s3::primitives::ByteStream::from(body.clone()),
            body.len() as i64,
        )
        .await?;
    let read = async {
        let (stream, _) = storage.get_object(&key).await?;
        let bytes = stream.collect().await?.into_bytes();
        anyhow::ensure!(bytes.as_ref() == body.as_slice(), "read back other bytes");
        Ok(())
    }
    .await;
    let removed = storage.delete(&key).await;
    read?;
    removed
}

/// Mail is on where the LMTP receiver is (`MAIL_INBOUND_TOKEN`); then
/// Stalwart's submission port must take a connection.
async fn mail(state: &AppState, timeout: Duration) -> ProbeCheck {
    if state.config.mail_inbound_token.is_empty() {
        return ProbeCheck {
            status: CheckStatus::Off,
            millis: None,
            error: None,
        };
    }
    let address = state.config.mail_submission_addr.clone();
    probe(timeout, async move {
        tokio::net::TcpStream::connect(&address).await?;
        Ok(())
    })
    .await
}

async fn jobs(state: &AppState) -> JobsCheck {
    let grace = Duration::from_secs(
        HEALTH_JOB_GRACE_SECONDS
            .load(&state.pool)
            .await
            .unwrap_or(HEALTH_JOB_GRACE_SECONDS.default)
            .max(0) as u64,
    );
    let rows: Result<Vec<(String, OffsetDateTime)>, sqlx::Error> =
        sqlx::query_as("SELECT job, last_success_at FROM job_heartbeats")
            .fetch_all(&state.pool)
            .await;
    let Ok(rows) = rows else {
        return JobsCheck {
            status: CheckStatus::Fail,
            jobs: Vec::new(),
        };
    };
    let last: std::collections::HashMap<String, OffsetDateTime> = rows.into_iter().collect();
    let now = OffsetDateTime::now_utc();
    let jobs: Vec<JobCheck> = crate::job_health::registered()
        .into_iter()
        .map(|(name, registered)| {
            let last_success_at = last.get(name).copied();
            let status = match crate::job_health::judge(now, &registered, last_success_at, grace) {
                crate::job_health::JobState::Ok => CheckStatus::Ok,
                crate::job_health::JobState::Starting => CheckStatus::Starting,
                crate::job_health::JobState::Late => CheckStatus::Fail,
            };
            JobCheck {
                name: name.to_owned(),
                status,
                interval_seconds: registered.interval.as_secs(),
                last_success_at,
            }
        })
        .collect();
    let status = if jobs.iter().any(|job| job.status.failed()) {
        CheckStatus::Fail
    } else {
        CheckStatus::Ok
    };
    JobsCheck { status, jobs }
}

async fn backups(state: &AppState) -> BackupsCheck {
    let max_age = HEALTH_BACKUP_MAX_AGE_SECONDS
        .load(&state.pool)
        .await
        .unwrap_or(HEALTH_BACKUP_MAX_AGE_SECONDS.default);
    let off = || BackupCheck {
        status: CheckStatus::Off,
        name: None,
        finished_at: None,
        age_seconds: None,
    };
    let rows: Result<Vec<(String, String, OffsetDateTime)>, sqlx::Error> =
        sqlx::query_as("SELECT kind, name, finished_at FROM backup_runs")
            .fetch_all(&state.pool)
            .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(_) if max_age == 0 => Vec::new(),
        Err(_) => {
            return BackupsCheck {
                status: CheckStatus::Fail,
                max_age_seconds: max_age,
                database: BackupCheck {
                    status: CheckStatus::Fail,
                    ..off()
                },
                mail: off(),
            }
        }
    };
    let now = OffsetDateTime::now_utc();
    let judge = |kind: &str, checked: bool| {
        let row = rows.iter().find(|(k, _, _)| k == kind);
        let age_seconds = row.map(|(_, _, at)| (now - *at).whole_seconds());
        let status = if !checked {
            CheckStatus::Off
        } else {
            match age_seconds {
                Some(age) if age <= max_age => CheckStatus::Ok,
                _ => CheckStatus::Fail,
            }
        };
        BackupCheck {
            status,
            name: row.map(|(_, name, _)| name.clone()),
            finished_at: row.map(|(_, _, at)| *at),
            age_seconds,
        }
    };
    let database = judge("database", max_age > 0);
    let mail = judge(
        "mail",
        max_age > 0 && !state.config.mail_inbound_token.is_empty(),
    );
    let status = if max_age == 0 {
        CheckStatus::Off
    } else if database.status.failed() || mail.status.failed() {
        CheckStatus::Fail
    } else {
        CheckStatus::Ok
    };
    BackupsCheck {
        status,
        max_age_seconds: max_age,
        database,
        mail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn peer(ip: &str) -> Option<SocketAddr> {
        Some(SocketAddr::new(ip.parse().unwrap(), 40000))
    }

    #[test]
    fn internal_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.18.0.5",
            "192.168.1.9",
            "169.254.1.1",
            "::1",
            "fd00::5",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(internal_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "::ffff:1.1.1.1"] {
            assert!(!internal_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn a_proxied_outside_client_is_not_internal() {
        let mut headers = HeaderMap::new();
        // Straight from the internal network.
        assert!(from_internal_network(peer("172.18.0.3"), &headers));
        assert!(from_internal_network(peer("127.0.0.1"), &headers));
        // No peer known, or an outside one.
        assert!(!from_internal_network(None, &headers));
        assert!(!from_internal_network(peer("203.0.113.9"), &headers));
        // Through the proxy, for a client on the internal network.
        headers.insert("x-real-ip", HeaderValue::from_static("192.168.1.20"));
        assert!(from_internal_network(peer("172.18.0.3"), &headers));
        // Through the proxy, for an outside client.
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        assert!(!from_internal_network(peer("172.18.0.3"), &headers));
        // Any outside hop, or one that isn't an address, is outside.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 198.51.100.4"),
        );
        assert!(!from_internal_network(peer("172.18.0.3"), &headers));
        headers.insert("x-forwarded-for", HeaderValue::from_static("unknown"));
        assert!(!from_internal_network(peer("172.18.0.3"), &headers));
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", HeaderValue::from_static("for=10.0.0.1"));
        assert!(!from_internal_network(peer("172.18.0.3"), &headers));
    }
}
