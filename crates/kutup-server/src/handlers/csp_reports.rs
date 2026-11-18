//! Content-Security-Policy violation reports from the web apps
//! (docs/content-security-policy.md). Browsers send one when a page breaks
//! its policy, enforced or report-only: `report-uri` posts
//! `application/csp-report`, the Reporting API (`report-to`) posts
//! `application/reports+json`.
//!
//! A report names the page and what was blocked, with paths and queries that
//! can carry a share token, a file id or a search; the server keeps none of
//! it. It logs, at warn level, only the app's host, the directive broken and
//! the origin (or the kind: inline, eval, data, blob) of what was blocked.
//! Nothing is stored. Anyone may post; a small body limit and a per-address
//! limit (`RATE_LIMIT_CSP_REPORTS_PER_MIN`) keep it from being a log flood.

use axum::body::Bytes;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

/// The largest body taken: a browser's report is well under 4 KiB; a batch
/// of Reporting API reports a few of them.
pub const BODY_LIMIT: usize = 64 * 1024;
/// Reports logged from one body; the rest are dropped.
const MAX_REPORTS: usize = 20;

/// What a report is reduced to before it is logged.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    /// The page's host (`drive.example.org`), or `-`.
    host: String,
    /// The directive broken (`script-src-elem`), or `-`.
    directive: String,
    /// The blocked resource's origin, or its kind (`inline`, `eval`,
    /// `data`, `blob`, …), or `-`.
    blocked: String,
    /// `enforce` or `report`, or `-`.
    disposition: String,
}

/// `POST /api/csp-report` — a browser's report of a page breaking its
/// Content-Security-Policy. Anonymous; logged in part, never stored.
#[utoipa::path(
    post,
    path = "/api/csp-report",
    tag = "account",
    request_body(
        content = String,
        description = "A CSP violation report: `application/csp-report` (report-uri) or \
                       `application/reports+json` (Reporting API)",
        content_type = "application/csp-report"
    ),
    responses(
        (status = 204, description = "Received"),
        (status = 413, description = "The body is too large"),
        (status = 415, description = "Not a report"),
        (status = 429, description = "Too many reports from this address")
    )
)]
pub async fn csp_report(headers: HeaderMap, body: Bytes) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let reports = match content_type.as_str() {
        "application/csp-report" | "application/json" => serde_json::from_slice::<Value>(&body)
            .ok()
            .map(from_report_uri),
        "application/reports+json" => serde_json::from_slice::<Value>(&body)
            .ok()
            .map(from_reporting_api),
        _ => return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    };
    for violation in reports.unwrap_or_default().into_iter().take(MAX_REPORTS) {
        tracing::warn!(
            host = %violation.host,
            directive = %violation.directive,
            blocked = %violation.blocked,
            disposition = %violation.disposition,
            "content security policy violation"
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `{"csp-report": {"document-uri", "violated-directive", "effective-directive", "blocked-uri", "disposition"}}`.
fn from_report_uri(value: Value) -> Vec<Violation> {
    let Some(report) = value.get("csp-report") else {
        return Vec::new();
    };
    let text = |key: &str| report.get(key).and_then(Value::as_str);
    vec![Violation {
        host: host_of(text("document-uri")),
        directive: directive_of(text("effective-directive").or(text("violated-directive"))),
        blocked: blocked_of(text("blocked-uri")),
        disposition: disposition_of(text("disposition")),
    }]
}

/// `[{"type": "csp-violation", "body": {"documentURL", "effectiveDirective", "blockedURL", "disposition"}}]`.
fn from_reporting_api(value: Value) -> Vec<Violation> {
    let Some(reports) = value.as_array() else {
        return Vec::new();
    };
    reports
        .iter()
        .filter(|report| report.get("type").and_then(Value::as_str) == Some("csp-violation"))
        .filter_map(|report| report.get("body"))
        .map(|body| {
            let text = |key: &str| body.get(key).and_then(Value::as_str);
            Violation {
                host: host_of(text("documentURL")),
                directive: directive_of(text("effectiveDirective")),
                blocked: blocked_of(text("blockedURL")),
                disposition: disposition_of(text("disposition")),
            }
        })
        .collect()
}

/// A page address's host, lowercased; `-` when it has none.
fn host_of(url: Option<&str>) -> String {
    url.and_then(|url| url::Url::parse(url).ok())
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_else(|| "-".into())
}

/// A directive's name (`script-src-elem`): letters and `-` only, the first
/// word of a `violated-directive` that carries its sources.
fn directive_of(directive: Option<&str>) -> String {
    directive
        .and_then(|d| d.split_whitespace().next())
        .filter(|d| d.len() <= 40 && d.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        .map(str::to_owned)
        .unwrap_or_else(|| "-".into())
}

/// What was blocked: a URL's origin, a scheme's name for `data:`, `blob:`
/// and the like, or the browser's keyword (`inline`, `eval`, `wasm-eval`,
/// `trusted-types-policy`, …). Never a path or a query.
fn blocked_of(blocked: Option<&str>) -> String {
    let Some(blocked) = blocked.map(str::trim).filter(|b| !b.is_empty()) else {
        return "-".into();
    };
    if let Ok(url) = url::Url::parse(blocked) {
        let origin = url.origin();
        if origin.is_tuple() {
            return origin.ascii_serialization();
        }
        return url.scheme().to_ascii_lowercase();
    }
    // A keyword, or a scheme alone (`data`, `blob` in older reports).
    let keyword = blocked.trim_end_matches(':');
    if keyword.len() <= 40
        && keyword
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        keyword.to_ascii_lowercase()
    } else {
        "-".into()
    }
}

fn disposition_of(disposition: Option<&str>) -> String {
    match disposition {
        Some("enforce") => "enforce".into(),
        Some("report") => "report".into(),
        _ => "-".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_report_uri_report_keeps_no_path_or_query() {
        let reports = from_report_uri(json!({
            "csp-report": {
                "document-uri": "https://Drive.example.org/s/secret-token/file?q=private",
                "violated-directive": "img-src 'self' data: blob:",
                "effective-directive": "img-src",
                "blocked-uri": "https://tracker.example.com/pixel.gif?user=42",
                "disposition": "report"
            }
        }));
        assert_eq!(
            reports,
            vec![Violation {
                host: "drive.example.org".into(),
                directive: "img-src".into(),
                blocked: "https://tracker.example.com".into(),
                disposition: "report".into(),
            }]
        );
    }

    #[test]
    fn reporting_api_batches_are_read_and_other_kinds_skipped() {
        let reports = from_reporting_api(json!([
            {
                "type": "csp-violation",
                "url": "https://mail.example.org/inbox",
                "body": {
                    "documentURL": "https://mail.example.org/inbox/123",
                    "effectiveDirective": "script-src-elem",
                    "blockedURL": "inline",
                    "disposition": "enforce"
                }
            },
            { "type": "deprecation", "body": { "id": "x" } }
        ]));
        assert_eq!(
            reports,
            vec![Violation {
                host: "mail.example.org".into(),
                directive: "script-src-elem".into(),
                blocked: "inline".into(),
                disposition: "enforce".into(),
            }]
        );
    }

    #[test]
    fn blocked_resources_become_origins_or_kinds() {
        assert_eq!(
            blocked_of(Some("blob:https://chat.example.org/1234")),
            "https://chat.example.org"
        );
        assert_eq!(blocked_of(Some("data:image/png;base64,AAAA")), "data");
        assert_eq!(blocked_of(Some("data")), "data");
        assert_eq!(blocked_of(Some("eval")), "eval");
        assert_eq!(blocked_of(Some("wasm-eval")), "wasm-eval");
        assert_eq!(
            blocked_of(Some("wss://sfu.example.org/rtc?access_token=x")),
            "wss://sfu.example.org"
        );
        assert_eq!(blocked_of(Some("<script>alert(1)</script>")), "-");
        assert_eq!(blocked_of(None), "-");
        assert_eq!(directive_of(Some("script-src 'self'")), "script-src");
        assert_eq!(directive_of(Some("bad\ndirective")), "bad");
        assert_eq!(directive_of(Some("Évil")), "-");
        assert_eq!(host_of(Some("not a url")), "-");
    }
}
