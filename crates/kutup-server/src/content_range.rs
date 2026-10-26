//! Ranged reads of stored objects (docs/plans/drive-block-format.md §3): one
//! `bytes=` range per request, as RFC 9110 §14 allows a server to serve.
//! Every content route answers `206` with `Content-Range`, or `416`, or the
//! whole object when no range applies (none asked, several asked, a malformed
//! one, or an `If-Range` that no longer matches). The ETag is the revision
//! id, which names immutable bytes. One answer carries at most
//! `drive_stream_response_max_bytes`: a longer range is answered in part, as
//! `Content-Range` then says: its first part, or for a suffix (the end of
//! the object) its last.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::storage::StorageService;

/// Bytes `start..=end` of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

/// What a request asks of an object of `total` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requested {
    Whole,
    Part(ByteRange),
    /// A range that starts past the end: `416`.
    Unsatisfiable,
}

/// One range spec as asked, before it meets the object's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeSpec {
    /// `a-b`.
    Closed(u64, u64),
    /// `a-`.
    From(u64),
    /// `-k`: the last `k` bytes.
    Suffix(u64),
}

impl RangeSpec {
    /// Parses a `Range` value: `bytes=` and one spec. `None` for anything
    /// else (another unit, several ranges, a malformed spec), which the
    /// server ignores and answers whole (RFC 9110 §14.2).
    pub fn parse(value: &str) -> Option<Self> {
        let spec = value.trim().strip_prefix("bytes=")?.trim();
        if spec.contains(',') {
            return None;
        }
        let (first, last) = spec.split_once('-')?;
        let number = |text: &str| -> Option<u64> {
            (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
                .then(|| text.parse().ok())
                .flatten()
        };
        match (first.trim(), last.trim()) {
            ("", suffix) => number(suffix).map(Self::Suffix),
            (start, "") => number(start).map(Self::From),
            (start, end) => {
                let (start, end) = (number(start)?, number(end)?);
                (start <= end).then_some(Self::Closed(start, end))
            }
        }
    }

    /// The spec as a query value (`a-b`, `a-` or `-k`), for a federated read.
    pub fn to_query(self) -> String {
        match self {
            Self::Closed(start, end) => format!("{start}-{end}"),
            Self::From(start) => format!("{start}-"),
            Self::Suffix(length) => format!("-{length}"),
        }
    }

    /// From a query value (`a-b`, `a-` or `-k`).
    pub fn from_query(value: &str) -> Option<Self> {
        Self::parse(&format!("bytes={value}"))
    }

    /// Against an object of `total` bytes, at most `max_part` of them: the
    /// first `max_part` of a longer range, the last of a longer suffix.
    pub fn resolve(self, total: u64, max_part: u64) -> Requested {
        let max_part = max_part.max(1);
        let (start, end) = match self {
            Self::Closed(start, end) => (start, end),
            Self::From(start) => (start, u64::MAX),
            Self::Suffix(0) => return Requested::Unsatisfiable,
            Self::Suffix(length) => {
                let taken = length.min(total).min(max_part);
                (total.saturating_sub(taken), u64::MAX)
            }
        };
        if total == 0 || start >= total {
            return Requested::Unsatisfiable;
        }
        let end = end.min(total - 1).min(start.saturating_add(max_part - 1));
        Requested::Part(ByteRange { start, end })
    }

    /// The same request cut to one answer's worth (`max_part` bytes), as a
    /// relaying server asks it of the owner: it then signs only what it can
    /// take, whatever the owner's own limit.
    pub fn clamped(self, max_part: u64) -> Self {
        let max_part = max_part.max(1);
        match self {
            Self::Closed(start, end) => {
                Self::Closed(start, end.min(start.saturating_add(max_part - 1)))
            }
            Self::From(start) => Self::Closed(start, start.saturating_add(max_part - 1)),
            Self::Suffix(length) => Self::Suffix(length.min(max_part)),
        }
    }
}

/// The strong ETag of immutable content named by `revision`.
pub fn etag(revision: Uuid) -> String {
    format!("\"{}\"", revision.hyphenated())
}

/// What `headers` ask of an object of `total` bytes whose ETag is `etag`.
pub fn requested(headers: &HeaderMap, total: u64, etag: &str, max_part: u64) -> Requested {
    let Some(spec) = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(RangeSpec::parse)
    else {
        return Requested::Whole;
    };
    // A range of what the client had: if the content changed since, it gets
    // the whole of the new content (RFC 9110 §13.1.5, strong comparison).
    if let Some(if_range) = headers.get(header::IF_RANGE) {
        if if_range.to_str().map(str::trim).ok() != Some(etag) {
            return Requested::Whole;
        }
    }
    spec.resolve(total, max_part)
}

/// The largest part one answer carries (a site setting).
pub async fn max_part_bytes(pool: &sqlx::PgPool) -> AppResult<u64> {
    Ok(crate::site_settings::DRIVE_STREAM_RESPONSE_MAX_BYTES
        .load(pool)
        .await?
        .max(1) as u64)
}

/// Serves stored object `path` of `total` bytes (its length as recorded),
/// whole or the range `headers` ask for.
pub async fn serve(
    storage: &StorageService,
    path: &str,
    total: u64,
    etag: &str,
    requested: Requested,
    extra: &[(HeaderName, String)],
) -> AppResult<Response> {
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, etag);
    for (name, value) in extra {
        if let Ok(value) = HeaderValue::from_str(value) {
            builder = builder.header(name, value);
        }
    }
    let (status, body, length) = match requested {
        Requested::Unsatisfiable => {
            return Ok(builder
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{total}"))
                .body(Body::empty())
                .expect("valid 416 response"));
        }
        Requested::Whole => {
            let (body, size) = storage
                .get_object(path)
                .await
                .map_err(|_| AppError::internal("storage"))?;
            if size as u64 != total {
                return Err(AppError::internal("stored object length mismatch"));
            }
            (StatusCode::OK, body, total)
        }
        Requested::Part(range) => {
            let body = storage
                .get_object_range(path, range.start, range.end, total)
                .await
                .map_err(|_| AppError::internal("storage"))?;
            builder = builder.header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{total}", range.start, range.end),
            );
            (StatusCode::PARTIAL_CONTENT, body, range.len())
        }
    };
    Ok(builder
        .status(status)
        .header(header::CONTENT_LENGTH, length)
        .body(Body::from_stream(ReaderStream::new(body.into_async_read())))
        .expect("valid octet-stream response"))
}

/// Serves stored object `path` of `size` bytes, named by `revision`:
/// whole, or the range `headers` ask for, at most one answer's worth.
pub async fn serve_revision(
    pool: &sqlx::PgPool,
    storage: &StorageService,
    path: &str,
    size: i64,
    revision: Uuid,
    headers: &HeaderMap,
    extra: &[(HeaderName, String)],
) -> AppResult<Response> {
    let total = u64::try_from(size).map_err(|_| AppError::internal("negative object size"))?;
    let tag = etag(revision);
    let asked = requested(headers, total, &tag, max_part_bytes(pool).await?);
    serve(storage, path, total, &tag, asked, extra).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(start: u64, end: u64) -> Requested {
        Requested::Part(ByteRange { start, end })
    }

    #[test]
    fn one_range_is_read_and_anything_else_is_whole() {
        assert_eq!(
            RangeSpec::parse("bytes=0-99"),
            Some(RangeSpec::Closed(0, 99))
        );
        assert_eq!(RangeSpec::parse("bytes=100-"), Some(RangeSpec::From(100)));
        assert_eq!(RangeSpec::parse("bytes=-12"), Some(RangeSpec::Suffix(12)));
        assert_eq!(
            RangeSpec::parse(" bytes= 5 - 6 "),
            Some(RangeSpec::Closed(5, 6))
        );
        for ignored in [
            "bytes=0-1,4-5",
            "items=0-1",
            "bytes=5-4",
            "bytes=-",
            "bytes=a-b",
            "bytes=+1-2",
            "bytes=0-99999999999999999999999",
            "bytes",
            "",
        ] {
            assert_eq!(RangeSpec::parse(ignored), None, "{ignored}");
        }
    }

    #[test]
    fn a_range_meets_the_length_and_the_part_limit() {
        let max = 1000;
        assert_eq!(RangeSpec::Closed(0, 99).resolve(500, max), part(0, 99));
        // Past the end: up to the end.
        assert_eq!(
            RangeSpec::Closed(400, 900).resolve(500, max),
            part(400, 499)
        );
        assert_eq!(RangeSpec::From(10).resolve(500, max), part(10, 499));
        assert_eq!(RangeSpec::Suffix(12).resolve(500, max), part(488, 499));
        assert_eq!(RangeSpec::Suffix(900).resolve(500, max), part(0, 499));
        // Longer than one answer: the first part of it.
        assert_eq!(RangeSpec::From(0).resolve(5000, max), part(0, 999));
        // A suffix longer than one answer: its end, where a reader looks.
        assert_eq!(RangeSpec::Suffix(3000).resolve(5000, max), part(4000, 4999));
        // Cut to one answer's worth, a request resolves the same anywhere.
        for spec in [
            RangeSpec::From(0),
            RangeSpec::From(4500),
            RangeSpec::Closed(10, 4000),
            RangeSpec::Closed(10, 20),
            RangeSpec::Suffix(3000),
            RangeSpec::Suffix(12),
        ] {
            assert_eq!(
                spec.clamped(max).resolve(5000, max),
                spec.resolve(5000, max),
                "{spec:?}"
            );
            assert_eq!(
                spec.clamped(max).resolve(5000, 2 * max),
                spec.resolve(5000, max),
                "{spec:?}"
            );
        }
        // Unsatisfiable: past the end, nothing to take, an empty object.
        assert_eq!(
            RangeSpec::Closed(500, 600).resolve(500, max),
            Requested::Unsatisfiable
        );
        assert_eq!(
            RangeSpec::Suffix(0).resolve(500, max),
            Requested::Unsatisfiable
        );
        assert_eq!(RangeSpec::From(0).resolve(0, max), Requested::Unsatisfiable);
        // A query value round-trips.
        for spec in [
            RangeSpec::Closed(1, 2),
            RangeSpec::From(3),
            RangeSpec::Suffix(4),
        ] {
            assert_eq!(RangeSpec::from_query(&spec.to_query()), Some(spec));
        }
    }

    #[test]
    fn if_range_gives_a_range_only_of_the_same_content() {
        let tag = etag(Uuid::from_bytes([1; 16]));
        let mut headers = HeaderMap::new();
        assert_eq!(requested(&headers, 500, &tag, 1000), Requested::Whole);
        headers.insert(header::RANGE, "bytes=0-9".parse().unwrap());
        assert_eq!(requested(&headers, 500, &tag, 1000), part(0, 9));
        headers.insert(header::IF_RANGE, tag.parse().unwrap());
        assert_eq!(requested(&headers, 500, &tag, 1000), part(0, 9));
        headers.insert(
            header::IF_RANGE,
            etag(Uuid::from_bytes([2; 16])).parse().unwrap(),
        );
        assert_eq!(requested(&headers, 500, &tag, 1000), Requested::Whole);
        // A date or a weak tag never matches a strong one.
        headers.insert(header::IF_RANGE, format!("W/{tag}").parse().unwrap());
        assert_eq!(requested(&headers, 500, &tag, 1000), Requested::Whole);
    }
}
