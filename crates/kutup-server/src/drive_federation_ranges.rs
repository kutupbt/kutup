//! Ranged reads of Drive content across servers
//! (docs/plans/drive-block-format.md §3). A client's one `Range` (and its
//! `If-Range`) goes to the owner's server in the signed request's query, so
//! the part asked for is the part the request signs. The owner answers
//! `206` signed over an RFC 9530 `content-digest` of that part, at most
//! `drive_stream_response_max_bytes` long, or `416`. The receiving server
//! checks the signature and digest (the transport does) and that the part is
//! the one asked before it releases a byte. `Content-Range`'s total is not
//! signed: a reader learns the object's length from its own metadata, and
//! the manifest it commits to fixes every byte in any case.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use kutup_federation_proto::{content_digest_sha256_from_digest, ContentDigest};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::content_range::{self, RangeSpec, Requested};
use crate::drive_federation::{
    drive_spec, gateway_error, JSON_CONTENT_TYPE, OCTET_STREAM_CONTENT_TYPE,
};
use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationStack};
use crate::AppState;

/// What a federated content read asks: nothing (the whole object), or one
/// range, with the ETag the reader holds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ContentReadQuery {
    pub range: Option<RangeSpec>,
    pub if_range: Option<String>,
}

impl ContentReadQuery {
    /// From a signed request's raw query: `range` (`a-b`, `a-` or `-k`) and
    /// `ifRange`, each at most once, nothing else.
    pub fn parse(query: Option<&str>) -> AppResult<Self> {
        let invalid = || AppError::bad_request("invalid content read query");
        let mut read = Self::default();
        for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
            match key.as_ref() {
                "range" if read.range.is_none() => {
                    read.range = Some(RangeSpec::from_query(&value).ok_or_else(invalid)?);
                }
                "ifRange" if read.if_range.is_none() => read.if_range = Some(value.into_owned()),
                _ => return Err(invalid()),
            }
        }
        if read.if_range.is_some() && read.range.is_none() {
            return Err(invalid());
        }
        Ok(read)
    }

    /// From a client's headers: the one range it asks (none for anything
    /// the server would answer whole) and its `If-Range`.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let range = headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(RangeSpec::parse);
        Self {
            range,
            if_range: range.and_then(|_| {
                headers
                    .get(header::IF_RANGE)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.trim().to_owned())
            }),
        }
    }

    /// The query a receiving server signs; `None` for a whole read.
    pub fn to_query(&self) -> Option<String> {
        let range = self.range?;
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("range", &range.to_query());
        if let Some(if_range) = &self.if_range {
            query.append_pair("ifRange", if_range);
        }
        Some(query.finish())
    }

    /// Against an object of `total` bytes whose ETag is `etag`.
    fn resolve(&self, total: u64, etag: &str, max_part: u64) -> Requested {
        match self.range {
            None => Requested::Whole,
            Some(_) if self.if_range.as_deref().is_some_and(|tag| tag != etag) => Requested::Whole,
            Some(spec) => spec.resolve(total, max_part),
        }
    }
}

/// The owner's side: the part of stored object `path` (`size` bytes, named
/// by `revision`) that `read` asks, signed: `206`, or `416`. `None` when the
/// whole object is to be served (no range, or an `If-Range` for other
/// content), which the caller signs over its stored digest as before.
pub(crate) async fn signed_part(
    state: &AppState,
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    path: &str,
    size: i64,
    revision: Uuid,
    read: &ContentReadQuery,
) -> AppResult<Option<Response>> {
    let total = u64::try_from(size).map_err(|_| AppError::internal("negative object size"))?;
    let etag = content_range::etag(revision);
    let max_part = content_range::max_part_bytes(&state.pool).await?;
    let (status, bytes, content_range) = match read.resolve(total, &etag, max_part) {
        Requested::Whole => return Ok(None),
        Requested::Unsatisfiable => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            Vec::new(),
            format!("bytes */{total}"),
        ),
        Requested::Part(range) => {
            // At most one answer's worth (a site setting, 16 MiB at most):
            // held whole to sign its digest.
            let bytes = state
                .storage
                .get_object_range(path, range.start, range.end, total)
                .await
                .map_err(|error| AppError::internal(format!("read Drive object: {error}")))?
                .collect()
                .await
                .map_err(|error| AppError::internal(format!("read Drive object: {error}")))?
                .into_bytes()
                .to_vec();
            (
                StatusCode::PARTIAL_CONTENT,
                bytes,
                format!("bytes {}-{}/{total}", range.start, range.end),
            )
        }
    };
    let mut digest = ContentDigest::new();
    digest.update(&bytes);
    let length = bytes.len() as u64;
    let mut response = federation.signed_stream_response(
        authenticated,
        status,
        OCTET_STREAM_CONTENT_TYPE,
        &content_digest_sha256_from_digest(&digest.finish()),
        length,
        Body::from(bytes),
    )?;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_RANGE, header_value(&content_range)?);
    headers.insert(header::ETAG, header_value(&etag)?);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(Some(response))
}

/// The owner's ETag on a whole answer, so a reader can ask a range of the
/// same content later.
pub(crate) fn with_etag(mut response: Response, revision: Uuid) -> AppResult<Response> {
    let headers = response.headers_mut();
    headers.insert(header::ETAG, header_value(&content_range::etag(revision))?);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(response)
}

fn header_value(value: &str) -> AppResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| AppError::internal("invalid header value"))
}

/// The receiving side: reads `path` from `remote_domain` with the client's
/// one range forwarded in the signed query, and relays the answer once the
/// part is the one asked (the transport has checked its signature and
/// digest).
pub(crate) async fn relay(
    state: &AppState,
    headers: &HeaderMap,
    remote_domain: &str,
    path: String,
    capability: &str,
) -> AppResult<Response> {
    let read = ContentReadQuery::from_headers(headers);
    let max_part = content_range::max_part_bytes(&state.pool).await?;
    let limit = if read.range.is_some() {
        usize::try_from(max_part).unwrap_or(usize::MAX)
    } else {
        crate::drive_federation::max_drive_object_bytes(&state.pool).await?
    };
    let mut spec = drive_spec(
        Method::GET,
        path,
        JSON_CONTENT_TYPE.into(),
        Vec::new(),
        Some(capability),
        limit,
    )?;
    spec.query = read.to_query();
    let response = crate::drive_federation::configured_stack(state)?
        .send_streamed(remote_domain, spec)
        .await
        .map_err(gateway_error)?;
    let mut builder = Response::builder()
        .status(response.status)
        .header(header::CONTENT_TYPE, &response.content_type)
        .header(header::CONTENT_LENGTH, response.content_length)
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(etag) = &response.etag {
        builder = builder.header(header::ETAG, etag);
    }
    match response.status {
        StatusCode::PARTIAL_CONTENT => {
            let range = response
                .content_range
                .as_deref()
                .and_then(|value| check_part(read.range, value, response.content_length, max_part))
                .ok_or_else(|| AppError::bad_gateway("the peer answered another range"))?;
            builder = builder.header(header::CONTENT_RANGE, range);
        }
        StatusCode::RANGE_NOT_SATISFIABLE => {
            if let Some(range) = response.content_range.as_deref() {
                builder = builder.header(header::CONTENT_RANGE, range);
            }
        }
        _ => {}
    }
    builder
        .body(Body::from_stream(ReaderStream::new(response.file)))
        .map_err(|error| AppError::internal(error.to_string()))
}

/// Whether a peer's `206` is the part asked: a `Content-Range` of `length`
/// bytes (the length its signed digest covers), at most one answer's worth,
/// starting where the request did (the end of an open or suffix range is the
/// peer's to set). The value to relay, if so.
fn check_part(asked: Option<RangeSpec>, value: &str, length: u64, max_part: u64) -> Option<&str> {
    let (span, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let digits = |text: &str| -> Option<u64> {
        (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    };
    let (start, end, total) = (digits(start)?, digits(end)?, digits(total)?);
    if start > end || end >= total || end - start + 1 != length || length > max_part {
        return None;
    }
    let fits = match asked? {
        RangeSpec::Closed(first, last) => start == first && end <= last,
        RangeSpec::From(first) => start == first,
        RangeSpec::Suffix(count) => end == total - 1 && length <= count,
    };
    fits.then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_query_carries_one_range_and_its_tag() {
        assert_eq!(
            ContentReadQuery::parse(None).unwrap(),
            ContentReadQuery::default()
        );
        let read = ContentReadQuery {
            range: Some(RangeSpec::Closed(5, 9)),
            if_range: Some("\"22222222-2222-4222-8222-222222222222\"".into()),
        };
        let query = read.to_query().unwrap();
        assert_eq!(ContentReadQuery::parse(Some(&query)).unwrap(), read);
        assert_eq!(ContentReadQuery::default().to_query(), None);
        for bad in [
            "range=1-2&range=3-4",
            "range=1-2&other=x",
            "ifRange=%22x%22",
            "range=2-1",
            "range=a",
        ] {
            assert!(ContentReadQuery::parse(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn if_range_for_other_content_reads_whole() {
        let read = ContentReadQuery {
            range: Some(RangeSpec::From(0)),
            if_range: Some("\"a\"".into()),
        };
        assert_eq!(read.resolve(100, "\"b\"", 50), Requested::Whole);
        assert_eq!(
            read.resolve(100, "\"a\"", 50),
            Requested::Part(content_range::ByteRange { start: 0, end: 49 })
        );
    }

    #[test]
    fn a_peers_part_must_be_the_one_asked() {
        let max = 1000;
        let closed = Some(RangeSpec::Closed(10, 19));
        assert!(check_part(closed, "bytes 10-19/100", 10, max).is_some());
        // Cut short at the end of the object, or by the part limit.
        assert!(check_part(closed, "bytes 10-14/15", 5, max).is_some());
        // Another start, past the asked end, a length its digest does not
        // cover, longer than one answer, malformed.
        assert!(check_part(closed, "bytes 11-19/100", 9, max).is_none());
        assert!(check_part(closed, "bytes 10-29/100", 20, max).is_none());
        assert!(check_part(closed, "bytes 10-19/100", 9, max).is_none());
        assert!(check_part(Some(RangeSpec::From(0)), "bytes 0-1999/5000", 2000, max).is_none());
        assert!(check_part(closed, "bytes 10-19/19", 10, max).is_none());
        assert!(check_part(closed, "bytes */100", 0, max).is_none());
        assert!(check_part(None, "bytes 10-19/100", 10, max).is_none());
        // A suffix ends at the end.
        let suffix = Some(RangeSpec::Suffix(12));
        assert!(check_part(suffix, "bytes 88-99/100", 12, max).is_some());
        assert!(check_part(suffix, "bytes 80-91/100", 12, max).is_none());
    }
}
