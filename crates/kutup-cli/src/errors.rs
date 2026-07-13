//! Marker error types for exit-code classification.
//!
//! Commands wrap failures in these thin newtypes so `main` can map an
//! `anyhow::Error` chain to a differentiated process exit code (see
//! `exit_code_for`) without string-matching messages. `api::ApiError` plays
//! the same role for HTTP failures.

use thiserror::Error;

/// No usable session/device key — exit code 3.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct NotLoggedIn(pub String);

/// A named file/folder/version doesn't exist or isn't accessible — exit code 4.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct NotFound(pub String);

/// The invocation itself is wrong (bad flag combination, missing --yes in a
/// non-interactive run) — exit code 2, matching clap's parse-error code.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct UsageError(pub String);
