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

/// The server showed this device an older account history than it has seen,
/// or another one (docs/plans/rollback-protection.md): listed writes stop
/// until `kutup account reanchor` — exit code 6. Holds `rollback` or `fork`.
#[derive(Debug, Error)]
#[error("the account's data on the server is not the history this device knows ({0}): another device may have been shown a different one, or the server was restored from a backup; review, then run `kutup account reanchor`")]
pub struct HeadBlocked(pub String);
