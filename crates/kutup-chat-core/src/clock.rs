//! Platform wall-clock boundary.
//!
//! `std::time::SystemTime::now()` panics in a browser. Keep the workaround in
//! one place so protocol code never accidentally reaches that unsupported API.

use std::time::{Duration, SystemTime};

/// Current wall time as a `SystemTime`, including on `wasm32-unknown-unknown`.
pub(crate) fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(unix_millis() as u64)
}

/// Current Unix-epoch time in milliseconds.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

/// Browsers expose wall time through JavaScript's `Date.now()`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn unix_millis() -> i64 {
    js_sys::Date::now().max(0.0).min(i64::MAX as f64) as i64
}
