//! Latency and outcome per operation, shared by every virtual user: a
//! histogram of successes (microseconds), and counts of errors by kind.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<Mutex<BTreeMap<&'static str, Operation>>>,
    sockets: Arc<AtomicUsize>,
}

/// Counts an open WebSocket until dropped.
pub struct OpenSocket(Arc<AtomicUsize>);

impl Drop for OpenSocket {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Operation {
    latency: Histogram<u64>,
    /// Since the last interval report.
    interval: Histogram<u64>,
    errors: BTreeMap<String, u64>,
    interval_errors: u64,
}

impl Operation {
    fn new() -> Self {
        // 1 µs to 10 minutes, three significant digits.
        let histogram = || Histogram::new_with_bounds(1, 600_000_000, 3).expect("valid bounds");
        Operation {
            latency: histogram(),
            interval: histogram(),
            errors: BTreeMap::new(),
            interval_errors: 0,
        }
    }
}

/// One operation's figures.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationReport {
    pub operation: String,
    pub ok: u64,
    pub errors: u64,
    pub per_second: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    /// Error kinds and their counts (an HTTP status, a timeout, …).
    pub error_kinds: BTreeMap<String, u64>,
}

impl Metrics {
    pub fn socket_opened(&self) -> OpenSocket {
        self.sockets.fetch_add(1, Ordering::Relaxed);
        OpenSocket(self.sockets.clone())
    }

    /// Chat WebSockets open right now.
    pub fn open_sockets(&self) -> usize {
        self.sockets.load(Ordering::Relaxed)
    }

    pub fn ok(&self, operation: &'static str, took: Duration) {
        let micros = (took.as_micros() as u64).clamp(1, 600_000_000);
        let mut inner = self.inner.lock().expect("metrics lock");
        let entry = inner.entry(operation).or_insert_with(Operation::new);
        let _ = entry.latency.record(micros);
        let _ = entry.interval.record(micros);
    }

    pub fn error(&self, operation: &'static str, kind: impl Into<String>) {
        let mut inner = self.inner.lock().expect("metrics lock");
        let entry = inner.entry(operation).or_insert_with(Operation::new);
        *entry.errors.entry(kind.into()).or_default() += 1;
        entry.interval_errors += 1;
    }

    /// Times `work`, recording its success or its error's kind.
    pub async fn time<T, F>(&self, operation: &'static str, work: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        let started = Instant::now();
        match work.await {
            Ok(value) => {
                self.ok(operation, started.elapsed());
                Ok(value)
            }
            Err(error) => {
                self.error(operation, kind(&error));
                Err(error)
            }
        }
    }

    /// Every operation since the start, over `elapsed`.
    pub fn report(&self, elapsed: Duration) -> Vec<OperationReport> {
        let inner = self.inner.lock().expect("metrics lock");
        inner
            .iter()
            .map(|(name, op)| summarize(name, &op.latency, op.errors.clone(), elapsed))
            .collect()
    }

    /// The interval since the last call, and starts the next.
    pub fn interval(&self, elapsed: Duration) -> Vec<OperationReport> {
        let mut inner = self.inner.lock().expect("metrics lock");
        inner
            .iter_mut()
            .map(|(name, op)| {
                let mut errors = BTreeMap::new();
                if op.interval_errors > 0 {
                    errors.insert("all".to_string(), op.interval_errors);
                }
                let report = summarize(name, &op.interval, errors, elapsed);
                op.interval.reset();
                op.interval_errors = 0;
                report
            })
            .collect()
    }
}

fn summarize(
    name: &str,
    histogram: &Histogram<u64>,
    errors: BTreeMap<String, u64>,
    elapsed: Duration,
) -> OperationReport {
    let ms = |micros: u64| micros as f64 / 1000.0;
    let ok = histogram.len();
    OperationReport {
        operation: name.to_string(),
        ok,
        errors: errors.values().sum(),
        per_second: ok as f64 / elapsed.as_secs_f64().max(0.001),
        p50_ms: ms(histogram.value_at_quantile(0.50)),
        p95_ms: ms(histogram.value_at_quantile(0.95)),
        p99_ms: ms(histogram.value_at_quantile(0.99)),
        max_ms: ms(histogram.max()),
        error_kinds: errors,
    }
}

/// A short kind for an error: its HTTP status when it has one, else the
/// first words of its message.
pub fn kind(error: &anyhow::Error) -> String {
    for cause in error.chain() {
        if let Some(status) = cause.downcast_ref::<crate::api::Status>() {
            return format!("http {}", status.0);
        }
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            if error.is_timeout() {
                return "timeout".into();
            }
            if error.is_connect() {
                return "connect".into();
            }
        }
    }
    let text = error.to_string();
    text.split_whitespace()
        .take(6)
        .collect::<Vec<_>>()
        .join(" ")
}

/// A table for the terminal.
pub fn table(reports: &[OperationReport]) -> String {
    let mut out = format!(
        "{:<22} {:>9} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9}\n",
        "operation", "ok", "errors", "per s", "p50 ms", "p95 ms", "p99 ms", "max ms"
    );
    for r in reports {
        out.push_str(&format!(
            "{:<22} {:>9} {:>7} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1}\n",
            r.operation, r.ok, r.errors, r.per_second, r.p50_ms, r.p95_ms, r.p99_ms, r.max_ms
        ));
    }
    out
}
