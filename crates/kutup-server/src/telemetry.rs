//! Privacy-bounded OpenTelemetry for the security-critical Chat paths.
//!
//! Export is deliberately opt-in. Once an OTLP endpoint is configured,
//! exporter construction is fallible startup state: the server never silently
//! drops back to logs-only operation because of a malformed collector setup.

use std::sync::OnceLock;

use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

const INSTRUMENTATION_SCOPE: &str = "kutup-server.chat-security";

pub enum TelemetryGuard {
    LogsOnly,
    Otlp {
        tracer_provider: SdkTracerProvider,
        meter_provider: SdkMeterProvider,
    },
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Self::Otlp {
            tracer_provider,
            meter_provider,
        } = self
        {
            let _ = meter_provider.shutdown();
            let _ = tracer_provider.shutdown();
        }
    }
}

pub fn init() -> anyhow::Result<TelemetryGuard> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,sqlx=warn".into());
    let generic_endpoint = nonempty_env("OTEL_EXPORTER_OTLP_ENDPOINT");
    let traces_endpoint = nonempty_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
    let metrics_endpoint = nonempty_env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");

    if !export_enabled(
        generic_endpoint.as_deref(),
        traces_endpoint.as_deref(),
        metrics_endpoint.as_deref(),
    )? {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()?;
        return Ok(TelemetryGuard::LogsOnly);
    }

    let service_name = nonempty_env("OTEL_SERVICE_NAME").unwrap_or_else(|| "kutup-server".into());
    let resource = Resource::builder().with_service_name(service_name).build();
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();
    let tracer = tracer_provider.tracer(INSTRUMENTATION_SCOPE);

    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(metric_exporter)
        .build();

    global::set_tracer_provider(tracer_provider.clone());
    global::set_meter_provider(meter_provider.clone());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;

    Ok(TelemetryGuard::Otlp {
        tracer_provider,
        meter_provider,
    })
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn export_enabled(
    generic_endpoint: Option<&str>,
    traces_endpoint: Option<&str>,
    metrics_endpoint: Option<&str>,
) -> anyhow::Result<bool> {
    if generic_endpoint.is_some() {
        return Ok(true);
    }
    match (traces_endpoint, metrics_endpoint) {
        (None, None) => Ok(false),
        (Some(_), Some(_)) => Ok(true),
        _ => anyhow::bail!(
            "OpenTelemetry requires OTEL_EXPORTER_OTLP_ENDPOINT or both signal-specific trace and metrics endpoints"
        ),
    }
}

pub fn policy_event(feature: &'static str, outcome: &'static str) {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    COUNTER
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_counter("kutup.chat.policy.events")
                .with_description("Authenticated Chat feature-policy lifecycle events")
                .build()
        })
        .add(
            1,
            &[
                KeyValue::new("feature", feature),
                KeyValue::new("outcome", outcome),
            ],
        );
}

pub fn monitor_event(outcome: &'static str, checkpoint_age_seconds: Option<u64>) {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    static AGE: OnceLock<Histogram<u64>> = OnceLock::new();
    COUNTER
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_counter("kutup.chat.transparency.monitor.events")
                .with_description("Remote transparency monitor verification outcomes")
                .build()
        })
        .add(1, &[KeyValue::new("outcome", outcome)]);
    if let Some(age) = checkpoint_age_seconds {
        AGE.get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_histogram("kutup.chat.transparency.monitor.checkpoint_age_seconds")
                .with_description("Age of authenticated remote checkpoints at verification")
                .with_unit("s")
                .build()
        })
        .record(age, &[KeyValue::new("outcome", outcome)]);
    }
}

pub fn proof_event(profile: &'static str, outcome: &'static str, entries: u64) {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    static SIZE: OnceLock<Histogram<u64>> = OnceLock::new();
    let attributes = [
        KeyValue::new("profile", profile),
        KeyValue::new("outcome", outcome),
    ];
    COUNTER
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_counter("kutup.chat.transparency.proof.events")
                .with_description("Transparency proof generation and verification outcomes")
                .build()
        })
        .add(1, &attributes);
    SIZE.get_or_init(|| {
        global::meter(INSTRUMENTATION_SCOPE)
            .u64_histogram("kutup.chat.transparency.proof.entries")
            .with_description("Number of manifest records bound into a range-proof page")
            .build()
    })
    .record(entries, &attributes);
}

pub fn witness_event(outcome: &'static str, quorum: u64) {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    static QUORUM: OnceLock<Histogram<u64>> = OnceLock::new();
    COUNTER
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_counter("kutup.chat.transparency.witness.events")
                .with_description("Witness checkpoint and quorum outcomes")
                .build()
        })
        .add(1, &[KeyValue::new("outcome", outcome)]);
    QUORUM
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_histogram("kutup.chat.transparency.witness.quorum")
                .with_description("Authenticated witness signatures participating in a checkpoint")
                .build()
        })
        .record(quorum, &[KeyValue::new("outcome", outcome)]);
}

pub fn fork_event(outcome: &'static str) {
    event_counter(
        &FORK_COUNTER,
        "kutup.chat.transparency.fork.events",
        "Independent transparency fork-audit outcomes",
        "outcome",
        outcome,
    );
}

pub fn certificate_event(outcome: &'static str) {
    event_counter(
        &CERTIFICATE_COUNTER,
        "kutup.chat.sealed_sender.certificate.events",
        "Online sealed-sender certificate issuance outcomes",
        "outcome",
        outcome,
    );
}

pub fn sealed_send_event(stage: &'static str, outcome: &'static str, envelopes: u64) {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    static ENVELOPES: OnceLock<Histogram<u64>> = OnceLock::new();
    let attributes = [
        KeyValue::new("stage", stage),
        KeyValue::new("outcome", outcome),
    ];
    COUNTER
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_counter("kutup.chat.sealed_sender.send.events")
                .with_description("Anonymous and federated sealed-delivery outcomes")
                .build()
        })
        .add(1, &attributes);
    ENVELOPES
        .get_or_init(|| {
            global::meter(INSTRUMENTATION_SCOPE)
                .u64_histogram("kutup.chat.sealed_sender.send.envelopes")
                .with_description("Opaque per-device envelopes in a sealed transaction")
                .build()
        })
        .record(envelopes, &attributes);
}

pub fn rate_limit_rejection(scope: &'static str) {
    event_counter(
        &RATE_LIMIT_COUNTER,
        "kutup.chat.rate_limit.rejections",
        "Security-path rate-limit rejections",
        "scope",
        scope,
    );
}

static FORK_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
static CERTIFICATE_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
static RATE_LIMIT_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();

fn event_counter(
    cell: &'static OnceLock<Counter<u64>>,
    name: &'static str,
    description: &'static str,
    attribute: &'static str,
    value: &'static str,
) {
    cell.get_or_init(|| {
        global::meter(INSTRUMENTATION_SCOPE)
            .u64_counter(name)
            .with_description(description)
            .build()
    })
    .add(1, &[KeyValue::new(attribute, value)]);
}

#[cfg(test)]
mod tests {
    use super::{export_enabled, nonempty_env};

    #[test]
    fn export_requires_both_signal_specific_endpoints() {
        assert!(!export_enabled(None, None, None).unwrap());
        assert!(export_enabled(Some("https://collector:4317"), None, None).unwrap());
        assert!(export_enabled(
            None,
            Some("https://traces:4317"),
            Some("https://metrics:4317")
        )
        .unwrap());
        assert!(export_enabled(None, Some("https://traces:4317"), None).is_err());
        assert!(export_enabled(None, None, Some("https://metrics:4317")).is_err());
    }

    #[test]
    fn blank_endpoint_is_not_configuration() {
        const NAME: &str = "KUTUP_TEST_BLANK_OTEL_ENDPOINT";
        // SAFETY: this test owns a process-unique variable name.
        unsafe { std::env::set_var(NAME, "  ") };
        assert_eq!(nonempty_env(NAME), None);
        // SAFETY: this test owns a process-unique variable name.
        unsafe { std::env::remove_var(NAME) };
    }
}
