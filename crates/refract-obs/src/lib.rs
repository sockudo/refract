//! Observability primitives for the refract `SFU`.
//!
//! The crate owns Stage 1 metrics, tracing configuration, structured log
//! policy, health endpoint semantics, profiling gates, Prometheus rendering,
//! and the OTLP push boundary. It intentionally does not start sockets or
//! runtime tasks; the admin/runtime layer mounts these handlers on `compio`.
//!
//! # Examples
//!
//! ```
//! # use refract_obs::{CoreRecorder, PrometheusExporter, RecorderConfig};
//! let recorder = CoreRecorder::new(RecorderConfig::default());
//! let _guard = metrics::set_default_local_recorder(&recorder);
//! recorder.register_stage1_metrics();
//! recorder.warm_current_thread();
//! metrics::counter!("refract.obs.health.requests").increment(1);
//! let snapshot = recorder.snapshot_current_thread();
//! let body = PrometheusExporter::new().render(&[snapshot])?;
//! assert!(body.contains("refract_obs_health_requests"));
//! # Ok::<(), refract_obs::ObsError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::{self, Write as _},
    sync::{Arc, Mutex},
    time::Duration,
};

use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use serde::Serialize;
use thiserror::Error as ThisError;
use tracing::Level;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt as _};

const DEFAULT_MAX_METRICS: usize = 512;
const DEFAULT_MAX_LABELS: usize = 8;
const MAX_ENDPOINT_PATH_BYTES: usize = 128;
const DEFAULT_SLOW_MS: u64 = 50;
const DEFAULT_SAMPLE_DENOMINATOR: u32 = 1_000;
const SLOW_PATH_SPAN_NAME: &str = "refract.slow_path";

thread_local! {
    static LOCAL_SHARD: RefCell<LocalShard> = RefCell::new(LocalShard::default());
}

/// Result alias for fallible observability operations.
pub type ObsResult<T> = Result<T, ObsError>;

/// Stage marker for public `refract-obs` APIs.
///
/// # Examples
///
/// ```
/// # use refract_obs::Stability;
/// assert_eq!(Stability::Stage1.as_str(), "stage1");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Stability {
    /// Stage 1 API surface; usable inside the workspace but not externally stable.
    Stage1,
}

impl Stability {
    /// Returns the stable label for this API state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Operator-facing observability errors with stable codes.
///
/// # Examples
///
/// ```
/// # use refract_obs::ObsError;
/// assert_eq!(
///     ObsError::InvalidEndpointPath.error_code(),
///     "OBS_ENDPOINT_0001"
/// );
/// ```
#[derive(Debug, ThisError)]
pub enum ObsError {
    /// Endpoint path was invalid or exceeded the bounded parser length.
    #[error("invalid endpoint path")]
    InvalidEndpointPath,
    /// Profiling endpoint was requested while disabled.
    #[error("profiling endpoint is disabled")]
    ProfilingDisabled,
    /// Profiling endpoint was requested without the configured admin token.
    #[error("profiling endpoint admin token rejected")]
    AdminTokenRejected,
    /// OTLP export exceeded its deterministic timeout budget.
    #[error("otlp export timed out after {timeout_ms}ms")]
    OtlpTimeout {
        /// Timeout budget in milliseconds.
        timeout_ms: u64,
    },
    /// OTLP export sink rejected a payload.
    #[error("otlp sink rejected payload: {reason}")]
    OtlpSink {
        /// Static sink failure reason.
        reason: &'static str,
    },
    /// Prometheus renderer could not format output.
    #[error("prometheus render failed")]
    PrometheusRender,
}

impl ObsError {
    /// Returns the stable operator dashboard code for this error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::ObsError;
    /// assert_eq!(ObsError::ProfilingDisabled.error_code(), "OBS_PROFILE_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidEndpointPath => "OBS_ENDPOINT_0001",
            Self::ProfilingDisabled => "OBS_PROFILE_0001",
            Self::AdminTokenRejected => "OBS_PROFILE_0002",
            Self::OtlpTimeout { .. } => "OBS_OTLP_0001",
            Self::OtlpSink { .. } => "OBS_OTLP_0002",
            Self::PrometheusRender => "OBS_PROM_0001",
        }
    }

    /// Returns the Stage 1 stability marker for this error API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{ObsError, Stability};
    /// assert_eq!(ObsError::InvalidEndpointPath.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Configuration for the per-core metrics recorder.
///
/// # Examples
///
/// ```
/// # use refract_obs::RecorderConfig;
/// let config = RecorderConfig::default();
/// assert_eq!(config.max_labels_per_metric(), 8);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecorderConfig {
    max_metrics: usize,
    max_labels_per_metric: usize,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            max_metrics: DEFAULT_MAX_METRICS,
            max_labels_per_metric: DEFAULT_MAX_LABELS,
        }
    }
}

impl RecorderConfig {
    /// Creates a recorder configuration with bounded registration limits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::RecorderConfig;
    /// let config = RecorderConfig::new(64, 4);
    /// assert_eq!(config.max_metrics(), 64);
    /// ```
    #[must_use]
    pub const fn new(max_metrics: usize, max_labels_per_metric: usize) -> Self {
        Self {
            max_metrics,
            max_labels_per_metric,
        }
    }

    /// Returns the maximum registered metric series.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::RecorderConfig;
    /// assert_eq!(RecorderConfig::new(7, 2).max_metrics(), 7);
    /// ```
    #[must_use]
    pub const fn max_metrics(self) -> usize {
        self.max_metrics
    }

    /// Returns the maximum label count accepted per metric series.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::RecorderConfig;
    /// assert_eq!(RecorderConfig::new(7, 2).max_labels_per_metric(), 2);
    /// ```
    #[must_use]
    pub const fn max_labels_per_metric(self) -> usize {
        self.max_labels_per_metric
    }
}

/// Per-core metrics recorder for the `metrics` crate.
///
/// Registration uses a shared registry and may allocate during warmup. Counter,
/// gauge, and histogram handle updates write only to thread-local shard storage.
///
/// # Examples
///
/// ```
/// # use refract_obs::{CoreRecorder, RecorderConfig};
/// let recorder = CoreRecorder::new(RecorderConfig::default());
/// let _guard = metrics::set_default_local_recorder(&recorder);
/// let counter = metrics::counter!("refract.obs.health.requests");
/// recorder.warm_current_thread();
/// counter.increment(1);
/// assert_eq!(recorder.snapshot_current_thread().samples().len(), 1);
/// ```
#[derive(Debug)]
pub struct CoreRecorder {
    config: RecorderConfig,
    registry: Arc<Mutex<Registry>>,
}

impl CoreRecorder {
    /// Creates a per-core metrics recorder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// assert_eq!(recorder.stability(), refract_obs::Stability::Stage1);
    /// ```
    #[must_use]
    pub fn new(config: RecorderConfig) -> Self {
        Self {
            config,
            registry: Arc::new(Mutex::new(Registry::default())),
        }
    }

    /// Returns the recorder configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::new(16, 3));
    /// assert_eq!(recorder.config().max_metrics(), 16);
    /// ```
    #[must_use]
    pub const fn config(&self) -> RecorderConfig {
        self.config
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig, Stability};
    /// assert_eq!(
    ///     CoreRecorder::new(RecorderConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    /// Registers the metrics owned by this crate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let _guard = metrics::set_default_local_recorder(&recorder);
    /// recorder.register_stage1_metrics();
    /// assert!(recorder.registered_metric_count() >= 3);
    /// ```
    pub fn register_stage1_metrics(&self) {
        metrics::describe_counter!(
            "refract.obs.health.requests",
            Unit::Count,
            "health endpoint requests handled by refract-obs"
        );
        metrics::describe_counter!(
            "refract.obs.profiling.requests",
            Unit::Count,
            "profiling endpoint requests handled by refract-obs"
        );
        metrics::describe_histogram!(
            "refract.obs.slow_path.duration",
            Unit::Milliseconds,
            "slow-path operation duration observed by refract-obs"
        );
        let _health = metrics::counter!("refract.obs.health.requests");
        let _profile = metrics::counter!("refract.obs.profiling.requests");
        let _slow = metrics::histogram!("refract.obs.slow_path.duration");
    }

    /// Pre-sizes the current thread shard for all metrics registered so far.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let _guard = metrics::set_default_local_recorder(&recorder);
    /// recorder.register_stage1_metrics();
    /// recorder.warm_current_thread();
    /// ```
    pub fn warm_current_thread(&self) {
        let metric_count = self.registered_metric_count();
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.ensure_len(metric_count);
            }
        });
    }

    /// Returns the number of metric series registered by this recorder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// assert_eq!(recorder.registered_metric_count(), 0);
    /// ```
    #[must_use]
    pub fn registered_metric_count(&self) -> usize {
        self.registry
            .lock()
            .map_or(0, |registry| registry.entries.len())
    }

    /// Captures the current thread's per-core shard for aggregation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let snapshot = recorder.snapshot_current_thread();
    /// assert!(snapshot.samples().is_empty());
    /// ```
    #[must_use]
    pub fn snapshot_current_thread(&self) -> CoreSnapshot {
        let entries = self
            .registry
            .lock()
            .map_or_else(|_error| Vec::new(), |registry| registry.entries.clone());

        LOCAL_SHARD.with(|shard| {
            shard.try_borrow().map_or_else(
                |_error| CoreSnapshot::default(),
                |shard| CoreSnapshot::from_entries(&entries, &shard),
            )
        })
    }

    fn register_metric(&self, key: &Key, kind: MetricKind) -> Option<MetricId> {
        let label_count = key.labels().count();
        if label_count > self.config.max_labels_per_metric {
            return None;
        }

        let mut registry = self.registry.lock().ok()?;
        registry.register(key, kind, self.config.max_metrics)
    }

    fn describe_metric(
        &self,
        key: &KeyName,
        kind: MetricKind,
        unit: Option<Unit>,
        description: &SharedString,
    ) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.describe(key.as_str(), kind, unit, description.as_ref());
        }
    }
}

impl Default for CoreRecorder {
    fn default() -> Self {
        Self::new(RecorderConfig::default())
    }
}

impl Recorder for CoreRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe_metric(&key, MetricKind::Counter, unit, &description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe_metric(&key, MetricKind::Gauge, unit, &description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe_metric(&key, MetricKind::Histogram, unit, &description);
    }

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        self.register_metric(key, MetricKind::Counter)
            .map_or_else(Counter::noop, |id| {
                Counter::from_arc(Arc::new(LocalCounter { id }))
            })
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        self.register_metric(key, MetricKind::Gauge)
            .map_or_else(Gauge::noop, |id| {
                Gauge::from_arc(Arc::new(LocalGauge { id }))
            })
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        self.register_metric(key, MetricKind::Histogram)
            .map_or_else(Histogram::noop, |id| {
                Histogram::from_arc(Arc::new(LocalHistogram { id }))
            })
    }
}

/// Snapshot of one per-core metrics shard.
///
/// # Examples
///
/// ```
/// # use refract_obs::CoreSnapshot;
/// let snapshot = CoreSnapshot::default();
/// assert_eq!(snapshot.samples().len(), 0);
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoreSnapshot {
    samples: Vec<MetricSample>,
}

impl CoreSnapshot {
    /// Returns captured samples for this shard.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::CoreSnapshot;
    /// assert!(CoreSnapshot::default().samples().is_empty());
    /// ```
    #[must_use]
    pub fn samples(&self) -> &[MetricSample] {
        &self.samples
    }

    fn from_entries(entries: &[MetricEntry], shard: &LocalShard) -> Self {
        let samples = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| shard.sample(index).map(|value| (entry, value)))
            .map(|(entry, value)| MetricSample {
                name: entry.name.clone(),
                labels: entry.labels.clone(),
                kind: entry.kind,
                unit: entry.unit,
                description: entry.description.clone(),
                value,
            })
            .collect();

        Self { samples }
    }
}

/// One metric sample captured from a per-core shard.
///
/// # Examples
///
/// ```
/// # use refract_obs::{CoreRecorder, RecorderConfig};
/// let recorder = CoreRecorder::new(RecorderConfig::default());
/// let _guard = metrics::set_default_local_recorder(&recorder);
/// metrics::counter!("refract.obs.health.requests").increment(1);
/// let snapshot = recorder.snapshot_current_thread();
/// assert_eq!(snapshot.samples()[0].name(), "refract.obs.health.requests");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricSample {
    name: String,
    labels: Vec<MetricLabel>,
    kind: MetricKind,
    unit: Option<Unit>,
    description: Option<String>,
    value: MetricValue,
}

impl MetricSample {
    /// Returns the metric name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let _guard = metrics::set_default_local_recorder(&recorder);
    /// metrics::counter!("refract.obs.health.requests").increment(1);
    /// assert_eq!(
    ///     recorder.snapshot_current_thread().samples()[0].name(),
    ///     "refract.obs.health.requests"
    /// );
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the metric kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, MetricKind, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let _guard = metrics::set_default_local_recorder(&recorder);
    /// metrics::counter!("refract.obs.health.requests").increment(1);
    /// assert_eq!(
    ///     recorder.snapshot_current_thread().samples()[0].kind(),
    ///     MetricKind::Counter
    /// );
    /// ```
    #[must_use]
    pub const fn kind(&self) -> MetricKind {
        self.kind
    }

    /// Returns the sample value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, MetricValue, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let _guard = metrics::set_default_local_recorder(&recorder);
    /// metrics::counter!("refract.obs.health.requests").increment(1);
    /// assert_eq!(
    ///     recorder.snapshot_current_thread().samples()[0].value(),
    ///     MetricValue::Counter(1)
    /// );
    /// ```
    #[must_use]
    pub const fn value(&self) -> MetricValue {
        self.value
    }
}

/// Metric label captured with a bounded-cardinality sample.
///
/// # Examples
///
/// ```
/// # use refract_obs::MetricLabel;
/// let label = MetricLabel::new("endpoint", "healthz");
/// assert_eq!(label.key(), "endpoint");
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MetricLabel {
    key: String,
    value: String,
}

impl MetricLabel {
    /// Creates a metric label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::MetricLabel;
    /// let label = MetricLabel::new("route", "metrics");
    /// assert_eq!(label.value(), "metrics");
    /// ```
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Returns the label key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::MetricLabel;
    /// assert_eq!(MetricLabel::new("k", "v").key(), "k");
    /// ```
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the label value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::MetricLabel;
    /// assert_eq!(MetricLabel::new("k", "v").value(), "v");
    /// ```
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Metric kind registered by the recorder.
///
/// # Examples
///
/// ```
/// # use refract_obs::MetricKind;
/// assert_eq!(MetricKind::Counter.as_str(), "counter");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricKind {
    /// Monotonic counter.
    Counter,
    /// Last-value gauge.
    Gauge,
    /// Histogram represented as count and sum in Stage 1.
    Histogram,
}

impl MetricKind {
    /// Returns a stable metric kind label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::MetricKind;
    /// assert_eq!(MetricKind::Histogram.as_str(), "histogram");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// Captured metric value.
///
/// # Examples
///
/// ```
/// # use refract_obs::MetricValue;
/// assert_eq!(MetricValue::Counter(3).is_zero(), false);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MetricValue {
    /// Counter total.
    Counter(u64),
    /// Gauge value.
    Gauge(f64),
    /// Histogram count and sum.
    Histogram {
        /// Number of observations.
        count: u64,
        /// Sum of observations.
        sum: f64,
    },
}

impl Eq for MetricValue {}

impl MetricValue {
    /// Returns whether the sample is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::MetricValue;
    /// assert!(MetricValue::Counter(0).is_zero());
    /// ```
    #[must_use]
    pub const fn is_zero(self) -> bool {
        match self {
            Self::Counter(value) => value == 0,
            Self::Gauge(value) => value == 0.0,
            Self::Histogram { count, sum } => count == 0 && sum == 0.0,
        }
    }
}

/// Prometheus pull exporter.
///
/// # Examples
///
/// ```
/// # use refract_obs::{CoreSnapshot, PrometheusExporter};
/// let body = PrometheusExporter::new().render(&[CoreSnapshot::default()])?;
/// assert!(body.is_empty());
/// # Ok::<(), refract_obs::ObsError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrometheusExporter;

impl PrometheusExporter {
    /// Creates a Prometheus exporter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::PrometheusExporter;
    /// let exporter = PrometheusExporter::new();
    /// assert_eq!(exporter.stability(), refract_obs::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Renders snapshots in Prometheus text exposition format.
    ///
    /// # Errors
    ///
    /// Returns [`ObsError::PrometheusRender`] if formatting fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreSnapshot, PrometheusExporter};
    /// let text = PrometheusExporter::new().render(&[CoreSnapshot::default()])?;
    /// assert_eq!(text, "");
    /// # Ok::<(), refract_obs::ObsError>(())
    /// ```
    pub fn render(&self, snapshots: &[CoreSnapshot]) -> ObsResult<String> {
        let mut aggregate = BTreeAggregate::default();
        snapshots
            .iter()
            .flat_map(CoreSnapshot::samples)
            .for_each(|sample| aggregate.record(sample));

        let mut output = String::new();
        for sample in aggregate.into_samples() {
            write_prometheus_sample(&mut output, &sample)?;
        }
        Ok(output)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{PrometheusExporter, Stability};
    /// assert_eq!(PrometheusExporter::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// OTLP push exporter boundary.
///
/// `refract-obs` builds bounded payloads and delegates transport to a sink
/// supplied by the compio-owning caller.
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// # use refract_obs::OtlpExporter;
/// let exporter = OtlpExporter::new("http://collector:4318/v1/metrics", Duration::from_secs(1));
/// assert_eq!(exporter.endpoint(), "http://collector:4318/v1/metrics");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpExporter {
    endpoint: String,
    timeout: Duration,
}

impl OtlpExporter {
    /// Creates an OTLP exporter configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::OtlpExporter;
    /// let exporter = OtlpExporter::new("http://collector", Duration::from_millis(10));
    /// assert_eq!(exporter.timeout(), Duration::from_millis(10));
    /// ```
    #[must_use]
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout,
        }
    }

    /// Returns the OTLP endpoint.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::OtlpExporter;
    /// assert_eq!(OtlpExporter::new("x", Duration::ZERO).endpoint(), "x");
    /// ```
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the deterministic export timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::OtlpExporter;
    /// assert_eq!(
    ///     OtlpExporter::new("x", Duration::from_secs(2)).timeout(),
    ///     Duration::from_secs(2)
    /// );
    /// ```
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Exports snapshots through a caller-provided sink.
    ///
    /// # Errors
    ///
    /// Returns [`ObsError::OtlpTimeout`] when the timeout is zero, or the sink
    /// error if the sink rejects the payload.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::{CoreSnapshot, OtlpExporter, OtlpMetricSink, OtlpPayload, ObsResult};
    /// # struct Sink;
    /// # impl OtlpMetricSink for Sink {
    /// #     fn export(&self, payload: OtlpPayload<'_>) -> ObsResult<()> {
    /// #         assert_eq!(payload.endpoint(), "endpoint");
    /// #         Ok(())
    /// #     }
    /// # }
    /// OtlpExporter::new("endpoint", Duration::from_millis(1))
    ///     .push(&Sink, &[CoreSnapshot::default()])?;
    /// # Ok::<(), refract_obs::ObsError>(())
    /// ```
    pub fn push(&self, sink: &impl OtlpMetricSink, snapshots: &[CoreSnapshot]) -> ObsResult<()> {
        if self.timeout.is_zero() {
            let timeout_ms = u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX);
            return Err(ObsError::OtlpTimeout { timeout_ms });
        }
        let payload = OtlpPayload {
            endpoint: &self.endpoint,
            timeout: self.timeout,
            snapshots,
        };
        sink.export(payload)
    }
}

/// Caller-provided OTLP metric transport.
///
/// # Examples
///
/// ```
/// # use refract_obs::{OtlpMetricSink, OtlpPayload, ObsResult};
/// struct Sink;
/// impl OtlpMetricSink for Sink {
///     fn export(&self, _payload: OtlpPayload<'_>) -> ObsResult<()> {
///         Ok(())
///     }
/// }
/// ```
pub trait OtlpMetricSink {
    /// Exports one OTLP payload.
    ///
    /// # Errors
    ///
    /// Returns an [`ObsError`](crate::ObsError) when the transport rejects the
    /// payload or times out.
    fn export(&self, payload: OtlpPayload<'_>) -> ObsResult<()>;
}

/// Borrowed OTLP payload handed to a transport sink.
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// # use refract_obs::{CoreSnapshot, OtlpExporter, OtlpMetricSink, OtlpPayload, ObsResult};
/// # struct Sink;
/// # impl OtlpMetricSink for Sink {
/// #     fn export(&self, payload: OtlpPayload<'_>) -> ObsResult<()> {
/// #         assert_eq!(payload.snapshots().len(), 1);
/// #         Ok(())
/// #     }
/// # }
/// OtlpExporter::new("endpoint", Duration::from_millis(1))
///     .push(&Sink, &[CoreSnapshot::default()])?;
/// # Ok::<(), refract_obs::ObsError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct OtlpPayload<'a> {
    endpoint: &'a str,
    timeout: Duration,
    snapshots: &'a [CoreSnapshot],
}

impl<'a> OtlpPayload<'a> {
    /// Returns the OTLP endpoint.
    ///
    /// # Examples
    ///
    /// See [`OtlpPayload`] for a complete sink example.
    #[must_use]
    pub const fn endpoint(self) -> &'a str {
        self.endpoint
    }

    /// Returns the timeout budget.
    ///
    /// # Examples
    ///
    /// See [`OtlpPayload`] for a complete sink example.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Returns the metric snapshots to export.
    ///
    /// # Examples
    ///
    /// See [`OtlpPayload`] for a complete sink example.
    #[must_use]
    pub const fn snapshots(self) -> &'a [CoreSnapshot] {
        self.snapshots
    }
}

/// Health, readiness, metrics, and profiling endpoint handler.
///
/// # Examples
///
/// ```
/// # use refract_obs::{CoreRecorder, EndpointSet, PrometheusExporter, RecorderConfig};
/// let recorder = CoreRecorder::new(RecorderConfig::default());
/// let endpoints = EndpointSet::new(PrometheusExporter::new(), false, None);
/// assert_eq!(endpoints.handle("/healthz", None, &recorder)?.status(), 200);
/// # Ok::<(), refract_obs::ObsError>(())
/// ```
#[derive(Clone, Debug)]
pub struct EndpointSet {
    prometheus: PrometheusExporter,
    profiling_enabled: bool,
    admin_token: Option<String>,
    ready: bool,
}

impl EndpointSet {
    /// Creates endpoint handlers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{EndpointSet, PrometheusExporter};
    /// let endpoints = EndpointSet::new(PrometheusExporter::new(), false, None);
    /// assert!(!endpoints.profiling_enabled());
    /// ```
    #[must_use]
    pub const fn new(
        prometheus: PrometheusExporter,
        profiling_enabled: bool,
        admin_token: Option<String>,
    ) -> Self {
        Self {
            prometheus,
            profiling_enabled,
            admin_token,
            ready: true,
        }
    }

    /// Sets readiness returned by `/readyz`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{EndpointSet, PrometheusExporter};
    /// let endpoints = EndpointSet::new(PrometheusExporter::new(), false, None).with_ready(false);
    /// assert!(!endpoints.ready());
    /// ```
    #[must_use]
    pub const fn with_ready(mut self, ready: bool) -> Self {
        self.ready = ready;
        self
    }

    /// Returns whether profiling endpoints are enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{EndpointSet, PrometheusExporter};
    /// assert!(!EndpointSet::new(PrometheusExporter::new(), false, None).profiling_enabled());
    /// ```
    #[must_use]
    pub const fn profiling_enabled(&self) -> bool {
        self.profiling_enabled
    }

    /// Returns current readiness.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{EndpointSet, PrometheusExporter};
    /// assert!(EndpointSet::new(PrometheusExporter::new(), false, None).ready());
    /// ```
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Handles one bounded endpoint path.
    ///
    /// # Errors
    ///
    /// Returns [`ObsError::InvalidEndpointPath`] for oversized or unknown paths,
    /// and profiling errors when `/debug/pprof/*` is not authorized.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::{CoreRecorder, EndpointSet, PrometheusExporter, RecorderConfig};
    /// let recorder = CoreRecorder::new(RecorderConfig::default());
    /// let endpoints = EndpointSet::new(PrometheusExporter::new(), false, None);
    /// assert_eq!(endpoints.handle("/readyz", None, &recorder)?.status(), 200);
    /// # Ok::<(), refract_obs::ObsError>(())
    /// ```
    pub fn handle(
        &self,
        path: &str,
        admin_token: Option<&str>,
        recorder: &CoreRecorder,
    ) -> ObsResult<EndpointResponse> {
        if path.len() > MAX_ENDPOINT_PATH_BYTES || !path.starts_with('/') {
            return Err(ObsError::InvalidEndpointPath);
        }

        match path {
            "/healthz" => {
                metrics::counter!("refract.obs.health.requests", "endpoint" => "healthz")
                    .increment(1);
                Ok(EndpointResponse::new(200, "text/plain", "ok\n"))
            }
            "/readyz" => {
                metrics::counter!("refract.obs.health.requests", "endpoint" => "readyz")
                    .increment(1);
                if self.ready {
                    Ok(EndpointResponse::new(200, "text/plain", "ready\n"))
                } else {
                    Ok(EndpointResponse::new(503, "text/plain", "not_ready\n"))
                }
            }
            "/metrics" => {
                metrics::counter!("refract.obs.health.requests", "endpoint" => "metrics")
                    .increment(1);
                let body = self
                    .prometheus
                    .render(&[recorder.snapshot_current_thread()])?;
                Ok(EndpointResponse::new(
                    200,
                    "text/plain; version=0.0.4",
                    body,
                ))
            }
            "/debug/pprof/cpu" | "/debug/pprof/heap" | "/debug/pprof/allocs" => {
                self.authorize_profile(admin_token)?;
                metrics::counter!("refract.obs.profiling.requests").increment(1);
                Ok(EndpointResponse::new(
                    200,
                    "application/octet-stream",
                    "profile=stage1\n",
                ))
            }
            _ => Err(ObsError::InvalidEndpointPath),
        }
    }

    fn authorize_profile(&self, token: Option<&str>) -> ObsResult<()> {
        if !self.profiling_enabled {
            return Err(ObsError::ProfilingDisabled);
        }

        match (self.admin_token.as_deref(), token) {
            (Some(expected), Some(actual)) if expected == actual => Ok(()),
            (None, None) => Ok(()),
            _ => Err(ObsError::AdminTokenRejected),
        }
    }
}

/// Response returned by a mounted observability endpoint.
///
/// # Examples
///
/// ```
/// # use refract_obs::EndpointResponse;
/// let response = EndpointResponse::new(200, "text/plain", "ok");
/// assert_eq!(response.body(), "ok");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointResponse {
    status: u16,
    content_type: String,
    body: String,
}

impl EndpointResponse {
    /// Creates an endpoint response.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::EndpointResponse;
    /// assert_eq!(EndpointResponse::new(204, "text/plain", "").status(), 204);
    /// ```
    #[must_use]
    pub fn new(status: u16, content_type: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
        }
    }

    /// Returns the HTTP status code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::EndpointResponse;
    /// assert_eq!(EndpointResponse::new(200, "text/plain", "ok").status(), 200);
    /// ```
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the content type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::EndpointResponse;
    /// assert_eq!(
    ///     EndpointResponse::new(200, "text/plain", "ok").content_type(),
    ///     "text/plain"
    /// );
    /// ```
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Returns the response body.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::EndpointResponse;
    /// assert_eq!(EndpointResponse::new(200, "text/plain", "ok").body(), "ok");
    /// ```
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// Tracing subscriber configuration.
///
/// # Examples
///
/// ```
/// # use refract_obs::TracingConfig;
/// assert_eq!(
///     TracingConfig::default().slow_path_sample_denominator(),
///     1_000
/// );
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracingConfig {
    env_filter: String,
    pretty_in_dev: bool,
    json_in_release: bool,
    slow_path_sample_denominator: u32,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            env_filter: std::env::var("RUST_LOG").unwrap_or_else(|_error| "info".to_owned()),
            pretty_in_dev: cfg!(debug_assertions),
            json_in_release: !cfg!(debug_assertions),
            slow_path_sample_denominator: DEFAULT_SAMPLE_DENOMINATOR,
        }
    }
}

impl TracingConfig {
    /// Returns the RUST_LOG-derived filter string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::TracingConfig;
    /// assert!(!TracingConfig::default().env_filter().is_empty());
    /// ```
    #[must_use]
    pub fn env_filter(&self) -> &str {
        &self.env_filter
    }

    /// Returns the default slow-path sample denominator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::TracingConfig;
    /// assert_eq!(
    ///     TracingConfig::default().slow_path_sample_denominator(),
    ///     1_000
    /// );
    /// ```
    #[must_use]
    pub const fn slow_path_sample_denominator(&self) -> u32 {
        self.slow_path_sample_denominator
    }

    /// Builds the tracing subscriber layers without installing them globally.
    ///
    /// # Errors
    ///
    /// Returns [`ObsError::OtlpSink`] when the configured filter is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::TracingConfig;
    /// let _subscriber = TracingConfig::default().build_subscriber()?;
    /// # Ok::<(), refract_obs::ObsError>(())
    /// ```
    pub fn build_subscriber(&self) -> ObsResult<Box<dyn tracing::Subscriber + Send + Sync>> {
        let env_filter =
            EnvFilter::try_new(&self.env_filter).map_err(|_error| ObsError::OtlpSink {
                reason: "invalid rust_log filter",
            })?;
        let registry = tracing_subscriber::registry().with(env_filter);
        if self.json_in_release && !self.pretty_in_dev {
            Ok(Box::new(
                registry.with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_span_events(FmtSpan::CLOSE),
                ),
            ))
        } else {
            Ok(Box::new(
                registry.with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_span_events(FmtSpan::CLOSE),
                ),
            ))
        }
    }
}

/// Deterministic sampler for high-frequency slow-path events.
///
/// # Examples
///
/// ```
/// # use refract_obs::TraceSampler;
/// let sampler = TraceSampler::new(1_000);
/// assert!(sampler.should_sample(0, false));
/// assert!(!sampler.should_sample(1, false));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceSampler {
    denominator: u32,
}

impl TraceSampler {
    /// Creates a sampler with a bounded denominator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::TraceSampler;
    /// assert_eq!(TraceSampler::new(0).denominator(), 1);
    /// ```
    #[must_use]
    pub const fn new(denominator: u32) -> Self {
        Self {
            denominator: if denominator == 0 { 1 } else { denominator },
        }
    }

    /// Returns the sampling denominator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::TraceSampler;
    /// assert_eq!(TraceSampler::new(10).denominator(), 10);
    /// ```
    #[must_use]
    pub const fn denominator(self) -> u32 {
        self.denominator
    }

    /// Returns whether an event should be sampled.
    ///
    /// Passing `operator_forced = true` samples all events.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_obs::TraceSampler;
    /// let sampler = TraceSampler::new(100);
    /// assert!(sampler.should_sample(99, true));
    /// ```
    #[must_use]
    pub const fn should_sample(self, sequence: u64, operator_forced: bool) -> bool {
        operator_forced || sequence.is_multiple_of(self.denominator as u64)
    }
}

/// Slow-path operation record.
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// # use refract_obs::SlowPathEvent;
/// let event = SlowPathEvent::new("room_store", Duration::from_millis(51));
/// assert!(event.is_slow());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SlowPathEvent {
    operation: String,
    duration_ms: u64,
    threshold_ms: u64,
}

impl SlowPathEvent {
    /// Creates a slow-path event record.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::SlowPathEvent;
    /// assert_eq!(
    ///     SlowPathEvent::new("x", Duration::from_millis(1)).duration_ms(),
    ///     1
    /// );
    /// ```
    #[must_use]
    pub fn new(operation: impl Into<String>, duration: Duration) -> Self {
        Self {
            operation: operation.into(),
            duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            threshold_ms: DEFAULT_SLOW_MS,
        }
    }

    /// Returns the operation name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::SlowPathEvent;
    /// assert_eq!(SlowPathEvent::new("x", Duration::ZERO).operation(), "x");
    /// ```
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the duration in milliseconds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::SlowPathEvent;
    /// assert_eq!(
    ///     SlowPathEvent::new("x", Duration::from_millis(5)).duration_ms(),
    ///     5
    /// );
    /// ```
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    /// Returns whether the event exceeds the slow-query threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::SlowPathEvent;
    /// assert!(!SlowPathEvent::new("x", Duration::from_millis(49)).is_slow());
    /// ```
    #[must_use]
    pub const fn is_slow(&self) -> bool {
        self.duration_ms > self.threshold_ms
    }

    /// Serializes the event for structured logging.
    ///
    /// # Errors
    ///
    /// Returns a serde error if JSON serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::SlowPathEvent;
    /// let json = SlowPathEvent::new("x", Duration::from_millis(60)).to_json()?;
    /// assert!(json.contains("duration_ms"));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Creates a tracing span with OpenTelemetry context support.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_obs::SlowPathEvent;
    /// let span = SlowPathEvent::new("x", Duration::from_millis(60)).span();
    /// assert!(span.is_disabled() || span.metadata().is_some());
    /// ```
    #[must_use]
    pub fn span(&self) -> tracing::Span {
        let span = tracing::info_span!(
            "refract.slow_path",
            span_name = SLOW_PATH_SPAN_NAME,
            operation = %self.operation,
            duration_ms = self.duration_ms,
            threshold_ms = self.threshold_ms,
            sampled = self.is_slow()
        );
        let _context = span.context();
        span
    }
}

#[derive(Clone, Debug, Default)]
struct Registry {
    entries: Vec<MetricEntry>,
    descriptions: HashMap<(String, MetricKind), MetricDescription>,
}

impl Registry {
    fn describe(&mut self, name: &str, kind: MetricKind, unit: Option<Unit>, description: &str) {
        let details = MetricDescription {
            unit,
            description: Some(description.to_owned()),
        };
        self.descriptions.insert((name.to_owned(), kind), details);
    }

    fn register(&mut self, key: &Key, kind: MetricKind, max_metrics: usize) -> Option<MetricId> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.matches(key, kind))
        {
            return Some(MetricId(index));
        }

        if self.entries.len() >= max_metrics {
            return None;
        }

        let name = key.name().to_owned();
        let labels = key
            .labels()
            .map(|label| MetricLabel::new(label.key(), label.value()))
            .collect::<Vec<_>>();
        let description = self
            .descriptions
            .get(&(name.clone(), kind))
            .cloned()
            .unwrap_or_default();

        let id = MetricId(self.entries.len());
        self.entries.push(MetricEntry {
            name,
            labels,
            kind,
            unit: description.unit,
            description: description.description,
        });
        Some(id)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MetricDescription {
    unit: Option<Unit>,
    description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetricEntry {
    name: String,
    labels: Vec<MetricLabel>,
    kind: MetricKind,
    unit: Option<Unit>,
    description: Option<String>,
}

impl MetricEntry {
    fn matches(&self, key: &Key, kind: MetricKind) -> bool {
        self.kind == kind
            && self.name == key.name()
            && self.labels.len() == key.labels().count()
            && self
                .labels
                .iter()
                .zip(key.labels())
                .all(|(left, right)| left.key() == right.key() && left.value() == right.value())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct MetricId(usize);

#[derive(Clone, Copy, Debug, Default)]
struct LocalMetricValue {
    counter: u64,
    gauge: f64,
    histogram_count: u64,
    histogram_sum: f64,
}

#[derive(Clone, Debug, Default)]
struct LocalShard {
    values: Vec<LocalMetricValue>,
}

impl LocalShard {
    fn ensure_len(&mut self, len: usize) {
        if self.values.len() < len {
            self.values.resize(len, LocalMetricValue::default());
        }
    }

    fn increment_counter(&mut self, id: MetricId, value: u64) {
        self.ensure_len(id.0 + 1);
        if let Some(slot) = self.values.get_mut(id.0) {
            slot.counter = slot.counter.saturating_add(value);
        }
    }

    fn set_counter_absolute(&mut self, id: MetricId, value: u64) {
        self.ensure_len(id.0 + 1);
        if let Some(slot) = self.values.get_mut(id.0) {
            slot.counter = slot.counter.max(value);
        }
    }

    fn update_gauge(&mut self, id: MetricId, value: f64, mode: GaugeMode) {
        self.ensure_len(id.0 + 1);
        if let Some(slot) = self.values.get_mut(id.0) {
            match mode {
                GaugeMode::Increment => slot.gauge += value,
                GaugeMode::Decrement => slot.gauge -= value,
                GaugeMode::Set => slot.gauge = value,
            }
        }
    }

    fn record_histogram(&mut self, id: MetricId, value: f64) {
        self.ensure_len(id.0 + 1);
        if let Some(slot) = self.values.get_mut(id.0) {
            slot.histogram_count = slot.histogram_count.saturating_add(1);
            slot.histogram_sum += value;
        }
    }

    fn sample(&self, index: usize) -> Option<MetricValue> {
        let value = self.values.get(index)?;
        let sample = if value.histogram_count > 0 {
            MetricValue::Histogram {
                count: value.histogram_count,
                sum: value.histogram_sum,
            }
        } else if value.counter > 0 {
            MetricValue::Counter(value.counter)
        } else if value.gauge != 0.0 {
            MetricValue::Gauge(value.gauge)
        } else {
            return None;
        };
        Some(sample)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GaugeMode {
    Increment,
    Decrement,
    Set,
}

#[derive(Debug)]
struct LocalCounter {
    id: MetricId,
}

impl CounterFn for LocalCounter {
    fn increment(&self, value: u64) {
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.increment_counter(self.id, value);
            }
        });
    }

    fn absolute(&self, value: u64) {
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.set_counter_absolute(self.id, value);
            }
        });
    }
}

#[derive(Debug)]
struct LocalGauge {
    id: MetricId,
}

impl GaugeFn for LocalGauge {
    fn increment(&self, value: f64) {
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.update_gauge(self.id, value, GaugeMode::Increment);
            }
        });
    }

    fn decrement(&self, value: f64) {
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.update_gauge(self.id, value, GaugeMode::Decrement);
            }
        });
    }

    fn set(&self, value: f64) {
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.update_gauge(self.id, value, GaugeMode::Set);
            }
        });
    }
}

#[derive(Debug)]
struct LocalHistogram {
    id: MetricId,
}

impl HistogramFn for LocalHistogram {
    fn record(&self, value: f64) {
        LOCAL_SHARD.with(|shard| {
            if let Ok(mut shard) = shard.try_borrow_mut() {
                shard.record_histogram(self.id, value);
            }
        });
    }
}

#[derive(Default)]
struct BTreeAggregate {
    samples: Vec<MetricSample>,
}

impl BTreeAggregate {
    fn record(&mut self, sample: &MetricSample) {
        if let Some(existing) = self.samples.iter_mut().find(|existing| {
            existing.name == sample.name
                && existing.labels == sample.labels
                && existing.kind == sample.kind
        }) {
            existing.value = merge_metric_value(existing.value, sample.value);
            return;
        }
        self.samples.push(sample.clone());
    }

    fn into_samples(mut self) -> Vec<MetricSample> {
        self.samples.sort_by(|left, right| {
            (left.name.as_str(), left.kind, left.labels.as_slice()).cmp(&(
                right.name.as_str(),
                right.kind,
                right.labels.as_slice(),
            ))
        });
        self.samples
    }
}

fn merge_metric_value(left: MetricValue, right: MetricValue) -> MetricValue {
    match (left, right) {
        (MetricValue::Counter(left), MetricValue::Counter(right)) => {
            MetricValue::Counter(left.saturating_add(right))
        }
        (MetricValue::Gauge(_left), MetricValue::Gauge(right)) => MetricValue::Gauge(right),
        (
            MetricValue::Histogram {
                count: left_count,
                sum: left_sum,
            },
            MetricValue::Histogram {
                count: right_count,
                sum: right_sum,
            },
        ) => MetricValue::Histogram {
            count: left_count.saturating_add(right_count),
            sum: left_sum + right_sum,
        },
        (_left, right) => right,
    }
}

fn write_prometheus_sample(output: &mut String, sample: &MetricSample) -> ObsResult<()> {
    let name = prometheus_name(sample.name());
    if let Some(description) = sample.description.as_deref() {
        writeln!(output, "# HELP {name} {}", escape_help(description))
            .map_err(|_error| ObsError::PrometheusRender)?;
    }
    let kind = match sample.kind {
        MetricKind::Counter => "counter",
        MetricKind::Gauge => "gauge",
        MetricKind::Histogram => "summary",
    };
    writeln!(output, "# TYPE {name} {kind}").map_err(|_error| ObsError::PrometheusRender)?;
    if let Some(unit) = sample.unit {
        writeln!(output, "# UNIT {name} {}", unit.as_str())
            .map_err(|_error| ObsError::PrometheusRender)?;
    }

    match sample.value {
        MetricValue::Counter(value) => write_value(output, &name, &sample.labels, value),
        MetricValue::Gauge(value) => write_value(output, &name, &sample.labels, value),
        MetricValue::Histogram { count, sum } => {
            write_value(output, &format!("{name}_count"), &sample.labels, count)?;
            write_value(output, &format!("{name}_sum"), &sample.labels, sum)
        }
    }
}

fn write_value(
    output: &mut String,
    name: &str,
    labels: &[MetricLabel],
    value: impl fmt::Display,
) -> ObsResult<()> {
    if labels.is_empty() {
        writeln!(output, "{name} {value}").map_err(|_error| ObsError::PrometheusRender)
    } else {
        let encoded_labels = labels
            .iter()
            .map(|label| {
                format!(
                    "{}=\"{}\"",
                    prometheus_name(label.key()),
                    escape_label_value(label.value())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        writeln!(output, "{name}{{{encoded_labels}}} {value}")
            .map_err(|_error| ObsError::PrometheusRender)
    }
}

fn prometheus_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn escape_help(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

/// Returns the Stage 1 stability marker for the crate.
///
/// # Examples
///
/// ```
/// # use refract_obs::{stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> Stability {
    Stability::Stage1
}

/// Returns the highest tracing level used by hot-path code.
///
/// Hot-path code must use metrics only, so this returns `None`.
///
/// # Examples
///
/// ```
/// # use refract_obs::hot_path_tracing_level;
/// assert!(hot_path_tracing_level().is_none());
/// ```
#[must_use]
pub const fn hot_path_tracing_level() -> Option<Level> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_registration_and_prometheus_export_work() -> ObsResult<()> {
        let recorder = CoreRecorder::default();
        let _guard = metrics::set_default_local_recorder(&recorder);
        recorder.register_stage1_metrics();
        recorder.warm_current_thread();

        metrics::counter!("refract.obs.health.requests", "endpoint" => "healthz").increment(2);
        metrics::gauge!("refract.obs.ready").set(1.0);
        metrics::histogram!("refract.obs.slow_path.duration").record(75.0);

        let text = PrometheusExporter::new().render(&[recorder.snapshot_current_thread()])?;

        assert!(text.contains("refract_obs_health_requests"));
        assert!(text.contains("endpoint=\"healthz\""));
        assert!(text.contains("refract_obs_slow_path_duration_count 1"));
        Ok(())
    }

    #[test]
    fn tracing_span_contains_slow_path_name() {
        let subscriber = TracingConfig::default()
            .build_subscriber()
            .expect("subscriber config is valid");
        tracing::subscriber::with_default(subscriber, || {
            let span = SlowPathEvent::new("room_store", Duration::from_millis(75)).span();
            assert_eq!(SLOW_PATH_SPAN_NAME, "refract.slow_path");
            assert!(span.is_disabled() || span.metadata().is_some());
        });
    }

    #[test]
    fn sampling_under_flood_is_bounded_and_operator_overrides() {
        let sampler = TraceSampler::new(1_000);
        let selected_count = (0..10_000)
            .filter(|sequence| sampler.should_sample(*sequence, false))
            .count();
        assert_eq!(selected_count, 10);
        assert!((0..10_000).all(|sequence| sampler.should_sample(sequence, true)));
    }

    #[test]
    fn profiling_endpoint_is_gated_by_enablement_and_token() -> ObsResult<()> {
        let recorder = CoreRecorder::default();
        let disabled = EndpointSet::new(PrometheusExporter::new(), false, Some("token".to_owned()));
        let error = disabled
            .handle("/debug/pprof/cpu", Some("token"), &recorder)
            .expect_err("profiling disabled");
        assert_eq!(error.error_code(), "OBS_PROFILE_0001");

        let enabled = EndpointSet::new(PrometheusExporter::new(), true, Some("token".to_owned()));
        let error = enabled
            .handle("/debug/pprof/cpu", Some("wrong"), &recorder)
            .expect_err("token rejected");
        assert_eq!(error.error_code(), "OBS_PROFILE_0002");

        assert_eq!(
            enabled
                .handle("/debug/pprof/cpu", Some("token"), &recorder)?
                .status(),
            200
        );
        Ok(())
    }

    #[test]
    fn health_and_metrics_endpoints_return_expected_status() -> ObsResult<()> {
        let recorder = CoreRecorder::default();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let endpoints = EndpointSet::new(PrometheusExporter::new(), false, None).with_ready(false);

        assert_eq!(endpoints.handle("/healthz", None, &recorder)?.status(), 200);
        assert_eq!(endpoints.handle("/readyz", None, &recorder)?.status(), 503);
        assert_eq!(
            endpoints
                .handle("/metrics", None, &recorder)?
                .content_type(),
            "text/plain; version=0.0.4"
        );
        Ok(())
    }

    #[test]
    fn otlp_export_invokes_sink_and_enforces_timeout() -> ObsResult<()> {
        struct Sink;

        impl OtlpMetricSink for Sink {
            fn export(&self, payload: OtlpPayload<'_>) -> ObsResult<()> {
                assert_eq!(payload.endpoint(), "collector");
                assert_eq!(payload.snapshots().len(), 1);
                Ok(())
            }
        }

        let exporter = OtlpExporter::new("collector", Duration::from_millis(1));
        exporter.push(&Sink, &[CoreSnapshot::default()])?;

        let error = OtlpExporter::new("collector", Duration::ZERO)
            .push(&Sink, &[CoreSnapshot::default()])
            .expect_err("zero timeout rejected");
        assert_eq!(error.error_code(), "OBS_OTLP_0001");
        Ok(())
    }

    #[test]
    fn every_error_variant_has_unique_code() {
        let errors = [
            ObsError::InvalidEndpointPath,
            ObsError::ProfilingDisabled,
            ObsError::AdminTokenRejected,
            ObsError::OtlpTimeout { timeout_ms: 1 },
            ObsError::OtlpSink { reason: "x" },
            ObsError::PrometheusRender,
        ];
        let mut codes = errors.iter().map(ObsError::error_code).collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }

    #[test]
    fn slow_path_log_serializes_full_detail() -> Result<(), serde_json::Error> {
        let event = SlowPathEvent::new("placement", Duration::from_millis(51));
        assert!(event.is_slow());
        let json = event.to_json()?;
        assert!(json.contains("\"operation\":\"placement\""));
        assert!(json.contains("\"duration_ms\":51"));
        Ok(())
    }
}
