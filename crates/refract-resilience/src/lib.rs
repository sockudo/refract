//! Panic isolation, memory pressure, watchdog, and load-shed resilience.
//!
//! `refract-resilience` contains safe Stage 1 control-plane primitives for
//! keeping one peer, one stalled core, or one saturated component from taking
//! down the process. The actual runtime wires these primitives into the SFU hot
//! loop, allocator boundary, and admin drain executor.
//!
//! # Examples
//!
//! ```
//! # use refract_core::PeerId;
//! # use refract_resilience::{DrainSignal, PanicGuard};
//! let drain = DrainSignal::default();
//! let guard = PanicGuard::new(drain);
//! let value = guard.run_peer(PeerId::from_raw(1), "forward", || 7)?;
//! assert_eq!(value, 7);
//! # Ok::<(), refract_resilience::ResilienceError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    backtrace::Backtrace,
    borrow::Borrow,
    fmt,
    panic::{AssertUnwindSafe, UnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use refract_core::PeerId;
use thiserror::Error as ThisError;
use tracing::{error, warn};

const WATCHDOG_ERROR_CODE: &str = "HSF-WD-001";
const PANIC_ERROR_CODE: &str = "HSF-PANIC-PEER";
const OOM_ERROR_CODE: &str = "HSF-OOM-001";
const RESOURCE_ERROR_CODE: &str = "HSF-RESOURCE-001";
const BACKPRESSURE_ERROR_CODE: &str = "HSF-BP-001";
const DEFAULT_WATCHDOG_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MEMORY_HIGH_RATIO_PER_MILLE: u16 = 950;

/// Result alias for resilience operations.
pub type ResilienceResult<T> = Result<T, ResilienceError>;

/// Stage marker for public `refract-resilience` APIs.
///
/// # Examples
///
/// ```
/// # use refract_resilience::Stability;
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
    /// # use refract_resilience::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Resilience error taxonomy with stable operator codes.
///
/// # Examples
///
/// ```
/// # use refract_resilience::ResilienceError;
/// assert_eq!(
///     ResilienceError::PeerPanicked.error_code(),
///     "RESILIENCE_PANIC_0001"
/// );
/// ```
#[derive(Debug, ThisError)]
pub enum ResilienceError {
    /// Peer-local handler panicked and was isolated.
    #[error("peer handler panicked")]
    PeerPanicked,
    /// A core heartbeat exceeded the watchdog deadline.
    #[error("watchdog timeout on core {core_id}")]
    WatchdogTimeout {
        /// Core identifier.
        core_id: u16,
    },
    /// Resource limit admission rejected an operation.
    #[error("resource limit exceeded for {resource}: limit {limit}, requested {requested}")]
    ResourceLimit {
        /// Rejected resource.
        resource: ResourceKind,
        /// Configured limit.
        limit: u64,
        /// Requested amount.
        requested: u64,
    },
    /// Memory pressure reached OOM drain threshold.
    #[error("memory pressure reached drain threshold")]
    MemoryPressure,
    /// Backpressure requires load shedding.
    #[error("backpressure signal raised by {component}")]
    Backpressure {
        /// Saturated component.
        component: &'static str,
    },
}

impl ResilienceError {
    /// Returns the stable operator dashboard code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_resilience::ResilienceError;
    /// assert_eq!(
    ///     ResilienceError::MemoryPressure.error_code(),
    ///     "RESILIENCE_OOM_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::PeerPanicked => "RESILIENCE_PANIC_0001",
            Self::WatchdogTimeout { .. } => "RESILIENCE_WATCHDOG_0001",
            Self::ResourceLimit { .. } => "RESILIENCE_RESOURCE_0001",
            Self::MemoryPressure => "RESILIENCE_OOM_0001",
            Self::Backpressure { .. } => "RESILIENCE_BACKPRESSURE_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_resilience::{ResilienceError, Stability};
    /// assert_eq!(ResilienceError::PeerPanicked.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Drain mode requested by resilience primitives.
///
/// # Examples
///
/// ```
/// # use refract_resilience::DrainMode;
/// assert_eq!(DrainMode::Fast.as_str(), "fast");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DrainMode {
    /// Gracefully refuse new sessions and let active sessions leave.
    Graceful,
    /// Refuse new sessions and kill remaining live sessions quickly.
    Fast,
}

impl DrainMode {
    /// Returns the stable drain mode label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Fast => "fast",
        }
    }
}

impl fmt::Display for DrainMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Drain request raised by resilience code.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{DrainMode, DrainRequest};
/// let request = DrainRequest::new(DrainMode::Graceful, "oom", "HSF-OOM-001");
/// assert_eq!(request.mode(), DrainMode::Graceful);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainRequest {
    mode: DrainMode,
    reason: &'static str,
    error_code: &'static str,
}

impl DrainRequest {
    /// Creates a drain request.
    #[must_use]
    pub const fn new(mode: DrainMode, reason: &'static str, error_code: &'static str) -> Self {
        Self {
            mode,
            reason,
            error_code,
        }
    }

    /// Returns the drain mode.
    #[must_use]
    pub const fn mode(self) -> DrainMode {
        self.mode
    }

    /// Returns the drain reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }

    /// Returns the drain error code.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        self.error_code
    }
}

/// Shared drain signal set by resilience triggers.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{DrainMode, DrainRequest, DrainSignal};
/// let signal = DrainSignal::default();
/// signal.trigger(DrainRequest::new(DrainMode::Fast, "watchdog", "HSF-WD-001"));
/// assert_eq!(
///     signal.request().map(DrainRequest::mode),
///     Some(DrainMode::Fast)
/// );
/// ```
#[derive(Clone, Debug, Default)]
pub struct DrainSignal {
    inner: Arc<DrainSignalInner>,
}

#[derive(Debug, Default)]
struct DrainSignalInner {
    requested: AtomicBool,
    mode: AtomicU64,
    reason: AtomicU64,
}

impl DrainSignal {
    /// Triggers a drain request.
    pub fn trigger(&self, request: DrainRequest) {
        self.inner
            .mode
            .store(encode_mode(request.mode()), Ordering::Release);
        self.inner
            .reason
            .store(encode_reason(request.reason()), Ordering::Release);
        self.inner.requested.store(true, Ordering::Release);
        metrics::counter!(
            "refract.resilience.drain.triggered",
            "mode" => request.mode().as_str(),
            "reason" => request.reason(),
            "error_code" => request.error_code()
        )
        .increment(1);
    }

    /// Returns the current drain request if one was triggered.
    #[must_use]
    pub fn request(&self) -> Option<DrainRequest> {
        self.inner.requested.load(Ordering::Acquire).then(|| {
            let mode = decode_mode(self.inner.mode.load(Ordering::Acquire));
            let reason = decode_reason(self.inner.reason.load(Ordering::Acquire));
            let error_code = match mode {
                DrainMode::Graceful if reason == "oom" => OOM_ERROR_CODE,
                DrainMode::Fast if reason == "watchdog" => WATCHDOG_ERROR_CODE,
                DrainMode::Fast if reason == "backpressure" => BACKPRESSURE_ERROR_CODE,
                DrainMode::Fast => RESOURCE_ERROR_CODE,
                DrainMode::Graceful => OOM_ERROR_CODE,
            };
            DrainRequest::new(mode, reason, error_code)
        })
    }

    /// Returns whether a drain has been requested.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.inner.requested.load(Ordering::Acquire)
    }
}

/// Result of peer panic isolation.
///
/// # Examples
///
/// ```
/// # use refract_resilience::PanicOutcome;
/// assert!(
///     PanicOutcome::Recovered {
///         peer_torn_down: true
///     }
///     .peer_torn_down()
/// );
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PanicOutcome {
    /// Peer handler completed normally.
    Completed,
    /// Peer handler panicked and the peer should be torn down.
    Recovered {
        /// Whether peer teardown was requested.
        peer_torn_down: bool,
    },
}

impl PanicOutcome {
    /// Returns whether the peer must be torn down.
    #[must_use]
    pub const fn peer_torn_down(self) -> bool {
        matches!(
            self,
            Self::Recovered {
                peer_torn_down: true
            }
        )
    }
}

/// Per-peer panic isolation guard.
///
/// # Examples
///
/// ```
/// # use refract_core::PeerId;
/// # use refract_resilience::{DrainSignal, PanicGuard};
/// let guard = PanicGuard::new(DrainSignal::default());
/// assert_eq!(guard.run_peer(PeerId::from_raw(1), "forward", || 1)?, 1);
/// # Ok::<(), refract_resilience::ResilienceError>(())
/// ```
#[derive(Clone, Debug)]
pub struct PanicGuard {}

impl PanicGuard {
    /// Creates a panic guard.
    #[must_use]
    pub fn new(_drain: DrainSignal) -> Self {
        Self {}
    }

    /// Runs peer-owned hot-path work behind `catch_unwind`.
    ///
    /// # Errors
    ///
    /// Returns [`ResilienceError::PeerPanicked`] when the closure panics. The
    /// caller should tear down only that peer and continue the process.
    pub fn run_peer<T, F>(
        &self,
        peer_id: PeerId,
        operation: &'static str,
        work: F,
    ) -> ResilienceResult<T>
    where
        F: FnOnce() -> T + UnwindSafe,
    {
        catch_unwind(AssertUnwindSafe(work)).map_err(|payload| {
            let panic_message = panic_payload(payload.as_ref());
            metrics::counter!(
                "refract.resilience.peer.panics",
                "error_code" => PANIC_ERROR_CODE,
                "operation" => operation
            )
            .increment(1);
            error!(
                error_code = PANIC_ERROR_CODE,
                peer_id = %peer_id,
                operation,
                panic.message = panic_message,
                "peer panic isolated"
            );
            ResilienceError::PeerPanicked
        })
    }

    /// Runs peer work and returns an explicit [`PanicOutcome`].
    ///
    /// # Errors
    ///
    /// This method does not return errors; panics are converted to
    /// [`PanicOutcome::Recovered`].
    pub fn isolate_peer<F>(&self, peer_id: PeerId, operation: &'static str, work: F) -> PanicOutcome
    where
        F: FnOnce() + UnwindSafe,
    {
        match self.run_peer(peer_id, operation, work) {
            Ok(()) => PanicOutcome::Completed,
            Err(ResilienceError::PeerPanicked) => PanicOutcome::Recovered {
                peer_torn_down: true,
            },
            Err(_error) => PanicOutcome::Recovered {
                peer_torn_down: true,
            },
        }
    }
}

/// Memory pressure snapshot.
///
/// # Examples
///
/// ```
/// # use refract_resilience::MemorySnapshot;
/// let snapshot = MemorySnapshot::new(100, Some(100), Some(100));
/// assert!(snapshot.at_or_above_high(950));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemorySnapshot {
    current: u64,
    high: Option<u64>,
    max: Option<u64>,
}

impl MemorySnapshot {
    /// Creates a memory snapshot.
    #[must_use]
    pub const fn new(current_bytes: u64, high_bytes: Option<u64>, max_bytes: Option<u64>) -> Self {
        Self {
            current: current_bytes,
            high: high_bytes,
            max: max_bytes,
        }
    }

    /// Returns current memory usage in bytes.
    #[must_use]
    pub const fn current_bytes(self) -> u64 {
        self.current
    }

    /// Returns whether memory reached `memory.high` or the fallback max ratio.
    #[must_use]
    pub const fn at_or_above_high(self, fallback_ratio_per_mille: u16) -> bool {
        if let Some(high) = self.high {
            return self.current >= high;
        }
        if let Some(max) = self.max {
            return self.current.saturating_mul(1_000)
                >= max.saturating_mul(fallback_ratio_per_mille as u64);
        }
        false
    }
}

/// OOM and cgroup memory pressure handler.
///
/// The crate stays `#![forbid(unsafe_code)]`, so it exposes the safe action
/// used by an allocator wrapper instead of implementing `GlobalAlloc` here.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{DrainMode, DrainRequest, DrainSignal, MemorySnapshot, OomHandler};
/// let drain = DrainSignal::default();
/// let handler = OomHandler::new(drain.clone());
/// assert!(handler.observe_memory(MemorySnapshot::new(100, Some(100), None)).is_err());
/// assert_eq!(drain.request().map(DrainRequest::mode), Some(DrainMode::Graceful));
/// ```
#[derive(Clone, Debug)]
pub struct OomHandler {
    drain: DrainSignal,
    high_ratio_per_mille: u16,
}

impl OomHandler {
    /// Creates an OOM handler.
    #[must_use]
    pub const fn new(drain: DrainSignal) -> Self {
        Self {
            drain,
            high_ratio_per_mille: DEFAULT_MEMORY_HIGH_RATIO_PER_MILLE,
        }
    }

    /// Returns a handler with a custom fallback `memory.max` threshold ratio.
    #[must_use]
    pub const fn with_high_ratio_per_mille(mut self, ratio: u16) -> Self {
        self.high_ratio_per_mille = ratio;
        self
    }

    /// Handles an allocation failure signal from a global allocator wrapper.
    ///
    /// # Errors
    ///
    /// Always returns [`ResilienceError::MemoryPressure`] after triggering
    /// graceful drain.
    pub fn allocation_failed(&self) -> ResilienceResult<()> {
        warn!(
            error_code = OOM_ERROR_CODE,
            "allocation failure requested graceful drain"
        );
        self.drain.trigger(DrainRequest::new(
            DrainMode::Graceful,
            "oom",
            OOM_ERROR_CODE,
        ));
        Err(ResilienceError::MemoryPressure)
    }

    /// Observes a cgroup memory pressure snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ResilienceError::MemoryPressure`] when the snapshot reaches
    /// `memory.high` or the fallback ratio of `memory.max`.
    pub fn observe_memory(&self, snapshot: MemorySnapshot) -> ResilienceResult<()> {
        if snapshot.at_or_above_high(self.high_ratio_per_mille) {
            metrics::counter!(
                "refract.resilience.oom.graceful_drains",
                "error_code" => OOM_ERROR_CODE
            )
            .increment(1);
            return self.allocation_failed();
        }
        Ok(())
    }
}

/// One core heartbeat monitored by the watchdog.
///
/// # Examples
///
/// ```
/// # use refract_resilience::CoreHeartbeat;
/// let heartbeat = CoreHeartbeat::new(1);
/// heartbeat.bump_at(10);
/// assert_eq!(heartbeat.last_progress_ms(), 10);
/// ```
#[derive(Debug)]
pub struct CoreHeartbeat {
    core_id: u16,
    counter: AtomicU64,
    last_progress_ms: AtomicU64,
}

impl CoreHeartbeat {
    /// Creates a core heartbeat.
    #[must_use]
    pub const fn new(core_id: u16) -> Self {
        Self {
            core_id,
            counter: AtomicU64::new(0),
            last_progress_ms: AtomicU64::new(0),
        }
    }

    /// Returns the core id.
    #[must_use]
    pub const fn core_id(&self) -> u16 {
        self.core_id
    }

    /// Bumps the heartbeat counter in the hot loop.
    pub fn bump_at(&self, now_ms: u64) {
        self.counter.fetch_add(1, Ordering::Relaxed);
        self.last_progress_ms.store(now_ms, Ordering::Release);
    }

    /// Returns the heartbeat counter.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter.load(Ordering::Acquire)
    }

    /// Returns the last progress timestamp in milliseconds.
    #[must_use]
    pub fn last_progress_ms(&self) -> u64 {
        self.last_progress_ms.load(Ordering::Acquire)
    }
}

/// Watchdog result.
///
/// # Examples
///
/// ```
/// # use refract_resilience::WatchdogOutcome;
/// assert!(WatchdogOutcome::Healthy.is_healthy());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogOutcome {
    /// All cores made progress within the timeout.
    Healthy,
    /// A stalled core was detected and fast drain was triggered.
    Stalled {
        /// Stalled core id.
        core_id: u16,
        /// Captured stack/backtrace text.
        stack: String,
    },
}

impl WatchdogOutcome {
    /// Returns whether the watchdog found no stalls.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Core progress watchdog.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{CoreHeartbeat, DrainSignal, Watchdog};
/// let heartbeat = CoreHeartbeat::new(0);
/// heartbeat.bump_at(1_000);
/// let watchdog = Watchdog::new(DrainSignal::default());
/// assert!(watchdog.check_at(2_000, [&heartbeat]).is_healthy());
/// ```
#[derive(Clone, Debug)]
pub struct Watchdog {
    drain: DrainSignal,
    timeout_ms: u64,
}

impl Watchdog {
    /// Creates a watchdog with the Stage 1 default five-second timeout.
    #[must_use]
    pub const fn new(drain: DrainSignal) -> Self {
        Self {
            drain,
            timeout_ms: DEFAULT_WATCHDOG_TIMEOUT_MS,
        }
    }

    /// Creates a watchdog with a custom timeout.
    #[must_use]
    pub const fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Checks all core heartbeats at a deterministic timestamp.
    ///
    /// # Errors
    ///
    /// This method does not return errors; stalls are returned as
    /// [`WatchdogOutcome::Stalled`] and trigger fast drain.
    pub fn check_at<I>(&self, now_ms: u64, heartbeats: I) -> WatchdogOutcome
    where
        I: IntoIterator,
        I::Item: Borrow<CoreHeartbeat>,
    {
        for heartbeat in heartbeats {
            let heartbeat = heartbeat.borrow();
            let last = heartbeat.last_progress_ms();
            if now_ms.saturating_sub(last) > self.timeout_ms {
                let stack = format!("{:?}", Backtrace::capture());
                error!(
                    error_code = WATCHDOG_ERROR_CODE,
                    core_id = heartbeat.core_id(),
                    last_progress_ms = last,
                    now_ms,
                    stack = %stack,
                    "watchdog detected stalled core"
                );
                metrics::counter!(
                    "refract.resilience.watchdog.stalls",
                    "error_code" => WATCHDOG_ERROR_CODE
                )
                .increment(1);
                self.drain.trigger(DrainRequest::new(
                    DrainMode::Fast,
                    "watchdog",
                    WATCHDOG_ERROR_CODE,
                ));
                return WatchdogOutcome::Stalled {
                    core_id: heartbeat.core_id(),
                    stack,
                };
            }
        }
        WatchdogOutcome::Healthy
    }
}

/// Resource kind guarded by in-process ulimit-style limits.
///
/// # Examples
///
/// ```
/// # use refract_resilience::ResourceKind;
/// assert_eq!(ResourceKind::FileDescriptors.as_str(), "file_descriptors");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceKind {
    /// File descriptors.
    FileDescriptors,
    /// Threads.
    Threads,
    /// Memory bytes.
    MemoryBytes,
}

impl ResourceKind {
    /// Returns a bounded label for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileDescriptors => "file_descriptors",
            Self::Threads => "threads",
            Self::MemoryBytes => "memory_bytes",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// In-process resource limits.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{ResourceKind, ResourceLimits};
/// let limits = ResourceLimits::new(8, 4, 1024);
/// assert!(limits.admit(ResourceKind::Threads, 3).is_ok());
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    fds: u64,
    threads: u64,
    memory: u64,
}

impl ResourceLimits {
    /// Creates resource limits.
    #[must_use]
    pub const fn new(max_fds: u64, max_threads: u64, max_memory_bytes: u64) -> Self {
        Self {
            fds: max_fds,
            threads: max_threads,
            memory: max_memory_bytes,
        }
    }

    /// Returns whether a requested resource amount is admitted.
    ///
    /// # Errors
    ///
    /// Returns [`ResilienceError::ResourceLimit`] when the request exceeds the
    /// configured limit.
    pub fn admit(self, resource: ResourceKind, requested: u64) -> ResilienceResult<()> {
        let limit = match resource {
            ResourceKind::FileDescriptors => self.fds,
            ResourceKind::Threads => self.threads,
            ResourceKind::MemoryBytes => self.memory,
        };
        if requested > limit {
            metrics::counter!(
                "refract.resilience.resource.rejected",
                "resource" => resource.as_str(),
                "error_code" => RESOURCE_ERROR_CODE
            )
            .increment(1);
            return Err(ResilienceError::ResourceLimit {
                resource,
                limit,
                requested,
            });
        }
        Ok(())
    }
}

/// Global backpressure signal propagated toward signaling.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{BackpressureSignal, DrainMode, DrainRequest, DrainSignal};
/// let drain = DrainSignal::default();
/// let signal = BackpressureSignal::new(drain.clone());
/// signal.raise("router");
/// assert!(signal.is_raised());
/// assert_eq!(
///     drain.request().map(DrainRequest::mode),
///     Some(DrainMode::Fast)
/// );
/// ```
#[derive(Clone, Debug)]
pub struct BackpressureSignal {
    drain: DrainSignal,
    raised: Arc<AtomicBool>,
}

impl BackpressureSignal {
    /// Creates a backpressure signal.
    #[must_use]
    pub fn new(drain: DrainSignal) -> Self {
        Self {
            drain,
            raised: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Raises backpressure and triggers fast drain/load shedding.
    pub fn raise(&self, component: &'static str) {
        self.raised.store(true, Ordering::Release);
        warn!(
            error_code = BACKPRESSURE_ERROR_CODE,
            component, "backpressure signal raised"
        );
        metrics::counter!(
            "refract.resilience.backpressure.raised",
            "component" => component,
            "error_code" => BACKPRESSURE_ERROR_CODE
        )
        .increment(1);
        self.drain.trigger(DrainRequest::new(
            DrainMode::Fast,
            "backpressure",
            BACKPRESSURE_ERROR_CODE,
        ));
    }

    /// Clears backpressure.
    pub fn clear(&self) {
        self.raised.store(false, Ordering::Release);
    }

    /// Returns whether backpressure is raised.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        self.raised.load(Ordering::Acquire)
    }
}

const fn encode_mode(mode: DrainMode) -> u64 {
    match mode {
        DrainMode::Graceful => 1,
        DrainMode::Fast => 2,
    }
}

const fn decode_mode(raw: u64) -> DrainMode {
    match raw {
        2 => DrainMode::Fast,
        _ => DrainMode::Graceful,
    }
}

fn encode_reason(reason: &str) -> u64 {
    match reason {
        "watchdog" => 1,
        "backpressure" => 2,
        _ => 0,
    }
}

const fn decode_reason(raw: u64) -> &'static str {
    match raw {
        1 => "watchdog",
        2 => "backpressure",
        _ => "oom",
    }
}

fn panic_payload(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "non-string panic payload"
    }
}

/// Returns the Stage 1 stability marker for this crate.
///
/// # Examples
///
/// ```
/// # use refract_resilience::{stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> Stability {
    Stability::Stage1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_panic_in_peer_handler_survives_process() {
        let guard = PanicGuard::new(DrainSignal::default());

        let outcome = guard.isolate_peer(PeerId::from_raw(7), "forward", || {
            panic!("injected peer panic");
        });

        assert!(outcome.peer_torn_down());
        assert_eq!(
            guard
                .run_peer(PeerId::from_raw(8), "forward", || 42)
                .unwrap_or_default(),
            42
        );
    }

    #[test]
    fn injected_infinite_loop_is_caught_by_watchdog() {
        let drain = DrainSignal::default();
        let watchdog = Watchdog::new(drain.clone());
        let heartbeat = CoreHeartbeat::new(3);
        heartbeat.bump_at(1_000);

        let outcome = watchdog.check_at(6_001, [&heartbeat]);

        assert!(matches!(
            outcome,
            WatchdogOutcome::Stalled { core_id: 3, .. }
        ));
        assert_eq!(
            drain.request().map(DrainRequest::mode),
            Some(DrainMode::Fast)
        );
    }

    #[test]
    fn cgroup_memory_limit_reached_triggers_graceful_drain() {
        let drain = DrainSignal::default();
        let handler = OomHandler::new(drain.clone());
        let result = handler.observe_memory(MemorySnapshot::new(1_024, Some(1_024), Some(2_048)));

        assert!(matches!(result, Err(ResilienceError::MemoryPressure)));
        assert_eq!(
            drain.request().map(DrainRequest::mode),
            Some(DrainMode::Graceful)
        );
    }

    #[test]
    fn resource_limits_reject_excessive_operations() {
        let limits = ResourceLimits::new(10, 4, 1024);

        let error = limits
            .admit(ResourceKind::Threads, 5)
            .expect_err("thread limit rejects");

        assert!(matches!(
            error,
            ResilienceError::ResourceLimit {
                resource: ResourceKind::Threads,
                limit: 4,
                requested: 5
            }
        ));
    }

    #[test]
    fn backpressure_propagates_to_fast_drain() {
        let drain = DrainSignal::default();
        let signal = BackpressureSignal::new(drain.clone());

        signal.raise("router");

        assert!(signal.is_raised());
        assert_eq!(
            drain.request().map(DrainRequest::reason),
            Some("backpressure")
        );
    }

    #[test]
    fn every_error_variant_has_unique_code() {
        let errors = [
            ResilienceError::PeerPanicked,
            ResilienceError::WatchdogTimeout { core_id: 1 },
            ResilienceError::ResourceLimit {
                resource: ResourceKind::MemoryBytes,
                limit: 1,
                requested: 2,
            },
            ResilienceError::MemoryPressure,
            ResilienceError::Backpressure {
                component: "router",
            },
        ];
        let mut codes = errors
            .iter()
            .map(ResilienceError::error_code)
            .collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }
}
