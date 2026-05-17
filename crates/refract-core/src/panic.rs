//! Panic hook and worker panic isolation.

use std::{backtrace::Backtrace, panic as std_panic, thread};

use tracing::{Span, error};

use crate::{Error, PeerId, Result, limits};

/// Installs the process-wide panic hook.
///
/// Runtime driver thread panics abort the process after structured telemetry is
/// emitted. Other thread panics are logged and may be contained by
/// [`catch_peer_panic`].
pub fn set_panic_hook() {
    std_panic::set_hook(Box::new(|info| {
        let location = info.location();
        let file = location.map_or("unknown", std_panic::Location::file);
        let line = location.map_or_else(u32::default, std_panic::Location::line);
        let column = location.map_or_else(u32::default, std_panic::Location::column);
        let payload = panic_payload(info.payload());
        let backtrace = Backtrace::capture();
        let current_span = Span::current();
        let span_name = current_span
            .metadata()
            .map_or("unknown", |metadata| metadata.name());
        let current_thread = thread::current();
        let thread_name = current_thread.name().unwrap_or("unnamed");
        let runtime_driver = is_runtime_driver_thread_name(thread_name);

        error!(
            error_code = limits::PANIC_ERROR_CODE,
            panic.file = file,
            panic.line = line,
            panic.column = column,
            panic.message = payload,
            panic.span = span_name,
            thread.name = thread_name,
            runtime_driver,
            backtrace = ?backtrace,
            "panic captured"
        );
        metrics::counter!(
            limits::PANIC_METRIC_NAME,
            "error_code" => limits::PANIC_ERROR_CODE
        )
        .increment(1);

        if runtime_driver {
            std::process::abort();
        }
    }));
}

/// Runs peer-owned worker code and converts panics into peer-scoped teardown
/// errors.
///
/// # Errors
///
/// Returns [`Error::Internal`] when `work` panics.
///
/// # Examples
///
/// ```
/// use refract_core::{PeerId, panic::catch_peer_panic};
///
/// let peer_id = PeerId::from_raw(7);
/// let value = catch_peer_panic(peer_id, "example", || 42)?;
/// assert_eq!(value, 42);
/// # Ok::<(), refract_core::Error>(())
/// ```
pub fn catch_peer_panic<T, F>(peer_id: PeerId, operation: &'static str, work: F) -> Result<T>
where
    F: FnOnce() -> T + std_panic::UnwindSafe,
{
    std_panic::catch_unwind(work).map_err(|payload| {
        let message = panic_payload(payload.as_ref());
        error!(
            error_code = limits::ERROR_CODE_INTERNAL,
            peer_id = %peer_id,
            operation,
            panic.message = message,
            "peer worker panic contained"
        );
        Error::Internal {
            component: "worker",
            message: "peer worker panicked",
        }
    })
}

/// Returns whether the current thread is a runtime driver thread.
#[must_use]
pub fn is_runtime_driver_thread() -> bool {
    thread::current()
        .name()
        .is_some_and(is_runtime_driver_thread_name)
}

fn is_runtime_driver_thread_name(name: &str) -> bool {
    name.contains(limits::RUNTIME_DRIVER_THREAD_NAME_FRAGMENT)
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

#[cfg(test)]
mod tests {
    use super::{catch_peer_panic, is_runtime_driver_thread};
    use crate::{Error, PeerId};

    #[test]
    fn worker_panic_is_converted_to_internal_error() {
        let result = catch_peer_panic(PeerId::from_raw(7), "test", || panic!("boom"));

        assert!(matches!(result, Err(Error::Internal { .. })));
    }

    #[test]
    fn default_test_thread_is_not_runtime_driver() {
        assert!(!is_runtime_driver_thread());
    }
}
