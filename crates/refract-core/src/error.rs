//! Error taxonomy with stable operator-facing codes.

use core::{fmt, time::Duration};

use thiserror::Error as ThisError;

use crate::limits;

/// Result alias for fallible refract core operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Error category used by retry policy, dashboards, and alert routing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorCategory {
    /// Operation may succeed if retried later.
    Transient,
    /// Operation failed permanently for the current state.
    Permanent,
    /// Caller supplied invalid input.
    BadInput,
    /// Implementation or invariant failure.
    Internal,
}

impl ErrorCategory {
    /// Returns a stable category label for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::BadInput => "bad_input",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Structured value stored in an [`ErrorField`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldValue<'a> {
    /// UTF-8 string value borrowed from the error.
    Str(&'a str),
    /// Unsigned integer value.
    U64(u64),
    /// Boolean value.
    Bool(bool),
}

impl fmt::Display for FieldValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(value) => formatter.write_str(value),
            Self::U64(value) => write!(formatter, "{value}"),
            Self::Bool(value) => write!(formatter, "{value}"),
        }
    }
}

/// One structured `key=value` field attached to an [`Error`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorField<'a> {
    key: &'static str,
    value: FieldValue<'a>,
}

impl<'a> ErrorField<'a> {
    /// Creates a structured error field.
    #[must_use]
    pub const fn new(key: &'static str, value: FieldValue<'a>) -> Self {
        Self { key, value }
    }

    /// Returns the stable field key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        self.key
    }

    /// Returns the field value.
    #[must_use]
    pub const fn value(self) -> FieldValue<'a> {
        self.value
    }
}

/// Fixed-capacity iterator over structured error fields.
#[derive(Clone, Debug)]
pub struct ErrorFields<'a> {
    fields: [Option<ErrorField<'a>>; limits::ERROR_FIELD_CAPACITY],
    next_index: usize,
}

impl<'a> ErrorFields<'a> {
    fn new(fields: [Option<ErrorField<'a>>; limits::ERROR_FIELD_CAPACITY]) -> Self {
        Self {
            fields,
            next_index: usize::default(),
        }
    }

    fn from_slice(source: &[ErrorField<'a>]) -> Self {
        let mut fields = [None; limits::ERROR_FIELD_CAPACITY];

        for (index, field) in source.iter().copied().enumerate() {
            if let Some(slot) = fields.get_mut(index) {
                *slot = Some(field);
            }
        }

        Self::new(fields)
    }
}

impl<'a> Iterator for ErrorFields<'a> {
    type Item = ErrorField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(field) = self.fields.get(self.next_index).copied() {
            self.next_index += 1;
            if field.is_some() {
                return field;
            }
        }

        None
    }
}

/// Single crate-wide error enum.
#[derive(Debug, ThisError)]
pub enum Error {
    /// I/O failure.
    #[error("io failure during {operation}: {source}")]
    Io {
        /// Operation that performed I/O.
        operation: &'static str,
        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Defensive parser rejected input.
    #[error("parse failure in {context}: {message}")]
    Parse {
        /// Parser or field context.
        context: &'static str,
        /// Static parse failure description.
        message: &'static str,
    },
    /// Cryptographic operation failed.
    #[error("crypto failure in {context}: {message}")]
    Crypto {
        /// Crypto operation context.
        context: &'static str,
        /// Static crypto failure description.
        message: &'static str,
    },
    /// Protocol state or wire contract failed.
    #[error("protocol failure in {context}: {message}")]
    Protocol {
        /// Protocol context.
        context: &'static str,
        /// Static protocol failure description.
        message: &'static str,
    },
    /// Bounded capacity was exceeded.
    #[error("capacity exceeded for {resource}: limit {limit}, actual {actual}")]
    Capacity {
        /// Bounded resource name.
        resource: &'static str,
        /// Configured limit.
        limit: u64,
        /// Attempted or observed value.
        actual: u64,
    },
    /// Deterministic timeout elapsed.
    #[error("timeout during {operation} after {after:?}")]
    Timeout {
        /// Timed operation.
        operation: &'static str,
        /// Timeout duration.
        after: Duration,
    },
    /// Resource was already closed.
    #[error("resource closed: {resource}")]
    Closed {
        /// Closed resource name.
        resource: &'static str,
    },
    /// Configuration is invalid.
    #[error("configuration failure for {key}: {message}")]
    Config {
        /// Configuration key.
        key: &'static str,
        /// Static configuration failure description.
        message: &'static str,
    },
    /// Authentication or authorization failed.
    #[error("auth failure for {principal}: {message}")]
    Auth {
        /// Principal or credential class.
        principal: &'static str,
        /// Static authentication failure description.
        message: &'static str,
    },
    /// Rate limit was exceeded.
    #[error("rate limit exceeded for {scope}: limit {limit}, actual {actual}")]
    RateLimit {
        /// Rate-limit scope.
        scope: &'static str,
        /// Configured limit.
        limit: u64,
        /// Attempted or observed value.
        actual: u64,
    },
    /// Internal invariant failed.
    #[error("internal failure in {component}: {message}")]
    Internal {
        /// Component that detected the invariant failure.
        component: &'static str,
        /// Static internal failure description.
        message: &'static str,
    },
}

impl Error {
    /// Returns the stable operator-facing error code.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Io { .. } => limits::ERROR_CODE_IO,
            Self::Parse { .. } => limits::ERROR_CODE_PARSE,
            Self::Crypto { .. } => limits::ERROR_CODE_CRYPTO,
            Self::Protocol { .. } => limits::ERROR_CODE_PROTOCOL,
            Self::Capacity { .. } => limits::ERROR_CODE_CAPACITY,
            Self::Timeout { .. } => limits::ERROR_CODE_TIMEOUT,
            Self::Closed { .. } => limits::ERROR_CODE_CLOSED,
            Self::Config { .. } => limits::ERROR_CODE_CONFIG,
            Self::Auth { .. } => limits::ERROR_CODE_AUTH,
            Self::RateLimit { .. } => limits::ERROR_CODE_RATE_LIMIT,
            Self::Internal { .. } => limits::ERROR_CODE_INTERNAL,
        }
    }

    /// Returns the retry and alerting category for the error.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Io { .. }
            | Self::Capacity { .. }
            | Self::Timeout { .. }
            | Self::RateLimit { .. } => ErrorCategory::Transient,
            Self::Closed { .. } | Self::Config { .. } | Self::Crypto { .. } => {
                ErrorCategory::Permanent
            }
            Self::Parse { .. } | Self::Protocol { .. } | Self::Auth { .. } => {
                ErrorCategory::BadInput
            }
            Self::Internal { .. } => ErrorCategory::Internal,
        }
    }

    /// Returns structured `key=value` fields for logs.
    #[must_use]
    pub fn fields(&self) -> ErrorFields<'_> {
        let common = [
            ErrorField::new("error_code", FieldValue::Str(self.error_code())),
            ErrorField::new("category", FieldValue::Str(self.category().as_str())),
        ];

        match self {
            Self::Io { operation, source } => ErrorFields::from_slice(&[
                common[0],
                common[1],
                ErrorField::new("variant", FieldValue::Str("io")),
                ErrorField::new("operation", FieldValue::Str(operation)),
                ErrorField::new("io_kind", FieldValue::Str(io_error_kind(source.kind()))),
            ]),
            Self::Parse { context, message } => {
                fields_for_context("parse", context, message, common)
            }
            Self::Crypto { context, message } => {
                fields_for_context("crypto", context, message, common)
            }
            Self::Protocol { context, message } => {
                fields_for_context("protocol", context, message, common)
            }
            Self::Capacity {
                resource,
                limit,
                actual,
            } => fields_for_limit("capacity", resource, *limit, *actual, common),
            Self::Timeout { operation, after } => ErrorFields::from_slice(&[
                common[0],
                common[1],
                ErrorField::new("variant", FieldValue::Str("timeout")),
                ErrorField::new("operation", FieldValue::Str(operation)),
                ErrorField::new("after_ms", FieldValue::U64(saturating_millis(*after))),
            ]),
            Self::Closed { resource } => ErrorFields::from_slice(&[
                common[0],
                common[1],
                ErrorField::new("variant", FieldValue::Str("closed")),
                ErrorField::new("resource", FieldValue::Str(resource)),
            ]),
            Self::Config { key, message } => ErrorFields::from_slice(&[
                common[0],
                common[1],
                ErrorField::new("variant", FieldValue::Str("config")),
                ErrorField::new("key", FieldValue::Str(key)),
                ErrorField::new("message", FieldValue::Str(message)),
            ]),
            Self::Auth { principal, message } => ErrorFields::from_slice(&[
                common[0],
                common[1],
                ErrorField::new("variant", FieldValue::Str("auth")),
                ErrorField::new("principal", FieldValue::Str(principal)),
                ErrorField::new("message", FieldValue::Str(message)),
            ]),
            Self::RateLimit {
                scope,
                limit,
                actual,
            } => fields_for_limit("rate_limit", scope, *limit, *actual, common),
            Self::Internal { component, message } => ErrorFields::from_slice(&[
                common[0],
                common[1],
                ErrorField::new("variant", FieldValue::Str("internal")),
                ErrorField::new("component", FieldValue::Str(component)),
                ErrorField::new("message", FieldValue::Str(message)),
            ]),
        }
    }
}

fn fields_for_context<'a>(
    variant: &'static str,
    context: &'a str,
    message: &'a str,
    common: [ErrorField<'a>; 2],
) -> ErrorFields<'a> {
    ErrorFields::from_slice(&[
        common[0],
        common[1],
        ErrorField::new("variant", FieldValue::Str(variant)),
        ErrorField::new("context", FieldValue::Str(context)),
        ErrorField::new("message", FieldValue::Str(message)),
    ])
}

fn fields_for_limit<'a>(
    variant: &'static str,
    resource: &'a str,
    limit: u64,
    actual: u64,
    common: [ErrorField<'a>; 2],
) -> ErrorFields<'a> {
    ErrorFields::from_slice(&[
        common[0],
        common[1],
        ErrorField::new("variant", FieldValue::Str(variant)),
        ErrorField::new("resource", FieldValue::Str(resource)),
        ErrorField::new("limit", FieldValue::U64(limit)),
        ErrorField::new("actual", FieldValue::U64(actual)),
    ])
}

fn saturating_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

const fn io_error_kind(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::ConnectionRefused => "connection_refused",
        std::io::ErrorKind::ConnectionReset => "connection_reset",
        std::io::ErrorKind::ConnectionAborted => "connection_aborted",
        std::io::ErrorKind::NotConnected => "not_connected",
        std::io::ErrorKind::AddrInUse => "addr_in_use",
        std::io::ErrorKind::AddrNotAvailable => "addr_not_available",
        std::io::ErrorKind::BrokenPipe => "broken_pipe",
        std::io::ErrorKind::AlreadyExists => "already_exists",
        std::io::ErrorKind::WouldBlock => "would_block",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        std::io::ErrorKind::InvalidData => "invalid_data",
        std::io::ErrorKind::TimedOut => "timed_out",
        std::io::ErrorKind::WriteZero => "write_zero",
        std::io::ErrorKind::Interrupted => "interrupted",
        std::io::ErrorKind::Unsupported => "unsupported",
        std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
        std::io::ErrorKind::OutOfMemory => "out_of_memory",
        _ => "other",
    }
}

/// Returns early with an [`Error`] while logging its stable code at the call
/// site.
#[macro_export]
macro_rules! bail {
    ($error:expr $(,)?) => {{
        let error = $error;
        ::tracing::debug!(
            error_code = error.error_code(),
            file = file!(),
            line = line!(),
            column = column!(),
            "returning error"
        );
        return Err(error);
    }};
}

/// Ensures a condition is true or returns early with an [`Error`] while logging
/// its stable code at the call site.
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $error:expr $(,)?) => {{
        if !$condition {
            $crate::bail!($error);
        }
    }};
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{Error, ErrorCategory, FieldValue};
    use crate::limits;

    fn fail_with_bail() -> super::Result<()> {
        crate::bail!(Error::Internal {
            component: "test",
            message: "forced",
        });
    }

    fn fail_with_ensure() -> super::Result<()> {
        crate::ensure!(
            false,
            Error::Parse {
                context: "test",
                message: "missing",
            },
        );
        Ok(())
    }

    #[test]
    fn stable_codes_are_unique() {
        let codes = [
            limits::ERROR_CODE_IO,
            limits::ERROR_CODE_PARSE,
            limits::ERROR_CODE_CRYPTO,
            limits::ERROR_CODE_PROTOCOL,
            limits::ERROR_CODE_CAPACITY,
            limits::ERROR_CODE_TIMEOUT,
            limits::ERROR_CODE_CLOSED,
            limits::ERROR_CODE_CONFIG,
            limits::ERROR_CODE_AUTH,
            limits::ERROR_CODE_RATE_LIMIT,
            limits::ERROR_CODE_INTERNAL,
        ];

        for (index, code) in codes.iter().enumerate() {
            assert!(!codes[..index].contains(code));
        }
    }

    #[test]
    fn categories_match_retry_policy() {
        let timeout = Error::Timeout {
            operation: "join",
            after: Duration::from_millis(1),
        };
        let parse = Error::Parse {
            context: "rtp",
            message: "short",
        };
        let internal = Error::Internal {
            component: "router",
            message: "missing shard",
        };

        assert_eq!(timeout.category(), ErrorCategory::Transient);
        assert_eq!(parse.category(), ErrorCategory::BadInput);
        assert_eq!(internal.category(), ErrorCategory::Internal);
    }

    #[test]
    fn fields_include_common_and_variant_values() {
        let error = Error::Capacity {
            resource: "peers",
            limit: 10,
            actual: 11,
        };
        let fields = error.fields().collect::<Vec<_>>();

        assert_eq!(fields[0].key(), "error_code");
        assert_eq!(
            fields[0].value(),
            FieldValue::Str(limits::ERROR_CODE_CAPACITY)
        );
        assert!(fields.iter().any(|field| field.key() == "actual"));
    }

    #[test]
    fn macros_return_errors() {
        assert!(matches!(fail_with_bail(), Err(Error::Internal { .. })));
        assert!(matches!(fail_with_ensure(), Err(Error::Parse { .. })));
    }
}
