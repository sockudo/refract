//! Metrics helpers for `refract-crypto`.
//!
//! Hot packet forwarding must not log; this boundary records bounded counters
//! for handshake and policy failures.
//!
//! # Examples
//!
//! ```
//! # use refract_crypto::{metrics::stability, Stability};
//! assert_eq!(stability(), Stability::Stage1);
//! ```

use metrics::counter;

use crate::CryptoError;

/// Records a crypto error with bounded labels.
///
/// # Examples
///
/// ```
/// # use refract_crypto::{record_error, CryptoError};
/// record_error(&CryptoError::UnsupportedProtocolVersion { version: "TLS 1.2" });
/// ```
pub fn record_error(error: &CryptoError) {
    counter!(
        "refract.crypto.errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

/// Returns the Stage 1 stability marker for metrics in this crate.
///
/// # Examples
///
/// ```
/// # use refract_crypto::{metrics::stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> crate::Stability {
    crate::Stability::Stage1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_stability_is_stage1() {
        assert_eq!(stability(), crate::Stability::Stage1);
    }
}
