//! Error surface for the XDP loader and configuration layer.
//!
//! # Examples
//!
//! ```
//! let err = refract_xdp::ListenPort::try_from(80).err();
//! assert!(err.is_some());
//! ```

use thiserror::Error;

/// Result alias for XDP operations.
pub type XdpResult<T> = Result<T, XdpError>;

/// XDP configuration and loader errors with stable operator codes.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum XdpError {
    /// The operating system cannot load XDP programs.
    #[error("xdp is only supported on linux")]
    UnsupportedPlatform,
    /// Interface name failed bounded validation.
    #[error("invalid interface name: name={name}")]
    InvalidInterfaceName {
        /// Rejected interface name.
        name: String,
    },
    /// Listen port is outside the allowed media-port range.
    #[error("invalid xdp listen port: port={port}")]
    InvalidListenPort {
        /// Rejected port.
        port: u16,
    },
    /// STUN token bucket settings are internally inconsistent.
    #[error("invalid stun rate limit: rate_per_second={rate_per_second} burst={burst}")]
    InvalidRateLimit {
        /// Requested refill rate.
        rate_per_second: u32,
        /// Requested bucket burst.
        burst: u32,
    },
    /// Aya failed to load or attach the program.
    #[cfg(target_os = "linux")]
    #[error("aya xdp operation failed: op={operation} message={message}")]
    Aya {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying Aya error.
        message: String,
    },
    /// Required eBPF object file is missing.
    #[cfg(target_os = "linux")]
    #[error("xdp object file not found: path={path}")]
    ObjectNotFound {
        /// Missing path.
        path: String,
    },
}

impl XdpError {
    /// Returns the stable operator-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// let err = refract_xdp::XdpError::UnsupportedPlatform;
    /// assert_eq!(err.error_code(), "XDP_PLATFORM_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "XDP_PLATFORM_0001",
            Self::InvalidInterfaceName { .. } => "XDP_CONFIG_0001",
            Self::InvalidListenPort { .. } => "XDP_CONFIG_0002",
            Self::InvalidRateLimit { .. } => "XDP_CONFIG_0003",
            #[cfg(target_os = "linux")]
            Self::Aya { .. } => "XDP_AYA_0001",
            #[cfg(target_os = "linux")]
            Self::ObjectNotFound { .. } => "XDP_OBJECT_0001",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            XdpError::UnsupportedPlatform.error_code(),
            "XDP_PLATFORM_0001"
        );
        assert_eq!(
            XdpError::InvalidListenPort { port: 1 }.error_code(),
            "XDP_CONFIG_0002"
        );
    }
}
