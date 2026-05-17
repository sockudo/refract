//! Error taxonomy for `DTLS` policy and `SRTP` exporter handling.
//!
//! Every error variant has a unique stable operations-facing code.
//!
//! # Examples
//!
//! ```
//! # use refract_crypto::CryptoError;
//! let error = CryptoError::UnsupportedProtocolVersion { version: "DTLS 1.2" };
//! assert_eq!(error.error_code(), "HSF-CRY-001");
//! ```

use core::time::Duration;

use thiserror::Error;

/// Result alias for `refract-crypto` operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Cryptographic identity, policy, and handshake state errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A peer offered a forbidden protocol version.
    #[error("unsupported protocol version: version={version}")]
    UnsupportedProtocolVersion {
        /// Rejected protocol version label.
        version: &'static str,
    },
    /// A peer offered a forbidden `DTLS-SRTP` protection profile.
    #[error("unsupported srtp protection profile: profile=0x{profile:04x}")]
    UnsupportedSrtpProfile {
        /// IANA protection profile identifier.
        profile: u16,
    },
    /// A datagram was too short to inspect defensively.
    #[error("dtls datagram too short: len={len}")]
    DatagramTooShort {
        /// Observed datagram length.
        len: usize,
    },
    /// The handshake exceeded its deterministic timeout.
    #[error("dtls handshake timeout: elapsed={elapsed:?} timeout={timeout:?}")]
    HandshakeTimeout {
        /// Observed elapsed duration.
        elapsed: Duration,
        /// Configured timeout duration.
        timeout: Duration,
    },
    /// The handshake exceeded the retransmission budget.
    #[error("dtls retransmit budget exceeded: attempts={attempts} max={max}")]
    RetransmitLimit {
        /// Observed retransmission attempts.
        attempts: u8,
        /// Configured maximum retransmission attempts.
        max: u8,
    },
    /// A full handshake transcript was replayed.
    #[error("dtls handshake replay rejected")]
    HandshakeReplay,
    /// Key exporter material had an invalid length for the selected profile.
    #[error("invalid srtp exporter length: profile={profile} len={len} expected={expected}")]
    InvalidExporterLength {
        /// SRTP profile label.
        profile: &'static str,
        /// Observed exporter length.
        len: usize,
        /// Required exporter length.
        expected: usize,
    },
    /// Persistent identity file I/O failed.
    #[error("identity io failure: operation={operation} path={path} source={source}")]
    IdentityIo {
        /// Failed operation.
        operation: &'static str,
        /// Identity path as display text.
        path: String,
        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Persistent identity parsing failed.
    #[error("identity parse failure: path={path} message={message}")]
    IdentityParse {
        /// Identity path as display text.
        path: String,
        /// Static parse failure label.
        message: &'static str,
    },
    /// Certificate generation failed.
    #[error("certificate generation failure: {source}")]
    CertificateGeneration {
        /// Source rcgen error.
        #[from]
        source: rcgen::Error,
    },
    /// rustls policy or configuration failed.
    #[error("rustls configuration failure: {source}")]
    RustlsConfig {
        /// Source rustls error.
        #[from]
        source: rustls::Error,
    },
    /// A rustls protocol version set was rejected.
    #[error("rustls protocol version configuration failure: {message}")]
    RustlsProtocolVersion {
        /// Static rustls version failure label.
        message: &'static str,
    },
    /// A deterministic exporter failed.
    #[error("exporter failure: {message}")]
    Exporter {
        /// Static exporter failure label.
        message: &'static str,
    },
}

impl CryptoError {
    /// Returns the unique stable error code for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::CryptoError;
    /// let error = CryptoError::UnsupportedProtocolVersion { version: "TLS 1.2" };
    /// assert_eq!(error.error_code(), "HSF-CRY-001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion { .. } => "HSF-CRY-001",
            Self::UnsupportedSrtpProfile { .. } => "HSF-CRY-002",
            Self::DatagramTooShort { .. } => "HSF-CRY-003",
            Self::HandshakeTimeout { .. } => "HSF-CRY-004",
            Self::RetransmitLimit { .. } => "HSF-CRY-005",
            Self::HandshakeReplay => "HSF-CRY-006",
            Self::InvalidExporterLength { .. } => "HSF-CRY-007",
            Self::IdentityIo { .. } => "HSF-CRY-008",
            Self::IdentityParse { .. } => "HSF-CRY-009",
            Self::CertificateGeneration { .. } => "HSF-CRY-010",
            Self::RustlsConfig { .. } => "HSF-CRY-011",
            Self::RustlsProtocolVersion { .. } => "HSF-CRY-012",
            Self::Exporter { .. } => "HSF-CRY-013",
        }
    }

    /// Returns the Stage 1 stability marker for the error taxonomy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{CryptoError, Stability};
    /// let error = CryptoError::UnsupportedProtocolVersion { version: "DTLS 1.2" };
    /// assert_eq!(error.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls12_rejection_uses_required_error_code() {
        let error = CryptoError::UnsupportedProtocolVersion { version: "TLS 1.2" };

        assert_eq!(error.error_code(), "HSF-CRY-001");
    }

    #[test]
    fn every_error_variant_has_unique_code() {
        let errors = [
            CryptoError::UnsupportedProtocolVersion {
                version: "DTLS 1.2",
            },
            CryptoError::UnsupportedSrtpProfile { profile: 1 },
            CryptoError::DatagramTooShort { len: 2 },
            CryptoError::HandshakeTimeout {
                elapsed: Duration::from_secs(11),
                timeout: Duration::from_secs(10),
            },
            CryptoError::RetransmitLimit {
                attempts: 7,
                max: 6,
            },
            CryptoError::HandshakeReplay,
            CryptoError::InvalidExporterLength {
                profile: "SRTP_AEAD_AES_128_GCM",
                len: 1,
                expected: 56,
            },
            CryptoError::IdentityParse {
                path: "x".to_owned(),
                message: "bad",
            },
            CryptoError::RustlsProtocolVersion { message: "bad" },
            CryptoError::Exporter { message: "bad" },
        ];

        let mut codes = errors
            .iter()
            .map(CryptoError::error_code)
            .collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }
}
