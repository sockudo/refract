//! `DTLS` policy configuration for `refract-crypto`.
//!
//! The configuration fixes the Stage 1 crypto posture: aws-lc-rs provider,
//! TLS 1.3 primitives only, X25519 ECDHE only, no resumption, no 0-RTT, and
//! AES-GCM-only SRTP protection profiles.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_crypto::DtlsConfig;
//! let config = DtlsConfig::new("identity.pem")
//!     .with_handshake_timeout(Duration::from_secs(5))
//!     .with_max_retransmits(4);
//! assert_eq!(config.handshake_timeout(), Duration::from_secs(5));
//! assert_eq!(config.max_retransmits(), 4);
//! ```

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{ServerConfig, crypto::aws_lc_rs, server::NoServerSessionStorage, version};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::{
    error::{CryptoError, CryptoResult},
    identity::Identity,
};

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RETRANSMITS: u8 = 6;
const WEBRTC_ALPN: &[u8] = b"webrtc";

/// Configuration for the sans-I/O `DTLS` acceptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DtlsConfig {
    identity_path: PathBuf,
    handshake_timeout: Duration,
    max_retransmits: u8,
}

impl DtlsConfig {
    /// Creates a configuration with production defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_crypto::DtlsConfig;
    /// let config = DtlsConfig::new("identity.pem");
    /// assert_eq!(config.handshake_timeout(), Duration::from_secs(10));
    /// assert_eq!(config.max_retransmits(), 6);
    /// ```
    #[must_use]
    pub fn new(identity_path: impl Into<PathBuf>) -> Self {
        Self {
            identity_path: identity_path.into(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_retransmits: DEFAULT_MAX_RETRANSMITS,
        }
    }

    /// Sets the deterministic handshake timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_crypto::DtlsConfig;
    /// let config = DtlsConfig::new("identity.pem").with_handshake_timeout(Duration::from_secs(3));
    /// assert_eq!(config.handshake_timeout(), Duration::from_secs(3));
    /// ```
    #[must_use]
    pub const fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the handshake retransmit budget.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::DtlsConfig;
    /// let config = DtlsConfig::new("identity.pem").with_max_retransmits(2);
    /// assert_eq!(config.max_retransmits(), 2);
    /// ```
    #[must_use]
    pub const fn with_max_retransmits(mut self, max_retransmits: u8) -> Self {
        self.max_retransmits = max_retransmits;
        self
    }

    /// Returns the configured identity path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::path::Path;
    /// # use refract_crypto::DtlsConfig;
    /// let config = DtlsConfig::new("identity.pem");
    /// assert_eq!(config.identity_path(), Path::new("identity.pem"));
    /// ```
    #[must_use]
    pub fn identity_path(&self) -> &Path {
        &self.identity_path
    }

    /// Returns the deterministic handshake timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_crypto::DtlsConfig;
    /// assert_eq!(DtlsConfig::new("identity.pem").handshake_timeout(), Duration::from_secs(10));
    /// ```
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Returns the handshake retransmit budget.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::DtlsConfig;
    /// assert_eq!(DtlsConfig::new("identity.pem").max_retransmits(), 6);
    /// ```
    #[must_use]
    pub const fn max_retransmits(&self) -> u8 {
        self.max_retransmits
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{DtlsConfig, Stability};
    /// assert_eq!(DtlsConfig::new("identity.pem").stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }

    pub(crate) fn rustls_server_config(identity: &Identity) -> CryptoResult<ServerConfig> {
        let cert = CertificateDer::from_pem_slice(identity.certificate_pem().as_bytes()).map_err(
            |_| CryptoError::IdentityParse {
                path: identity.path().display().to_string(),
                message: "invalid certificate pem",
            },
        )?;
        let key =
            PrivateKeyDer::from_pem_slice(identity.private_key_pem().as_bytes()).map_err(|_| {
                CryptoError::IdentityParse {
                    path: identity.path().display().to_string(),
                    message: "invalid private key pem",
                }
            })?;
        let mut provider = aws_lc_rs::default_provider();
        provider.cipher_suites = vec![
            aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ];
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];

        let builder = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])
            .map_err(|_| CryptoError::RustlsProtocolVersion {
                message: "tls13 not supported by aws-lc-rs provider",
            })?
            .with_no_client_auth();
        let mut config = builder.with_single_cert(vec![cert], key)?;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.enable_secret_extraction = true;
        config.alpn_protocols = vec![WEBRTC_ALPN.to_vec()];
        Ok(config)
    }
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self::new("refract-dtls-identity.pem")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_prompt() {
        let config = DtlsConfig::new("identity.pem");

        assert_eq!(config.handshake_timeout(), Duration::from_secs(10));
        assert_eq!(config.max_retransmits(), 6);
    }

    #[test]
    fn builder_overrides_timeout_and_retransmits() {
        let config = DtlsConfig::new("identity.pem")
            .with_handshake_timeout(Duration::from_secs(2))
            .with_max_retransmits(3);

        assert_eq!(config.handshake_timeout(), Duration::from_secs(2));
        assert_eq!(config.max_retransmits(), 3);
    }
}
