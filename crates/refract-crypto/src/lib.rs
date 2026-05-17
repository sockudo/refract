//! `DTLS` policy, certificate identity, and `SRTP` exporter boundary.
//!
//! The crate owns the production policy around WebRTC `DTLS`: TLS 1.3
//! primitives from rustls, the aws-lc-rs crypto provider, X25519-only key
//! exchange, persistent self-signed ECDSA P-256 identity, and strict
//! `DTLS-SRTP` profile negotiation.
//!
//! # Examples
//!
//! ```
//! # use std::{fs, time::Instant};
//! # use refract_crypto::{DtlsAcceptor, DtlsConfig, SrtpProtectionProfile};
//! # let path = std::env::temp_dir().join("refract-crypto-lib-example.pem");
//! # let _ = fs::remove_file(&path);
//! let config = DtlsConfig::new(path);
//! let acceptor = DtlsAcceptor::new(config)?;
//! assert_eq!(acceptor.config().max_retransmits(), 6);
//! assert!(SrtpProtectionProfile::try_from(0x0007).is_ok());
//! # let _ = fs::remove_file(acceptor.identity().path());
//! # let _ = Instant::now();
//! # Ok::<(), refract_crypto::CryptoError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

mod config;
mod error;
mod identity;
pub mod metrics;
mod srtp;
mod stability;
mod state;

pub use config::DtlsConfig;
pub use error::{CryptoError, CryptoResult};
pub use identity::{Fingerprint, Identity};
pub use metrics::record_error;
pub use srtp::{DTLS_SRTP_EXPORTER_LABEL, ExporterMaterial, SrtpKeys, SrtpProtectionProfile};
pub use stability::Stability;
pub use state::{DtlsAcceptor, DtlsConn, DtlsState, HandshakeOutcome};
