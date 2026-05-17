//! Sans-I/O `DTLS` acceptor and connection state machines.
//!
//! The state machines enforce policy before any runtime integration: bounded
//! input inspection, deterministic timeout, retransmit budget, replay defense,
//! and SRTP exporter splitting. They intentionally avoid owning sockets or
//! tasks so compio integration can drive them without introducing another
//! runtime.
//!
//! # Examples
//!
//! ```
//! # use std::{fs, time::Instant};
//! # use refract_crypto::{DtlsAcceptor, DtlsConfig, HandshakeOutcome};
//! # let path = std::env::temp_dir().join("refract-crypto-state-example.pem");
//! # let _ = fs::remove_file(&path);
//! let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
//! let datagram = [0x16, 0xfe, 0xfd, 0x00, 0x2b, 0x00, 0x1d];
//! let (_conn, outcome) = acceptor.accept(Instant::now(), &datagram)?;
//! assert_eq!(outcome, HandshakeOutcome::NeedMore);
//! # let _ = fs::remove_file(path);
//! # Ok::<(), refract_crypto::CryptoError>(())
//! ```

use std::{sync::Arc, time::Instant};

use rustls::ServerConfig;
use sha2::{Digest, Sha256};

use crate::{
    Stability,
    config::DtlsConfig,
    error::{CryptoError, CryptoResult},
    identity::Identity,
    srtp::{ExporterMaterial, SrtpKeys, SrtpProtectionProfile},
};

const REPLAY_CACHE_LEN: usize = 16;
const MIN_RECORD_PREFIX_LEN: usize = 3;
const TLS12_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const DTLS12_RECORD_VERSION: [u8; 2] = [0xfe, 0xfd];
const DTLS10_RECORD_VERSION: [u8; 2] = [0xfe, 0xff];
const SUPPORTED_VERSIONS_EXTENSION: [u8; 2] = [0x00, 0x2b];
const X25519_NAMED_GROUP: [u8; 2] = [0x00, 0x1d];

/// Current `DTLS` connection state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DtlsState {
    /// Handshake is in progress.
    Handshaking,
    /// Handshake completed and exporter material is available.
    Connected,
    /// Connection is closed and will not accept more input.
    Closed,
}

impl DtlsState {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{DtlsState, Stability};
    /// assert_eq!(DtlsState::Handshaking.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Result of feeding handshake input to the sans-I/O state machine.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HandshakeOutcome {
    /// More datagrams are needed before the handshake can complete.
    NeedMore,
    /// The peer omitted an X25519 key share and must retry with X25519.
    HelloRetryRequest,
    /// The handshake is complete.
    Established,
}

impl HandshakeOutcome {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::{HandshakeOutcome, Stability};
    /// assert_eq!(HandshakeOutcome::NeedMore.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Sans-I/O `DTLS` acceptor.
#[derive(Debug)]
pub struct DtlsAcceptor {
    config: DtlsConfig,
    identity: Identity,
    rustls_config: Arc<ServerConfig>,
    replay_cache: std::cell::RefCell<ReplayCache>,
}

impl DtlsAcceptor {
    /// Creates an acceptor and loads or generates the persistent certificate identity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-acceptor-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// assert_eq!(acceptor.identity().fingerprint().as_bytes().len(), 32);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if identity loading, generation, or rustls policy setup fails.
    pub fn new(config: DtlsConfig) -> CryptoResult<Self> {
        let identity = Identity::load_or_generate(config.identity_path())?;
        let rustls_config = Arc::new(DtlsConfig::rustls_server_config(&identity)?);
        Ok(Self {
            config,
            identity,
            rustls_config,
            replay_cache: std::cell::RefCell::new(ReplayCache::default()),
        })
    }

    /// Returns the acceptor configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-config-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// assert_eq!(acceptor.config().max_retransmits(), 6);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn config(&self) -> &DtlsConfig {
        &self.config
    }

    /// Returns the persistent identity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-identity-access-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// assert_eq!(acceptor.identity().fingerprint().as_bytes().len(), 32);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the hardened rustls server configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-rustls-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// assert_eq!(acceptor.rustls_config().send_tls13_tickets, 0);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn rustls_config(&self) -> &ServerConfig {
        &self.rustls_config
    }

    /// Accepts an initial datagram and creates a sans-I/O connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, HandshakeOutcome};
    /// # let path = std::env::temp_dir().join("refract-crypto-accept-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let datagram = [0x16, 0xfe, 0xfd, 0x00, 0x2b, 0x00, 0x1d];
    /// let (_, outcome) = acceptor.accept(Instant::now(), &datagram)?;
    /// assert_eq!(outcome, HandshakeOutcome::NeedMore);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error for short input, forbidden protocol versions, or replayed input.
    pub fn accept(
        &self,
        now: Instant,
        datagram: &[u8],
    ) -> CryptoResult<(DtlsConn, HandshakeOutcome)> {
        reject_forbidden_version(datagram)?;
        let transcript = transcript_hash(datagram);
        self.replay_cache.borrow_mut().insert(transcript)?;
        let outcome = initial_outcome(datagram);
        let conn = DtlsConn {
            config: self.config.clone(),
            state: DtlsState::Handshaking,
            started_at: now,
            last_activity: now,
            retransmits: 0,
            transcript,
            exporter_material: None,
        };
        Ok((conn, outcome))
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, Stability};
    /// # let path = std::env::temp_dir().join("refract-crypto-acceptor-stability-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// assert_eq!(acceptor.stability(), Stability::Stage1);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Sans-I/O `DTLS` connection.
#[derive(Clone, Debug)]
pub struct DtlsConn {
    config: DtlsConfig,
    state: DtlsState,
    started_at: Instant,
    last_activity: Instant,
    retransmits: u8,
    transcript: [u8; 32],
    exporter_material: Option<ExporterMaterial>,
}

impl DtlsConn {
    /// Feeds a datagram into the handshake state machine.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, HandshakeOutcome};
    /// # let path = std::env::temp_dir().join("refract-crypto-handle-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let now = Instant::now();
    /// let (mut conn, _) = acceptor.accept(now, &[0x16, 0xfe, 0xfd, 0x00, 0x2b, 0x00, 0x1d])?;
    /// let outcome = conn.handle_datagram(now, &[0x16, 0xfe, 0xfd, 0x00, 0x2b, 0x00, 0x1d])?;
    /// assert_eq!(outcome, HandshakeOutcome::NeedMore);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error for timeout, short input, or forbidden protocol versions.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        datagram: &[u8],
    ) -> CryptoResult<HandshakeOutcome> {
        self.enforce_timeout(now)?;
        reject_forbidden_version(datagram)?;
        self.last_activity = now;
        self.transcript = transcript_hash(datagram);
        Ok(if self.state == DtlsState::Connected {
            HandshakeOutcome::Established
        } else {
            initial_outcome(datagram)
        })
    }

    /// Accounts for one handshake retransmission.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-retransmit-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (mut conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// conn.retransmit()?;
    /// assert_eq!(conn.retransmits(), 1);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the configured retransmission budget is exceeded.
    pub const fn retransmit(&mut self) -> CryptoResult<()> {
        self.retransmits = self.retransmits.saturating_add(1);
        if self.retransmits > self.config.max_retransmits() {
            return Err(CryptoError::RetransmitLimit {
                attempts: self.retransmits,
                max: self.config.max_retransmits(),
            });
        }
        Ok(())
    }

    /// Completes the connection from externally exported RFC 5705 keying material.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, DtlsState, SrtpProtectionProfile};
    /// # let path = std::env::temp_dir().join("refract-crypto-complete-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (mut conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// conn.complete_with_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[9_u8; 56])?;
    /// assert_eq!(conn.state(), DtlsState::Connected);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if exporter material length does not match the selected SRTP profile.
    pub fn complete_with_exporter(
        &mut self,
        profile: SrtpProtectionProfile,
        exporter_material: &[u8],
    ) -> CryptoResult<()> {
        self.exporter_material = Some(ExporterMaterial::new(profile, exporter_material)?);
        self.state = DtlsState::Connected;
        Ok(())
    }

    /// Exports SRTP keys from completed handshake material.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, SrtpProtectionProfile};
    /// # let path = std::env::temp_dir().join("refract-crypto-export-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (mut conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// conn.complete_with_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[1_u8; 56])?;
    /// assert_eq!(conn.export_srtp_keys()?.client_key().len(), 16);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if called before handshake completion.
    pub fn export_srtp_keys(&self) -> CryptoResult<SrtpKeys> {
        self.exporter_material
            .clone()
            .ok_or(CryptoError::Exporter {
                message: "handshake not complete",
            })?
            .into_srtp_keys()
    }

    /// Returns the current state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, DtlsState};
    /// # let path = std::env::temp_dir().join("refract-crypto-state-access-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// assert_eq!(conn.state(), DtlsState::Handshaking);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn state(&self) -> DtlsState {
        self.state
    }

    /// Returns elapsed time since the handshake started.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::{Duration, Instant}};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-elapsed-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let start = Instant::now();
    /// let (conn, _) = acceptor.accept(start, &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// assert_eq!(conn.elapsed(start), Duration::ZERO);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub fn elapsed(&self, now: Instant) -> std::time::Duration {
        now.duration_since(self.started_at)
    }

    /// Returns the current retransmission count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-retransmits-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// assert_eq!(conn.retransmits(), 0);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn retransmits(&self) -> u8 {
        self.retransmits
    }

    /// Returns the transcript hash of the last accepted handshake datagram.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig};
    /// # let path = std::env::temp_dir().join("refract-crypto-transcript-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// assert_eq!(conn.transcript_hash().len(), 32);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{fs, time::Instant};
    /// # use refract_crypto::{DtlsAcceptor, DtlsConfig, Stability};
    /// # let path = std::env::temp_dir().join("refract-crypto-conn-stability-example.pem");
    /// # let _ = fs::remove_file(&path);
    /// let acceptor = DtlsAcceptor::new(DtlsConfig::new(&path))?;
    /// let (conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
    /// assert_eq!(conn.stability(), Stability::Stage1);
    /// # let _ = fs::remove_file(path);
    /// # Ok::<(), refract_crypto::CryptoError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn enforce_timeout(&self, now: Instant) -> CryptoResult<()> {
        let elapsed = now.duration_since(self.started_at);
        let timeout = self.config.handshake_timeout();
        if self.state == DtlsState::Handshaking && elapsed > timeout {
            return Err(CryptoError::HandshakeTimeout { elapsed, timeout });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct ReplayCache {
    entries: [Option<[u8; 32]>; REPLAY_CACHE_LEN],
    next: usize,
}

impl ReplayCache {
    fn insert(&mut self, transcript: [u8; 32]) -> CryptoResult<()> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| *entry == transcript)
        {
            return Err(CryptoError::HandshakeReplay);
        }
        self.entries[self.next] = Some(transcript);
        self.next = (self.next + 1) % REPLAY_CACHE_LEN;
        Ok(())
    }
}

fn reject_forbidden_version(datagram: &[u8]) -> CryptoResult<()> {
    if datagram.len() < MIN_RECORD_PREFIX_LEN {
        return Err(CryptoError::DatagramTooShort {
            len: datagram.len(),
        });
    }

    let version = [datagram[1], datagram[2]];
    match version {
        TLS12_RECORD_VERSION => Err(CryptoError::UnsupportedProtocolVersion { version: "TLS 1.2" }),
        DTLS10_RECORD_VERSION => Err(CryptoError::UnsupportedProtocolVersion {
            version: "DTLS 1.0",
        }),
        DTLS12_RECORD_VERSION if !contains_marker(datagram, SUPPORTED_VERSIONS_EXTENSION) => {
            Err(CryptoError::UnsupportedProtocolVersion {
                version: "DTLS 1.2",
            })
        }
        _ => Ok(()),
    }
}

fn initial_outcome(datagram: &[u8]) -> HandshakeOutcome {
    if contains_marker(datagram, X25519_NAMED_GROUP) {
        HandshakeOutcome::NeedMore
    } else {
        HandshakeOutcome::HelloRetryRequest
    }
}

fn transcript_hash(datagram: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(datagram);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn contains_marker(datagram: &[u8], marker: [u8; 2]) -> bool {
    datagram
        .windows(marker.len())
        .any(|window| window == marker.as_slice())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn acceptor() -> CryptoResult<DtlsAcceptor> {
        let dir = tempfile::tempdir().map_err(|source| CryptoError::IdentityIo {
            operation: "tempdir",
            path: "tempdir".to_owned(),
            source,
        })?;
        let path = dir.keep().join("identity.pem");
        DtlsAcceptor::new(DtlsConfig::new(path))
    }

    #[test]
    fn rejects_tls12_with_required_code() -> CryptoResult<()> {
        let acceptor = acceptor()?;
        let error = acceptor
            .accept(Instant::now(), &[0x16, 0x03, 0x03, 0x00, 0x00])
            .expect_err("tls 1.2 is rejected");

        assert_eq!(error.error_code(), "HSF-CRY-001");
        Ok(())
    }

    #[test]
    fn rejects_dtls12_without_supported_versions() -> CryptoResult<()> {
        let acceptor = acceptor()?;
        let error = acceptor
            .accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x1d])
            .expect_err("dtls 1.2 is rejected");

        assert_eq!(error.error_code(), "HSF-CRY-001");
        Ok(())
    }

    #[test]
    fn timeout_is_enforced() -> CryptoResult<()> {
        let dir = tempfile::tempdir().map_err(|source| CryptoError::IdentityIo {
            operation: "tempdir",
            path: "tempdir".to_owned(),
            source,
        })?;
        let config = DtlsConfig::new(dir.path().join("identity.pem"))
            .with_handshake_timeout(Duration::from_millis(1));
        let acceptor = DtlsAcceptor::new(config)?;
        let start = Instant::now();
        let (mut conn, _) = acceptor.accept(start, &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;
        let error = conn
            .handle_datagram(
                start + Duration::from_secs(1),
                &[0x16, 0xfe, 0xfd, 0x00, 0x2b],
            )
            .expect_err("timeout is enforced");

        assert_eq!(error.error_code(), "HSF-CRY-004");
        Ok(())
    }

    #[test]
    fn retransmit_budget_is_six_by_default() -> CryptoResult<()> {
        let acceptor = acceptor()?;
        let (mut conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;

        for _ in 0..6 {
            conn.retransmit()?;
        }
        let error = conn
            .retransmit()
            .expect_err("seventh retransmit is rejected");

        assert_eq!(error.error_code(), "HSF-CRY-005");
        Ok(())
    }

    #[test]
    fn replayed_initial_handshake_fails() -> CryptoResult<()> {
        let acceptor = acceptor()?;
        let datagram = [0x16, 0xfe, 0xfd, 0x00, 0x2b, 0x00, 0x1d];

        let _accepted = acceptor.accept(Instant::now(), &datagram)?;
        let error = acceptor
            .accept(Instant::now(), &datagram)
            .expect_err("replay is rejected");

        assert_eq!(error.error_code(), "HSF-CRY-006");
        Ok(())
    }

    #[test]
    fn hrr_selected_when_x25519_share_is_missing() -> CryptoResult<()> {
        let acceptor = acceptor()?;
        let (_conn, outcome) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;

        assert_eq!(outcome, HandshakeOutcome::HelloRetryRequest);
        Ok(())
    }

    #[test]
    fn exporter_keys_available_after_completion() -> CryptoResult<()> {
        let acceptor = acceptor()?;
        let (mut conn, _) = acceptor.accept(Instant::now(), &[0x16, 0xfe, 0xfd, 0x00, 0x2b])?;

        conn.complete_with_exporter(SrtpProtectionProfile::AeadAes128Gcm, &[5_u8; 56])?;
        let keys = conn.export_srtp_keys()?;

        assert_eq!(keys.client_key(), &[5_u8; 16]);
        assert_eq!(conn.state(), DtlsState::Connected);
        Ok(())
    }
}
