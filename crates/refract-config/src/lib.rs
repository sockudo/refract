//! Strongly typed configuration and online reload support.
//!
//! Configuration is loaded with `figment` using the Stage 1 precedence order:
//! environment overrides file values, and file values override defaults.
//! Runtime consumers read immutable [`ConfigSnapshot`] values from an
//! [`ArcSwap`](arc_swap::ArcSwap)-backed [`ConfigStore`], so in-flight work keeps
//! its old snapshot while new work observes validated hot reloads.
//!
//! # Examples
//!
//! ```
//! # use refract_config::{Config, ConfigStore};
//! let config = Config::default();
//! config.validate()?;
//! let store = ConfigStore::new(config);
//! assert_eq!(store.snapshot().runtime().cores(), 1);
//! # Ok::<(), refract_config::ConfigError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::BTreeMap,
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use figment::{
    Figment, Provider,
    providers::{Env, Format as _, Serialized, Toml},
};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

const DEFAULT_MTU: u16 = 1_200;
const MIN_MTU: u16 = 576;
const MAX_MTU: u16 = 9_000;
const DEFAULT_DTLS_TIMEOUT_MS: u64 = 1_000;
const DEFAULT_RAFT_ELECTION_MS: u64 = 1_500;
const DEFAULT_RAFT_HEARTBEAT_MS: u64 = 250;
const MAX_PEERS: usize = 512;
const MAX_APPS: usize = 64;
const MAX_EXPORTER_TARGETS: usize = 16;

/// Result alias for configuration operations.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Stage marker for public `refract-config` APIs.
///
/// # Examples
///
/// ```
/// # use refract_config::Stability;
/// assert_eq!(Stability::Stage1.as_str(), "stage1");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Stability {
    /// Stage 1 API surface; usable inside the workspace but not externally stable.
    Stage1,
}

impl Stability {
    /// Returns a stable label for this API state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Configuration loading and validation errors.
///
/// # Examples
///
/// ```
/// # use refract_config::ConfigError;
/// let error = ConfigError::Validation {
///     issue: refract_config::ValidationIssue::new(
///         "runtime.cores",
///         "must be greater than zero",
///         None,
///     ),
/// };
/// assert_eq!(error.error_code(), "CONFIG_VALIDATION_0001");
/// ```
#[derive(Debug, ThisError)]
pub enum ConfigError {
    /// Figment could not load or deserialize configuration.
    #[error("configuration load failed at {path}: {message}")]
    Load {
        /// Stable field path when known.
        path: String,
        /// Clear source error message.
        message: String,
        /// Best-effort source line.
        line: Option<usize>,
    },
    /// A field validator rejected the configuration.
    #[error("configuration validation failed: {issue}")]
    Validation {
        /// Validation failure details.
        issue: ValidationIssue,
    },
    /// File watcher setup failed.
    #[error("configuration watcher failed: {message}")]
    Watcher {
        /// Clear watcher failure message.
        message: String,
    },
}

impl ConfigError {
    /// Returns the stable operator-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::ConfigError;
    /// let error = ConfigError::Watcher {
    ///     message: "x".to_owned(),
    /// };
    /// assert_eq!(error.error_code(), "CONFIG_WATCHER_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Load { .. } => "CONFIG_LOAD_0001",
            Self::Validation { .. } => "CONFIG_VALIDATION_0001",
            Self::Watcher { .. } => "CONFIG_WATCHER_0001",
        }
    }

    /// Returns the best-known line for this error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::{ConfigError, ValidationIssue};
    /// let error = ConfigError::Validation {
    ///     issue: ValidationIssue::new("net.mtu", "invalid", Some(7)),
    /// };
    /// assert_eq!(error.line(), Some(7));
    /// ```
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        match self {
            Self::Load { line, .. } => *line,
            Self::Validation { issue } => issue.line(),
            Self::Watcher { .. } => None,
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::{ConfigError, Stability};
    /// assert_eq!(
    ///     ConfigError::Watcher {
    ///         message: String::new()
    ///     }
    ///     .stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// One clear field validation failure.
///
/// # Examples
///
/// ```
/// # use refract_config::ValidationIssue;
/// let issue = ValidationIssue::new("runtime.cores", "must be greater than zero", Some(3));
/// assert_eq!(issue.field(), "runtime.cores");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationIssue {
    field: String,
    message: String,
    line: Option<usize>,
}

impl ValidationIssue {
    /// Creates a validation issue.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::ValidationIssue;
    /// let issue = ValidationIssue::new("x", "bad", None);
    /// assert_eq!(issue.message(), "bad");
    /// ```
    #[must_use]
    pub fn new(field: impl Into<String>, message: impl Into<String>, line: Option<usize>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            line,
        }
    }

    /// Returns the rejected field path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::ValidationIssue;
    /// assert_eq!(ValidationIssue::new("x", "bad", None).field(), "x");
    /// ```
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Returns the validation message.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::ValidationIssue;
    /// assert_eq!(ValidationIssue::new("x", "bad", None).message(), "bad");
    /// ```
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the source line when known.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::ValidationIssue;
    /// assert_eq!(ValidationIssue::new("x", "bad", Some(4)).line(), Some(4));
    /// ```
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        self.line
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(formatter, "{}: {} at line {line}", self.field, self.message),
            None => write!(formatter, "{}: {}", self.field, self.message),
        }
    }
}

/// Complete strongly typed refract configuration.
///
/// # Examples
///
/// ```
/// # use refract_config::Config;
/// let config = Config::default();
/// assert!(config.validate().is_ok());
/// ```
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    runtime: RuntimeConfig,
    net: NetConfig,
    crypto: CryptoConfig,
    limits: LimitsConfig,
    apps: BTreeMap<String, AppConfig>,
    cluster: ClusterConfig,
    obs: ObsConfig,
}

impl Config {
    /// Loads configuration from a file with environment overrides.
    ///
    /// Environment keys use the `REFRACT_` prefix and `__` as a nesting
    /// separator, for example `REFRACT_RUNTIME__CORES=8`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when figment extraction or validation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use refract_config::Config;
    /// let config = Config::from_file("refract.toml")?;
    /// assert!(config.runtime().cores() > 0);
    /// # Ok::<(), refract_config::ConfigError>(())
    /// ```
    pub fn from_file(path: impl AsRef<Path>) -> ConfigResult<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|error| ConfigError::Load {
            path: path.display().to_string(),
            message: error.to_string(),
            line: None,
        })?;
        let figment = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file_exact(path))
            .merge(Self::env_provider());
        Self::extract_figment(&figment, Some(&text))
    }

    /// Loads configuration from TOML text without reading environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when figment extraction or validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// let config = Config::from_toml_str("[runtime]\ncores = 2\n")?;
    /// assert_eq!(config.runtime().cores(), 2);
    /// # Ok::<(), refract_config::ConfigError>(())
    /// ```
    pub fn from_toml_str(text: &str) -> ConfigResult<Self> {
        let figment =
            Figment::from(Serialized::defaults(Self::default())).merge(Toml::string(text));
        Self::extract_figment(&figment, Some(text))
    }

    /// Loads configuration from figment with defaults and an override provider.
    ///
    /// This is primarily useful for tests that need deterministic environment
    /// precedence without mutating process-global environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when figment extraction or validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use figment::providers::{Format, Serialized, Toml};
    /// # use refract_config::Config;
    /// let config = Config::from_file_and_env_providers(
    ///     Toml::string("[runtime]\ncores = 2\n"),
    ///     Serialized::default("runtime.cores", 4),
    ///     None,
    /// )?;
    /// assert_eq!(config.runtime().cores(), 4);
    /// # Ok::<(), refract_config::ConfigError>(())
    /// ```
    pub fn from_file_and_env_providers<F, E>(
        file_provider: F,
        env_provider: E,
        source_text: Option<&str>,
    ) -> ConfigResult<Self>
    where
        F: Provider,
        E: Provider,
    {
        let figment = Figment::from(Serialized::defaults(Self::default()))
            .merge(file_provider)
            .merge(env_provider);
        Self::extract_figment(&figment, source_text)
    }

    /// Returns the environment provider used by [`Config::from_file`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// let _provider = Config::env_provider();
    /// ```
    #[must_use]
    pub fn env_provider() -> Env {
        Env::prefixed("REFRACT_").split("__")
    }

    /// Validates every field in the configuration.
    ///
    /// # Errors
    ///
    /// Returns the first validation issue with a clear field path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// Config::default().validate()?;
    /// # Ok::<(), refract_config::ConfigError>(())
    /// ```
    pub fn validate(&self) -> ConfigResult<()> {
        self.validate_with_source(None)
    }

    /// Returns the runtime section.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert_eq!(Config::default().runtime().cores(), 1);
    /// ```
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeConfig {
        &self.runtime
    }

    /// Returns the networking section.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert_eq!(Config::default().net().mtu(), 1_200);
    /// ```
    #[must_use]
    pub const fn net(&self) -> &NetConfig {
        &self.net
    }

    /// Returns the crypto section.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert_eq!(Config::default().crypto().dtls_timeout_ms(), 1_000);
    /// ```
    #[must_use]
    pub const fn crypto(&self) -> &CryptoConfig {
        &self.crypto
    }

    /// Returns the limits section.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert_eq!(
    ///     Config::default().limits().payload_type_max(),
    ///     refract_core::limits::PAYLOAD_TYPE_MAX
    /// );
    /// ```
    #[must_use]
    pub const fn limits(&self) -> &LimitsConfig {
        &self.limits
    }

    /// Returns per-application configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert!(Config::default().apps().is_empty());
    /// ```
    #[must_use]
    pub const fn apps(&self) -> &BTreeMap<String, AppConfig> {
        &self.apps
    }

    /// Returns the cluster section.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert_eq!(Config::default().cluster().raft().heartbeat_ms(), 250);
    /// ```
    #[must_use]
    pub const fn cluster(&self) -> &ClusterConfig {
        &self.cluster
    }

    /// Returns the observability section.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::Config;
    /// assert!(Config::default().obs().metric_exporter_targets().is_empty());
    /// ```
    #[must_use]
    pub const fn obs(&self) -> &ObsConfig {
        &self.obs
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::{Config, Stability};
    /// assert_eq!(Config::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn extract_figment(figment: &Figment, source_text: Option<&str>) -> ConfigResult<Self> {
        let config = figment.extract::<Self>().map_err(|error| {
            let path = error.path.join(".");
            ConfigError::Load {
                line: source_text.and_then(|text| find_line_for_path(text, &path)),
                path,
                message: error.to_string(),
            }
        })?;
        config.validate_with_source(source_text)?;
        Ok(config)
    }

    fn validate_with_source(&self, source_text: Option<&str>) -> ConfigResult<()> {
        let mut issues = Vec::new();
        self.runtime.validate(&mut issues);
        self.net.validate(&mut issues);
        self.crypto.validate(&mut issues);
        self.limits.validate(&mut issues);
        validate_apps(&self.apps, &mut issues);
        self.cluster.validate(&mut issues);
        self.obs.validate(&mut issues);

        if let Some(issue) = issues.into_iter().next() {
            let line = issue
                .line()
                .or_else(|| source_text.and_then(|text| find_line_for_path(text, issue.field())));
            return Err(ConfigError::Validation {
                issue: ValidationIssue::new(issue.field(), issue.message(), line),
            });
        }

        Ok(())
    }

    fn reload_compatible_with(&self, current: &Self) -> (Self, Vec<ReloadWarning>) {
        let mut next = self.clone();
        let mut warnings = Vec::new();

        preserve_immutable(
            current.runtime(),
            &mut next.runtime,
            "runtime",
            "runtime topology is immutable after startup",
            &mut warnings,
        );
        preserve_immutable(
            current.net(),
            &mut next.net,
            "net",
            "media sockets are immutable after startup",
            &mut warnings,
        );
        if current.crypto.cert_path() != next.crypto.cert_path() {
            warnings.push(ReloadWarning::immutable_ignored(
                "crypto.cert_path",
                "certificate path changes require a drain or restart",
            ));
            next.crypto.cert_path.clone_from(&current.crypto.cert_path);
        }
        if current.cluster.raft().node_id() != next.cluster.raft().node_id() {
            warnings.push(ReloadWarning::immutable_ignored(
                "cluster.raft.node_id",
                "raft node identity is immutable after startup",
            ));
            next.cluster.raft.node_id = current.cluster.raft.node_id;
        }

        (next, warnings)
    }
}

/// Runtime execution configuration.
///
/// Runtime fields are immutable at hot reload; changing them requires a drain
/// or process restart.
///
/// # Examples
///
/// ```
/// # use refract_config::RuntimeConfig;
/// assert!(!RuntimeConfig::default().pinning());
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    cores: usize,
    pinning: bool,
    hugepages: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            cores: 1,
            pinning: false,
            hugepages: false,
        }
    }
}

impl RuntimeConfig {
    /// Creates runtime configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::RuntimeConfig;
    /// assert_eq!(RuntimeConfig::new(2, true, false).cores(), 2);
    /// ```
    #[must_use]
    pub const fn new(cores: usize, pinning: bool, hugepages: bool) -> Self {
        Self {
            cores,
            pinning,
            hugepages,
        }
    }

    /// Returns configured thread-per-core count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::RuntimeConfig;
    /// assert_eq!(RuntimeConfig::default().cores(), 1);
    /// ```
    #[must_use]
    pub const fn cores(&self) -> usize {
        self.cores
    }

    /// Returns whether CPU pinning is requested.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::RuntimeConfig;
    /// assert!(!RuntimeConfig::default().pinning());
    /// ```
    #[must_use]
    pub const fn pinning(&self) -> bool {
        self.pinning
    }

    /// Returns whether hugepages are requested.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::RuntimeConfig;
    /// assert!(!RuntimeConfig::default().hugepages());
    /// ```
    #[must_use]
    pub const fn hugepages(&self) -> bool {
        self.hugepages
    }

    /// Returns whether a field can be changed during hot reload.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::RuntimeConfig;
    /// assert!(!RuntimeConfig::is_runtime_mutable("runtime.cores"));
    /// ```
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        matches!(field, "")
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.cores == 0 {
            issues.push(ValidationIssue::new(
                "runtime.cores",
                "must be greater than zero",
                None,
            ));
        }
    }
}

/// Network socket configuration.
///
/// Network bind fields are immutable at hot reload.
///
/// # Examples
///
/// ```
/// # use refract_config::NetConfig;
/// assert_eq!(NetConfig::default().mtu(), 1_200);
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    bind_addrs: Vec<SocketAddr>,
    rtp_port: u16,
    rtcp_port: u16,
    mtu: u16,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            bind_addrs: Vec::new(),
            rtp_port: 50_000,
            rtcp_port: 50_001,
            mtu: DEFAULT_MTU,
        }
    }
}

impl NetConfig {
    /// Returns bind addresses for media sockets.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::NetConfig;
    /// assert!(NetConfig::default().bind_addrs().is_empty());
    /// ```
    #[must_use]
    pub fn bind_addrs(&self) -> &[SocketAddr] {
        &self.bind_addrs
    }

    /// Returns the RTP port.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::NetConfig;
    /// assert_eq!(NetConfig::default().rtp_port(), 50_000);
    /// ```
    #[must_use]
    pub const fn rtp_port(&self) -> u16 {
        self.rtp_port
    }

    /// Returns the RTCP port.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::NetConfig;
    /// assert_eq!(NetConfig::default().rtcp_port(), 50_001);
    /// ```
    #[must_use]
    pub const fn rtcp_port(&self) -> u16 {
        self.rtcp_port
    }

    /// Returns the MTU.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::NetConfig;
    /// assert_eq!(NetConfig::default().mtu(), 1_200);
    /// ```
    #[must_use]
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Returns whether a field can be changed during hot reload.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::NetConfig;
    /// assert!(!NetConfig::is_runtime_mutable("net.mtu"));
    /// ```
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        matches!(field, "")
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.bind_addrs.len() > MAX_PEERS {
            issues.push(ValidationIssue::new(
                "net.bind_addrs",
                "must not exceed 512 addresses",
                None,
            ));
        }
        if self.rtp_port == 0 {
            issues.push(ValidationIssue::new(
                "net.rtp_port",
                "must be in range 1..=65535",
                None,
            ));
        }
        if self.rtcp_port == 0 {
            issues.push(ValidationIssue::new(
                "net.rtcp_port",
                "must be in range 1..=65535",
                None,
            ));
        }
        if self.rtp_port == self.rtcp_port {
            issues.push(ValidationIssue::new(
                "net.rtcp_port",
                "must differ from net.rtp_port",
                None,
            ));
        }
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            issues.push(ValidationIssue::new(
                "net.mtu",
                "must be in range 576..=9000",
                None,
            ));
        }
    }
}

/// Crypto and DTLS configuration.
///
/// `dtls_timeout_ms` is mutable at runtime. `cert_path` is immutable and is
/// ignored during hot reload if changed.
///
/// # Examples
///
/// ```
/// # use refract_config::CryptoConfig;
/// assert_eq!(CryptoConfig::default().dtls_timeout_ms(), 1_000);
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CryptoConfig {
    cert_path: PathBuf,
    dtls_timeout_ms: u64,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("certs/refract.pem"),
            dtls_timeout_ms: DEFAULT_DTLS_TIMEOUT_MS,
        }
    }
}

impl CryptoConfig {
    /// Returns the certificate path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::CryptoConfig;
    /// assert_eq!(
    ///     CryptoConfig::default().cert_path(),
    ///     std::path::Path::new("certs/refract.pem")
    /// );
    /// ```
    #[must_use]
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Returns the DTLS timeout in milliseconds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::CryptoConfig;
    /// assert_eq!(CryptoConfig::default().dtls_timeout_ms(), 1_000);
    /// ```
    #[must_use]
    pub const fn dtls_timeout_ms(&self) -> u64 {
        self.dtls_timeout_ms
    }

    /// Returns the DTLS timeout as a [`Duration`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_config::CryptoConfig;
    /// assert_eq!(
    ///     CryptoConfig::default().dtls_timeout(),
    ///     Duration::from_millis(1_000)
    /// );
    /// ```
    #[must_use]
    pub const fn dtls_timeout(&self) -> Duration {
        Duration::from_millis(self.dtls_timeout_ms)
    }

    /// Returns whether a field can be changed during hot reload.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::CryptoConfig;
    /// assert!(CryptoConfig::is_runtime_mutable("crypto.dtls_timeout_ms"));
    /// ```
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        matches!(field, "crypto.dtls_timeout_ms")
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.cert_path.as_os_str().is_empty() {
            issues.push(ValidationIssue::new(
                "crypto.cert_path",
                "must not be empty",
                None,
            ));
        }
        if self.dtls_timeout_ms == 0 || self.dtls_timeout_ms > 60_000 {
            issues.push(ValidationIssue::new(
                "crypto.dtls_timeout_ms",
                "must be in range 1..=60000",
                None,
            ));
        }
    }
}

/// Bounded limits mirrored from `refract-core::limits`.
///
/// All fields are mutable at hot reload.
///
/// # Examples
///
/// ```
/// # use refract_config::LimitsConfig;
/// assert_eq!(
///     LimitsConfig::default().error_field_capacity(),
///     refract_core::limits::ERROR_FIELD_CAPACITY
/// );
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    id_low_bits: u32,
    id_hex_width: usize,
    payload_type_max: u8,
    max_spatial_layer: u8,
    max_temporal_layer: u8,
    error_field_capacity: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            id_low_bits: refract_core::limits::ID_LOW_BITS,
            id_hex_width: refract_core::limits::ID_HEX_WIDTH,
            payload_type_max: refract_core::limits::PAYLOAD_TYPE_MAX,
            max_spatial_layer: refract_core::limits::MAX_SPATIAL_LAYER,
            max_temporal_layer: refract_core::limits::MAX_TEMPORAL_LAYER,
            error_field_capacity: refract_core::limits::ERROR_FIELD_CAPACITY,
        }
    }
}

impl LimitsConfig {
    /// Returns the configured ID low-bit width.
    #[must_use]
    pub const fn id_low_bits(&self) -> u32 {
        self.id_low_bits
    }

    /// Returns the configured ID hexadecimal width.
    #[must_use]
    pub const fn id_hex_width(&self) -> usize {
        self.id_hex_width
    }

    /// Returns the maximum RTP payload type.
    #[must_use]
    pub const fn payload_type_max(&self) -> u8 {
        self.payload_type_max
    }

    /// Returns the maximum spatial layer.
    #[must_use]
    pub const fn max_spatial_layer(&self) -> u8 {
        self.max_spatial_layer
    }

    /// Returns the maximum temporal layer.
    #[must_use]
    pub const fn max_temporal_layer(&self) -> u8 {
        self.max_temporal_layer
    }

    /// Returns the maximum structured error field count.
    #[must_use]
    pub const fn error_field_capacity(&self) -> usize {
        self.error_field_capacity
    }

    /// Returns whether a field can be changed during hot reload.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_config::LimitsConfig;
    /// assert!(LimitsConfig::is_runtime_mutable("limits.payload_type_max"));
    /// ```
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        matches!(
            field,
            "limits.id_low_bits"
                | "limits.id_hex_width"
                | "limits.payload_type_max"
                | "limits.max_spatial_layer"
                | "limits.max_temporal_layer"
                | "limits.error_field_capacity"
        )
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.id_low_bits == 0 || self.id_low_bits > u64::BITS {
            issues.push(ValidationIssue::new(
                "limits.id_low_bits",
                "must be in range 1..=64",
                None,
            ));
        }
        if self.id_hex_width == 0 || self.id_hex_width > 32 {
            issues.push(ValidationIssue::new(
                "limits.id_hex_width",
                "must be in range 1..=32",
                None,
            ));
        }
        if self.payload_type_max > 127 {
            issues.push(ValidationIssue::new(
                "limits.payload_type_max",
                "must be less than or equal to 127",
                None,
            ));
        }
        if self.max_spatial_layer > 7 {
            issues.push(ValidationIssue::new(
                "limits.max_spatial_layer",
                "must be less than or equal to 7",
                None,
            ));
        }
        if self.max_temporal_layer > 7 {
            issues.push(ValidationIssue::new(
                "limits.max_temporal_layer",
                "must be less than or equal to 7",
                None,
            ));
        }
        if self.error_field_capacity == 0 {
            issues.push(ValidationIssue::new(
                "limits.error_field_capacity",
                "must be greater than zero",
                None,
            ));
        }
    }
}

/// Per-application configuration.
///
/// Application configs are mutable at runtime.
///
/// # Examples
///
/// ```
/// # use refract_config::AppConfig;
/// assert!(AppConfig::default().enabled());
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    enabled: bool,
    max_sessions: usize,
    settings: BTreeMap<String, String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_sessions: 100_000,
            settings: BTreeMap::new(),
        }
    }
}

impl AppConfig {
    /// Returns whether the app is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the per-app session cap.
    #[must_use]
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Returns opaque per-app settings.
    #[must_use]
    pub const fn settings(&self) -> &BTreeMap<String, String> {
        &self.settings
    }

    /// Returns whether a field can be changed during hot reload.
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        field.starts_with("apps.")
    }

    fn validate(&self, name: &str, issues: &mut Vec<ValidationIssue>) {
        if name.is_empty() || name.len() > 64 {
            issues.push(ValidationIssue::new(
                "apps",
                "app names must be non-empty and at most 64 bytes",
                None,
            ));
        }
        if self.max_sessions == 0 {
            issues.push(ValidationIssue::new(
                format!("apps.{name}.max_sessions"),
                "must be greater than zero",
                None,
            ));
        }
        if self.settings.len() > 128 {
            issues.push(ValidationIssue::new(
                format!("apps.{name}.settings"),
                "must not exceed 128 keys",
                None,
            ));
        }
    }
}

/// Cluster membership and raft configuration.
///
/// Peer addresses and raft timing are mutable. Raft node identity is immutable
/// during hot reload.
///
/// # Examples
///
/// ```
/// # use refract_config::ClusterConfig;
/// assert!(ClusterConfig::default().peer_addrs().is_empty());
/// ```
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterConfig {
    peer_addrs: Vec<SocketAddr>,
    raft: RaftConfig,
}

impl ClusterConfig {
    /// Returns cluster peer addresses.
    #[must_use]
    pub fn peer_addrs(&self) -> &[SocketAddr] {
        &self.peer_addrs
    }

    /// Returns raft settings.
    #[must_use]
    pub const fn raft(&self) -> &RaftConfig {
        &self.raft
    }

    /// Returns whether a field can be changed during hot reload.
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        matches!(
            field,
            "cluster.peer_addrs" | "cluster.raft.election_timeout_ms" | "cluster.raft.heartbeat_ms"
        )
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.peer_addrs.len() > MAX_PEERS {
            issues.push(ValidationIssue::new(
                "cluster.peer_addrs",
                "must not exceed 512 peers",
                None,
            ));
        }
        self.raft.validate(issues);
    }
}

/// Raft timing and identity settings.
///
/// # Examples
///
/// ```
/// # use refract_config::RaftConfig;
/// assert_eq!(RaftConfig::default().heartbeat_ms(), 250);
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RaftConfig {
    node_id: u64,
    election_timeout_ms: u64,
    heartbeat_ms: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: 1,
            election_timeout_ms: DEFAULT_RAFT_ELECTION_MS,
            heartbeat_ms: DEFAULT_RAFT_HEARTBEAT_MS,
        }
    }
}

impl RaftConfig {
    /// Returns the raft node identity.
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Returns the election timeout in milliseconds.
    #[must_use]
    pub const fn election_timeout_ms(&self) -> u64 {
        self.election_timeout_ms
    }

    /// Returns the heartbeat interval in milliseconds.
    #[must_use]
    pub const fn heartbeat_ms(&self) -> u64 {
        self.heartbeat_ms
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.node_id == 0 {
            issues.push(ValidationIssue::new(
                "cluster.raft.node_id",
                "must be greater than zero",
                None,
            ));
        }
        if self.heartbeat_ms == 0 {
            issues.push(ValidationIssue::new(
                "cluster.raft.heartbeat_ms",
                "must be greater than zero",
                None,
            ));
        }
        if self.election_timeout_ms <= self.heartbeat_ms {
            issues.push(ValidationIssue::new(
                "cluster.raft.election_timeout_ms",
                "must be greater than cluster.raft.heartbeat_ms",
                None,
            ));
        }
    }
}

/// Observability exporter configuration.
///
/// Exporter targets are mutable at runtime.
///
/// # Examples
///
/// ```
/// # use refract_config::ObsConfig;
/// assert!(ObsConfig::default().metric_exporter_targets().is_empty());
/// ```
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObsConfig {
    metric_exporter_targets: Vec<String>,
}

impl ObsConfig {
    /// Returns metric exporter targets.
    #[must_use]
    pub fn metric_exporter_targets(&self) -> &[String] {
        &self.metric_exporter_targets
    }

    /// Returns whether a field can be changed during hot reload.
    #[must_use]
    pub fn is_runtime_mutable(field: &str) -> bool {
        matches!(field, "obs.metric_exporter_targets")
    }

    fn validate(&self, issues: &mut Vec<ValidationIssue>) {
        if self.metric_exporter_targets.len() > MAX_EXPORTER_TARGETS {
            issues.push(ValidationIssue::new(
                "obs.metric_exporter_targets",
                "must not exceed 16 targets",
                None,
            ));
        }
        self.metric_exporter_targets
            .iter()
            .enumerate()
            .filter(|(_index, target)| target.is_empty())
            .for_each(|(index, _target)| {
                issues.push(ValidationIssue::new(
                    format!("obs.metric_exporter_targets.{index}"),
                    "must not be empty",
                    None,
                ));
            });
    }
}

/// Immutable snapshot loaded from [`ConfigStore`].
///
/// # Examples
///
/// ```
/// # use refract_config::{Config, ConfigStore};
/// let store = ConfigStore::new(Config::default());
/// let snapshot = store.snapshot();
/// assert_eq!(snapshot.runtime().cores(), 1);
/// ```
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    inner: Arc<Config>,
}

impl ConfigSnapshot {
    /// Returns the underlying configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.inner
    }

    /// Returns the runtime section.
    #[must_use]
    pub fn runtime(&self) -> &RuntimeConfig {
        self.inner.runtime()
    }

    /// Returns the networking section.
    #[must_use]
    pub fn net(&self) -> &NetConfig {
        self.inner.net()
    }

    /// Returns the crypto section.
    #[must_use]
    pub fn crypto(&self) -> &CryptoConfig {
        self.inner.crypto()
    }

    /// Returns the limits section.
    #[must_use]
    pub fn limits(&self) -> &LimitsConfig {
        self.inner.limits()
    }

    /// Returns the apps section.
    #[must_use]
    pub fn apps(&self) -> &BTreeMap<String, AppConfig> {
        self.inner.apps()
    }

    /// Returns the cluster section.
    #[must_use]
    pub fn cluster(&self) -> &ClusterConfig {
        self.inner.cluster()
    }

    /// Returns the observability section.
    #[must_use]
    pub fn obs(&self) -> &ObsConfig {
        self.inner.obs()
    }
}

/// Hot-reload store for validated configuration.
///
/// # Examples
///
/// ```
/// # use refract_config::{Config, ConfigStore};
/// let store = ConfigStore::new(Config::default());
/// assert_eq!(store.snapshot().runtime().cores(), 1);
/// ```
#[derive(Debug)]
pub struct ConfigStore {
    current: ArcSwap<Config>,
}

impl ConfigStore {
    /// Creates a store from a validated configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            current: ArcSwap::from_pointee(config),
        }
    }

    /// Returns an in-flight safe configuration snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ConfigSnapshot {
        ConfigSnapshot {
            inner: self.current.load_full(),
        }
    }

    /// Reloads from an already parsed configuration.
    ///
    /// Immutable runtime fields are preserved from the current snapshot and
    /// reported as warnings.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when validation fails.
    pub fn reload(&self, next: &Config) -> ConfigResult<ReloadReport> {
        next.validate()?;
        let current = self.current.load_full();
        let (compatible, warnings) = next.reload_compatible_with(&current);
        self.current.store(Arc::new(compatible));
        Ok(ReloadReport::new(true, warnings))
    }

    /// Reloads from a TOML file path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when loading or validation fails.
    pub fn reload_from_path(&self, path: impl AsRef<Path>) -> ConfigResult<ReloadReport> {
        let config = Config::from_file(path)?;
        self.reload(&config)
    }
}

/// Hot-reload result.
///
/// # Examples
///
/// ```
/// # use refract_config::ReloadReport;
/// assert!(ReloadReport::new(true, Vec::new()).applied());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadReport {
    applied: bool,
    warnings: Vec<ReloadWarning>,
}

impl ReloadReport {
    /// Creates a reload report.
    #[must_use]
    pub const fn new(applied: bool, warnings: Vec<ReloadWarning>) -> Self {
        Self { applied, warnings }
    }

    /// Returns whether a validated configuration was applied.
    #[must_use]
    pub const fn applied(&self) -> bool {
        self.applied
    }

    /// Returns immutable-field warnings.
    #[must_use]
    pub fn warnings(&self) -> &[ReloadWarning] {
        &self.warnings
    }
}

/// Warning emitted during reload.
///
/// # Examples
///
/// ```
/// # use refract_config::ReloadWarning;
/// let warning = ReloadWarning::immutable_ignored("runtime.cores", "restart required");
/// assert_eq!(warning.field(), "runtime.cores");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadWarning {
    field: String,
    message: String,
}

impl ReloadWarning {
    /// Creates an immutable-field warning.
    #[must_use]
    pub fn immutable_ignored(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Returns the ignored field.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Returns the warning message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Notify-rs watcher that triggers config reload on file changes.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # use refract_config::{Config, ConfigStore, ConfigWatcher};
/// let store = Arc::new(ConfigStore::new(Config::default()));
/// let _watcher = ConfigWatcher::watch("refract.toml", store, |_report| {})?;
/// # Ok::<(), refract_config::ConfigError>(())
/// ```
#[derive(Debug)]
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
    path: PathBuf,
}

impl ConfigWatcher {
    /// Watches a file and reloads the store on change events.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Watcher`] when notify-rs cannot create or attach
    /// the watcher.
    pub fn watch(
        path: impl AsRef<Path>,
        store: Arc<ConfigStore>,
        on_reload: impl Fn(ConfigResult<ReloadReport>) + Send + 'static,
    ) -> ConfigResult<Self> {
        let path = path.as_ref().to_path_buf();
        let watched_path = path.clone();
        let callback_path = path.clone();
        let mut watcher = RecommendedWatcher::new(
            move |event: notify::Result<Event>| match event {
                Ok(event) if event.paths.iter().any(|changed| changed == &callback_path) => {
                    on_reload(store.reload_from_path(&callback_path));
                }
                Ok(_event) => {}
                Err(error) => on_reload(Err(ConfigError::Watcher {
                    message: error.to_string(),
                })),
            },
            NotifyConfig::default(),
        )
        .map_err(|error| ConfigError::Watcher {
            message: error.to_string(),
        })?;
        watcher
            .watch(&watched_path, RecursiveMode::NonRecursive)
            .map_err(|error| ConfigError::Watcher {
                message: error.to_string(),
            })?;
        Ok(Self {
            _watcher: watcher,
            path,
        })
    }

    /// Returns the watched path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_apps(apps: &BTreeMap<String, AppConfig>, issues: &mut Vec<ValidationIssue>) {
    if apps.len() > MAX_APPS {
        issues.push(ValidationIssue::new(
            "apps",
            "must not contain more than 64 applications",
            None,
        ));
    }
    for (name, config) in apps {
        config.validate(name, issues);
    }
}

fn preserve_immutable<T>(
    current: &T,
    next: &mut T,
    field: &'static str,
    message: &'static str,
    warnings: &mut Vec<ReloadWarning>,
) where
    T: Clone + Eq,
{
    if current != next {
        warnings.push(ReloadWarning::immutable_ignored(field, message));
        next.clone_from(current);
    }
}

fn find_line_for_path(text: &str, path: &str) -> Option<usize> {
    let mut section = String::new();
    text.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .clone_into(&mut section);
            return None;
        }
        let (key, _value) = trimmed.split_once('=')?;
        let full_path = if section.is_empty() {
            key.trim().to_owned()
        } else {
            format!("{}.{}", section, key.trim())
        };
        if full_path == path || path.starts_with(&format!("{full_path}.")) {
            Some(index + 1)
        } else {
            None
        }
    })
}

/// Returns the Stage 1 stability marker for the crate.
///
/// # Examples
///
/// ```
/// # use refract_config::{stability, Stability};
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
    fn env_provider_override_wins_over_file_and_defaults() -> ConfigResult<()> {
        let config = Config::from_file_and_env_providers(
            Toml::string("[runtime]\ncores = 2\n"),
            Serialized::default("runtime.cores", 4),
            None,
        )?;

        assert_eq!(config.runtime().cores(), 4);
        Ok(())
    }

    #[test]
    fn invalid_config_rejected_with_line_number() {
        let text = "[runtime]\ncores = 1\n[net]\nmtu = 32\n";
        let error = Config::from_toml_str(text).expect_err("mtu validator rejects");

        assert_eq!(error.error_code(), "CONFIG_VALIDATION_0001");
        assert_eq!(error.line(), Some(4));
    }

    #[test]
    fn hot_reload_during_traffic_keeps_old_snapshot_and_updates_new() -> ConfigResult<()> {
        let initial =
            Config::from_toml_str("[runtime]\ncores = 2\n[crypto]\ndtls_timeout_ms = 1000\n")?;
        let store = ConfigStore::new(initial);
        let in_flight = store.snapshot();

        let next = Config::from_toml_str(
            "[runtime]\ncores = 8\n[crypto]\ndtls_timeout_ms = 2000\n[limits]\nerror_field_capacity = 12\n",
        )?;
        let report = store.reload(&next)?;
        let fresh = store.snapshot();

        assert!(report.applied());
        assert_eq!(report.warnings().len(), 1);
        assert_eq!(report.warnings()[0].field(), "runtime");
        assert_eq!(in_flight.runtime().cores(), 2);
        assert_eq!(fresh.runtime().cores(), 2);
        assert_eq!(fresh.crypto().dtls_timeout_ms(), 2_000);
        assert_eq!(fresh.limits().error_field_capacity(), 12);
        Ok(())
    }

    #[test]
    fn reload_from_path_rejects_invalid_file_without_swap() -> ConfigResult<()> {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("refract.toml");
        fs::write(&path, "[net]\nmtu = 1200\n").expect("write valid config");

        let store = ConfigStore::new(Config::from_file(&path)?);
        fs::write(&path, "[net]\nmtu = 12\n").expect("write invalid config");
        let error = store
            .reload_from_path(&path)
            .expect_err("invalid reload rejected");

        assert_eq!(error.line(), Some(2));
        assert_eq!(store.snapshot().net().mtu(), 1_200);
        Ok(())
    }

    #[test]
    fn all_declared_mutability_markers_are_explicit() {
        assert!(!RuntimeConfig::is_runtime_mutable("runtime.cores"));
        assert!(!NetConfig::is_runtime_mutable("net.mtu"));
        assert!(CryptoConfig::is_runtime_mutable("crypto.dtls_timeout_ms"));
        assert!(LimitsConfig::is_runtime_mutable("limits.payload_type_max"));
        assert!(AppConfig::is_runtime_mutable("apps.echo.enabled"));
        assert!(ClusterConfig::is_runtime_mutable("cluster.peer_addrs"));
        assert!(ObsConfig::is_runtime_mutable("obs.metric_exporter_targets"));
    }

    #[test]
    fn every_error_variant_has_unique_code() {
        let errors = [
            ConfigError::Load {
                path: "x".to_owned(),
                message: "x".to_owned(),
                line: None,
            },
            ConfigError::Validation {
                issue: ValidationIssue::new("x", "bad", None),
            },
            ConfigError::Watcher {
                message: "x".to_owned(),
            },
        ];
        let mut codes = errors
            .iter()
            .map(ConfigError::error_code)
            .collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }
}
