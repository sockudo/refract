//! WASI 0.2 component-model extension sandbox.
//!
//! `refract-wasm` hosts Stage 1 slow-path policy extensions behind a
//! fail-closed Wasmtime component boundary. Extension components implement the
//! WIT world in `wit/refract-extension.wit`; Refract exposes no filesystem,
//! network, environment, or clock imports, so components that require ambient
//! capabilities fail instantiation instead of receiving host authority.
//!
//! # Examples
//!
//! ```
//! # use refract_core::{PeerId, RoomId, TrackId};
//! # use refract_wasm::{
//! #     AuthContext, ExtensionDecision, SubscribeContext, WasmExtensionRuntime,
//! # };
//! # let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
//! #     "allow-all",
//! #     refract_wasm::testing::ALLOW_ALL_COMPONENT,
//! # )?;
//! let decision = runtime.on_auth(AuthContext::new(PeerId::from_raw(7), 99));
//! assert_eq!(decision.decision(), ExtensionDecision::Allow);
//!
//! let subscription = SubscribeContext::new(
//!     PeerId::from_raw(7),
//!     RoomId::from_raw(9),
//!     TrackId::from_raw(11),
//!     0,
//!     0,
//! );
//! assert_eq!(
//!     runtime.on_subscribe(subscription).decision(),
//!     ExtensionDecision::Allow
//! );
//! # Ok::<(), refract_wasm::WasmError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use arc_swap::ArcSwap;
use refract_core::{PeerId, RoomId, TrackId};
use thiserror::Error;
use wasmtime::{
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder,
    component::{Component, Linker},
};

/// Result alias for extension loading operations.
pub type WasmResult<T> = Result<T, WasmError>;

/// Default fuel budget applied to every hook call.
pub const DEFAULT_FUEL_LIMIT: u64 = 1_000_000;

/// Default linear-memory ceiling applied to every hook call.
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// Default deterministic wall-clock deadline applied to every hook call.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_millis(50);

/// Maximum human-readable extension name bytes accepted by this crate.
pub const MAX_EXTENSION_NAME_BYTES: usize = 64;

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns the bounded stability label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Error taxonomy for loading and executing extension components.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WasmError {
    /// Extension name is empty, too long, or contains an unsupported byte.
    #[error("invalid extension name")]
    InvalidExtensionName,
    /// Wasmtime engine setup failed.
    #[error("wasm engine setup failed: {message}")]
    Engine {
        /// Human-readable source error.
        message: String,
    },
    /// Component compilation failed.
    #[error("wasm component compile failed: {message}")]
    Compile {
        /// Human-readable source error.
        message: String,
    },
    /// Component instantiation failed.
    #[error("wasm component instantiate failed: {message}")]
    Instantiate {
        /// Human-readable source error.
        message: String,
    },
    /// A required hook export is missing or has the wrong type.
    #[error("wasm extension hook export invalid: {hook}")]
    HookExport {
        /// Required hook export.
        hook: &'static str,
        /// Human-readable source error.
        message: String,
    },
    /// A hook trapped or exceeded sandbox limits.
    #[error("wasm sandbox rejected hook: {hook}")]
    SandboxLimit {
        /// Hook being executed.
        hook: &'static str,
        /// Human-readable source error.
        message: String,
    },
    /// The per-call watchdog could not be created.
    #[error("wasm timeout watchdog unavailable: {message}")]
    Watchdog {
        /// Human-readable source error.
        message: String,
    },
}

impl WasmError {
    /// Returns the stable operational error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::WasmError;
    /// let err = WasmError::InvalidExtensionName;
    /// assert_eq!(err.error_code(), "HSF-WASM-NAME");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidExtensionName => "HSF-WASM-NAME",
            Self::Engine { .. } => "HSF-WASM-ENGINE",
            Self::Compile { .. } => "HSF-WASM-COMPILE",
            Self::Instantiate { .. } => "HSF-WASM-INSTANTIATE",
            Self::HookExport { .. } => "HSF-WASM-HOOK",
            Self::SandboxLimit { .. } => "HSF-WASM-SANDBOX",
            Self::Watchdog { .. } => "HSF-WASM-WATCHDOG",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{Stability, WasmError};
    /// assert_eq!(
    ///     WasmError::InvalidExtensionName.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Sandbox settings applied independently to every hook call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxLimits {
    fuel: u64,
    memory_bytes: usize,
    call_timeout: Duration,
}

impl SandboxLimits {
    /// Creates sandbox limits for extension execution.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::SandboxLimit`] when any limit is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_wasm::SandboxLimits;
    /// let limits = SandboxLimits::new(100, 16 * 1024 * 1024, Duration::from_millis(50))?;
    /// assert_eq!(limits.memory_bytes(), 16 * 1024 * 1024);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn new(fuel: u64, memory_bytes: usize, call_timeout: Duration) -> WasmResult<Self> {
        if fuel == 0 || memory_bytes == 0 || call_timeout.is_zero() {
            return Err(WasmError::SandboxLimit {
                hook: "sandbox-config",
                message: "sandbox limits must be non-zero".to_owned(),
            });
        }
        Ok(Self {
            fuel,
            memory_bytes,
            call_timeout,
        })
    }

    /// Returns the per-call fuel budget.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{DEFAULT_FUEL_LIMIT, SandboxLimits};
    /// assert_eq!(SandboxLimits::default().fuel(), DEFAULT_FUEL_LIMIT);
    /// ```
    #[must_use]
    pub const fn fuel(self) -> u64 {
        self.fuel
    }

    /// Returns the linear memory limit in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{DEFAULT_MEMORY_LIMIT_BYTES, SandboxLimits};
    /// assert_eq!(
    ///     SandboxLimits::default().memory_bytes(),
    ///     DEFAULT_MEMORY_LIMIT_BYTES
    /// );
    /// ```
    #[must_use]
    pub const fn memory_bytes(self) -> usize {
        self.memory_bytes
    }

    /// Returns the per-call timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{DEFAULT_CALL_TIMEOUT, SandboxLimits};
    /// assert_eq!(
    ///     SandboxLimits::default().call_timeout(),
    ///     DEFAULT_CALL_TIMEOUT
    /// );
    /// ```
    #[must_use]
    pub const fn call_timeout(self) -> Duration {
        self.call_timeout
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{SandboxLimits, Stability};
    /// assert_eq!(SandboxLimits::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL_LIMIT,
            memory_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            call_timeout: DEFAULT_CALL_TIMEOUT,
        }
    }
}

/// Authorization context for the `on-auth` extension hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthContext {
    peer: PeerId,
    token_hash: u64,
}

impl AuthContext {
    /// Creates an auth hook context.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_wasm::AuthContext;
    /// let context = AuthContext::new(PeerId::from_raw(1), 42);
    /// assert_eq!(context.token_hash(), 42);
    /// ```
    #[must_use]
    pub const fn new(peer: PeerId, token_hash: u64) -> Self {
        Self { peer, token_hash }
    }

    /// Returns the peer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_wasm::AuthContext;
    /// assert_eq!(
    ///     AuthContext::new(PeerId::from_raw(1), 2).peer(),
    ///     PeerId::from_raw(1)
    /// );
    /// ```
    #[must_use]
    pub const fn peer(self) -> PeerId {
        self.peer
    }

    /// Returns the caller-provided bounded token hash.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_wasm::AuthContext;
    /// assert_eq!(AuthContext::new(PeerId::from_raw(1), 2).token_hash(), 2);
    /// ```
    #[must_use]
    pub const fn token_hash(self) -> u64 {
        self.token_hash
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_wasm::{AuthContext, Stability};
    /// assert_eq!(
    ///     AuthContext::new(PeerId::from_raw(1), 2).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Room-creation context for the `on-room-create` extension hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomCreateContext {
    peer: PeerId,
    room: RoomId,
}

impl RoomCreateContext {
    /// Creates a room creation hook context.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_wasm::RoomCreateContext;
    /// let context = RoomCreateContext::new(PeerId::from_raw(1), RoomId::from_raw(2));
    /// assert_eq!(context.room(), RoomId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn new(peer: PeerId, room: RoomId) -> Self {
        Self { peer, room }
    }

    /// Returns the peer requesting room creation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_wasm::RoomCreateContext;
    /// assert_eq!(
    ///     RoomCreateContext::new(PeerId::from_raw(1), RoomId::from_raw(2)).peer(),
    ///     PeerId::from_raw(1),
    /// );
    /// ```
    #[must_use]
    pub const fn peer(self) -> PeerId {
        self.peer
    }

    /// Returns the requested room.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_wasm::RoomCreateContext;
    /// assert_eq!(
    ///     RoomCreateContext::new(PeerId::from_raw(1), RoomId::from_raw(2)).room(),
    ///     RoomId::from_raw(2),
    /// );
    /// ```
    #[must_use]
    pub const fn room(self) -> RoomId {
        self.room
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_wasm::{RoomCreateContext, Stability};
    /// assert_eq!(
    ///     RoomCreateContext::new(PeerId::from_raw(1), RoomId::from_raw(2)).stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Subscription context for the `on-subscribe` extension hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscribeContext {
    peer: PeerId,
    room: RoomId,
    track: TrackId,
    spatial_layer: u8,
    temporal_layer: u8,
}

impl SubscribeContext {
    /// Creates a subscription hook context.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::SubscribeContext;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     1,
    /// );
    /// assert_eq!(context.temporal_layer(), 1);
    /// ```
    #[must_use]
    pub const fn new(
        peer: PeerId,
        room: RoomId,
        track: TrackId,
        spatial_layer: u8,
        temporal_layer: u8,
    ) -> Self {
        Self {
            peer,
            room,
            track,
            spatial_layer,
            temporal_layer,
        }
    }

    /// Returns the peer requesting the subscription.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::SubscribeContext;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     0,
    /// );
    /// assert_eq!(context.peer(), PeerId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn peer(self) -> PeerId {
        self.peer
    }

    /// Returns the room containing the publisher track.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::SubscribeContext;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     0,
    /// );
    /// assert_eq!(context.room(), RoomId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn room(self) -> RoomId {
        self.room
    }

    /// Returns the requested track.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::SubscribeContext;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     0,
    /// );
    /// assert_eq!(context.track(), TrackId::from_raw(3));
    /// ```
    #[must_use]
    pub const fn track(self) -> TrackId {
        self.track
    }

    /// Returns the requested spatial layer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::SubscribeContext;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     4,
    ///     0,
    /// );
    /// assert_eq!(context.spatial_layer(), 4);
    /// ```
    #[must_use]
    pub const fn spatial_layer(self) -> u8 {
        self.spatial_layer
    }

    /// Returns the requested temporal layer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::SubscribeContext;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     5,
    /// );
    /// assert_eq!(context.temporal_layer(), 5);
    /// ```
    #[must_use]
    pub const fn temporal_layer(self) -> u8 {
        self.temporal_layer
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::{Stability, SubscribeContext};
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     0,
    /// );
    /// assert_eq!(context.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Extension hook decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExtensionDecision {
    /// The extension allowed the operation.
    Allow,
    /// The extension denied the operation or failed closed.
    Deny,
}

impl ExtensionDecision {
    /// Returns whether the decision allows the operation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::ExtensionDecision;
    /// assert!(ExtensionDecision::Allow.is_allowed());
    /// assert!(!ExtensionDecision::Deny.is_allowed());
    /// ```
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{ExtensionDecision, Stability};
    /// assert_eq!(ExtensionDecision::Allow.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl From<bool> for ExtensionDecision {
    fn from(value: bool) -> Self {
        if value { Self::Allow } else { Self::Deny }
    }
}

/// Result of one fail-closed extension hook invocation.
#[derive(Debug)]
pub struct ExtensionOutcome {
    decision: ExtensionDecision,
    failure: Option<WasmError>,
    generation: u64,
}

impl ExtensionOutcome {
    /// Creates an allowed extension outcome.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{ExtensionDecision, ExtensionOutcome};
    /// assert_eq!(
    ///     ExtensionOutcome::allowed(1).decision(),
    ///     ExtensionDecision::Allow
    /// );
    /// ```
    #[must_use]
    pub const fn allowed(generation: u64) -> Self {
        Self {
            decision: ExtensionDecision::Allow,
            failure: None,
            generation,
        }
    }

    /// Creates a denied extension outcome.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{ExtensionDecision, ExtensionOutcome};
    /// assert_eq!(
    ///     ExtensionOutcome::denied(1).decision(),
    ///     ExtensionDecision::Deny
    /// );
    /// ```
    #[must_use]
    pub const fn denied(generation: u64) -> Self {
        Self {
            decision: ExtensionDecision::Deny,
            failure: None,
            generation,
        }
    }

    /// Creates a fail-closed extension outcome from an execution failure.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{ExtensionDecision, ExtensionOutcome, WasmError};
    /// let outcome = ExtensionOutcome::failed(1, WasmError::InvalidExtensionName);
    /// assert_eq!(outcome.decision(), ExtensionDecision::Deny);
    /// assert!(outcome.failure().is_some());
    /// ```
    #[must_use]
    pub const fn failed(generation: u64, failure: WasmError) -> Self {
        Self {
            decision: ExtensionDecision::Deny,
            failure: Some(failure),
            generation,
        }
    }

    /// Returns the policy decision.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{ExtensionDecision, ExtensionOutcome};
    /// assert_eq!(
    ///     ExtensionOutcome::allowed(1).decision(),
    ///     ExtensionDecision::Allow
    /// );
    /// ```
    #[must_use]
    pub const fn decision(&self) -> ExtensionDecision {
        self.decision
    }

    /// Returns the fail-closed execution failure, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::ExtensionOutcome;
    /// assert!(ExtensionOutcome::allowed(1).failure().is_none());
    /// ```
    #[must_use]
    pub const fn failure(&self) -> Option<&WasmError> {
        self.failure.as_ref()
    }

    /// Returns the extension generation used for this call.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::ExtensionOutcome;
    /// assert_eq!(ExtensionOutcome::allowed(7).generation(), 7);
    /// ```
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{ExtensionOutcome, Stability};
    /// assert_eq!(ExtensionOutcome::allowed(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Hot-reloadable Wasmtime component extension runtime.
pub struct WasmExtensionRuntime {
    active: ArcSwap<LoadedExtension>,
    limits: SandboxLimits,
}

impl WasmExtensionRuntime {
    /// Compiles a component from bytes and installs it as generation 1.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] when the extension name is invalid, the engine
    /// cannot be created, or the component cannot be compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(runtime.generation(), 1);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn from_component_bytes(name: &str, component: &[u8]) -> WasmResult<Self> {
        Self::from_component_bytes_with_limits(name, component, SandboxLimits::default())
    }

    /// Compiles a component from bytes with explicit sandbox limits.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] when the extension name is invalid, the engine
    /// cannot be created, or the component cannot be compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, SandboxLimits, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests_with_limits(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    ///     SandboxLimits::default(),
    /// )?;
    /// assert_eq!(runtime.generation(), 1);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn from_component_bytes_with_limits(
        name: &str,
        component: &[u8],
        limits: SandboxLimits,
    ) -> WasmResult<Self> {
        let loaded = LoadedExtension::compile(name, component, limits, 1)?;
        Ok(Self {
            active: ArcSwap::from_pointee(loaded),
            limits,
        })
    }

    /// Compiles a component from WAT text and installs it as generation 1.
    ///
    /// This constructor exists for tests and examples. Production callers should
    /// load prebuilt component bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] when the extension name is invalid, the engine
    /// cannot be created, or the component cannot be compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(runtime.generation(), 1);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn from_component_wat_for_tests(name: &str, component: &str) -> WasmResult<Self> {
        Self::from_component_wat_for_tests_with_limits(name, component, SandboxLimits::default())
    }

    /// Compiles a component from WAT text with explicit limits.
    ///
    /// This constructor exists for tests and examples. Production callers should
    /// load prebuilt component bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] when the extension name is invalid, the engine
    /// cannot be created, or the component cannot be compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, SandboxLimits, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests_with_limits(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    ///     SandboxLimits::default(),
    /// )?;
    /// assert_eq!(runtime.generation(), 1);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn from_component_wat_for_tests_with_limits(
        name: &str,
        component: &str,
        limits: SandboxLimits,
    ) -> WasmResult<Self> {
        Self::from_component_bytes_with_limits(name, component.as_bytes(), limits)
    }

    /// Hot-reloads the active extension component.
    ///
    /// Active calls retain their previous compiled component through `ArcSwap`;
    /// subsequent calls use the new generation.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] when the replacement extension name is invalid,
    /// the engine cannot be created, or the component cannot be compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// runtime.reload_component_wat_for_tests("deny-all", testing::DENY_ALL_COMPONENT)?;
    /// assert_eq!(runtime.generation(), 2);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn reload_component_bytes(&self, name: &str, component: &[u8]) -> WasmResult<u64> {
        let generation = self.active.load().generation.saturating_add(1);
        let loaded = LoadedExtension::compile(name, component, self.limits, generation)?;
        self.active.store(Arc::new(loaded));
        Ok(generation)
    }

    /// Hot-reloads the active extension from WAT text.
    ///
    /// This method exists for tests and examples. Production callers should
    /// reload prebuilt component bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] when the replacement extension name is invalid,
    /// the engine cannot be created, or the component cannot be compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(
    ///     runtime.reload_component_wat_for_tests("deny-all", testing::DENY_ALL_COMPONENT)?,
    ///     2,
    /// );
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    pub fn reload_component_wat_for_tests(&self, name: &str, component: &str) -> WasmResult<u64> {
        self.reload_component_bytes(name, component.as_bytes())
    }

    /// Runs the `on-auth` hook and fails closed on error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_wasm::{testing, AuthContext, ExtensionDecision, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// let outcome = runtime.on_auth(AuthContext::new(PeerId::from_raw(1), 2));
    /// assert_eq!(outcome.decision(), ExtensionDecision::Allow);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub fn on_auth(&self, context: AuthContext) -> ExtensionOutcome {
        let loaded = self.active.load_full();
        loaded.call_bool(
            "on-auth",
            (context.peer().raw(), context.token_hash()),
            loaded.generation,
        )
    }

    /// Runs the `on-room-create` hook and fails closed on error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_wasm::{testing, ExtensionDecision, RoomCreateContext, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// let outcome = runtime.on_room_create(RoomCreateContext::new(PeerId::from_raw(1), RoomId::from_raw(2)));
    /// assert_eq!(outcome.decision(), ExtensionDecision::Allow);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub fn on_room_create(&self, context: RoomCreateContext) -> ExtensionOutcome {
        let loaded = self.active.load_full();
        loaded.call_bool(
            "on-room-create",
            (context.peer().raw(), context.room().raw()),
            loaded.generation,
        )
    }

    /// Runs the `on-subscribe` hook and fails closed on error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, TrackId};
    /// # use refract_wasm::{testing, ExtensionDecision, SubscribeContext, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// let context = SubscribeContext::new(
    ///     PeerId::from_raw(1),
    ///     RoomId::from_raw(2),
    ///     TrackId::from_raw(3),
    ///     0,
    ///     0,
    /// );
    /// assert_eq!(
    ///     runtime.on_subscribe(context).decision(),
    ///     ExtensionDecision::Allow
    /// );
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub fn on_subscribe(&self, context: SubscribeContext) -> ExtensionOutcome {
        let loaded = self.active.load_full();
        loaded.call_bool(
            "on-subscribe",
            (
                context.peer().raw(),
                context.room().raw(),
                context.track().raw(),
                context.spatial_layer(),
                context.temporal_layer(),
            ),
            loaded.generation,
        )
    }

    /// Returns the currently active extension generation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(runtime.generation(), 1);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.active.load().generation
    }

    /// Returns the active extension name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{testing, WasmExtensionRuntime};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(runtime.name().as_ref(), "allow-all");
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Arc<str> {
        Arc::clone(&self.active.load().name)
    }

    /// Returns the configured sandbox limits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{DEFAULT_MEMORY_LIMIT_BYTES, SandboxLimits, WasmExtensionRuntime, testing};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(runtime.limits().memory_bytes(), DEFAULT_MEMORY_LIMIT_BYTES);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub const fn limits(&self) -> SandboxLimits {
        self.limits
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_wasm::{Stability, WasmExtensionRuntime, testing};
    /// let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
    ///     "allow-all",
    ///     testing::ALLOW_ALL_COMPONENT,
    /// )?;
    /// assert_eq!(runtime.stability(), Stability::Stage1);
    /// # Ok::<(), refract_wasm::WasmError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

struct LoadedExtension {
    name: Arc<str>,
    engine: Engine,
    component: Component,
    generation: u64,
    limits: SandboxLimits,
}

impl LoadedExtension {
    fn compile(
        name: &str,
        component_bytes: &[u8],
        limits: SandboxLimits,
        generation: u64,
    ) -> WasmResult<Self> {
        validate_extension_name(name)?;
        let engine = sandbox_engine()?;
        let component =
            Component::new(&engine, component_bytes).map_err(|source| WasmError::Compile {
                message: source.to_string(),
            })?;
        Ok(Self {
            name: Arc::from(name),
            engine,
            component,
            generation,
            limits,
        })
    }

    fn call_bool<Params>(
        &self,
        hook: &'static str,
        params: Params,
        generation: u64,
    ) -> ExtensionOutcome
    where
        Params: wasmtime::component::ComponentNamedList + wasmtime::component::Lower + Send,
    {
        let result = self.call_bool_inner(hook, params);
        match result {
            Ok(true) => ExtensionOutcome::allowed(generation),
            Ok(false) => ExtensionOutcome::denied(generation),
            Err(error) => ExtensionOutcome::failed(generation, error),
        }
    }

    fn call_bool_inner<Params>(&self, hook: &'static str, params: Params) -> WasmResult<bool>
    where
        Params: wasmtime::component::ComponentNamedList + wasmtime::component::Lower + Send,
    {
        let mut store = Store::new(
            &self.engine,
            StoreState {
                limits: store_limits(self.limits),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|source| WasmError::SandboxLimit {
                hook,
                message: source.to_string(),
            })?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();

        let linker = Linker::<StoreState>::new(&self.engine);
        let instance = self.with_watchdog(|| {
            linker
                .instantiate(&mut store, &self.component)
                .map_err(|source| WasmError::Instantiate {
                    message: source.to_string(),
                })
        })??;

        let function = instance
            .get_typed_func::<Params, (bool,)>(&mut store, hook)
            .map_err(|source| WasmError::HookExport {
                hook,
                message: source.to_string(),
            })?;

        let (allowed,) = self.with_watchdog(|| {
            function
                .call(&mut store, params)
                .map_err(|source| WasmError::SandboxLimit {
                    hook,
                    message: source.to_string(),
                })
        })??;
        function
            .post_return(&mut store)
            .map_err(|source| WasmError::SandboxLimit {
                hook,
                message: source.to_string(),
            })?;

        Ok(allowed)
    }

    fn with_watchdog<T>(&self, call: impl FnOnce() -> T) -> WasmResult<T> {
        let active = Arc::new(AtomicBool::new(true));
        let active_for_thread = Arc::clone(&active);
        let engine = self.engine.clone();
        let timeout = self.limits.call_timeout;
        thread::Builder::new()
            .name("refract-wasm-watchdog".to_owned())
            .spawn(move || {
                thread::sleep(timeout);
                if active_for_thread.swap(false, Ordering::AcqRel) {
                    engine.increment_epoch();
                }
            })
            .map_err(|source| WasmError::Watchdog {
                message: source.to_string(),
            })?;
        let result = call();
        active.store(false, Ordering::Release);
        Ok(result)
    }
}

#[derive(Debug)]
struct StoreState {
    limits: StoreLimits,
}

fn sandbox_engine() -> WasmResult<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    Engine::new(&config).map_err(|source| WasmError::Engine {
        message: source.to_string(),
    })
}

fn store_limits(limits: SandboxLimits) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(limits.memory_bytes)
        .memories(1)
        .tables(4)
        .table_elements(1024)
        .instances(1)
        .trap_on_grow_failure(true)
        .build()
}

fn validate_extension_name(name: &str) -> WasmResult<()> {
    if name.is_empty()
        || name.len() > MAX_EXTENSION_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WasmError::InvalidExtensionName);
    }
    Ok(())
}

impl fmt::Display for ExtensionDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => formatter.write_str("allow"),
            Self::Deny => formatter.write_str("deny"),
        }
    }
}

impl fmt::Debug for WasmExtensionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmExtensionRuntime")
            .field("name", &self.name())
            .field("generation", &self.generation())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LoadedExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedExtension")
            .field("name", &self.name)
            .field("generation", &self.generation)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

pub mod testing {
    //! Test-only component fixtures that model output from `wit-bindgen` exports.

    /// WIT contract compiled by guest extensions with `wit-bindgen`.
    pub const REFRACT_EXTENSION_WIT: &str = include_str!("../wit/refract-extension.wit");

    /// Rust guest skeleton showing the intended `wit-bindgen` export path.
    pub const WIT_BINDGEN_SAMPLE_RUST: &str = r#"
//! Sample Refract extension component.

wit_bindgen::generate!({
    world: "refract-extension",
    path: "wit",
});

struct Extension;

impl Guest for Extension {
    fn on_auth(_peer_id: u64, _token_hash: u64) -> bool {
        true
    }

    fn on_room_create(_peer_id: u64, _room_id: u64) -> bool {
        true
    }

    fn on_subscribe(
        _peer_id: u64,
        _room_id: u64,
        _track_id: u64,
        _spatial_layer: u8,
        _temporal_layer: u8,
    ) -> bool {
        true
    }
}

export!(Extension);
"#;

    /// Component WAT equivalent of an allow-all `wit-bindgen` extension.
    pub const ALLOW_ALL_COMPONENT: &str = r#"
(component
  (core module $core
    (func (export "on-auth") (param i64 i64) (result i32)
      i32.const 1)
    (func (export "on-room-create") (param i64 i64) (result i32)
      i32.const 1)
    (func (export "on-subscribe") (param i64 i64 i64 i32 i32) (result i32)
      i32.const 1)
  )
  (core instance $core-instance (instantiate $core))
  (func (export "on-auth") (param "peer-id" u64) (param "token-hash" u64) (result bool)
    (canon lift (core func $core-instance "on-auth")))
  (func (export "on-room-create") (param "peer-id" u64) (param "room-id" u64) (result bool)
    (canon lift (core func $core-instance "on-room-create")))
  (func (export "on-subscribe")
    (param "peer-id" u64)
    (param "room-id" u64)
    (param "track-id" u64)
    (param "spatial-layer" u8)
    (param "temporal-layer" u8)
    (result bool)
    (canon lift (core func $core-instance "on-subscribe")))
)
"#;

    /// Component WAT equivalent of a deny-all `wit-bindgen` extension.
    pub const DENY_ALL_COMPONENT: &str = r#"
(component
  (core module $core
    (func (export "on-auth") (param i64 i64) (result i32)
      i32.const 0)
    (func (export "on-room-create") (param i64 i64) (result i32)
      i32.const 0)
    (func (export "on-subscribe") (param i64 i64 i64 i32 i32) (result i32)
      i32.const 0)
  )
  (core instance $core-instance (instantiate $core))
  (func (export "on-auth") (param "peer-id" u64) (param "token-hash" u64) (result bool)
    (canon lift (core func $core-instance "on-auth")))
  (func (export "on-room-create") (param "peer-id" u64) (param "room-id" u64) (result bool)
    (canon lift (core func $core-instance "on-room-create")))
  (func (export "on-subscribe")
    (param "peer-id" u64)
    (param "room-id" u64)
    (param "track-id" u64)
    (param "spatial-layer" u8)
    (param "temporal-layer" u8)
    (result bool)
    (canon lift (core func $core-instance "on-subscribe")))
)
"#;

    /// Component WAT that loops until fuel or the epoch watchdog rejects it.
    pub const SPIN_COMPONENT: &str = r#"
(component
  (core module $core
    (func $spin (loop br 0))
    (func (export "on-auth") (param i64 i64) (result i32)
      call $spin
      i32.const 1)
    (func (export "on-room-create") (param i64 i64) (result i32)
      i32.const 1)
    (func (export "on-subscribe") (param i64 i64 i64 i32 i32) (result i32)
      i32.const 1)
  )
  (core instance $core-instance (instantiate $core))
  (func (export "on-auth") (param "peer-id" u64) (param "token-hash" u64) (result bool)
    (canon lift (core func $core-instance "on-auth")))
  (func (export "on-room-create") (param "peer-id" u64) (param "room-id" u64) (result bool)
    (canon lift (core func $core-instance "on-room-create")))
  (func (export "on-subscribe")
    (param "peer-id" u64)
    (param "room-id" u64)
    (param "track-id" u64)
    (param "spatial-layer" u8)
    (param "temporal-layer" u8)
    (result bool)
    (canon lift (core func $core-instance "on-subscribe")))
)
"#;

    /// Component WAT that requests more than the default 16 MiB linear memory.
    pub const OVERSIZED_MEMORY_COMPONENT: &str = r#"
(component
  (core module $core
    (memory 257)
    (func (export "on-auth") (param i64 i64) (result i32)
      i32.const 1)
    (func (export "on-room-create") (param i64 i64) (result i32)
      i32.const 1)
    (func (export "on-subscribe") (param i64 i64 i64 i32 i32) (result i32)
      i32.const 1)
  )
  (core instance $core-instance (instantiate $core))
  (func (export "on-auth") (param "peer-id" u64) (param "token-hash" u64) (result bool)
    (canon lift (core func $core-instance "on-auth")))
  (func (export "on-room-create") (param "peer-id" u64) (param "room-id" u64) (result bool)
    (canon lift (core func $core-instance "on-room-create")))
  (func (export "on-subscribe")
    (param "peer-id" u64)
    (param "room-id" u64)
    (param "track-id" u64)
    (param "spatial-layer" u8)
    (param "temporal-layer" u8)
    (result bool)
    (canon lift (core func $core-instance "on-subscribe")))
)
"#;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_extension_via_wit_bindgen_contract_allows_hooks() {
        assert!(testing::WIT_BINDGEN_SAMPLE_RUST.contains("wit_bindgen::generate!"));
        assert!(testing::REFRACT_EXTENSION_WIT.contains("on-auth"));
        let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
            "allow-all",
            testing::ALLOW_ALL_COMPONENT,
        )
        .expect("runtime");

        let auth = runtime.on_auth(AuthContext::new(PeerId::from_raw(1), 2));
        let room = runtime.on_room_create(RoomCreateContext::new(
            PeerId::from_raw(1),
            RoomId::from_raw(3),
        ));
        let subscribe = runtime.on_subscribe(SubscribeContext::new(
            PeerId::from_raw(1),
            RoomId::from_raw(3),
            TrackId::from_raw(4),
            0,
            0,
        ));

        assert_eq!(auth.decision(), ExtensionDecision::Allow);
        assert_eq!(room.decision(), ExtensionDecision::Allow);
        assert_eq!(subscribe.decision(), ExtensionDecision::Allow);
    }

    #[test]
    fn resource_limit_violations_are_rejected() {
        let limits = SandboxLimits::new(100, DEFAULT_MEMORY_LIMIT_BYTES, DEFAULT_CALL_TIMEOUT)
            .expect("limits");
        let runtime = WasmExtensionRuntime::from_component_wat_for_tests_with_limits(
            "spin",
            testing::SPIN_COMPONENT,
            limits,
        )
        .expect("runtime");

        let outcome = runtime.on_auth(AuthContext::new(PeerId::from_raw(1), 2));

        assert_eq!(outcome.decision(), ExtensionDecision::Deny);
        assert_eq!(
            outcome.failure().map(WasmError::error_code),
            Some("HSF-WASM-SANDBOX"),
        );
    }

    #[test]
    fn memory_limit_violations_are_rejected() {
        let runtime = WasmExtensionRuntime::from_component_wat_for_tests(
            "oversized-memory",
            testing::OVERSIZED_MEMORY_COMPONENT,
        )
        .expect("runtime");

        let outcome = runtime.on_auth(AuthContext::new(PeerId::from_raw(1), 2));

        assert_eq!(outcome.decision(), ExtensionDecision::Deny);
        assert_eq!(
            outcome.failure().map(WasmError::error_code),
            Some("HSF-WASM-INSTANTIATE"),
        );
    }

    #[test]
    fn hot_reload_during_active_calls_is_generation_safe() {
        let runtime = Arc::new(
            WasmExtensionRuntime::from_component_wat_for_tests(
                "allow-all",
                testing::ALLOW_ALL_COMPONENT,
            )
            .expect("runtime"),
        );
        let active = Arc::clone(&runtime);
        let handle =
            thread::spawn(move || active.on_auth(AuthContext::new(PeerId::from_raw(1), 2)));

        let generation = runtime
            .reload_component_wat_for_tests("deny-all", testing::DENY_ALL_COMPONENT)
            .expect("reload");
        let after_reload = runtime.on_auth(AuthContext::new(PeerId::from_raw(1), 2));
        let active_call = handle.join().expect("active call");

        assert_eq!(generation, 2);
        assert_eq!(active_call.generation(), 1);
        assert_eq!(active_call.decision(), ExtensionDecision::Allow);
        assert_eq!(after_reload.generation(), 2);
        assert_eq!(after_reload.decision(), ExtensionDecision::Deny);
    }
}
