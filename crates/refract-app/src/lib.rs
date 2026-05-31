//! Application trait boundary for room policy and subscription decisions.
//!
//! `refract-app` is the slow-path contract between signaling policy and the
//! per-core `SFU` forwarding engine. Applications implement [`Application`] and
//! [`Session`] with return-position `impl Future`; the runtime stores them
//! through explicit erased wrappers because app dispatch is not on the media hot
//! path.
//!
//! # Examples
//!
//! ```
//! # use refract_app::{
//! #     AppRegistry, Application, ApiVersion, ClientMessage, Session, SessionContext,
//! #     SessionHandle,
//! # };
//! # use refract_core::{PeerId, RoomId, SessionId};
//! # #[derive(Debug)]
//! # struct EchoApp;
//! # #[derive(Debug)]
//! # struct EchoSession;
//! # impl Application for EchoApp {
//! #     type Session = EchoSession;
//! #     fn name(&self) -> &'static str { "echo" }
//! #     fn api_version(&self) -> ApiVersion { ApiVersion::new(1) }
//! #     async fn create_session(
//! #         &self,
//! #         _context: SessionContext,
//! #     ) -> refract_app::AppResult<Self::Session> { Ok(EchoSession) }
//! # }
//! # impl Session for EchoSession {
//! #     async fn handle_message(
//! #         &mut self,
//! #         message: ClientMessage,
//! #         handle: &mut SessionHandle,
//! #     ) -> refract_app::AppResult<()> { handle.send(message) }
//! # }
//! let mut registry = AppRegistry::new();
//! registry.register(EchoApp)?;
//! assert!(registry.contains("echo"));
//! # let _context = SessionContext::new(
//! #     SessionId::from_raw(1),
//! #     PeerId::from_raw(2),
//! #     RoomId::from_raw(3),
//! # );
//! # Ok::<(), refract_app::AppError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use refract_core::{PeerId, RoomId, SessionId};
use refract_router::{IngressSsrc, Layer, PublisherTrackId, SubscriberSessionId, Subscription};
use rtrb::{Consumer, Producer, PushError, RingBuffer};
use thiserror::Error;

/// Result alias for application slow-path operations.
pub type AppResult<T> = Result<T, AppError>;

/// Boxed future used only by the slow-path erased application factory.
///
/// # Examples
///
/// ```ignore
/// let future: refract_app::ErasedSessionFactoryFuture<'_> =
///     app.create_erased_session(context);
/// ```
pub type ErasedSessionFactoryFuture<'a> =
    Pin<Box<dyn Future<Output = AppResult<Box<dyn ErasedSession>>> + 'a>>;

/// Boxed future used only by slow-path erased session dispatch.
///
/// # Examples
///
/// ```ignore
/// let future: refract_app::ErasedOperationFuture<'_> =
///     session.handle_message_erased(message, handle);
/// ```
pub type ErasedOperationFuture<'a> = Pin<Box<dyn Future<Output = AppResult<()>> + 'a>>;

/// Maximum application name bytes accepted by the registry.
pub const MAX_APPLICATION_NAME_BYTES: usize = 64;

/// Maximum client control message bytes accepted by this boundary.
pub const MAX_CLIENT_MESSAGE_BYTES: usize = 16 * 1024;

/// Maximum SDP or negotiation text bytes accepted by this boundary.
pub const MAX_NEGOTIATION_TEXT_BYTES: usize = 64 * 1024;

/// Maximum members included in one room snapshot.
pub const MAX_ROOM_MEMBERS: usize = 4096;

/// Target p99 latency for slow-path application operations.
pub const SLOW_PATH_P99_TARGET: Duration = Duration::from_millis(5);

/// Latency threshold that emits a structured `slow-path` warning.
pub const SLOW_PATH_WARN_THRESHOLD: Duration = Duration::from_millis(50);

/// Default deterministic timeout for one application operation.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_millis(100);

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
    /// # use refract_app::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Application API version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApiVersion(u16);

impl ApiVersion {
    /// Creates an application API version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::ApiVersion;
    /// assert_eq!(ApiVersion::new(1).as_u16(), 1);
    /// ```
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw API version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::ApiVersion;
    /// assert_eq!(ApiVersion::new(7).as_u16(), 7);
    /// ```
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{ApiVersion, Stability};
    /// assert_eq!(ApiVersion::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}", self.0)
    }
}

/// Error taxonomy for application slow-path operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    /// Application name is empty, too long, or contains an unsupported byte.
    #[error("invalid application name")]
    InvalidApplicationName,
    /// An application with this name already exists.
    #[error("duplicate application: {name}")]
    DuplicateApplication {
        /// Duplicate application name.
        name: &'static str,
    },
    /// No registered application matched the requested name.
    #[error("unknown application: {name}")]
    UnknownApplication {
        /// Requested application name.
        name: String,
    },
    /// A client message exceeded the bounded control-plane limit.
    #[error("client message too large: {len} > {max}")]
    MessageTooLarge {
        /// Observed message length.
        len: usize,
        /// Configured maximum length.
        max: usize,
    },
    /// Negotiation text exceeded the bounded control-plane limit.
    #[error("negotiation text too large: {len} > {max}")]
    NegotiationTooLarge {
        /// Observed text length.
        len: usize,
        /// Configured maximum length.
        max: usize,
    },
    /// Room snapshot exceeded its bounded member limit.
    #[error("room snapshot too large: {len} > {max}")]
    RoomTooLarge {
        /// Observed member count.
        len: usize,
        /// Configured maximum member count.
        max: usize,
    },
    /// Queue capacity was zero.
    #[error("invalid queue capacity: {field}")]
    InvalidQueueCapacity {
        /// Invalid queue capacity field.
        field: &'static str,
    },
    /// Bounded allocation failed while copying validated slow-path input.
    #[error("allocation failed in {component}")]
    Allocation {
        /// Component that failed to reserve memory.
        component: &'static str,
    },
    /// Client egress queue is full.
    #[error("client outbox full")]
    ClientOutboxFull,
    /// `SFU` core command queue is full.
    #[error("sfu core inbox full")]
    CoreInboxFull,
    /// A session operation exceeded its deterministic timeout.
    #[error("slow-path operation timed out")]
    SlowPathTimeout {
        /// Timed-out operation.
        operation: SessionOperation,
        /// Timeout applied to the operation.
        timeout: Duration,
    },
    /// Router subscription construction failed.
    #[error("router operation failed: {0}")]
    Router(#[from] refract_router::RouterError),
}

impl AppError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::AppError;
    /// assert_eq!(AppError::ClientOutboxFull.error_code(), "APP_QUEUE_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidApplicationName => "APP_REGISTRY_0001",
            Self::DuplicateApplication { .. } => "APP_REGISTRY_0002",
            Self::UnknownApplication { .. } => "APP_REGISTRY_0003",
            Self::MessageTooLarge { .. } => "APP_INPUT_0001",
            Self::NegotiationTooLarge { .. } => "APP_INPUT_0002",
            Self::RoomTooLarge { .. } => "APP_ROOM_0001",
            Self::InvalidQueueCapacity { .. } => "APP_QUEUE_0003",
            Self::Allocation { .. } => "APP_ALLOC_0001",
            Self::ClientOutboxFull => "APP_QUEUE_0001",
            Self::CoreInboxFull => "APP_QUEUE_0002",
            Self::SlowPathTimeout { .. } => "APP_LATENCY_0001",
            Self::Router(_) => "APP_ROUTER_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{AppError, Stability};
    /// assert_eq!(AppError::ClientOutboxFull.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Session operation labels used by metrics, logs, and timeout errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionOperation {
    /// Client message handling.
    HandleMessage,
    /// SDP or transport negotiation handling.
    Negotiation,
    /// Publisher track admission handling.
    Publish,
    /// Subscriber route admission handling.
    Subscribe,
    /// Subscriber route removal handling.
    Unsubscribe,
    /// Session disconnect handling.
    Disconnect,
}

impl SessionOperation {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SessionOperation;
    /// assert_eq!(SessionOperation::HandleMessage.as_str(), "handle_message");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HandleMessage => "handle_message",
            Self::Negotiation => "negotiation",
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
            Self::Unsubscribe => "unsubscribe",
            Self::Disconnect => "disconnect",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{SessionOperation, Stability};
    /// assert_eq!(SessionOperation::Disconnect.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for SessionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Latency sample for one completed slow-path operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlowPathSample {
    operation: SessionOperation,
    elapsed: Duration,
}

impl SlowPathSample {
    /// Creates a latency sample.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_app::{SessionOperation, SlowPathSample};
    /// let sample = SlowPathSample::new(SessionOperation::HandleMessage, Duration::ZERO);
    /// assert_eq!(sample.operation(), SessionOperation::HandleMessage);
    /// ```
    #[must_use]
    pub const fn new(operation: SessionOperation, elapsed: Duration) -> Self {
        Self { operation, elapsed }
    }

    /// Returns the sampled operation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_app::{SessionOperation, SlowPathSample};
    /// assert_eq!(
    ///     SlowPathSample::new(SessionOperation::Disconnect, Duration::ZERO).operation(),
    ///     SessionOperation::Disconnect,
    /// );
    /// ```
    #[must_use]
    pub const fn operation(self) -> SessionOperation {
        self.operation
    }

    /// Returns elapsed wall time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_app::{SessionOperation, SlowPathSample};
    /// assert_eq!(
    ///     SlowPathSample::new(SessionOperation::HandleMessage, Duration::from_millis(1)).elapsed(),
    ///     Duration::from_millis(1),
    /// );
    /// ```
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    /// Returns whether this sample should emit a slow-path warning.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_app::{SessionOperation, SlowPathSample};
    /// assert!(
    ///     SlowPathSample::new(SessionOperation::Publish, Duration::from_millis(51))
    ///         .is_warn_threshold_exceeded()
    /// );
    /// ```
    #[must_use]
    pub const fn is_warn_threshold_exceeded(self) -> bool {
        self.elapsed.as_nanos() > SLOW_PATH_WARN_THRESHOLD.as_nanos()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_app::{SessionOperation, SlowPathSample, Stability};
    /// assert_eq!(
    ///     SlowPathSample::new(SessionOperation::Publish, Duration::ZERO).stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Bounded client control message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientMessage {
    bytes: Box<[u8]>,
}

impl ClientMessage {
    /// Copies a client control message after validating its byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::MessageTooLarge`] when `bytes` exceeds
    /// [`MAX_CLIENT_MESSAGE_BYTES`], or [`AppError::Allocation`] when bounded
    /// reservation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::ClientMessage;
    /// let message = ClientMessage::try_from_bytes(b"ping")?;
    /// assert_eq!(message.as_bytes(), b"ping");
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn try_from_bytes(bytes: &[u8]) -> AppResult<Self> {
        if bytes.len() > MAX_CLIENT_MESSAGE_BYTES {
            return Err(AppError::MessageTooLarge {
                len: bytes.len(),
                max: MAX_CLIENT_MESSAGE_BYTES,
            });
        }
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(bytes.len())
            .map_err(|_source| AppError::Allocation {
                component: "client_message",
            })?;
        copied.extend_from_slice(bytes);
        Ok(Self {
            bytes: copied.into_boxed_slice(),
        })
    }

    /// Returns the validated message bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::ClientMessage;
    /// let message = ClientMessage::try_from_bytes(b"pong")?;
    /// assert_eq!(message.as_bytes(), b"pong");
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the message byte length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::ClientMessage;
    /// assert_eq!(ClientMessage::try_from_bytes(b"x")?.len(), 1);
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the message is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::ClientMessage;
    /// assert!(ClientMessage::try_from_bytes(b"")?.is_empty());
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{ClientMessage, Stability};
    /// assert_eq!(
    ///     ClientMessage::try_from_bytes(b"x")?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Negotiation event carrying bounded SDP or transport text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationEvent {
    text: Box<str>,
}

impl NegotiationEvent {
    /// Copies negotiation text after validating its byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NegotiationTooLarge`] when `text` exceeds
    /// [`MAX_NEGOTIATION_TEXT_BYTES`], or [`AppError::Allocation`] when bounded
    /// reservation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::NegotiationEvent;
    /// let event = NegotiationEvent::try_from_text("v=0")?;
    /// assert_eq!(event.as_str(), "v=0");
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn try_from_text(text: &str) -> AppResult<Self> {
        if text.len() > MAX_NEGOTIATION_TEXT_BYTES {
            return Err(AppError::NegotiationTooLarge {
                len: text.len(),
                max: MAX_NEGOTIATION_TEXT_BYTES,
            });
        }
        let mut copied = String::new();
        copied
            .try_reserve_exact(text.len())
            .map_err(|_source| AppError::Allocation {
                component: "negotiation",
            })?;
        copied.push_str(text);
        Ok(Self {
            text: copied.into_boxed_str(),
        })
    }

    /// Returns the negotiation text.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::NegotiationEvent;
    /// assert_eq!(
    ///     NegotiationEvent::try_from_text("answer")?.as_str(),
    ///     "answer"
    /// );
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{NegotiationEvent, Stability};
    /// assert_eq!(
    ///     NegotiationEvent::try_from_text("x")?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Publisher track event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishEvent {
    publisher_track: PublisherTrackId,
    ingress_ssrc: IngressSsrc,
}

impl PublishEvent {
    /// Creates a publisher event.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::PublishEvent;
    /// # use refract_router::{IngressSsrc, PublisherTrackId};
    /// let event = PublishEvent::new(PublisherTrackId::new(1), IngressSsrc::new(42));
    /// assert_eq!(event.ingress_ssrc(), IngressSsrc::new(42));
    /// ```
    #[must_use]
    pub const fn new(publisher_track: PublisherTrackId, ingress_ssrc: IngressSsrc) -> Self {
        Self {
            publisher_track,
            ingress_ssrc,
        }
    }

    /// Returns the publisher track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::PublishEvent;
    /// # use refract_router::{IngressSsrc, PublisherTrackId};
    /// assert_eq!(
    ///     PublishEvent::new(PublisherTrackId::new(1), IngressSsrc::new(2)).publisher_track(),
    ///     PublisherTrackId::new(1),
    /// );
    /// ```
    #[must_use]
    pub const fn publisher_track(&self) -> PublisherTrackId {
        self.publisher_track
    }

    /// Returns the ingress SSRC for this publisher.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::PublishEvent;
    /// # use refract_router::{IngressSsrc, PublisherTrackId};
    /// assert_eq!(
    ///     PublishEvent::new(PublisherTrackId::new(1), IngressSsrc::new(2)).ingress_ssrc(),
    ///     IngressSsrc::new(2),
    /// );
    /// ```
    #[must_use]
    pub const fn ingress_ssrc(&self) -> IngressSsrc {
        self.ingress_ssrc
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{PublishEvent, Stability};
    /// # use refract_router::{IngressSsrc, PublisherTrackId};
    /// assert_eq!(
    ///     PublishEvent::new(PublisherTrackId::new(1), IngressSsrc::new(2)).stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Subscriber route admission event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeEvent {
    publisher_track: PublisherTrackId,
    ingress_ssrc: IngressSsrc,
    layers: Box<[Layer]>,
}

impl SubscribeEvent {
    /// Creates a bounded subscriber route event.
    ///
    /// # Errors
    ///
    /// Returns router validation errors when the resulting subscription would
    /// have an empty, oversized, or duplicate-bandwidth layer set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SubscribeEvent;
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// # };
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// let event = SubscribeEvent::new(PublisherTrackId::new(1), IngressSsrc::new(2), &[layer])?;
    /// assert_eq!(event.layers().len(), 1);
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn new(
        publisher_track: PublisherTrackId,
        ingress_ssrc: IngressSsrc,
        layers: &[Layer],
    ) -> AppResult<Self> {
        let _validated = Subscription::new(
            publisher_track,
            SubscriberSessionId::new(0),
            ingress_ssrc,
            layers.to_vec(),
        )?;
        Ok(Self {
            publisher_track,
            ingress_ssrc,
            layers: layers.to_vec().into_boxed_slice(),
        })
    }

    /// Builds the concrete router subscription for `subscriber`.
    ///
    /// # Errors
    ///
    /// Returns router validation errors when the layer set is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SubscribeEvent;
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId,
    /// # };
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// let event = SubscribeEvent::new(PublisherTrackId::new(1), IngressSsrc::new(2), &[layer])?;
    /// assert_eq!(
    ///     event
    ///         .to_subscription(SubscriberSessionId::new(9))?
    ///         .subscriber_session(),
    ///     SubscriberSessionId::new(9),
    /// );
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn to_subscription(&self, subscriber: SubscriberSessionId) -> AppResult<Subscription> {
        Ok(Subscription::new(
            self.publisher_track,
            subscriber,
            self.ingress_ssrc,
            self.layers.to_vec(),
        )?)
    }

    /// Returns the publisher track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SubscribeEvent;
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// # };
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// let event = SubscribeEvent::new(PublisherTrackId::new(3), IngressSsrc::new(4), &[layer])?;
    /// assert_eq!(event.publisher_track(), PublisherTrackId::new(3));
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn publisher_track(&self) -> PublisherTrackId {
        self.publisher_track
    }

    /// Returns the ingress SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SubscribeEvent;
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// # };
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// let event = SubscribeEvent::new(PublisherTrackId::new(3), IngressSsrc::new(4), &[layer])?;
    /// assert_eq!(event.ingress_ssrc(), IngressSsrc::new(4));
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn ingress_ssrc(&self) -> IngressSsrc {
        self.ingress_ssrc
    }

    /// Returns the requested routable layers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SubscribeEvent;
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// # };
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// let event = SubscribeEvent::new(PublisherTrackId::new(3), IngressSsrc::new(4), &[layer])?;
    /// assert_eq!(event.layers(), &[layer]);
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{Stability, SubscribeEvent};
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// # };
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// assert_eq!(
    ///     SubscribeEvent::new(PublisherTrackId::new(3), IngressSsrc::new(4), &[layer])?.stability(),
    ///     Stability::Stage1,
    /// );
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Subscriber route removal event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsubscribeEvent {
    publisher_track: PublisherTrackId,
}

impl UnsubscribeEvent {
    /// Creates a subscriber route removal event.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::UnsubscribeEvent;
    /// # use refract_router::PublisherTrackId;
    /// assert_eq!(
    ///     UnsubscribeEvent::new(PublisherTrackId::new(1)).publisher_track(),
    ///     PublisherTrackId::new(1),
    /// );
    /// ```
    #[must_use]
    pub const fn new(publisher_track: PublisherTrackId) -> Self {
        Self { publisher_track }
    }

    /// Returns the publisher track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::UnsubscribeEvent;
    /// # use refract_router::PublisherTrackId;
    /// assert_eq!(
    ///     UnsubscribeEvent::new(PublisherTrackId::new(9)).publisher_track(),
    ///     PublisherTrackId::new(9),
    /// );
    /// ```
    #[must_use]
    pub const fn publisher_track(self) -> PublisherTrackId {
        self.publisher_track
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{Stability, UnsubscribeEvent};
    /// # use refract_router::PublisherTrackId;
    /// assert_eq!(
    ///     UnsubscribeEvent::new(PublisherTrackId::new(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Disconnect reason provided to application sessions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DisconnectReason {
    /// Client closed the signaling session cleanly.
    ClientClosed,
    /// Transport timed out.
    Timeout,
    /// Operator or load-shedder drained the session.
    Drained,
    /// Protocol violation forced the session down.
    ProtocolError,
}

impl DisconnectReason {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::DisconnectReason;
    /// assert_eq!(DisconnectReason::Drained.as_str(), "drained");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::Timeout => "timeout",
            Self::Drained => "drained",
            Self::ProtocolError => "protocol_error",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{DisconnectReason, Stability};
    /// assert_eq!(DisconnectReason::Timeout.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Immutable session creation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionContext {
    session: SessionId,
    peer: PeerId,
    room: RoomId,
}

impl SessionContext {
    /// Creates a session context.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SessionContext;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// assert_eq!(context.room_id(), RoomId::from_raw(3));
    /// ```
    #[must_use]
    pub const fn new(session_id: SessionId, peer_id: PeerId, room_id: RoomId) -> Self {
        Self {
            session: session_id,
            peer: peer_id,
            room: room_id,
        }
    }

    /// Returns the session identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SessionContext;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// assert_eq!(context.session_id(), SessionId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session
    }

    /// Returns the peer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SessionContext;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// assert_eq!(context.peer_id(), PeerId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn peer_id(self) -> PeerId {
        self.peer
    }

    /// Returns the room identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SessionContext;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// assert_eq!(context.room_id(), RoomId::from_raw(3));
    /// ```
    #[must_use]
    pub const fn room_id(self) -> RoomId {
        self.room
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{SessionContext, Stability};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// assert_eq!(context.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Member entry returned by bounded room queries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoomMember {
    session: SessionId,
    peer: PeerId,
}

impl RoomMember {
    /// Creates a room member entry.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::RoomMember;
    /// # use refract_core::{PeerId, SessionId};
    /// let member = RoomMember::new(SessionId::from_raw(1), PeerId::from_raw(2));
    /// assert_eq!(member.peer_id(), PeerId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn new(session_id: SessionId, peer_id: PeerId) -> Self {
        Self {
            session: session_id,
            peer: peer_id,
        }
    }

    /// Returns the member session identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::RoomMember;
    /// # use refract_core::{PeerId, SessionId};
    /// assert_eq!(
    ///     RoomMember::new(SessionId::from_raw(1), PeerId::from_raw(2)).session_id(),
    ///     SessionId::from_raw(1),
    /// );
    /// ```
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session
    }

    /// Returns the member peer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::RoomMember;
    /// # use refract_core::{PeerId, SessionId};
    /// assert_eq!(
    ///     RoomMember::new(SessionId::from_raw(1), PeerId::from_raw(2)).peer_id(),
    ///     PeerId::from_raw(2),
    /// );
    /// ```
    #[must_use]
    pub const fn peer_id(self) -> PeerId {
        self.peer
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomMember, Stability};
    /// # use refract_core::{PeerId, SessionId};
    /// assert_eq!(
    ///     RoomMember::new(SessionId::from_raw(1), PeerId::from_raw(2)).stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Bounded room snapshot visible to one application session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomView {
    room_id: RoomId,
    members: Box<[RoomMember]>,
}

impl RoomView {
    /// Copies a bounded room snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::RoomTooLarge`] when `members` exceeds
    /// [`MAX_ROOM_MEMBERS`], or [`AppError::Allocation`] when bounded
    /// reservation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomMember, RoomView};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let member = RoomMember::new(SessionId::from_raw(1), PeerId::from_raw(2));
    /// let view = RoomView::from_members(RoomId::from_raw(9), &[member])?;
    /// assert_eq!(view.members(), &[member]);
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn from_members(room_id: RoomId, members: &[RoomMember]) -> AppResult<Self> {
        if members.len() > MAX_ROOM_MEMBERS {
            return Err(AppError::RoomTooLarge {
                len: members.len(),
                max: MAX_ROOM_MEMBERS,
            });
        }
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(members.len())
            .map_err(|_source| AppError::Allocation {
                component: "room_view",
            })?;
        copied.extend_from_slice(members);
        Ok(Self {
            room_id,
            members: copied.into_boxed_slice(),
        })
    }

    /// Creates an empty room snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::RoomView;
    /// # use refract_core::RoomId;
    /// assert!(RoomView::empty(RoomId::from_raw(1)).members().is_empty());
    /// ```
    #[must_use]
    pub fn empty(room_id: RoomId) -> Self {
        Self {
            room_id,
            members: Box::from([]),
        }
    }

    /// Returns the room identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::RoomView;
    /// # use refract_core::RoomId;
    /// assert_eq!(
    ///     RoomView::empty(RoomId::from_raw(1)).room_id(),
    ///     RoomId::from_raw(1)
    /// );
    /// ```
    #[must_use]
    pub const fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Returns room members in this bounded snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::RoomView;
    /// # use refract_core::RoomId;
    /// assert_eq!(RoomView::empty(RoomId::from_raw(1)).members().len(), 0);
    /// ```
    #[must_use]
    pub const fn members(&self) -> &[RoomMember] {
        &self.members
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, Stability};
    /// # use refract_core::RoomId;
    /// assert_eq!(
    ///     RoomView::empty(RoomId::from_raw(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Command posted from application slow path to one `SFU` core inbox.
#[derive(Debug, Eq, PartialEq)]
pub enum SfuCoreCommand {
    /// Add or refresh a forwarding route.
    AddSubscription(Subscription),
    /// Remove a forwarding route for one subscriber.
    RemoveSubscription {
        /// Publisher track being removed.
        publisher_track: PublisherTrackId,
        /// Subscriber session whose route is removed.
        subscriber_session: SubscriberSessionId,
    },
}

impl SfuCoreCommand {
    /// Returns the bounded command label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::SfuCoreCommand;
    /// # use refract_router::{PublisherTrackId, SubscriberSessionId};
    /// let command = SfuCoreCommand::RemoveSubscription {
    ///     publisher_track: PublisherTrackId::new(1),
    ///     subscriber_session: SubscriberSessionId::new(2),
    /// };
    /// assert_eq!(command.as_str(), "remove_subscription");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AddSubscription(_) => "add_subscription",
            Self::RemoveSubscription { .. } => "remove_subscription",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{SfuCoreCommand, Stability};
    /// # use refract_router::{PublisherTrackId, SubscriberSessionId};
    /// let command = SfuCoreCommand::RemoveSubscription {
    ///     publisher_track: PublisherTrackId::new(1),
    ///     subscriber_session: SubscriberSessionId::new(2),
    /// };
    /// assert_eq!(command.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Queue consumers paired with a [`SessionHandle`] for tests or core owners.
#[derive(Debug)]
pub struct SessionIo {
    /// Client egress messages emitted by the application.
    pub client_outbox: Consumer<ClientMessage>,
    /// `SFU` core commands emitted by the application.
    pub core_inbox: Consumer<SfuCoreCommand>,
}

impl SessionIo {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(io.stability(), refract_app::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Session handle used by application code to send client messages, query room
/// state, and post route changes to the `SFU` core inbox.
#[derive(Debug)]
pub struct SessionHandle {
    context: SessionContext,
    room: RoomView,
    client_outbox: Producer<ClientMessage>,
    core_inbox: Producer<SfuCoreCommand>,
}

impl SessionHandle {
    /// Creates a handle and paired consumers backed by bounded `rtrb` rings.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidApplicationName`] when either capacity is
    /// zero. The concrete error preserves the no-extra-dependency Stage 1
    /// taxonomy while rejecting unusable rings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, SessionContext, SessionHandle};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// let (_handle, _io) = SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 8, 8)?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn new(
        context: SessionContext,
        room: RoomView,
        client_capacity: usize,
        core_capacity: usize,
    ) -> AppResult<(Self, SessionIo)> {
        if client_capacity == 0 {
            return Err(AppError::InvalidQueueCapacity {
                field: "client_capacity",
            });
        }
        if core_capacity == 0 {
            return Err(AppError::InvalidQueueCapacity {
                field: "core_capacity",
            });
        }
        let (client_outbox, client_consumer) = RingBuffer::new(client_capacity);
        let (core_inbox, core_consumer) = RingBuffer::new(core_capacity);
        Ok((
            Self {
                context,
                room,
                client_outbox,
                core_inbox,
            },
            SessionIo {
                client_outbox: client_consumer,
                core_inbox: core_consumer,
            },
        ))
    }

    /// Sends a message to the client outbox.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::ClientOutboxFull`] when the bounded client ring is
    /// full.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{ClientMessage, RoomView, SessionContext, SessionHandle};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(SessionId::from_raw(1), PeerId::from_raw(2), RoomId::from_raw(3));
    /// let (mut handle, mut io) = SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 1, 1)?;
    /// handle.send(ClientMessage::try_from_bytes(b"hello")?)?;
    /// assert!(matches!(io.client_outbox.pop(), Ok(message) if message.as_bytes() == b"hello"));
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn send(&mut self, message: ClientMessage) -> AppResult<()> {
        self.client_outbox
            .push(message)
            .map_err(|PushError::Full(_message)| AppError::ClientOutboxFull)
    }

    /// Adds a route by posting to the `SFU` core inbox.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::CoreInboxFull`] when the bounded core command ring is
    /// full.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, SessionContext, SessionHandle, SfuCoreCommand};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId, Subscription,
    /// # };
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(9),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// let (mut handle, mut io) =
    ///     SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 1, 1)?;
    /// let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// let sub = Subscription::new(
    ///     PublisherTrackId::new(1),
    ///     SubscriberSessionId::new(9),
    ///     IngressSsrc::new(2),
    ///     vec![layer],
    /// )?;
    /// handle.add_route(sub)?;
    /// assert!(matches!(
    ///     io.core_inbox.pop(),
    ///     Ok(SfuCoreCommand::AddSubscription(_))
    /// ));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_route(&mut self, subscription: Subscription) -> AppResult<()> {
        self.core_inbox
            .push(SfuCoreCommand::AddSubscription(subscription))
            .map_err(|PushError::Full(_command)| AppError::CoreInboxFull)
    }

    /// Removes a route by posting to the `SFU` core inbox.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::CoreInboxFull`] when the bounded core command ring is
    /// full.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, SessionContext, SessionHandle, SfuCoreCommand};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_router::PublisherTrackId;
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(9),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// let (mut handle, mut io) =
    ///     SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 1, 1)?;
    /// handle.remove_route(PublisherTrackId::new(1))?;
    /// assert!(matches!(
    ///     io.core_inbox.pop(),
    ///     Ok(SfuCoreCommand::RemoveSubscription { .. })
    /// ));
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn remove_route(&mut self, publisher_track: PublisherTrackId) -> AppResult<()> {
        self.core_inbox
            .push(SfuCoreCommand::RemoveSubscription {
                publisher_track,
                subscriber_session: self.subscriber_id(),
            })
            .map_err(|PushError::Full(_command)| AppError::CoreInboxFull)
    }

    /// Returns the immutable room snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, SessionContext, SessionHandle};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// let (handle, _io) = SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 1, 1)?;
    /// assert_eq!(handle.room().room_id(), RoomId::from_raw(3));
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn room(&self) -> &RoomView {
        &self.room
    }

    /// Returns the session context.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, SessionContext, SessionHandle};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// let (handle, _io) = SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 1, 1)?;
    /// assert_eq!(handle.context(), context);
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn context(&self) -> SessionContext {
        self.context
    }

    /// Returns the router subscriber identifier for this session.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{RoomView, SessionContext, SessionHandle};
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_router::SubscriberSessionId;
    /// let context = SessionContext::new(
    ///     SessionId::from_raw(7),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    /// );
    /// let (handle, _io) = SessionHandle::new(context, RoomView::empty(RoomId::from_raw(3)), 1, 1)?;
    /// assert_eq!(handle.subscriber_id(), SubscriberSessionId::new(7));
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    #[must_use]
    pub const fn subscriber_id(&self) -> SubscriberSessionId {
        SubscriberSessionId::new(self.context.session_id().raw())
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(handle.stability(), refract_app::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Application factory trait using RPITIT.
pub trait Application: fmt::Debug {
    /// Concrete session type created by this application.
    type Session: Session + 'static;

    /// Returns the stable registry name.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(app.name(), "echo");
    /// ```
    #[must_use]
    fn name(&self) -> &'static str;

    /// Returns the supported app API version.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(app.api_version().as_u16(), 1);
    /// ```
    #[must_use]
    fn api_version(&self) -> ApiVersion;

    /// Creates one application session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when app-specific admission or initialization fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let session = app.create_session(context).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn create_session(
        &self,
        context: SessionContext,
    ) -> impl Future<Output = AppResult<Self::Session>>;
}

/// Application session trait using RPITIT.
pub trait Session: fmt::Debug {
    /// Handles one bounded client control message.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the message cannot be processed or emitted.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.handle_message(message, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> impl Future<Output = AppResult<()>>;

    /// Handles a negotiation update.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when negotiation policy rejects the update.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_negotiation(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_negotiation(
        &mut self,
        _event: NegotiationEvent,
        _handle: &mut SessionHandle,
    ) -> impl Future<Output = AppResult<()>> {
        async { Ok(()) }
    }

    /// Handles publisher track admission.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when publish policy rejects the track.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_publish(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_publish(
        &mut self,
        _event: PublishEvent,
        _handle: &mut SessionHandle,
    ) -> impl Future<Output = AppResult<()>> {
        async { Ok(()) }
    }

    /// Handles subscriber route admission.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when subscribe policy rejects the route or the core
    /// command inbox is full.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_subscribe(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_subscribe(
        &mut self,
        event: SubscribeEvent,
        handle: &mut SessionHandle,
    ) -> impl Future<Output = AppResult<()>> {
        async move { handle.add_route(event.to_subscription(handle.subscriber_id())?) }
    }

    /// Handles subscriber route removal.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the core command inbox is full.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_unsubscribe(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_unsubscribe(
        &mut self,
        event: UnsubscribeEvent,
        handle: &mut SessionHandle,
    ) -> impl Future<Output = AppResult<()>> {
        async move { handle.remove_route(event.publisher_track()) }
    }

    /// Handles session disconnect.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when cleanup fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_disconnect(reason, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_disconnect(
        &mut self,
        _reason: DisconnectReason,
        _handle: &mut SessionHandle,
    ) -> impl Future<Output = AppResult<()>> {
        async { Ok(()) }
    }
}

/// Type-erased application factory for registry storage.
pub trait ErasedApplication: fmt::Debug {
    /// Returns the stable registry name.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(app.name(), "echo");
    /// ```
    #[must_use]
    fn name(&self) -> &'static str;

    /// Returns the supported app API version.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(app.api_version().as_u16(), 1);
    /// ```
    #[must_use]
    fn api_version(&self) -> ApiVersion;

    /// Creates one type-erased session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when app-specific admission or initialization fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let session = app.create_erased_session(context).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn create_erased_session(&self, context: SessionContext) -> ErasedSessionFactoryFuture<'_>;
}

impl<T> ErasedApplication for T
where
    T: Application,
{
    fn name(&self) -> &'static str {
        Application::name(self)
    }

    fn api_version(&self) -> ApiVersion {
        Application::api_version(self)
    }

    fn create_erased_session(&self, context: SessionContext) -> ErasedSessionFactoryFuture<'_> {
        Box::pin(async move {
            let session = self.create_session(context).await?;
            Ok(Box::new(session) as Box<dyn ErasedSession>)
        })
    }
}

/// Type-erased session dispatch used by [`SessionRunner`].
pub trait ErasedSession: fmt::Debug {
    /// Handles one bounded client control message.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the message cannot be processed or emitted.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.handle_message_erased(message, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn handle_message_erased<'a>(
        &'a mut self,
        message: ClientMessage,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a>;

    /// Handles a negotiation update.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when negotiation policy rejects the update.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_negotiation_erased(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_negotiation_erased<'a>(
        &'a mut self,
        event: NegotiationEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a>;

    /// Handles publisher track admission.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when publish policy rejects the track.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_publish_erased(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_publish_erased<'a>(
        &'a mut self,
        event: PublishEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a>;

    /// Handles subscriber route admission.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when subscribe policy rejects the route or the core
    /// command inbox is full.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_subscribe_erased(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_subscribe_erased<'a>(
        &'a mut self,
        event: SubscribeEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a>;

    /// Handles subscriber route removal.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the core command inbox is full.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_unsubscribe_erased(event, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_unsubscribe_erased<'a>(
        &'a mut self,
        event: UnsubscribeEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a>;

    /// Handles session disconnect.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when cleanup fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.on_disconnect_erased(reason, handle).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    fn on_disconnect_erased<'a>(
        &'a mut self,
        reason: DisconnectReason,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a>;
}

impl<T> ErasedSession for T
where
    T: Session,
{
    fn handle_message_erased<'a>(
        &'a mut self,
        message: ClientMessage,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a> {
        Box::pin(self.handle_message(message, handle))
    }

    fn on_negotiation_erased<'a>(
        &'a mut self,
        event: NegotiationEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a> {
        Box::pin(self.on_negotiation(event, handle))
    }

    fn on_publish_erased<'a>(
        &'a mut self,
        event: PublishEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a> {
        Box::pin(self.on_publish(event, handle))
    }

    fn on_subscribe_erased<'a>(
        &'a mut self,
        event: SubscribeEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a> {
        Box::pin(self.on_subscribe(event, handle))
    }

    fn on_unsubscribe_erased<'a>(
        &'a mut self,
        event: UnsubscribeEvent,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a> {
        Box::pin(self.on_unsubscribe(event, handle))
    }

    fn on_disconnect_erased<'a>(
        &'a mut self,
        reason: DisconnectReason,
        handle: &'a mut SessionHandle,
    ) -> ErasedOperationFuture<'a> {
        Box::pin(self.on_disconnect(reason, handle))
    }
}

/// Type-erased session owner with deterministic slow-path budget monitoring.
#[derive(Debug)]
pub struct SessionRunner {
    session: Box<dyn ErasedSession>,
    operation_timeout: Duration,
}

impl SessionRunner {
    /// Creates a runner from an erased session.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let runner = refract_app::SessionRunner::new(session);
    /// assert_eq!(runner.operation_timeout(), refract_app::DEFAULT_OPERATION_TIMEOUT);
    /// ```
    #[must_use]
    pub const fn new(session: Box<dyn ErasedSession>) -> Self {
        Self {
            session,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        }
    }

    /// Sets the deterministic timeout applied to each operation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// runner.set_operation_timeout(std::time::Duration::from_millis(10));
    /// ```
    pub const fn set_operation_timeout(&mut self, timeout: Duration) {
        self.operation_timeout = timeout;
    }

    /// Returns the operation timeout.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert!(runner.operation_timeout() > std::time::Duration::ZERO);
    /// ```
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Handles one bounded client control message.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when session handling fails or exceeds the
    /// deterministic timeout.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let sample = runner.handle_message(message, handle).await?;
    /// assert_eq!(sample.operation(), refract_app::SessionOperation::HandleMessage);
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<SlowPathSample> {
        let operation = SessionOperation::HandleMessage;
        let start = Instant::now();
        let result = compio::time::timeout(
            self.operation_timeout,
            self.session.handle_message_erased(message, handle),
        )
        .await
        .map_err(|_elapsed| AppError::SlowPathTimeout {
            operation,
            timeout: self.operation_timeout,
        })?;
        let sample = SlowPathSample::new(operation, start.elapsed());
        observe_slow_path(sample);
        result?;
        Ok(sample)
    }

    /// Handles a negotiation update.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when session handling fails or exceeds the
    /// deterministic timeout.
    pub async fn on_negotiation(
        &mut self,
        event: NegotiationEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<SlowPathSample> {
        let operation = SessionOperation::Negotiation;
        let start = Instant::now();
        let result = compio::time::timeout(
            self.operation_timeout,
            self.session.on_negotiation_erased(event, handle),
        )
        .await
        .map_err(|_elapsed| AppError::SlowPathTimeout {
            operation,
            timeout: self.operation_timeout,
        })?;
        let sample = SlowPathSample::new(operation, start.elapsed());
        observe_slow_path(sample);
        result?;
        Ok(sample)
    }

    /// Handles publisher track admission.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when session handling fails or exceeds the
    /// deterministic timeout.
    pub async fn on_publish(
        &mut self,
        event: PublishEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<SlowPathSample> {
        let operation = SessionOperation::Publish;
        let start = Instant::now();
        let result = compio::time::timeout(
            self.operation_timeout,
            self.session.on_publish_erased(event, handle),
        )
        .await
        .map_err(|_elapsed| AppError::SlowPathTimeout {
            operation,
            timeout: self.operation_timeout,
        })?;
        let sample = SlowPathSample::new(operation, start.elapsed());
        observe_slow_path(sample);
        result?;
        Ok(sample)
    }

    /// Handles subscriber route admission.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when session handling fails or exceeds the
    /// deterministic timeout.
    pub async fn on_subscribe(
        &mut self,
        event: SubscribeEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<SlowPathSample> {
        let operation = SessionOperation::Subscribe;
        let start = Instant::now();
        let result = compio::time::timeout(
            self.operation_timeout,
            self.session.on_subscribe_erased(event, handle),
        )
        .await
        .map_err(|_elapsed| AppError::SlowPathTimeout {
            operation,
            timeout: self.operation_timeout,
        })?;
        let sample = SlowPathSample::new(operation, start.elapsed());
        observe_slow_path(sample);
        result?;
        Ok(sample)
    }

    /// Handles subscriber route removal.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when session handling fails or exceeds the
    /// deterministic timeout.
    pub async fn on_unsubscribe(
        &mut self,
        event: UnsubscribeEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<SlowPathSample> {
        let operation = SessionOperation::Unsubscribe;
        let start = Instant::now();
        let result = compio::time::timeout(
            self.operation_timeout,
            self.session.on_unsubscribe_erased(event, handle),
        )
        .await
        .map_err(|_elapsed| AppError::SlowPathTimeout {
            operation,
            timeout: self.operation_timeout,
        })?;
        let sample = SlowPathSample::new(operation, start.elapsed());
        observe_slow_path(sample);
        result?;
        Ok(sample)
    }

    /// Handles session disconnect.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when session handling fails or exceeds the
    /// deterministic timeout.
    pub async fn on_disconnect(
        &mut self,
        reason: DisconnectReason,
        handle: &mut SessionHandle,
    ) -> AppResult<SlowPathSample> {
        let operation = SessionOperation::Disconnect;
        let start = Instant::now();
        let result = compio::time::timeout(
            self.operation_timeout,
            self.session.on_disconnect_erased(reason, handle),
        )
        .await
        .map_err(|_elapsed| AppError::SlowPathTimeout {
            operation,
            timeout: self.operation_timeout,
        })?;
        let sample = SlowPathSample::new(operation, start.elapsed());
        observe_slow_path(sample);
        result?;
        Ok(sample)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(runner.stability(), refract_app::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Application registry keyed by application name.
#[derive(Debug, Default)]
pub struct AppRegistry {
    apps: HashMap<&'static str, Box<dyn ErasedApplication>>,
}

impl AppRegistry {
    /// Creates an empty registry.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::AppRegistry;
    /// assert!(AppRegistry::new().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
        }
    }

    /// Registers an application by name.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidApplicationName`] for invalid names and
    /// [`AppError::DuplicateApplication`] when the name is already registered.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// registry.register(app)?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub fn register<A>(&mut self, app: A) -> AppResult<()>
    where
        A: Application + 'static,
    {
        let name = app.name();
        validate_application_name(name)?;
        if self.apps.contains_key(name) {
            return Err(AppError::DuplicateApplication { name });
        }
        self.apps.insert(name, Box::new(app));
        Ok(())
    }

    /// Creates a type-erased session runner for `name`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UnknownApplication`] when `name` is not registered,
    /// or the app-specific error returned while creating the session.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let runner = registry.create_session("echo", context).await?;
    /// # Ok::<(), refract_app::AppError>(())
    /// ```
    pub async fn create_session(
        &self,
        name: &str,
        context: SessionContext,
    ) -> AppResult<SessionRunner> {
        let app = self
            .apps
            .get(name)
            .ok_or_else(|| AppError::UnknownApplication {
                name: name.to_owned(),
            })?;
        let session = app.create_erased_session(context).await?;
        Ok(SessionRunner::new(session))
    }

    /// Returns whether `name` is registered.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::AppRegistry;
    /// assert!(!AppRegistry::new().contains("echo"));
    /// ```
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.apps.contains_key(name)
    }

    /// Returns the number of registered applications.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::AppRegistry;
    /// assert_eq!(AppRegistry::new().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.apps.len()
    }

    /// Returns whether the registry is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::AppRegistry;
    /// assert!(AppRegistry::new().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{AppRegistry, Stability};
    /// assert_eq!(AppRegistry::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

fn validate_application_name(name: &str) -> AppResult<()> {
    if name.is_empty()
        || name.len() > MAX_APPLICATION_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::InvalidApplicationName);
    }
    Ok(())
}

fn observe_slow_path(sample: SlowPathSample) {
    metrics::histogram!(
        "refract.app.slow_path.latency.seconds",
        "operation" => sample.operation().as_str()
    )
    .record(sample.elapsed().as_secs_f64());
    if sample.is_warn_threshold_exceeded() {
        tracing::warn!(
            operation = sample.operation().as_str(),
            elapsed_micros = sample.elapsed().as_micros(),
            warn_threshold_micros = SLOW_PATH_WARN_THRESHOLD.as_micros(),
            "slow-path"
        );
    }
}

#[cfg(test)]
mod tests {
    use compio::runtime::Runtime;
    use refract_router::{BandwidthBps, LayerId, QualityScore};

    use super::*;

    #[derive(Debug)]
    struct EchoApp;

    #[derive(Debug)]
    struct EchoSession;

    impl Application for EchoApp {
        type Session = EchoSession;

        fn name(&self) -> &'static str {
            "echo"
        }

        fn api_version(&self) -> ApiVersion {
            ApiVersion::new(1)
        }

        async fn create_session(&self, _context: SessionContext) -> AppResult<Self::Session> {
            Ok(EchoSession)
        }
    }

    impl Session for EchoSession {
        async fn handle_message(
            &mut self,
            message: ClientMessage,
            handle: &mut SessionHandle,
        ) -> AppResult<()> {
            handle.send(message)
        }
    }

    #[derive(Debug)]
    struct SlowApp;

    #[derive(Debug)]
    struct SlowSession;

    impl Application for SlowApp {
        type Session = SlowSession;

        fn name(&self) -> &'static str {
            "slow"
        }

        fn api_version(&self) -> ApiVersion {
            ApiVersion::new(1)
        }

        async fn create_session(&self, _context: SessionContext) -> AppResult<Self::Session> {
            Ok(SlowSession)
        }
    }

    impl Session for SlowSession {
        async fn handle_message(
            &mut self,
            message: ClientMessage,
            handle: &mut SessionHandle,
        ) -> AppResult<()> {
            compio::time::sleep(Duration::from_millis(60)).await;
            handle.send(message)
        }
    }

    fn context() -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(9),
            PeerId::from_raw(2),
            RoomId::from_raw(3),
        )
    }

    fn handle() -> (SessionHandle, SessionIo) {
        SessionHandle::new(context(), RoomView::empty(RoomId::from_raw(3)), 128, 128).unwrap()
    }

    fn layer() -> Layer {
        Layer::new(
            LayerId::new(0),
            BandwidthBps::new(64_000),
            QualityScore::new(1),
        )
        .unwrap()
    }

    #[test]
    fn invalid_application_names_are_rejected() {
        assert!(validate_application_name("").is_err());
        assert!(validate_application_name("bad space").is_err());
        assert!(validate_application_name("echo").is_ok());
    }

    #[test]
    fn client_message_enforces_bound() {
        let bytes = vec![0; MAX_CLIENT_MESSAGE_BYTES + 1];

        assert!(matches!(
            ClientMessage::try_from_bytes(&bytes),
            Err(AppError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn room_view_enforces_bound() {
        let members = vec![
            RoomMember::new(SessionId::from_raw(1), PeerId::from_raw(1));
            MAX_ROOM_MEMBERS + 1
        ];

        assert!(matches!(
            RoomView::from_members(RoomId::from_raw(1), &members),
            Err(AppError::RoomTooLarge { .. })
        ));
    }

    #[test]
    fn subscribe_default_posts_route_command() {
        Runtime::new().unwrap().block_on(async {
            let mut session = EchoSession;
            let (mut handle, mut io) = handle();
            let event =
                SubscribeEvent::new(PublisherTrackId::new(1), IngressSsrc::new(2), &[layer()])
                    .unwrap();

            session.on_subscribe(event, &mut handle).await.unwrap();

            assert!(matches!(
                io.core_inbox.pop().unwrap(),
                SfuCoreCommand::AddSubscription(_)
            ));
        });
    }

    #[test]
    fn echo_app_end_to_end() {
        Runtime::new().unwrap().block_on(async {
            let mut registry = AppRegistry::new();
            registry.register(EchoApp).unwrap();
            let mut runner = registry.create_session("echo", context()).await.unwrap();
            let (mut handle, mut io) = handle();
            let message = ClientMessage::try_from_bytes(b"ping").unwrap();

            let sample = runner.handle_message(message, &mut handle).await.unwrap();

            assert_eq!(sample.operation(), SessionOperation::HandleMessage);
            assert_eq!(io.client_outbox.pop().unwrap().as_bytes(), b"ping");
        });
    }

    #[test]
    fn slow_path_latency_regression_suite() {
        Runtime::new().unwrap().block_on(async {
            let mut registry = AppRegistry::new();
            registry.register(EchoApp).unwrap();
            let mut runner = registry.create_session("echo", context()).await.unwrap();
            let (mut handle, _io) = handle();
            let mut samples = Vec::new();

            for _index in 0..64 {
                let message = ClientMessage::try_from_bytes(b"fast").unwrap();
                samples.push(runner.handle_message(message, &mut handle).await.unwrap());
            }

            samples.sort_unstable_by_key(|sample| sample.elapsed());
            let p99_index = samples.len().saturating_sub(1);
            assert!(samples[p99_index].elapsed() <= SLOW_PATH_P99_TARGET);
        });
    }

    #[test]
    fn slow_path_warning_threshold_is_observable() {
        Runtime::new().unwrap().block_on(async {
            let mut registry = AppRegistry::new();
            registry.register(SlowApp).unwrap();
            let mut runner = registry.create_session("slow", context()).await.unwrap();
            let (mut handle, mut io) = handle();
            let message = ClientMessage::try_from_bytes(b"slow").unwrap();

            let sample = runner.handle_message(message, &mut handle).await.unwrap();

            assert!(sample.is_warn_threshold_exceeded());
            assert_eq!(io.client_outbox.pop().unwrap().as_bytes(), b"slow");
        });
    }

    #[test]
    fn deterministic_timeout_is_enforced() {
        Runtime::new().unwrap().block_on(async {
            let mut registry = AppRegistry::new();
            registry.register(SlowApp).unwrap();
            let mut runner = registry.create_session("slow", context()).await.unwrap();
            runner.set_operation_timeout(Duration::from_millis(1));
            let (mut handle, _io) = handle();
            let message = ClientMessage::try_from_bytes(b"slow").unwrap();

            let result = runner.handle_message(message, &mut handle).await;

            assert!(matches!(
                result,
                Err(AppError::SlowPathTimeout {
                    operation: SessionOperation::HandleMessage,
                    ..
                })
            ));
        });
    }
}
