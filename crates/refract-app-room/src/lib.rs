//! Default multi-party room application for refract.
//!
//! `refract-app-room` implements room lifecycle policy on top of the Stage 1
//! [`refract_app`] boundary. The crate handles a bounded, versioned JSON
//! protocol, enforces role claims, manages multi-publisher/multi-subscriber
//! route commands, switches subscriptions on RTP audio-level reports, and
//! exposes a recording delegation hook for the recording app.
//!
//! # Examples
//!
//! ```
//! # use refract_app::{Application, SessionContext};
//! # use refract_app_room::{JwtClaims, RoleSet, RoomApp};
//! # use refract_core::{PeerId, RoomId, SessionId};
//! let app = RoomApp::new();
//! app.set_claims(SessionId::from_raw(1), JwtClaims::new(RoleSet::admin()));
//! let context = SessionContext::new(
//!     SessionId::from_raw(1),
//!     PeerId::from_raw(10),
//!     RoomId::from_raw(99),
//! );
//! # compio::runtime::Runtime::new()?.block_on(async {
//! let _session = app.create_session(context).await?;
//! # Ok::<(), refract_app::AppError>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, PublishEvent, Session, SessionContext,
    SessionHandle, Stability, SubscribeEvent, UnsubscribeEvent,
};
use refract_core::{Direction, PeerId, RoomId, SessionId};
use refract_router::{
    BandwidthBps, IngressSsrc, Layer, LayerId, MAX_LAYERS_PER_SUBSCRIPTION, PublisherTrackId,
    QualityScore, SubscriberSessionId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current room protocol version emitted by the server.
pub const CURRENT_PROTOCOL_VERSION: u16 = 2;

/// Oldest protocol version still accepted for backwards compatibility.
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Maximum JSON command bytes accepted by the room app.
pub const MAX_ROOM_COMMAND_BYTES: usize = refract_app::MAX_CLIENT_MESSAGE_BYTES;

/// Maximum sessions allowed in one room app instance.
pub const DEFAULT_MAX_SESSIONS: usize = 4096;

/// Maximum publisher layer accepted by this room app.
pub const MAX_PUBLISHER_LAYER: u8 = 7;

const _: () = assert!(MAX_PUBLISHER_LAYER as usize + 1 == MAX_LAYERS_PER_SUBSCRIPTION);

/// Default bandwidth assigned to layer zero routes.
pub const DEFAULT_LAYER0_BANDWIDTH_BPS: u64 = 64_000;

/// Default quality step used for generated route layers.
pub const DEFAULT_LAYER_QUALITY_STEP: u32 = 10;

/// Role set extracted from JWT claims.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RoleSet {
    publisher: bool,
    subscriber: bool,
    admin: bool,
}

impl RoleSet {
    /// Creates a role set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// let roles = RoleSet::new(true, false, true);
    /// assert!(roles.can_publish());
    /// assert!(roles.is_admin());
    /// ```
    #[must_use]
    pub const fn new(publisher: bool, subscriber: bool, admin: bool) -> Self {
        Self {
            publisher,
            subscriber,
            admin,
        }
    }

    /// Creates an admin role set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// assert!(RoleSet::admin().is_admin());
    /// ```
    #[must_use]
    pub const fn admin() -> Self {
        Self::new(true, true, true)
    }

    /// Creates a publisher-only role set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// assert!(RoleSet::publisher().can_publish());
    /// ```
    #[must_use]
    pub const fn publisher() -> Self {
        Self::new(true, false, false)
    }

    /// Creates a subscriber-only role set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// assert!(RoleSet::subscriber().can_subscribe());
    /// ```
    #[must_use]
    pub const fn subscriber() -> Self {
        Self::new(false, true, false)
    }

    /// Returns whether publishing is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// assert!(RoleSet::admin().can_publish());
    /// ```
    #[must_use]
    pub const fn can_publish(self) -> bool {
        self.publisher || self.admin
    }

    /// Returns whether subscribing is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// assert!(RoleSet::admin().can_subscribe());
    /// ```
    #[must_use]
    pub const fn can_subscribe(self) -> bool {
        self.subscriber || self.admin
    }

    /// Returns whether administrative lifecycle actions are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoleSet;
    /// assert!(RoleSet::admin().is_admin());
    /// ```
    #[must_use]
    pub const fn is_admin(self) -> bool {
        self.admin
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::{Stability};
    /// # use refract_app_room::RoleSet;
    /// assert_eq!(RoleSet::admin().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// JWT-derived claims used by the room app.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JwtClaims {
    roles: RoleSet,
}

impl JwtClaims {
    /// Creates claims from roles.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::{JwtClaims, RoleSet};
    /// assert!(JwtClaims::new(RoleSet::publisher()).roles().can_publish());
    /// ```
    #[must_use]
    pub const fn new(roles: RoleSet) -> Self {
        Self { roles }
    }

    /// Returns the role set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::{JwtClaims, RoleSet};
    /// assert!(
    ///     JwtClaims::new(RoleSet::subscriber())
    ///         .roles()
    ///         .can_subscribe()
    /// );
    /// ```
    #[must_use]
    pub const fn roles(self) -> RoleSet {
        self.roles
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_room::{JwtClaims, RoleSet};
    /// assert_eq!(
    ///     JwtClaims::new(RoleSet::admin()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl Default for JwtClaims {
    fn default() -> Self {
        Self::new(RoleSet::subscriber())
    }
}

/// Room app configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomConfig {
    auto_subscribe_on_join: bool,
    recording_enabled: bool,
    max_sessions: usize,
    default_max_layer: u8,
}

impl RoomConfig {
    /// Creates bounded room configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::InvalidConfig`] when any bound is zero or exceeds
    /// the Stage 1 limits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomConfig;
    /// let config = RoomConfig::new(true, false, 128, 2)?;
    /// assert!(config.auto_subscribe_on_join());
    /// # Ok::<(), refract_app_room::RoomError>(())
    /// ```
    pub const fn new(
        auto_subscribe_on_join: bool,
        recording_enabled: bool,
        max_sessions: usize,
        default_max_layer: u8,
    ) -> RoomResult<Self> {
        if max_sessions == 0 {
            return Err(RoomError::InvalidConfig {
                field: "max_sessions",
            });
        }
        if default_max_layer > MAX_PUBLISHER_LAYER {
            return Err(RoomError::InvalidConfig {
                field: "default_max_layer",
            });
        }
        Ok(Self {
            auto_subscribe_on_join,
            recording_enabled,
            max_sessions,
            default_max_layer,
        })
    }

    /// Returns whether new subscribers auto-subscribe to current publishers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomConfig;
    /// assert!(RoomConfig::default().auto_subscribe_on_join());
    /// ```
    #[must_use]
    pub const fn auto_subscribe_on_join(&self) -> bool {
        self.auto_subscribe_on_join
    }

    /// Returns whether recording delegation is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomConfig;
    /// assert!(!RoomConfig::default().recording_enabled());
    /// ```
    #[must_use]
    pub const fn recording_enabled(&self) -> bool {
        self.recording_enabled
    }

    /// Returns the session cap.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomConfig;
    /// assert_eq!(RoomConfig::default().max_sessions(), 4096);
    /// ```
    #[must_use]
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Returns the default maximum publisher layer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomConfig;
    /// assert_eq!(RoomConfig::default().default_max_layer(), 2);
    /// ```
    #[must_use]
    pub const fn default_max_layer(&self) -> u8 {
        self.default_max_layer
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_room::RoomConfig;
    /// assert_eq!(RoomConfig::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            auto_subscribe_on_join: true,
            recording_enabled: false,
            max_sessions: DEFAULT_MAX_SESSIONS,
            default_max_layer: 2,
        }
    }
}

/// Error taxonomy for room protocol and policy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RoomError {
    /// A configuration field is invalid.
    #[error("invalid room config: {field}")]
    InvalidConfig {
        /// Invalid configuration field.
        field: &'static str,
    },
    /// The JSON command exceeded the bounded input length.
    #[error("room command too large: {len} > {max}")]
    CommandTooLarge {
        /// Observed command length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// The JSON command could not be parsed.
    #[error("invalid room command json")]
    Json(#[from] serde_json::Error),
    /// Unsupported protocol version.
    #[error("unsupported protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Received protocol version.
        version: u16,
    },
    /// The room app is at capacity.
    #[error("room capacity exceeded: {max}")]
    Capacity {
        /// Configured maximum sessions.
        max: usize,
    },
}

impl RoomError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomError;
    /// assert_eq!(
    ///     RoomError::UnsupportedProtocolVersion { version: 99 }.error_code(),
    ///     "APP_ROOM_PROTOCOL_0001",
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "APP_ROOM_CONFIG_0001",
            Self::CommandTooLarge { .. } => "APP_ROOM_INPUT_0001",
            Self::Json(_) => "APP_ROOM_INPUT_0002",
            Self::UnsupportedProtocolVersion { .. } => "APP_ROOM_PROTOCOL_0001",
            Self::Capacity { .. } => "APP_ROOM_CAPACITY_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_room::RoomError;
    /// assert_eq!(
    ///     RoomError::InvalidConfig { field: "x" }.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Result alias for room app operations.
pub type RoomResult<T> = Result<T, RoomError>;

/// Recording delegation target.
pub trait RecordingDelegate: fmt::Debug {
    /// Starts recording for a room.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] when the recording trigger cannot be accepted.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// delegate.start_recording(room_id)?;
    /// # Ok::<(), refract_app_room::RoomError>(())
    /// ```
    fn start_recording(&self, room_id: RoomId) -> RoomResult<()>;
}

/// No-op recording delegate used when recording support is disabled.
#[derive(Debug, Default)]
pub struct NoopRecordingDelegate;

impl RecordingDelegate for NoopRecordingDelegate {
    fn start_recording(&self, _room_id: RoomId) -> RoomResult<()> {
        Ok(())
    }
}

/// Default room application.
#[derive(Clone, Debug)]
pub struct RoomApp {
    state: Rc<RefCell<RoomState>>,
}

impl RoomApp {
    /// Creates a room app with default configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomApp;
    /// assert_eq!(RoomApp::new().api_name(), "room");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RoomConfig::default())
    }

    /// Creates a room app with explicit configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::{RoomApp, RoomConfig};
    /// let app = RoomApp::with_config(RoomConfig::default());
    /// assert_eq!(app.protocol_version(), 2);
    /// ```
    #[must_use]
    pub fn with_config(config: RoomConfig) -> Self {
        Self {
            state: Rc::new(RefCell::new(RoomState::new(
                config,
                Box::new(NoopRecordingDelegate),
            ))),
        }
    }

    /// Replaces the recording delegate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::{NoopRecordingDelegate, RoomApp};
    /// let app = RoomApp::new();
    /// app.set_recording_delegate(Box::new(NoopRecordingDelegate));
    /// ```
    pub fn set_recording_delegate(&self, delegate: Box<dyn RecordingDelegate>) {
        self.state.borrow_mut().recording = delegate;
    }

    /// Assigns JWT claims to a session before it joins.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::{JwtClaims, RoleSet, RoomApp};
    /// # use refract_core::SessionId;
    /// let app = RoomApp::new();
    /// app.set_claims(SessionId::from_raw(1), JwtClaims::new(RoleSet::admin()));
    /// ```
    pub fn set_claims(&self, session_id: SessionId, claims: JwtClaims) {
        self.state.borrow_mut().claims.insert(session_id, claims);
    }

    /// Returns the stable application name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::RoomApp;
    /// assert_eq!(RoomApp::new().api_name(), "room");
    /// ```
    #[must_use]
    pub const fn api_name(&self) -> &'static str {
        "room"
    }

    /// Returns the current protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_room::{RoomApp, CURRENT_PROTOCOL_VERSION};
    /// assert_eq!(RoomApp::new().protocol_version(), CURRENT_PROTOCOL_VERSION);
    /// ```
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        CURRENT_PROTOCOL_VERSION
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_room::RoomApp;
    /// assert_eq!(RoomApp::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Default for RoomApp {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for RoomApp {
    type Session = RoomSession;

    fn name(&self) -> &'static str {
        self.api_name()
    }

    fn api_version(&self) -> ApiVersion {
        ApiVersion::new(CURRENT_PROTOCOL_VERSION)
    }

    async fn create_session(&self, context: SessionContext) -> AppResult<Self::Session> {
        let mut state = self.state.borrow_mut();
        if state.session_count >= state.config.max_sessions {
            return Err(refract_app::AppError::RoomTooLarge {
                len: state.session_count,
                max: state.config.max_sessions,
            });
        }
        let claims = state
            .claims
            .remove(&context.session_id())
            .unwrap_or_default();
        let room = state.room_mut(context.room_id());
        if room.banned_peers.contains(&context.peer_id()) {
            return Ok(RoomSession::banned(self.state.clone(), context, claims));
        }
        room.members.insert(
            context.session_id(),
            MemberState::new(context.peer_id(), claims.roles()),
        );
        state.session_count += 1;
        Ok(RoomSession::joined(self.state.clone(), context, claims))
    }
}

/// Session for one client in a room.
#[derive(Debug)]
pub struct RoomSession {
    state: Rc<RefCell<RoomState>>,
    context: SessionContext,
    claims: JwtClaims,
    joined: bool,
    auto_subscribed: bool,
}

impl RoomSession {
    const fn joined(
        state: Rc<RefCell<RoomState>>,
        context: SessionContext,
        claims: JwtClaims,
    ) -> Self {
        Self {
            state,
            context,
            claims,
            joined: true,
            auto_subscribed: false,
        }
    }

    const fn banned(
        state: Rc<RefCell<RoomState>>,
        context: SessionContext,
        claims: JwtClaims,
    ) -> Self {
        Self {
            state,
            context,
            claims,
            joined: false,
            auto_subscribed: true,
        }
    }

    /// Returns whether this session was admitted to the room.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert!(session.is_joined());
    /// ```
    #[must_use]
    pub const fn is_joined(&self) -> bool {
        self.joined
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(session.stability(), refract_app::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Session for RoomSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let command = match RoomCommand::parse(message.as_bytes()) {
            Ok(command) => command,
            Err(error) => {
                send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code())?;
                return Ok(());
            }
        };
        if !self.joined {
            send_error(handle, command.protocol_version(), "APP_ROOM_POLICY_BANNED")?;
            return Ok(());
        }
        self.auto_subscribe_existing(handle)?;
        self.apply_command(command, handle)
    }

    async fn on_publish(
        &mut self,
        event: PublishEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.roles().can_publish() {
            send_error(
                handle,
                CURRENT_PROTOCOL_VERSION,
                "APP_ROOM_PERMISSION_PUBLISH",
            )?;
            return Ok(());
        }
        let max_layer = self
            .state
            .borrow()
            .config
            .default_max_layer
            .min(MAX_PUBLISHER_LAYER);
        self.register_publish(
            event.publisher_track(),
            event.ingress_ssrc(),
            max_layer,
            handle,
        )
    }

    async fn on_subscribe(
        &mut self,
        event: SubscribeEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.roles().can_subscribe() {
            send_error(
                handle,
                CURRENT_PROTOCOL_VERSION,
                "APP_ROOM_PERMISSION_SUBSCRIBE",
            )?;
            return Ok(());
        }
        handle.add_route(event.to_subscription(handle.subscriber_id())?)
    }

    async fn on_unsubscribe(
        &mut self,
        event: UnsubscribeEvent,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        handle.remove_route(event.publisher_track())
    }
}

impl RoomSession {
    fn auto_subscribe_existing(&mut self, handle: &mut SessionHandle) -> AppResult<()> {
        if self.auto_subscribed || !self.claims.roles().can_subscribe() {
            self.auto_subscribed = true;
            return Ok(());
        }
        let state = self.state.borrow();
        if !state.config.auto_subscribe_on_join {
            self.auto_subscribed = true;
            return Ok(());
        }
        let room = state.room(self.context.room_id());
        let publishers: Vec<_> = room
            .into_iter()
            .flat_map(|room| room.publishers.iter())
            .filter(|(_track, publisher)| publisher.owner != self.context.session_id())
            .map(|(track, publisher)| (*track, publisher.ingress_ssrc, publisher.max_layer))
            .collect();
        drop(state);
        let subscriber = SubscriberSessionId::new(self.context.session_id().raw());
        for (track, ssrc, max_layer) in publishers {
            add_route_for(handle, subscriber, track, ssrc, max_layer)?;
        }
        self.auto_subscribed = true;
        Ok(())
    }

    fn apply_command(&self, command: RoomCommand, handle: &mut SessionHandle) -> AppResult<()> {
        let RoomCommand {
            protocol_version,
            kind,
        } = command;
        match kind {
            CommandKind::Create => self.admin_only(protocol_version, handle, |state| {
                state.room_mut(self.context.room_id()).destroyed = false;
                Ok(Response::ok(protocol_version, "created"))
            }),
            CommandKind::Destroy => self.admin_only(protocol_version, handle, |state| {
                state.room_mut(self.context.room_id()).destroyed = true;
                Ok(Response::ok(protocol_version, "destroyed"))
            }),
            CommandKind::List => {
                if self.claims.roles().is_admin() {
                    send_response(handle, &self.room_list_response(protocol_version))
                } else {
                    send_error(handle, protocol_version, "APP_ROOM_PERMISSION_ADMIN")
                }
            }
            CommandKind::Kick { session_id } => {
                self.admin_only(protocol_version, handle, |state| {
                    state.kick(self.context.room_id(), SessionId::from_raw(session_id));
                    Ok(Response::ok(protocol_version, "kicked"))
                })
            }
            CommandKind::Ban { peer_id } => self.admin_only(protocol_version, handle, |state| {
                state.ban(self.context.room_id(), PeerId::from_raw(peer_id));
                Ok(Response::ok(protocol_version, "banned"))
            }),
            CommandKind::Mute { session_id } => {
                self.set_direction(protocol_version, session_id, Direction::Inactive, handle)
            }
            CommandKind::Unmute { session_id } => {
                self.set_direction(protocol_version, session_id, Direction::SendRecv, handle)
            }
            CommandKind::Publish {
                track_id,
                ssrc,
                max_layer,
            } => self.register_publish(
                PublisherTrackId::new(track_id),
                IngressSsrc::new(ssrc),
                max_layer
                    .unwrap_or_else(|| self.state.borrow().config.default_max_layer)
                    .min(MAX_PUBLISHER_LAYER),
                handle,
            ),
            CommandKind::Subscribe { track_id } => {
                self.subscribe_to(protocol_version, PublisherTrackId::new(track_id), handle)
            }
            CommandKind::Unsubscribe { track_id } => {
                handle.remove_route(PublisherTrackId::new(track_id))?;
                send_response(handle, &Response::ok(protocol_version, "unsubscribed"))
            }
            CommandKind::AudioLevel { track_id, level } => self.update_audio_level(
                protocol_version,
                PublisherTrackId::new(track_id),
                level,
                handle,
            ),
            CommandKind::StartRecording => self.admin_only(protocol_version, handle, |state| {
                if state.config.recording_enabled {
                    state.recording.start_recording(self.context.room_id())?;
                    state.room_mut(self.context.room_id()).recording_started = true;
                    Ok(Response::ok(protocol_version, "recording_started"))
                } else {
                    Ok(Response::error(
                        protocol_version,
                        "APP_ROOM_RECORDING_DISABLED",
                    ))
                }
            }),
        }
    }

    fn register_publish(
        &self,
        track: PublisherTrackId,
        ssrc: IngressSsrc,
        max_layer: u8,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.roles().can_publish() {
            return send_error(
                handle,
                CURRENT_PROTOCOL_VERSION,
                "APP_ROOM_PERMISSION_PUBLISH",
            );
        }
        let mut state = self.state.borrow_mut();
        let auto_subscribe = state.config.auto_subscribe_on_join;
        let room = state.room_mut(self.context.room_id());
        let Some(member) = room.members.get(&self.context.session_id()) else {
            return send_error(handle, CURRENT_PROTOCOL_VERSION, "APP_ROOM_NOT_JOINED");
        };
        if !direction_allows_send(member.direction) {
            return send_error(handle, CURRENT_PROTOCOL_VERSION, "APP_ROOM_MUTED");
        }
        room.publishers.insert(
            track,
            PublisherState {
                owner: self.context.session_id(),
                ingress_ssrc: ssrc,
                max_layer,
                audio_level: None,
            },
        );
        let subscribers: Vec<_> = room
            .members
            .iter()
            .filter(|(session, subscriber)| {
                auto_subscribe
                    && **session != self.context.session_id()
                    && subscriber.roles.can_subscribe()
                    && direction_allows_recv(subscriber.direction)
            })
            .map(|(session, _subscriber)| SubscriberSessionId::new(session.raw()))
            .collect();
        drop(state);

        for subscriber in subscribers {
            add_route_for(handle, subscriber, track, ssrc, max_layer)?;
        }
        send_response(handle, &Response::ok(CURRENT_PROTOCOL_VERSION, "published"))
    }

    fn subscribe_to(
        &self,
        version: u16,
        track: PublisherTrackId,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.roles().can_subscribe() {
            return send_error(handle, version, "APP_ROOM_PERMISSION_SUBSCRIBE");
        }
        let state = self.state.borrow();
        let room = state.room(self.context.room_id());
        let Some(publisher) = room.and_then(|room| room.publishers.get(&track)) else {
            return send_error(handle, version, "APP_ROOM_UNKNOWN_TRACK");
        };
        let subscriber = SubscriberSessionId::new(self.context.session_id().raw());
        add_route_for(
            handle,
            subscriber,
            track,
            publisher.ingress_ssrc,
            publisher.max_layer,
        )?;
        send_response(handle, &Response::ok(version, "subscribed"))
    }

    fn update_audio_level(
        &self,
        version: u16,
        track: PublisherTrackId,
        level: u8,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let mut state = self.state.borrow_mut();
        let Some(room) = state.rooms.get_mut(&self.context.room_id()) else {
            return send_error(handle, version, "APP_ROOM_NOT_FOUND");
        };
        let Some(publisher) = room.publishers.get_mut(&track) else {
            return send_error(handle, version, "APP_ROOM_UNKNOWN_TRACK");
        };
        if publisher.owner != self.context.session_id() {
            return send_error(handle, version, "APP_ROOM_PERMISSION_AUDIO_LEVEL");
        }
        publisher.audio_level = Some(level);
        room.active_speaker = room
            .publishers
            .iter()
            .filter_map(|(track, publisher)| publisher.audio_level.map(|level| (*track, level)))
            .min_by_key(|(_track, level)| *level)
            .map(|(track, _level)| track);
        let active = room.active_speaker.map(PublisherTrackId::as_u64);
        drop(state);
        send_response(handle, &Response::active_speaker(version, active))
    }

    fn set_direction(
        &self,
        version: u16,
        session_id: Option<u64>,
        direction: Direction,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let target = session_id.map_or_else(|| self.context.session_id(), SessionId::from_raw);
        if target != self.context.session_id() && !self.claims.roles().is_admin() {
            return send_error(handle, version, "APP_ROOM_PERMISSION_ADMIN");
        }
        let mut state = self.state.borrow_mut();
        let room = state.room_mut(self.context.room_id());
        if let Some(member) = room.members.get_mut(&target) {
            member.direction = direction;
        }
        let message = match direction {
            Direction::Inactive => "muted",
            _ => "unmuted",
        };
        drop(state);
        send_response(handle, &Response::ok(version, message))
    }

    fn room_list_response(&self, version: u16) -> Response {
        let state = self.state.borrow();
        let rooms: Vec<_> = state
            .rooms
            .iter()
            .map(|(room_id, room)| WireRoom {
                room_id: room_id.raw(),
                members: room.members.len(),
                publishers: room.publishers.len(),
                destroyed: room.destroyed,
                active_speaker: room.active_speaker.map(PublisherTrackId::as_u64),
            })
            .collect();
        drop(state);
        Response::rooms(version, rooms)
    }

    fn admin_only(
        &self,
        version: u16,
        handle: &mut SessionHandle,
        apply: impl FnOnce(&mut RoomState) -> RoomResult<Response>,
    ) -> AppResult<()> {
        if !self.claims.roles().is_admin() {
            return send_error(handle, version, "APP_ROOM_PERMISSION_ADMIN");
        }
        let response = {
            let mut state = self.state.borrow_mut();
            apply(&mut state)
        };
        match response {
            Ok(response) => send_response(handle, &response),
            Err(error) => send_error(handle, version, error.error_code()),
        }
    }
}

#[derive(Debug)]
struct RoomState {
    config: RoomConfig,
    recording: Box<dyn RecordingDelegate>,
    claims: BTreeMap<SessionId, JwtClaims>,
    rooms: BTreeMap<RoomId, RoomEntry>,
    session_count: usize,
}

impl RoomState {
    fn new(config: RoomConfig, recording: Box<dyn RecordingDelegate>) -> Self {
        Self {
            config,
            recording,
            claims: BTreeMap::new(),
            rooms: BTreeMap::new(),
            session_count: 0,
        }
    }

    fn room(&self, room_id: RoomId) -> Option<&RoomEntry> {
        self.rooms.get(&room_id)
    }

    fn room_mut(&mut self, room_id: RoomId) -> &mut RoomEntry {
        self.rooms.entry(room_id).or_default()
    }

    fn kick(&mut self, room_id: RoomId, session_id: SessionId) {
        if let Some(room) = self.rooms.get_mut(&room_id) {
            if room.members.remove(&session_id).is_some() {
                self.session_count = self.session_count.saturating_sub(1);
            }
            room.publishers
                .retain(|_track, publisher| publisher.owner != session_id);
        }
    }

    fn ban(&mut self, room_id: RoomId, peer_id: PeerId) {
        let room = self.room_mut(room_id);
        room.banned_peers.insert(peer_id);
        let kicked: Vec<_> = room
            .members
            .iter()
            .filter(|(_session, member)| member.peer == peer_id)
            .map(|(session, _member)| *session)
            .collect();
        for session in kicked {
            self.kick(room_id, session);
        }
    }
}

#[derive(Debug, Default)]
struct RoomEntry {
    members: BTreeMap<SessionId, MemberState>,
    banned_peers: BTreeSet<PeerId>,
    publishers: BTreeMap<PublisherTrackId, PublisherState>,
    active_speaker: Option<PublisherTrackId>,
    destroyed: bool,
    recording_started: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MemberState {
    peer: PeerId,
    roles: RoleSet,
    direction: Direction,
}

impl MemberState {
    const fn new(peer: PeerId, roles: RoleSet) -> Self {
        Self {
            peer,
            roles,
            direction: Direction::SendRecv,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublisherState {
    owner: SessionId,
    ingress_ssrc: IngressSsrc,
    max_layer: u8,
    audio_level: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct RoomCommand {
    protocol_version: u16,
    #[serde(flatten)]
    kind: CommandKind,
}

impl RoomCommand {
    fn parse(bytes: &[u8]) -> RoomResult<Self> {
        if bytes.len() > MAX_ROOM_COMMAND_BYTES {
            return Err(RoomError::CommandTooLarge {
                len: bytes.len(),
                max: MAX_ROOM_COMMAND_BYTES,
            });
        }
        let command: Self = serde_json::from_slice(bytes)?;
        if !(MIN_PROTOCOL_VERSION..=CURRENT_PROTOCOL_VERSION).contains(&command.protocol_version) {
            return Err(RoomError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        Ok(command)
    }

    const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum CommandKind {
    Create,
    Destroy,
    List,
    Kick {
        session_id: u64,
    },
    Ban {
        peer_id: u64,
    },
    Mute {
        session_id: Option<u64>,
    },
    Unmute {
        session_id: Option<u64>,
    },
    Publish {
        track_id: u64,
        ssrc: u32,
        max_layer: Option<u8>,
    },
    Subscribe {
        track_id: u64,
    },
    Unsubscribe {
        track_id: u64,
    },
    AudioLevel {
        track_id: u64,
        level: u8,
    },
    StartRecording,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct Response {
    protocol_version: u16,
    kind: &'static str,
    status: &'static str,
    code: Option<&'static str>,
    message: Option<&'static str>,
    rooms: Option<Vec<WireRoom>>,
    active_speaker: Option<u64>,
}

impl Response {
    const fn ok(protocol_version: u16, message: &'static str) -> Self {
        Self {
            protocol_version,
            kind: "response",
            status: "ok",
            code: None,
            message: Some(message),
            rooms: None,
            active_speaker: None,
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            kind: "response",
            status: "error",
            code: Some(code),
            message: None,
            rooms: None,
            active_speaker: None,
        }
    }

    const fn active_speaker(protocol_version: u16, active_speaker: Option<u64>) -> Self {
        Self {
            protocol_version,
            kind: "active_speaker",
            status: "ok",
            code: None,
            message: None,
            rooms: None,
            active_speaker,
        }
    }

    const fn rooms(protocol_version: u16, rooms: Vec<WireRoom>) -> Self {
        Self {
            protocol_version,
            kind: "rooms",
            status: "ok",
            code: None,
            message: None,
            rooms: Some(rooms),
            active_speaker: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct WireRoom {
    room_id: u64,
    members: usize,
    publishers: usize,
    destroyed: bool,
    active_speaker: Option<u64>,
}

fn send_response(handle: &mut SessionHandle, response: &Response) -> AppResult<()> {
    let bytes =
        serde_json::to_vec(&response).map_err(|_source| refract_app::AppError::Allocation {
            component: "room_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(bytes.as_slice())?)
}

fn send_error(
    handle: &mut SessionHandle,
    protocol_version: u16,
    code: &'static str,
) -> AppResult<()> {
    send_response(handle, &Response::error(protocol_version, code))
}

fn add_route_for(
    handle: &mut SessionHandle,
    subscriber: SubscriberSessionId,
    track: PublisherTrackId,
    ssrc: IngressSsrc,
    max_layer: u8,
) -> AppResult<()> {
    let layers = layers_for(max_layer)?;
    let event = SubscribeEvent::new(track, ssrc, layers.as_slice())?;
    handle.add_route(event.to_subscription(subscriber)?)
}

fn layers_for(max_layer: u8) -> AppResult<Vec<Layer>> {
    let capped = max_layer.min(MAX_PUBLISHER_LAYER);
    let mut layers = Vec::new();
    layers
        .try_reserve_exact(usize::from(capped) + 1)
        .map_err(|_source| refract_app::AppError::Allocation {
            component: "room_layers",
        })?;
    for id in 0..=capped {
        let multiplier = u64::from(id) + 1;
        layers.push(Layer::new(
            LayerId::new(id),
            BandwidthBps::new(DEFAULT_LAYER0_BANDWIDTH_BPS.saturating_mul(multiplier)),
            QualityScore::new(DEFAULT_LAYER_QUALITY_STEP.saturating_mul(u32::from(id) + 1)),
        )?);
    }
    Ok(layers)
}

const fn direction_allows_send(direction: Direction) -> bool {
    matches!(direction, Direction::SendRecv | Direction::SendOnly)
}

const fn direction_allows_recv(direction: Direction) -> bool {
    matches!(direction, Direction::SendRecv | Direction::RecvOnly)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use compio::runtime::Runtime;
    use refract_app::{SessionIo, SfuCoreCommand};

    use super::*;

    fn context(session: u64, peer: u64) -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(session),
            PeerId::from_raw(peer),
            RoomId::from_raw(7),
        )
    }

    fn handle(session: u64, peer: u64) -> (SessionHandle, SessionIo) {
        SessionHandle::new(
            context(session, peer),
            refract_app::RoomView::empty(RoomId::from_raw(7)),
            64,
            256,
        )
        .unwrap()
    }

    fn msg(source: &str) -> ClientMessage {
        ClientMessage::try_from_bytes(source.as_bytes()).unwrap()
    }

    fn app_with_roles(roles: &[(u64, RoleSet)]) -> RoomApp {
        let app = RoomApp::new();
        for (session, role) in roles {
            app.set_claims(SessionId::from_raw(*session), JwtClaims::new(*role));
        }
        app
    }

    fn route_count(io: &mut SessionIo) -> usize {
        let mut count = 0;
        while let Ok(command) = io.core_inbox.pop() {
            if matches!(command, SfuCoreCommand::AddSubscription(_)) {
                count += 1;
            }
        }
        count
    }

    #[derive(Debug)]
    struct CountingRecordingDelegate {
        starts: Rc<Cell<u32>>,
    }

    impl RecordingDelegate for CountingRecordingDelegate {
        fn start_recording(&self, _room_id: RoomId) -> RoomResult<()> {
            self.starts.set(self.starts.get().saturating_add(1));
            Ok(())
        }
    }

    #[test]
    fn ten_client_integration_multi_pub_multi_sub() {
        Runtime::new().unwrap().block_on(async {
            let roles: Vec<_> = (1..=10).map(|id| (id, RoleSet::admin())).collect();
            let app = app_with_roles(roles.as_slice());
            let mut sessions = Vec::new();
            let mut ios = Vec::new();
            for id in 1..=10 {
                sessions
                    .push(app.create_session(context(id, id + 100)).await.unwrap());
                ios.push(handle(id, id + 100));
            }
            for (index, publisher) in [1_u64, 2, 3].into_iter().enumerate() {
                let (handle, _io) = &mut ios[index];
                sessions[index]
                    .handle_message(
                        msg(&format!(
                            "{{\"protocol_version\":2,\"type\":\"publish\",\"track_id\":{},\"ssrc\":{},\"max_layer\":2}}",
                            publisher, 1000 + publisher
                        )),
                        handle,
                    )
                    .await
                    .unwrap();
            }

            let routed = route_count(&mut ios[0].1)
                + route_count(&mut ios[1].1)
                + route_count(&mut ios[2].1);
            assert_eq!(routed, 30);
            assert_eq!(route_count(&mut ios[3].1), 0);
        });
    }

    #[test]
    fn active_speaker_under_churn() {
        Runtime::new().unwrap().block_on(async {
            let app = app_with_roles(&[(1, RoleSet::admin()), (2, RoleSet::admin())]);
            let mut session1 = app.create_session(context(1, 10)).await.unwrap();
            let mut session2 = app.create_session(context(2, 20)).await.unwrap();
            let (mut handle1, _io1) = handle(1, 10);
            let (mut handle2, mut io2) = handle(2, 20);
            session1
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"publish\",\"track_id\":1,\"ssrc\":11,\"max_layer\":1}"),
                    &mut handle1,
                )
                .await
                .unwrap();
            session2
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"publish\",\"track_id\":2,\"ssrc\":22,\"max_layer\":1}"),
                    &mut handle2,
                )
                .await
                .unwrap();
            session1
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"audio_level\",\"track_id\":1,\"level\":70}"),
                    &mut handle1,
                )
                .await
                .unwrap();
            session2
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"audio_level\",\"track_id\":2,\"level\":10}"),
                    &mut handle2,
                )
                .await
                .unwrap();

            let mut active_seen = false;
            while let Ok(message) = io2.client_outbox.pop() {
                active_seen |= std::str::from_utf8(message.as_bytes())
                    .unwrap()
                    .contains("\"active_speaker\":2");
            }
            assert!(active_seen);
        });
    }

    #[test]
    fn kick_and_ban_are_enforced() {
        Runtime::new().unwrap().block_on(async {
            let app = app_with_roles(&[(1, RoleSet::admin()), (2, RoleSet::subscriber())]);
            let mut admin = app.create_session(context(1, 10)).await.unwrap();
            let mut kicked = app.create_session(context(2, 20)).await.unwrap();
            let (mut admin_handle, _admin_io) = handle(1, 10);
            let (mut kicked_handle, mut kicked_io) = handle(2, 20);

            admin
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"kick\",\"session_id\":2}"),
                    &mut admin_handle,
                )
                .await
                .unwrap();
            kicked
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"subscribe\",\"track_id\":99}"),
                    &mut kicked_handle,
                )
                .await
                .unwrap();

            admin
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"ban\",\"peer_id\":20}"),
                    &mut admin_handle,
                )
                .await
                .unwrap();
            app.set_claims(SessionId::from_raw(3), JwtClaims::new(RoleSet::subscriber()));
            let banned = app.create_session(context(3, 20)).await.unwrap();

            assert!(!banned.is_joined());
            assert!(matches!(
                kicked_io.client_outbox.pop(),
                Ok(message) if std::str::from_utf8(message.as_bytes()).unwrap().contains("APP_ROOM_UNKNOWN_TRACK")
            ));
        });
    }

    #[test]
    fn protocol_version_negotiation_accepts_v1_and_rejects_future() {
        let v1 = RoomCommand::parse(
            b"{\"protocol_version\":1,\"type\":\"publish\",\"track_id\":1,\"ssrc\":55}",
        )
        .unwrap();
        assert_eq!(v1.protocol_version(), 1);

        assert!(matches!(
            RoomCommand::parse(b"{\"protocol_version\":99,\"type\":\"list\"}"),
            Err(RoomError::UnsupportedProtocolVersion { version: 99 })
        ));
    }

    #[test]
    fn auto_subscribe_on_join_covers_existing_publishers() {
        Runtime::new().unwrap().block_on(async {
            let app = app_with_roles(&[(1, RoleSet::admin()), (2, RoleSet::subscriber())]);
            let mut publisher = app.create_session(context(1, 10)).await.unwrap();
            let (mut publisher_handle, _publisher_io) = handle(1, 10);
            publisher
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"publish\",\"track_id\":1,\"ssrc\":44}"),
                    &mut publisher_handle,
                )
                .await
                .unwrap();
            let mut subscriber = app.create_session(context(2, 20)).await.unwrap();
            let (mut subscriber_handle, mut subscriber_io) = handle(2, 20);

            subscriber
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"list\"}"),
                    &mut subscriber_handle,
                )
                .await
                .unwrap();

            assert_eq!(route_count(&mut subscriber_io), 1);
        });
    }

    #[test]
    fn mute_blocks_server_enforced_publish_direction() {
        Runtime::new().unwrap().block_on(async {
            let app = app_with_roles(&[(1, RoleSet::admin())]);
            let mut session = app.create_session(context(1, 10)).await.unwrap();
            let (mut handle, mut io) = handle(1, 10);

            session
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"mute\",\"session_id\":1}"),
                    &mut handle,
                )
                .await
                .unwrap();
            session
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"publish\",\"track_id\":1,\"ssrc\":44}"),
                    &mut handle,
                )
                .await
                .unwrap();

            let mut muted = false;
            while let Ok(message) = io.client_outbox.pop() {
                muted |= std::str::from_utf8(message.as_bytes())
                    .unwrap()
                    .contains("APP_ROOM_MUTED");
            }
            assert!(muted);
            assert_eq!(route_count(&mut io), 0);
        });
    }

    #[test]
    fn recording_trigger_delegates_when_enabled() {
        Runtime::new().unwrap().block_on(async {
            let app = RoomApp::with_config(RoomConfig::new(true, true, 32, 2).unwrap());
            let starts = Rc::new(Cell::new(0));
            app.set_recording_delegate(Box::new(CountingRecordingDelegate {
                starts: starts.clone(),
            }));
            app.set_claims(SessionId::from_raw(1), JwtClaims::new(RoleSet::admin()));
            let mut session = app.create_session(context(1, 10)).await.unwrap();
            let (mut handle, _io) = handle(1, 10);

            session
                .handle_message(
                    msg("{\"protocol_version\":2,\"type\":\"start_recording\"}"),
                    &mut handle,
                )
                .await
                .unwrap();

            assert_eq!(starts.get(), 1);
        });
    }
}
