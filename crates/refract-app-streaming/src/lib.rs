//! Broadcast and streaming application boundary.
//!
//! `refract-app-streaming` validates versioned JSON control messages for
//! one-to-many stream publication and watching. The app enforces broadcaster,
//! viewer, and admin roles before posting bounded route commands to the Stage 1
//! `SFU` core inbox.
//!
//! # Examples
//!
//! ```
//! # use refract_app::{Application, SessionContext};
//! # use refract_app_streaming::{StreamingApp, StreamingClaims};
//! # use refract_core::{PeerId, RoomId, SessionId};
//! let app = StreamingApp::new();
//! app.set_claims(SessionId::from_raw(1), StreamingClaims::broadcaster());
//! let context = SessionContext::new(
//!     SessionId::from_raw(1),
//!     PeerId::from_raw(2),
//!     RoomId::from_raw(3),
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

#[cfg(not(feature = "app-streaming"))]
compile_error!("refract-app-streaming must be built with the app-streaming Cargo feature");

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, Session, SessionContext, SessionHandle,
    Stability,
};
use refract_core::SessionId;
use refract_router::{
    BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore, SubscriberSessionId,
    Subscription,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current streaming app protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted streaming app JSON command bytes.
pub const MAX_STREAMING_COMMAND_BYTES: usize = refract_app::MAX_CLIENT_MESSAGE_BYTES;

/// Maximum accepted stream identifier bytes.
pub const MAX_STREAM_ID_BYTES: usize = 128;

/// Maximum publisher layer accepted by the streaming app.
pub const MAX_STREAMING_LAYER: u8 = 7;

/// Base bandwidth assigned to streaming layer zero.
pub const STREAMING_LAYER0_BANDWIDTH_BPS: u64 = 128_000;

/// JWT-derived streaming claims.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct StreamingClaims {
    broadcaster: bool,
    viewer: bool,
    admin: bool,
}

impl StreamingClaims {
    /// Creates streaming claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::new(true, false, false).can_broadcast());
    /// ```
    #[must_use]
    pub const fn new(broadcaster: bool, viewer: bool, admin: bool) -> Self {
        Self {
            broadcaster,
            viewer,
            admin,
        }
    }

    /// Creates broadcaster claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::broadcaster().can_broadcast());
    /// ```
    #[must_use]
    pub const fn broadcaster() -> Self {
        Self::new(true, false, false)
    }

    /// Creates viewer claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::viewer().can_view());
    /// ```
    #[must_use]
    pub const fn viewer() -> Self {
        Self::new(false, true, false)
    }

    /// Creates admin claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::admin().is_admin());
    /// ```
    #[must_use]
    pub const fn admin() -> Self {
        Self::new(true, true, true)
    }

    /// Returns whether stream publication is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::admin().can_broadcast());
    /// ```
    #[must_use]
    pub const fn can_broadcast(self) -> bool {
        self.broadcaster || self.admin
    }

    /// Returns whether watching streams is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::admin().can_view());
    /// ```
    #[must_use]
    pub const fn can_view(self) -> bool {
        self.viewer || self.admin
    }

    /// Returns whether administrative operations are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingClaims;
    /// assert!(StreamingClaims::admin().is_admin());
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
    /// # use refract_app::Stability;
    /// # use refract_app_streaming::StreamingClaims;
    /// assert_eq!(StreamingClaims::viewer().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Streaming app error taxonomy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StreamingError {
    /// Command exceeded the bounded input limit.
    #[error("streaming command too large: {len} > {max}")]
    CommandTooLarge {
        /// Observed command length.
        len: usize,
        /// Maximum command length.
        max: usize,
    },
    /// Protocol version is unsupported.
    #[error("unsupported streaming protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Requested protocol version.
        version: u16,
    },
    /// Stream identifier exceeded its bounded limit.
    #[error("stream id too large: {len} > {max}")]
    StreamIdTooLarge {
        /// Observed stream identifier length.
        len: usize,
        /// Maximum stream identifier length.
        max: usize,
    },
    /// JSON decoding failed.
    #[error("invalid streaming json: {0}")]
    Json(#[from] serde_json::Error),
}

impl StreamingError {
    /// Returns the unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingError;
    /// let error = StreamingError::UnsupportedProtocolVersion { version: 2 };
    /// assert_eq!(error.error_code(), "APP_STREAMING_PROTOCOL_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::CommandTooLarge { .. } => "APP_STREAMING_INPUT_0001",
            Self::UnsupportedProtocolVersion { .. } => "APP_STREAMING_PROTOCOL_0001",
            Self::StreamIdTooLarge { .. } => "APP_STREAMING_INPUT_0002",
            Self::Json(_) => "APP_STREAMING_INPUT_0003",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_streaming::StreamingError;
    /// let error = StreamingError::UnsupportedProtocolVersion { version: 2 };
    /// assert_eq!(error.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

type StreamingResult<T> = Result<T, StreamingError>;

/// Streaming application factory.
#[derive(Clone, Debug, Default)]
pub struct StreamingApp {
    state: Rc<RefCell<StreamingState>>,
}

impl StreamingApp {
    /// Creates a streaming app.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingApp;
    /// let app = StreamingApp::new();
    /// assert_eq!(app.stability(), refract_app::Stability::Stage1);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets JWT-derived claims for a session.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::{StreamingApp, StreamingClaims};
    /// # use refract_core::SessionId;
    /// let app = StreamingApp::new();
    /// app.set_claims(SessionId::from_raw(1), StreamingClaims::viewer());
    /// ```
    pub fn set_claims(&self, session_id: SessionId, claims: StreamingClaims) {
        self.state.borrow_mut().claims.insert(session_id, claims);
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingApp;
    /// assert_eq!(
    ///     StreamingApp::new().stability(),
    ///     refract_app::Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Application for StreamingApp {
    type Session = StreamingSession;

    fn name(&self) -> &'static str {
        "streaming"
    }

    fn api_version(&self) -> ApiVersion {
        ApiVersion::new(CURRENT_PROTOCOL_VERSION)
    }

    async fn create_session(&self, context: SessionContext) -> AppResult<Self::Session> {
        let claims = self
            .state
            .borrow()
            .claims
            .get(&context.session_id())
            .copied()
            .unwrap_or_default();
        Ok(StreamingSession {
            context,
            claims,
            state: Rc::clone(&self.state),
        })
    }
}

/// Streaming application session.
#[derive(Clone, Debug)]
pub struct StreamingSession {
    context: SessionContext,
    claims: StreamingClaims,
    state: Rc<RefCell<StreamingState>>,
}

impl StreamingSession {
    /// Returns the session claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::{StreamingClaims, StreamingSession};
    /// # fn assert_claims(session: &StreamingSession) {
    /// let _claims: StreamingClaims = session.claims();
    /// # }
    /// ```
    #[must_use]
    pub const fn claims(&self) -> StreamingClaims {
        self.claims
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_streaming::StreamingSession;
    /// # fn assert_stability(session: &StreamingSession) {
    /// assert_eq!(session.stability(), refract_app::Stability::Stage1);
    /// # }
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Session for StreamingSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        match StreamingCommand::parse(message.as_bytes()) {
            Ok(command) => self.apply_command(command, handle),
            Err(error) => send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code()),
        }
    }
}

impl StreamingSession {
    fn apply_command(
        &self,
        command: StreamingCommand,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let StreamingCommand {
            protocol_version,
            kind,
        } = command;
        match kind {
            StreamingKind::Publish {
                stream_id,
                track_id,
                ssrc,
                max_layer,
            } => self.publish(
                protocol_version,
                stream_id,
                PublisherTrackId::new(track_id),
                IngressSsrc::new(ssrc),
                max_layer
                    .unwrap_or(MAX_STREAMING_LAYER)
                    .min(MAX_STREAMING_LAYER),
                handle,
            ),
            StreamingKind::Watch { stream_id } => self.watch(protocol_version, &stream_id, handle),
            StreamingKind::Unwatch { stream_id } => {
                let track = self
                    .state
                    .borrow()
                    .streams
                    .get(&stream_id)
                    .map(|stream| stream.track);
                if let Some(track) = track {
                    handle.remove_route(track)?;
                    send_response(handle, &Response::ok(protocol_version, "unwatched"))
                } else {
                    send_error(handle, protocol_version, "APP_STREAMING_UNKNOWN_STREAM")
                }
            }
            StreamingKind::End { stream_id } => {
                if !self.claims.can_broadcast() && !self.claims.is_admin() {
                    return send_error(
                        handle,
                        protocol_version,
                        "APP_STREAMING_PERMISSION_PUBLISH",
                    );
                }
                let removed = self.state.borrow_mut().streams.remove(&stream_id);
                if removed.is_some() {
                    send_response(handle, &Response::ok(protocol_version, "ended"))
                } else {
                    send_error(handle, protocol_version, "APP_STREAMING_UNKNOWN_STREAM")
                }
            }
            StreamingKind::List => {
                if self.claims.can_view() || self.claims.is_admin() {
                    let response = Response::list(protocol_version, &self.state.borrow().streams);
                    send_response(handle, &response)
                } else {
                    send_error(handle, protocol_version, "APP_STREAMING_PERMISSION_VIEW")
                }
            }
        }
    }

    fn publish(
        &self,
        protocol_version: u16,
        stream_id: String,
        track: PublisherTrackId,
        ssrc: IngressSsrc,
        max_layer: u8,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.can_broadcast() {
            return send_error(handle, protocol_version, "APP_STREAMING_PERMISSION_PUBLISH");
        }
        self.state.borrow_mut().streams.insert(
            stream_id,
            StreamEntry {
                owner: self.context.session_id(),
                track,
                ssrc,
                max_layer,
            },
        );
        send_response(handle, &Response::ok(protocol_version, "published"))
    }

    fn watch(
        &self,
        protocol_version: u16,
        stream_id: &str,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.can_view() {
            return send_error(handle, protocol_version, "APP_STREAMING_PERMISSION_VIEW");
        }
        let stream = self.state.borrow().streams.get(stream_id).copied();
        if let Some(stream) = stream {
            add_stream_route(handle, handle.subscriber_id(), stream)?;
            send_response(handle, &Response::ok(protocol_version, "watching"))
        } else {
            send_error(handle, protocol_version, "APP_STREAMING_UNKNOWN_STREAM")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StreamEntry {
    owner: SessionId,
    track: PublisherTrackId,
    ssrc: IngressSsrc,
    max_layer: u8,
}

#[derive(Clone, Debug, Default)]
struct StreamingState {
    claims: BTreeMap<SessionId, StreamingClaims>,
    streams: BTreeMap<String, StreamEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct StreamingCommand {
    protocol_version: u16,
    #[serde(flatten)]
    kind: StreamingKind,
}

impl StreamingCommand {
    fn parse(bytes: &[u8]) -> StreamingResult<Self> {
        if bytes.len() > MAX_STREAMING_COMMAND_BYTES {
            return Err(StreamingError::CommandTooLarge {
                len: bytes.len(),
                max: MAX_STREAMING_COMMAND_BYTES,
            });
        }
        let command: Self = serde_json::from_slice(bytes)?;
        if command.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(StreamingError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        command.validate()?;
        Ok(command)
    }

    const fn validate(&self) -> StreamingResult<()> {
        let stream_id = match &self.kind {
            StreamingKind::Publish { stream_id, .. }
            | StreamingKind::Watch { stream_id }
            | StreamingKind::Unwatch { stream_id }
            | StreamingKind::End { stream_id } => stream_id,
            StreamingKind::List => return Ok(()),
        };
        if stream_id.len() > MAX_STREAM_ID_BYTES {
            Err(StreamingError::StreamIdTooLarge {
                len: stream_id.len(),
                max: MAX_STREAM_ID_BYTES,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum StreamingKind {
    Publish {
        stream_id: String,
        track_id: u64,
        ssrc: u32,
        max_layer: Option<u8>,
    },
    Watch {
        stream_id: String,
    },
    Unwatch {
        stream_id: String,
    },
    End {
        stream_id: String,
    },
    List,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct Response {
    protocol_version: u16,
    status: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    streams: Vec<StreamView>,
}

impl Response {
    const fn ok(protocol_version: u16, status: &'static str) -> Self {
        Self {
            protocol_version,
            status,
            code: "ok",
            streams: Vec::new(),
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            status: "error",
            code,
            streams: Vec::new(),
        }
    }

    fn list(protocol_version: u16, streams: &BTreeMap<String, StreamEntry>) -> Self {
        Self {
            protocol_version,
            status: "streams",
            code: "ok",
            streams: streams
                .iter()
                .map(|(stream_id, stream)| StreamView {
                    stream_id: stream_id.clone(),
                    owner_session_id: stream.owner.raw(),
                    track_id: stream.track.as_u64(),
                    ssrc: stream.ssrc.as_u32(),
                    max_layer: stream.max_layer,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct StreamView {
    stream_id: String,
    owner_session_id: u64,
    track_id: u64,
    ssrc: u32,
    max_layer: u8,
}

fn add_stream_route(
    handle: &mut SessionHandle,
    subscriber: SubscriberSessionId,
    stream: StreamEntry,
) -> AppResult<()> {
    let layers = (0..=stream.max_layer)
        .map(|layer_id| {
            let ordinal = u64::from(layer_id) + 1;
            Layer::new(
                LayerId::new(layer_id),
                BandwidthBps::new(STREAMING_LAYER0_BANDWIDTH_BPS.saturating_mul(ordinal)),
                QualityScore::new(u32::from(layer_id) + 1),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let subscription = Subscription::new(stream.track, subscriber, stream.ssrc, layers)?;
    handle.add_route(subscription)
}

fn send_error(
    handle: &mut SessionHandle,
    protocol_version: u16,
    code: &'static str,
) -> AppResult<()> {
    send_response(handle, &Response::error(protocol_version, code))
}

fn send_response(handle: &mut SessionHandle, response: &Response) -> AppResult<()> {
    let bytes =
        serde_json::to_vec(response).map_err(|_source| refract_app::AppError::Allocation {
            component: "app_streaming_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(&bytes)?)
}

#[cfg(test)]
mod tests {
    use refract_app::{
        Application, RoomView, Session, SessionContext, SessionHandle, SfuCoreCommand,
    };
    use refract_core::{PeerId, RoomId, SessionId};
    use serde_json::json;

    use super::{StreamingApp, StreamingClaims};

    fn context(session: u64) -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(session),
            PeerId::from_raw(session + 100),
            RoomId::from_raw(12),
        )
    }

    fn handle(session: u64) -> (SessionHandle, refract_app::SessionIo) {
        SessionHandle::new(
            context(session),
            RoomView::empty(RoomId::from_raw(12)),
            16,
            16,
        )
        .unwrap()
    }

    fn message(value: &serde_json::Value) -> refract_app::ClientMessage {
        refract_app::ClientMessage::try_from_bytes(value.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn streaming_publish_watch_integration_posts_route() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = StreamingApp::new();
            app.set_claims(SessionId::from_raw(1), StreamingClaims::broadcaster());
            app.set_claims(SessionId::from_raw(2), StreamingClaims::viewer());
            let mut publisher = app.create_session(context(1)).await.unwrap();
            let mut viewer = app.create_session(context(2)).await.unwrap();
            let (mut publisher_handle, mut publisher_io) = handle(1);
            let (mut viewer_handle, mut viewer_io) = handle(2);

            publisher
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "publish",
                        "stream_id": "main",
                        "track_id": 77,
                        "ssrc": 1234,
                        "max_layer": 2
                    })),
                    &mut publisher_handle,
                )
                .await
                .unwrap();
            assert!(
                String::from_utf8_lossy(publisher_io.client_outbox.pop().unwrap().as_bytes())
                    .contains("\"status\":\"published\"")
            );

            viewer
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "watch",
                        "stream_id": "main"
                    })),
                    &mut viewer_handle,
                )
                .await
                .unwrap();
            assert!(matches!(
                viewer_io.core_inbox.pop().unwrap(),
                SfuCoreCommand::AddSubscription(_)
            ));
        });
    }

    #[test]
    fn streaming_permission_enforced() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = StreamingApp::new();
            let mut session = app.create_session(context(3)).await.unwrap();
            let (mut handle, mut io) = handle(3);
            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "watch",
                        "stream_id": "main"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let response = io.client_outbox.pop().unwrap();
            assert!(
                String::from_utf8_lossy(response.as_bytes())
                    .contains("APP_STREAMING_PERMISSION_VIEW")
            );
        });
    }

    #[test]
    fn streaming_protocol_version_rejected() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = StreamingApp::new();
            app.set_claims(SessionId::from_raw(4), StreamingClaims::viewer());
            let mut session = app.create_session(context(4)).await.unwrap();
            let (mut handle, mut io) = handle(4);
            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 2,
                        "type": "list"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let response = io.client_outbox.pop().unwrap();
            assert!(
                String::from_utf8_lossy(response.as_bytes())
                    .contains("APP_STREAMING_PROTOCOL_0001")
            );
        });
    }
}
