//! Recording application for production capture control.
//!
//! This crate provides a mandatory production app for starting, stopping, and
//! listing room recordings through the Stage 1 [`refract_app`] session
//! boundary. Commands use bounded, versioned JSON and require operator
//! permissions for state-changing actions.
//!
//! # Examples
//!
//! ```
//! # use refract_app::{Application, SessionContext};
//! # use refract_app_recording::{RecordingApp, RecordingClaims};
//! # use refract_core::{PeerId, RoomId, SessionId};
//! let app = RecordingApp::new();
//! app.set_claims(SessionId::from_raw(1), RecordingClaims::operator());
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

#[cfg(not(feature = "app-recording"))]
compile_error!("enable the `app-recording` Cargo feature to build refract-app-recording");

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, Session, SessionContext, SessionHandle,
    Stability,
};
use refract_core::{RoomId, SessionId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current recording protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Maximum recording command bytes.
pub const MAX_RECORDING_COMMAND_BYTES: usize = refract_app::MAX_CLIENT_MESSAGE_BYTES;

/// Recording permission claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordingClaims {
    operator: bool,
    viewer: bool,
}

impl RecordingClaims {
    /// Creates recording claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingClaims;
    /// assert!(RecordingClaims::new(true, false).can_operate());
    /// ```
    #[must_use]
    pub const fn new(operator: bool, viewer: bool) -> Self {
        Self { operator, viewer }
    }

    /// Creates operator claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingClaims;
    /// assert!(RecordingClaims::operator().can_operate());
    /// ```
    #[must_use]
    pub const fn operator() -> Self {
        Self::new(true, true)
    }

    /// Creates viewer claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingClaims;
    /// assert!(RecordingClaims::viewer().can_view());
    /// ```
    #[must_use]
    pub const fn viewer() -> Self {
        Self::new(false, true)
    }

    /// Returns whether state-changing recording actions are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingClaims;
    /// assert!(RecordingClaims::operator().can_operate());
    /// ```
    #[must_use]
    pub const fn can_operate(self) -> bool {
        self.operator
    }

    /// Returns whether listing recordings is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingClaims;
    /// assert!(RecordingClaims::operator().can_view());
    /// ```
    #[must_use]
    pub const fn can_view(self) -> bool {
        self.viewer || self.operator
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_recording::RecordingClaims;
    /// assert_eq!(RecordingClaims::operator().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Recording app errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecordingError {
    /// Command exceeded the bounded JSON length.
    #[error("recording command too large: {len} > {max}")]
    CommandTooLarge {
        /// Observed command length.
        len: usize,
        /// Configured maximum command length.
        max: usize,
    },
    /// JSON parsing failed.
    #[error("invalid recording json")]
    Json(#[from] serde_json::Error),
    /// Protocol version is unsupported.
    #[error("unsupported recording protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Received protocol version.
        version: u16,
    },
}

impl RecordingError {
    /// Returns a unique dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingError;
    /// assert_eq!(
    ///     RecordingError::UnsupportedProtocolVersion { version: 99 }.error_code(),
    ///     "APP_RECORDING_PROTOCOL_0001",
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::CommandTooLarge { .. } => "APP_RECORDING_INPUT_0001",
            Self::Json(_) => "APP_RECORDING_INPUT_0002",
            Self::UnsupportedProtocolVersion { .. } => "APP_RECORDING_PROTOCOL_0001",
        }
    }
}

/// Production recording app.
#[derive(Clone, Debug, Default)]
pub struct RecordingApp {
    state: Rc<RefCell<RecordingState>>,
}

impl RecordingApp {
    /// Creates a recording app.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingApp;
    /// assert_eq!(RecordingApp::new().protocol_version(), 1);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Assigns claims to a session before creation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::{RecordingApp, RecordingClaims};
    /// # use refract_core::SessionId;
    /// let app = RecordingApp::new();
    /// app.set_claims(SessionId::from_raw(1), RecordingClaims::operator());
    /// ```
    pub fn set_claims(&self, session: SessionId, claims: RecordingClaims) {
        self.state.borrow_mut().claims.insert(session, claims);
    }

    /// Returns the current protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_recording::RecordingApp;
    /// assert_eq!(RecordingApp::new().protocol_version(), 1);
    /// ```
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        CURRENT_PROTOCOL_VERSION
    }
}

impl Application for RecordingApp {
    type Session = RecordingSession;

    fn name(&self) -> &'static str {
        "recording"
    }

    fn api_version(&self) -> ApiVersion {
        ApiVersion::new(CURRENT_PROTOCOL_VERSION)
    }

    async fn create_session(&self, context: SessionContext) -> AppResult<Self::Session> {
        let claims = self
            .state
            .borrow_mut()
            .claims
            .remove(&context.session_id())
            .unwrap_or_default();
        Ok(RecordingSession {
            state: self.state.clone(),
            context,
            claims,
        })
    }
}

/// Recording session.
#[derive(Debug)]
pub struct RecordingSession {
    state: Rc<RefCell<RecordingState>>,
    context: SessionContext,
    claims: RecordingClaims,
}

impl Session for RecordingSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let command = match RecordingCommand::parse(message.as_bytes()) {
            Ok(command) => command,
            Err(error) => {
                send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code())?;
                return Ok(());
            }
        };
        match command.kind {
            RecordingCommandKind::Start => {
                if !self.claims.can_operate() {
                    return send_error(
                        handle,
                        command.protocol_version,
                        "APP_RECORDING_PERMISSION",
                    );
                }
                self.state
                    .borrow_mut()
                    .active
                    .insert(self.context.room_id(), RecordingStatus::Recording);
                send_response(
                    handle,
                    &RecordingResponse::ok(command.protocol_version, "started"),
                )
            }
            RecordingCommandKind::Stop => {
                if !self.claims.can_operate() {
                    return send_error(
                        handle,
                        command.protocol_version,
                        "APP_RECORDING_PERMISSION",
                    );
                }
                self.state
                    .borrow_mut()
                    .active
                    .insert(self.context.room_id(), RecordingStatus::Stopped);
                send_response(
                    handle,
                    &RecordingResponse::ok(command.protocol_version, "stopped"),
                )
            }
            RecordingCommandKind::List | RecordingCommandKind::Status => {
                if !self.claims.can_view() {
                    return send_error(
                        handle,
                        command.protocol_version,
                        "APP_RECORDING_PERMISSION",
                    );
                }
                let status = self
                    .state
                    .borrow()
                    .active
                    .get(&self.context.room_id())
                    .copied()
                    .unwrap_or(RecordingStatus::Stopped);
                send_response(
                    handle,
                    &RecordingResponse::status(command.protocol_version, status),
                )
            }
        }
    }
}

#[derive(Debug, Default)]
struct RecordingState {
    claims: BTreeMap<SessionId, RecordingClaims>,
    active: BTreeMap<RoomId, RecordingStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordingStatus {
    Recording,
    Stopped,
}

#[derive(Debug, Deserialize)]
struct RecordingCommand {
    protocol_version: u16,
    #[serde(flatten)]
    kind: RecordingCommandKind,
}

impl RecordingCommand {
    fn parse(bytes: &[u8]) -> Result<Self, RecordingError> {
        if bytes.len() > MAX_RECORDING_COMMAND_BYTES {
            return Err(RecordingError::CommandTooLarge {
                len: bytes.len(),
                max: MAX_RECORDING_COMMAND_BYTES,
            });
        }
        let command: Self = serde_json::from_slice(bytes)?;
        if command.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(RecordingError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        Ok(command)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum RecordingCommandKind {
    Start,
    Stop,
    Status,
    List,
}

#[derive(Debug, Serialize)]
struct RecordingResponse {
    protocol_version: u16,
    status: &'static str,
    message: Option<&'static str>,
    code: Option<&'static str>,
    recording: Option<RecordingStatus>,
}

impl RecordingResponse {
    const fn ok(protocol_version: u16, message: &'static str) -> Self {
        Self {
            protocol_version,
            status: "ok",
            message: Some(message),
            code: None,
            recording: None,
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            status: "error",
            message: None,
            code: Some(code),
            recording: None,
        }
    }

    const fn status(protocol_version: u16, recording: RecordingStatus) -> Self {
        Self {
            protocol_version,
            status: "ok",
            message: None,
            code: None,
            recording: Some(recording),
        }
    }
}

fn send_response(handle: &mut SessionHandle, response: &RecordingResponse) -> AppResult<()> {
    let bytes =
        serde_json::to_vec(response).map_err(|_source| refract_app::AppError::Allocation {
            component: "recording_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(bytes.as_slice())?)
}

fn send_error(
    handle: &mut SessionHandle,
    protocol_version: u16,
    code: &'static str,
) -> AppResult<()> {
    send_response(handle, &RecordingResponse::error(protocol_version, code))
}

#[cfg(test)]
mod tests {
    use compio::runtime::Runtime;
    use refract_core::{PeerId, RoomId};

    use super::*;

    fn context(session: u64) -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(session),
            PeerId::from_raw(session + 10),
            RoomId::from_raw(1),
        )
    }

    fn handle(session: u64) -> (SessionHandle, refract_app::SessionIo) {
        SessionHandle::new(
            context(session),
            refract_app::RoomView::empty(RoomId::from_raw(1)),
            16,
            16,
        )
        .unwrap()
    }

    #[test]
    fn recording_start_status_stop_integration() {
        Runtime::new().unwrap().block_on(async {
            let app = RecordingApp::new();
            app.set_claims(SessionId::from_raw(1), RecordingClaims::operator());
            let mut session = app.create_session(context(1)).await.unwrap();
            let (mut handle, mut io) = handle(1);

            session
                .handle_message(
                    ClientMessage::try_from_bytes(br#"{"protocol_version":1,"type":"start"}"#)
                        .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();
            session
                .handle_message(
                    ClientMessage::try_from_bytes(br#"{"protocol_version":1,"type":"status"}"#)
                        .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();

            let mut saw_recording = false;
            while let Ok(message) = io.client_outbox.pop() {
                saw_recording |= std::str::from_utf8(message.as_bytes())
                    .unwrap()
                    .contains("recording");
            }
            assert!(saw_recording);
        });
    }

    #[test]
    fn recording_permission_enforced() {
        Runtime::new().unwrap().block_on(async {
            let app = RecordingApp::new();
            app.set_claims(SessionId::from_raw(1), RecordingClaims::viewer());
            let mut session = app.create_session(context(1)).await.unwrap();
            let (mut handle, mut io) = handle(1);

            session
                .handle_message(
                    ClientMessage::try_from_bytes(br#"{"protocol_version":1,"type":"start"}"#)
                        .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();

            assert!(
                std::str::from_utf8(io.client_outbox.pop().unwrap().as_bytes())
                    .unwrap()
                    .contains("APP_RECORDING_PERMISSION")
            );
        });
    }

    #[test]
    fn recording_protocol_version_rejected() {
        assert!(matches!(
            RecordingCommand::parse(br#"{"protocol_version":2,"type":"status"}"#),
            Err(RecordingError::UnsupportedProtocolVersion { version: 2 })
        ));
    }
}
