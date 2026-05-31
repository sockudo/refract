//! Diagnostic echo application for loopback validation.
//!
//! The echo app accepts a versioned JSON `echo` command and returns the same
//! payload when the session has echo permission. It is useful for smoke tests,
//! control-plane latency checks, and client SDK validation.
//!
//! # Examples
//!
//! ```
//! # use refract_app_echo::{EchoApp, EchoClaims};
//! # use refract_core::SessionId;
//! let app = EchoApp::new();
//! app.set_claims(SessionId::from_raw(1), EchoClaims::enabled());
//! assert_eq!(app.protocol_version(), 1);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]

#[cfg(not(feature = "app-echo"))]
compile_error!("enable the `app-echo` Cargo feature to build refract-app-echo");

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, Session, SessionContext, SessionHandle,
    Stability,
};
use refract_core::SessionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current echo protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Maximum echo payload bytes.
pub const MAX_ECHO_PAYLOAD_BYTES: usize = 4096;

/// Echo permission claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EchoClaims {
    enabled: bool,
}

impl EchoClaims {
    /// Creates claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::EchoClaims;
    /// assert!(EchoClaims::new(true).can_echo());
    /// ```
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Creates enabled claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::EchoClaims;
    /// assert!(EchoClaims::enabled().can_echo());
    /// ```
    #[must_use]
    pub const fn enabled() -> Self {
        Self::new(true)
    }

    /// Returns whether echo is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::EchoClaims;
    /// assert!(!EchoClaims::default().can_echo());
    /// ```
    #[must_use]
    pub const fn can_echo(self) -> bool {
        self.enabled
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_echo::EchoClaims;
    /// assert_eq!(EchoClaims::enabled().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Echo protocol errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EchoError {
    /// JSON parsing failed.
    #[error("invalid echo json")]
    Json(#[from] serde_json::Error),
    /// Protocol version is unsupported.
    #[error("unsupported echo protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Received protocol version.
        version: u16,
    },
    /// Payload exceeds the echo limit.
    #[error("echo payload too large: {len} > {max}")]
    PayloadTooLarge {
        /// Observed payload bytes.
        len: usize,
        /// Configured maximum payload bytes.
        max: usize,
    },
}

impl EchoError {
    /// Returns a unique dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::EchoError;
    /// assert_eq!(
    ///     EchoError::UnsupportedProtocolVersion { version: 2 }.error_code(),
    ///     "APP_ECHO_PROTOCOL_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Json(_) => "APP_ECHO_INPUT_0001",
            Self::UnsupportedProtocolVersion { .. } => "APP_ECHO_PROTOCOL_0001",
            Self::PayloadTooLarge { .. } => "APP_ECHO_INPUT_0002",
        }
    }
}

/// Echo application.
#[derive(Clone, Debug, Default)]
pub struct EchoApp {
    claims: Rc<RefCell<BTreeMap<SessionId, EchoClaims>>>,
}

impl EchoApp {
    /// Creates an echo app.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::EchoApp;
    /// assert_eq!(EchoApp::new().protocol_version(), 1);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Assigns claims before session creation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::{EchoApp, EchoClaims};
    /// # use refract_core::SessionId;
    /// let app = EchoApp::new();
    /// app.set_claims(SessionId::from_raw(1), EchoClaims::enabled());
    /// ```
    pub fn set_claims(&self, session: SessionId, claims: EchoClaims) {
        self.claims.borrow_mut().insert(session, claims);
    }

    /// Returns the protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_echo::EchoApp;
    /// assert_eq!(EchoApp::new().protocol_version(), 1);
    /// ```
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        CURRENT_PROTOCOL_VERSION
    }
}

impl Application for EchoApp {
    type Session = EchoSession;

    fn name(&self) -> &'static str {
        "echo"
    }

    fn api_version(&self) -> ApiVersion {
        ApiVersion::new(CURRENT_PROTOCOL_VERSION)
    }

    async fn create_session(&self, context: SessionContext) -> AppResult<Self::Session> {
        let claims = self
            .claims
            .borrow_mut()
            .remove(&context.session_id())
            .unwrap_or_default();
        Ok(EchoSession { claims })
    }
}

/// Echo session.
#[derive(Debug)]
pub struct EchoSession {
    claims: EchoClaims,
}

impl Session for EchoSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let command = match EchoCommand::parse(message.as_bytes()) {
            Ok(command) => command,
            Err(error) => {
                return send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code());
            }
        };
        if !self.claims.can_echo() {
            return send_error(handle, command.protocol_version, "APP_ECHO_PERMISSION");
        }
        send_response(
            handle,
            &EchoResponse::ok(command.protocol_version, command.payload.as_str()),
        )
    }
}

#[derive(Debug, Deserialize)]
struct EchoCommand {
    protocol_version: u16,
    #[serde(rename = "type")]
    kind: EchoKind,
    payload: String,
}

impl EchoCommand {
    fn parse(bytes: &[u8]) -> Result<Self, EchoError> {
        let command: Self = serde_json::from_slice(bytes)?;
        if command.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(EchoError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        let EchoKind::Echo = command.kind;
        if command.payload.len() > MAX_ECHO_PAYLOAD_BYTES {
            return Err(EchoError::PayloadTooLarge {
                len: command.payload.len(),
                max: MAX_ECHO_PAYLOAD_BYTES,
            });
        }
        Ok(command)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum EchoKind {
    Echo,
}

#[derive(Debug, Serialize)]
struct EchoResponse<'a> {
    protocol_version: u16,
    status: &'static str,
    payload: Option<&'a str>,
    code: Option<&'static str>,
}

impl<'a> EchoResponse<'a> {
    const fn ok(protocol_version: u16, payload: &'a str) -> Self {
        Self {
            protocol_version,
            status: "ok",
            payload: Some(payload),
            code: None,
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            status: "error",
            payload: None,
            code: Some(code),
        }
    }
}

fn send_response(handle: &mut SessionHandle, response: &EchoResponse<'_>) -> AppResult<()> {
    let bytes =
        serde_json::to_vec(response).map_err(|_source| refract_app::AppError::Allocation {
            component: "echo_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(bytes.as_slice())?)
}

fn send_error(
    handle: &mut SessionHandle,
    protocol_version: u16,
    code: &'static str,
) -> AppResult<()> {
    send_response(handle, &EchoResponse::error(protocol_version, code))
}

#[cfg(test)]
mod tests {
    use compio::runtime::Runtime;
    use refract_core::{PeerId, RoomId};

    use super::*;

    fn context() -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(1),
            PeerId::from_raw(1),
            RoomId::from_raw(1),
        )
    }

    #[test]
    fn echo_integration_round_trips_payload() {
        Runtime::new().unwrap().block_on(async {
            let app = EchoApp::new();
            app.set_claims(SessionId::from_raw(1), EchoClaims::enabled());
            let mut session = app.create_session(context()).await.unwrap();
            let (mut handle, mut io) = SessionHandle::new(
                context(),
                refract_app::RoomView::empty(RoomId::from_raw(1)),
                4,
                4,
            )
            .unwrap();

            session
                .handle_message(
                    ClientMessage::try_from_bytes(
                        br#"{"protocol_version":1,"type":"echo","payload":"hello"}"#,
                    )
                    .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();

            assert!(
                std::str::from_utf8(io.client_outbox.pop().unwrap().as_bytes())
                    .unwrap()
                    .contains("hello")
            );
        });
    }

    #[test]
    fn echo_permission_enforced() {
        Runtime::new().unwrap().block_on(async {
            let app = EchoApp::new();
            let mut session = app.create_session(context()).await.unwrap();
            let (mut handle, mut io) = SessionHandle::new(
                context(),
                refract_app::RoomView::empty(RoomId::from_raw(1)),
                4,
                4,
            )
            .unwrap();

            session
                .handle_message(
                    ClientMessage::try_from_bytes(
                        br#"{"protocol_version":1,"type":"echo","payload":"hello"}"#,
                    )
                    .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();

            assert!(
                std::str::from_utf8(io.client_outbox.pop().unwrap().as_bytes())
                    .unwrap()
                    .contains("APP_ECHO_PERMISSION")
            );
        });
    }

    #[test]
    fn echo_protocol_version_rejected() {
        assert!(matches!(
            EchoCommand::parse(br#"{"protocol_version":2,"type":"echo","payload":"x"}"#),
            Err(EchoError::UnsupportedProtocolVersion { version: 2 })
        ));
    }
}
