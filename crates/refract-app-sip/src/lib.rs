//! SIP bridge application boundary.
//!
//! `refract-app-sip` owns the slow-path control protocol for admitting and
//! managing SIP bridge calls. Media forwarding remains in the `SFU` core; this
//! crate validates versioned JSON commands, enforces JWT-derived bridge/admin
//! permissions, and emits bounded client responses.
//!
//! # Examples
//!
//! ```
//! # use refract_app::{Application, SessionContext};
//! # use refract_app_sip::{SipApp, SipClaims};
//! # use refract_core::{PeerId, RoomId, SessionId};
//! let app = SipApp::new();
//! app.set_claims(SessionId::from_raw(1), SipClaims::bridge());
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

#[cfg(not(feature = "app-sip"))]
compile_error!("refract-app-sip must be built with the app-sip Cargo feature");

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, Session, SessionContext, SessionHandle,
    Stability,
};
use refract_core::SessionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current SIP app protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted SIP app JSON command bytes.
pub const MAX_SIP_COMMAND_BYTES: usize = refract_app::MAX_CLIENT_MESSAGE_BYTES;

/// Maximum accepted SIP URI bytes.
pub const MAX_SIP_URI_BYTES: usize = 512;

/// Maximum accepted DTMF digit bytes.
pub const MAX_DTMF_DIGITS: usize = 32;

/// JWT-derived SIP bridge claims.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SipClaims {
    bridge: bool,
    admin: bool,
}

impl SipClaims {
    /// Creates SIP claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipClaims;
    /// assert!(SipClaims::new(true, false).can_bridge());
    /// ```
    #[must_use]
    pub const fn new(bridge: bool, admin: bool) -> Self {
        Self { bridge, admin }
    }

    /// Creates bridge claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipClaims;
    /// assert!(SipClaims::bridge().can_bridge());
    /// ```
    #[must_use]
    pub const fn bridge() -> Self {
        Self::new(true, false)
    }

    /// Creates admin claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipClaims;
    /// assert!(SipClaims::admin().is_admin());
    /// ```
    #[must_use]
    pub const fn admin() -> Self {
        Self::new(true, true)
    }

    /// Returns whether SIP bridge operations are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipClaims;
    /// assert!(SipClaims::admin().can_bridge());
    /// ```
    #[must_use]
    pub const fn can_bridge(self) -> bool {
        self.bridge || self.admin
    }

    /// Returns whether administrative operations are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipClaims;
    /// assert!(SipClaims::admin().is_admin());
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
    /// # use refract_app_sip::SipClaims;
    /// assert_eq!(SipClaims::bridge().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// SIP app error taxonomy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SipError {
    /// Command exceeded the bounded input limit.
    #[error("sip command too large: {len} > {max}")]
    CommandTooLarge {
        /// Observed command length.
        len: usize,
        /// Maximum command length.
        max: usize,
    },
    /// Protocol version is unsupported.
    #[error("unsupported sip protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Requested protocol version.
        version: u16,
    },
    /// URI exceeded its bounded limit.
    #[error("sip uri too large: {len} > {max}")]
    UriTooLarge {
        /// Observed URI length.
        len: usize,
        /// Maximum URI length.
        max: usize,
    },
    /// DTMF sequence exceeded its bounded limit.
    #[error("dtmf sequence too large: {len} > {max}")]
    DtmfTooLarge {
        /// Observed digit length.
        len: usize,
        /// Maximum digit length.
        max: usize,
    },
    /// JSON decoding failed.
    #[error("invalid sip json: {0}")]
    Json(#[from] serde_json::Error),
}

impl SipError {
    /// Returns the unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipError;
    /// let error = SipError::UnsupportedProtocolVersion { version: 99 };
    /// assert_eq!(error.error_code(), "APP_SIP_PROTOCOL_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::CommandTooLarge { .. } => "APP_SIP_INPUT_0001",
            Self::UnsupportedProtocolVersion { .. } => "APP_SIP_PROTOCOL_0001",
            Self::UriTooLarge { .. } => "APP_SIP_INPUT_0002",
            Self::DtmfTooLarge { .. } => "APP_SIP_INPUT_0003",
            Self::Json(_) => "APP_SIP_INPUT_0004",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_sip::SipError;
    /// let error = SipError::UnsupportedProtocolVersion { version: 99 };
    /// assert_eq!(error.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

type SipResult<T> = Result<T, SipError>;

/// SIP application factory.
#[derive(Clone, Debug, Default)]
pub struct SipApp {
    state: Rc<RefCell<SipState>>,
}

impl SipApp {
    /// Creates a SIP app.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipApp;
    /// let app = SipApp::new();
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
    /// # use refract_app_sip::{SipApp, SipClaims};
    /// # use refract_core::SessionId;
    /// let app = SipApp::new();
    /// app.set_claims(SessionId::from_raw(7), SipClaims::bridge());
    /// ```
    pub fn set_claims(&self, session_id: SessionId, claims: SipClaims) {
        self.state.borrow_mut().claims.insert(session_id, claims);
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipApp;
    /// assert_eq!(SipApp::new().stability(), refract_app::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Application for SipApp {
    type Session = SipSession;

    fn name(&self) -> &'static str {
        "sip"
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
        Ok(SipSession {
            context,
            claims,
            state: Rc::clone(&self.state),
        })
    }
}

/// SIP application session.
#[derive(Clone, Debug)]
pub struct SipSession {
    context: SessionContext,
    claims: SipClaims,
    state: Rc<RefCell<SipState>>,
}

impl SipSession {
    /// Returns the session claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::{SipClaims, SipSession};
    /// # fn assert_claims(session: &SipSession) {
    /// let _claims: SipClaims = session.claims();
    /// # }
    /// ```
    #[must_use]
    pub const fn claims(&self) -> SipClaims {
        self.claims
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_sip::SipSession;
    /// # fn assert_stability(session: &SipSession) {
    /// assert_eq!(session.stability(), refract_app::Stability::Stage1);
    /// # }
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Session for SipSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        match SipCommand::parse(message.as_bytes()) {
            Ok(command) => self.apply_command(command, handle),
            Err(error) => send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code()),
        }
    }
}

impl SipSession {
    fn apply_command(&self, command: SipCommand, handle: &mut SessionHandle) -> AppResult<()> {
        let SipCommand {
            protocol_version,
            kind,
        } = command;
        match kind {
            SipKind::Invite { uri } => self.bridge_only(protocol_version, handle, |state| {
                let call_id = state.next_call_id;
                state.next_call_id = state.next_call_id.saturating_add(1);
                state.calls.insert(
                    call_id,
                    SipCall {
                        owner: self.context.session_id(),
                        uri,
                        active: true,
                    },
                );
                Ok(Response::call(protocol_version, "invited", call_id))
            }),
            SipKind::Bye { call_id } => self.bridge_only(protocol_version, handle, |state| {
                if let Some(call) = state.calls.get_mut(&call_id) {
                    call.active = false;
                    Ok(Response::call(protocol_version, "bye", call_id))
                } else {
                    Ok(Response::error(protocol_version, "APP_SIP_UNKNOWN_CALL"))
                }
            }),
            SipKind::Dtmf { call_id, digits } => {
                self.bridge_only(protocol_version, handle, |state| {
                    if state.calls.contains_key(&call_id) {
                        Ok(Response::dtmf(protocol_version, call_id, &digits))
                    } else {
                        Ok(Response::error(protocol_version, "APP_SIP_UNKNOWN_CALL"))
                    }
                })
            }
            SipKind::List => {
                if self.claims.is_admin() {
                    let response = Response::list(protocol_version, &self.state.borrow().calls);
                    send_response(handle, &response)
                } else {
                    send_error(handle, protocol_version, "APP_SIP_PERMISSION_ADMIN")
                }
            }
        }
    }

    fn bridge_only(
        &self,
        protocol_version: u16,
        handle: &mut SessionHandle,
        apply: impl FnOnce(&mut SipState) -> SipResult<Response>,
    ) -> AppResult<()> {
        if !self.claims.can_bridge() {
            return send_error(handle, protocol_version, "APP_SIP_PERMISSION_BRIDGE");
        }
        let response = apply(&mut self.state.borrow_mut())
            .unwrap_or_else(|error| Response::error(protocol_version, error.error_code()));
        send_response(handle, &response)
    }
}

#[derive(Clone, Debug, Default)]
struct SipState {
    claims: BTreeMap<SessionId, SipClaims>,
    calls: BTreeMap<u64, SipCall>,
    next_call_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SipCall {
    owner: SessionId,
    uri: String,
    active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct SipCommand {
    protocol_version: u16,
    #[serde(flatten)]
    kind: SipKind,
}

impl SipCommand {
    fn parse(bytes: &[u8]) -> SipResult<Self> {
        if bytes.len() > MAX_SIP_COMMAND_BYTES {
            return Err(SipError::CommandTooLarge {
                len: bytes.len(),
                max: MAX_SIP_COMMAND_BYTES,
            });
        }
        let command: Self = serde_json::from_slice(bytes)?;
        if command.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(SipError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        command.validate()?;
        Ok(command)
    }

    const fn validate(&self) -> SipResult<()> {
        match &self.kind {
            SipKind::Invite { uri } if uri.len() > MAX_SIP_URI_BYTES => {
                Err(SipError::UriTooLarge {
                    len: uri.len(),
                    max: MAX_SIP_URI_BYTES,
                })
            }
            SipKind::Dtmf { digits, .. } if digits.len() > MAX_DTMF_DIGITS => {
                Err(SipError::DtmfTooLarge {
                    len: digits.len(),
                    max: MAX_DTMF_DIGITS,
                })
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum SipKind {
    Invite { uri: String },
    Bye { call_id: u64 },
    Dtmf { call_id: u64, digits: String },
    List,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct Response {
    protocol_version: u16,
    status: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digits: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    calls: Vec<CallView>,
}

impl Response {
    const fn call(protocol_version: u16, status: &'static str, call_id: u64) -> Self {
        Self {
            protocol_version,
            status,
            code: "ok",
            call_id: Some(call_id),
            digits: None,
            calls: Vec::new(),
        }
    }

    fn dtmf(protocol_version: u16, call_id: u64, digits: &str) -> Self {
        Self {
            protocol_version,
            status: "dtmf",
            code: "ok",
            call_id: Some(call_id),
            digits: Some(digits.to_owned()),
            calls: Vec::new(),
        }
    }

    fn list(protocol_version: u16, calls: &BTreeMap<u64, SipCall>) -> Self {
        Self {
            protocol_version,
            status: "calls",
            code: "ok",
            call_id: None,
            digits: None,
            calls: calls
                .iter()
                .map(|(call_id, call)| CallView {
                    call_id: *call_id,
                    owner_session_id: call.owner.raw(),
                    uri: call.uri.clone(),
                    active: call.active,
                })
                .collect(),
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            status: "error",
            code,
            call_id: None,
            digits: None,
            calls: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct CallView {
    call_id: u64,
    owner_session_id: u64,
    uri: String,
    active: bool,
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
            component: "app_sip_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(&bytes)?)
}

#[cfg(test)]
mod tests {
    use refract_app::{Application, RoomView, Session, SessionContext, SessionHandle};
    use refract_core::{PeerId, RoomId, SessionId};
    use serde_json::json;

    use super::{SipApp, SipClaims};

    fn context(session: u64) -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(session),
            PeerId::from_raw(session + 100),
            RoomId::from_raw(9),
        )
    }

    fn handle(session: u64) -> (SessionHandle, refract_app::SessionIo) {
        SessionHandle::new(
            context(session),
            RoomView::empty(RoomId::from_raw(9)),
            16,
            16,
        )
        .unwrap()
    }

    fn message(value: &serde_json::Value) -> refract_app::ClientMessage {
        refract_app::ClientMessage::try_from_bytes(value.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn sip_invite_dtmf_bye_integration() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = SipApp::new();
            app.set_claims(SessionId::from_raw(1), SipClaims::bridge());
            let mut session = app.create_session(context(1)).await.unwrap();
            let (mut handle, mut io) = handle(1);

            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "invite",
                        "uri": "sip:room@example.test"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let invite = io.client_outbox.pop().unwrap();
            assert!(String::from_utf8_lossy(invite.as_bytes()).contains("\"call_id\":0"));

            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "dtmf",
                        "call_id": 0,
                        "digits": "123#"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let dtmf = io.client_outbox.pop().unwrap();
            assert!(String::from_utf8_lossy(dtmf.as_bytes()).contains("\"status\":\"dtmf\""));

            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "bye",
                        "call_id": 0
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let bye = io.client_outbox.pop().unwrap();
            assert!(String::from_utf8_lossy(bye.as_bytes()).contains("\"status\":\"bye\""));
        });
    }

    #[test]
    fn sip_permission_enforced() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = SipApp::new();
            let mut session = app.create_session(context(2)).await.unwrap();
            let (mut handle, mut io) = handle(2);
            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "invite",
                        "uri": "sip:room@example.test"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let response = io.client_outbox.pop().unwrap();
            assert!(
                String::from_utf8_lossy(response.as_bytes()).contains("APP_SIP_PERMISSION_BRIDGE")
            );
        });
    }

    #[test]
    fn sip_protocol_version_rejected() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = SipApp::new();
            app.set_claims(SessionId::from_raw(3), SipClaims::bridge());
            let mut session = app.create_session(context(3)).await.unwrap();
            let (mut handle, mut io) = handle(3);
            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 99,
                        "type": "list"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let response = io.client_outbox.pop().unwrap();
            assert!(String::from_utf8_lossy(response.as_bytes()).contains("APP_SIP_PROTOCOL_0001"));
        });
    }
}
