//! Text room application for non-media room events.
//!
//! The textroom app accepts bounded JSON commands for sending messages, listing
//! recent history, and deleting messages. Send and moderation permissions are
//! enforced from claim state assigned before session creation.
//!
//! # Examples
//!
//! ```
//! # use refract_app_textroom::{TextClaims, TextroomApp};
//! # use refract_core::SessionId;
//! let app = TextroomApp::new();
//! app.set_claims(SessionId::from_raw(1), TextClaims::moderator());
//! assert_eq!(app.protocol_version(), 1);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]

#[cfg(not(feature = "app-textroom"))]
compile_error!("enable the `app-textroom` Cargo feature to build refract-app-textroom");

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, Session, SessionContext, SessionHandle,
    Stability,
};
use refract_core::SessionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current textroom protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Maximum text payload bytes.
pub const MAX_TEXT_BYTES: usize = 4096;

/// Maximum retained messages.
pub const MAX_HISTORY: usize = 256;

/// Textroom claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextClaims {
    sender: bool,
    moderator: bool,
}

impl TextClaims {
    /// Creates textroom claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextClaims;
    /// assert!(TextClaims::new(true, false).can_send());
    /// ```
    #[must_use]
    pub const fn new(sender: bool, moderator: bool) -> Self {
        Self { sender, moderator }
    }

    /// Creates sender claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextClaims;
    /// assert!(TextClaims::sender().can_send());
    /// ```
    #[must_use]
    pub const fn sender() -> Self {
        Self::new(true, false)
    }

    /// Creates moderator claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextClaims;
    /// assert!(TextClaims::moderator().can_moderate());
    /// ```
    #[must_use]
    pub const fn moderator() -> Self {
        Self::new(true, true)
    }

    /// Returns whether sending is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextClaims;
    /// assert!(TextClaims::moderator().can_send());
    /// ```
    #[must_use]
    pub const fn can_send(self) -> bool {
        self.sender || self.moderator
    }

    /// Returns whether moderation is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextClaims;
    /// assert!(TextClaims::moderator().can_moderate());
    /// ```
    #[must_use]
    pub const fn can_moderate(self) -> bool {
        self.moderator
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_textroom::TextClaims;
    /// assert_eq!(TextClaims::sender().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Textroom protocol errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TextroomError {
    /// JSON parsing failed.
    #[error("invalid textroom json")]
    Json(#[from] serde_json::Error),
    /// Protocol version is unsupported.
    #[error("unsupported textroom protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Received protocol version.
        version: u16,
    },
    /// Text exceeds the configured limit.
    #[error("text too large: {len} > {max}")]
    TextTooLarge {
        /// Observed text bytes.
        len: usize,
        /// Configured maximum text bytes.
        max: usize,
    },
}

impl TextroomError {
    /// Returns a unique dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextroomError;
    /// assert_eq!(
    ///     TextroomError::UnsupportedProtocolVersion { version: 2 }.error_code(),
    ///     "APP_TEXTROOM_PROTOCOL_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Json(_) => "APP_TEXTROOM_INPUT_0001",
            Self::UnsupportedProtocolVersion { .. } => "APP_TEXTROOM_PROTOCOL_0001",
            Self::TextTooLarge { .. } => "APP_TEXTROOM_INPUT_0002",
        }
    }
}

/// Textroom app.
#[derive(Clone, Debug, Default)]
pub struct TextroomApp {
    state: Rc<RefCell<TextState>>,
}

impl TextroomApp {
    /// Creates a textroom app.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextroomApp;
    /// assert_eq!(TextroomApp::new().protocol_version(), 1);
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
    /// # use refract_app_textroom::{TextClaims, TextroomApp};
    /// # use refract_core::SessionId;
    /// let app = TextroomApp::new();
    /// app.set_claims(SessionId::from_raw(1), TextClaims::sender());
    /// ```
    pub fn set_claims(&self, session: SessionId, claims: TextClaims) {
        self.state.borrow_mut().claims.insert(session, claims);
    }

    /// Returns the protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_textroom::TextroomApp;
    /// assert_eq!(TextroomApp::new().protocol_version(), 1);
    /// ```
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        CURRENT_PROTOCOL_VERSION
    }
}

impl Application for TextroomApp {
    type Session = TextroomSession;

    fn name(&self) -> &'static str {
        "textroom"
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
        Ok(TextroomSession {
            state: self.state.clone(),
            context,
            claims,
        })
    }
}

/// Textroom session.
#[derive(Debug)]
pub struct TextroomSession {
    state: Rc<RefCell<TextState>>,
    context: SessionContext,
    claims: TextClaims,
}

impl Session for TextroomSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let command = match TextCommand::parse(message.as_bytes()) {
            Ok(command) => command,
            Err(error) => return send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code()),
        };
        match command.kind {
            TextCommandKind::Send { text } => {
                if !self.claims.can_send() {
                    return send_error(handle, command.protocol_version, "APP_TEXTROOM_PERMISSION");
                }
                let id = self
                    .state
                    .borrow_mut()
                    .push(self.context.session_id(), text);
                send_response(handle, &TextResponse::ok(command.protocol_version, id))
            }
            TextCommandKind::History => {
                let messages = self.state.borrow().messages.clone();
                send_response(
                    handle,
                    &TextResponse::history(command.protocol_version, messages),
                )
            }
            TextCommandKind::Delete { message_id } => {
                if !self.claims.can_moderate() {
                    return send_error(handle, command.protocol_version, "APP_TEXTROOM_PERMISSION");
                }
                self.state
                    .borrow_mut()
                    .messages
                    .retain(|message| message.id != message_id);
                send_response(
                    handle,
                    &TextResponse::ok(command.protocol_version, message_id),
                )
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TextState {
    claims: BTreeMap<SessionId, TextClaims>,
    messages: Vec<TextMessage>,
    next_id: u64,
}

impl TextState {
    fn push(&mut self, author: SessionId, text: String) -> u64 {
        self.next_id = self.next_id.saturating_add(1);
        self.messages.push(TextMessage {
            id: self.next_id,
            author: author.raw(),
            text,
        });
        if self.messages.len() > MAX_HISTORY {
            let overflow = self.messages.len() - MAX_HISTORY;
            self.messages.drain(0..overflow);
        }
        self.next_id
    }
}

#[derive(Clone, Debug, Serialize)]
struct TextMessage {
    id: u64,
    author: u64,
    text: String,
}

#[derive(Debug, Deserialize)]
struct TextCommand {
    protocol_version: u16,
    #[serde(flatten)]
    kind: TextCommandKind,
}

impl TextCommand {
    fn parse(bytes: &[u8]) -> Result<Self, TextroomError> {
        let command: Self = serde_json::from_slice(bytes)?;
        if command.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(TextroomError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        if let TextCommandKind::Send { text } = &command.kind
            && text.len() > MAX_TEXT_BYTES
        {
            return Err(TextroomError::TextTooLarge {
                len: text.len(),
                max: MAX_TEXT_BYTES,
            });
        }
        Ok(command)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum TextCommandKind {
    Send { text: String },
    History,
    Delete { message_id: u64 },
}

#[derive(Debug, Serialize)]
struct TextResponse {
    protocol_version: u16,
    status: &'static str,
    message_id: Option<u64>,
    messages: Option<Vec<TextMessage>>,
    code: Option<&'static str>,
}

impl TextResponse {
    const fn ok(protocol_version: u16, message_id: u64) -> Self {
        Self {
            protocol_version,
            status: "ok",
            message_id: Some(message_id),
            messages: None,
            code: None,
        }
    }

    const fn history(protocol_version: u16, messages: Vec<TextMessage>) -> Self {
        Self {
            protocol_version,
            status: "ok",
            message_id: None,
            messages: Some(messages),
            code: None,
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            status: "error",
            message_id: None,
            messages: None,
            code: Some(code),
        }
    }
}

fn send_response(handle: &mut SessionHandle, response: &TextResponse) -> AppResult<()> {
    let bytes =
        serde_json::to_vec(response).map_err(|_source| refract_app::AppError::Allocation {
            component: "textroom_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(bytes.as_slice())?)
}

fn send_error(
    handle: &mut SessionHandle,
    protocol_version: u16,
    code: &'static str,
) -> AppResult<()> {
    send_response(handle, &TextResponse::error(protocol_version, code))
}

#[cfg(test)]
mod tests {
    use compio::runtime::Runtime;
    use refract_core::{PeerId, RoomId};

    use super::*;

    fn context(session: u64) -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(session),
            PeerId::from_raw(session),
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
    fn textroom_send_history_integration() {
        Runtime::new().unwrap().block_on(async {
            let app = TextroomApp::new();
            app.set_claims(SessionId::from_raw(1), TextClaims::sender());
            let mut session = app.create_session(context(1)).await.unwrap();
            let (mut handle, mut io) = handle(1);

            session
                .handle_message(
                    ClientMessage::try_from_bytes(
                        br#"{"protocol_version":1,"type":"send","text":"hello"}"#,
                    )
                    .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();
            session
                .handle_message(
                    ClientMessage::try_from_bytes(br#"{"protocol_version":1,"type":"history"}"#)
                        .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();

            let mut saw_text = false;
            while let Ok(message) = io.client_outbox.pop() {
                saw_text |= std::str::from_utf8(message.as_bytes())
                    .unwrap()
                    .contains("hello");
            }
            assert!(saw_text);
        });
    }

    #[test]
    fn textroom_permission_enforced() {
        Runtime::new().unwrap().block_on(async {
            let app = TextroomApp::new();
            let mut session = app.create_session(context(1)).await.unwrap();
            let (mut handle, mut io) = handle(1);

            session
                .handle_message(
                    ClientMessage::try_from_bytes(
                        br#"{"protocol_version":1,"type":"send","text":"blocked"}"#,
                    )
                    .unwrap(),
                    &mut handle,
                )
                .await
                .unwrap();

            assert!(
                std::str::from_utf8(io.client_outbox.pop().unwrap().as_bytes())
                    .unwrap()
                    .contains("APP_TEXTROOM_PERMISSION")
            );
        });
    }

    #[test]
    fn textroom_protocol_version_rejected() {
        assert!(matches!(
            TextCommand::parse(br#"{"protocol_version":2,"type":"history"}"#),
            Err(TextroomError::UnsupportedProtocolVersion { version: 2 })
        ));
    }
}
