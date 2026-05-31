//! Audio mixing application boundary kept outside the forwarding hot path.
//!
//! `refract-app-audiomix` manages slow-path mixer membership, mute state, gain
//! control, and active-speaker selection through a bounded, versioned JSON
//! protocol. The app enforces JWT-derived participant, mixer, and admin roles
//! before mutating mixer state.
//!
//! # Examples
//!
//! ```
//! # use refract_app::{Application, SessionContext};
//! # use refract_app_audiomix::{AudiomixApp, AudiomixClaims};
//! # use refract_core::{PeerId, RoomId, SessionId};
//! let app = AudiomixApp::new();
//! app.set_claims(SessionId::from_raw(1), AudiomixClaims::participant());
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

#[cfg(not(feature = "app-audiomix"))]
compile_error!("refract-app-audiomix must be built with the app-audiomix Cargo feature");

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use refract_app::{
    ApiVersion, AppResult, Application, ClientMessage, Session, SessionContext, SessionHandle,
    Stability,
};
use refract_core::SessionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current audiomix app protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted audiomix app JSON command bytes.
pub const MAX_AUDIOMIX_COMMAND_BYTES: usize = refract_app::MAX_CLIENT_MESSAGE_BYTES;

/// Maximum accepted mix identifier bytes.
pub const MAX_MIX_ID_BYTES: usize = 128;

/// Minimum accepted gain in millibels.
pub const MIN_GAIN_MB: i16 = -6_000;

/// Maximum accepted gain in millibels.
pub const MAX_GAIN_MB: i16 = 2_400;

/// JWT-derived audiomix claims.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct AudiomixClaims {
    participant: bool,
    mixer: bool,
    admin: bool,
}

impl AudiomixClaims {
    /// Creates audiomix claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::new(true, false, false).can_participate());
    /// ```
    #[must_use]
    pub const fn new(participant: bool, mixer: bool, admin: bool) -> Self {
        Self {
            participant,
            mixer,
            admin,
        }
    }

    /// Creates participant claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::participant().can_participate());
    /// ```
    #[must_use]
    pub const fn participant() -> Self {
        Self::new(true, false, false)
    }

    /// Creates mixer claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::mixer().can_mix());
    /// ```
    #[must_use]
    pub const fn mixer() -> Self {
        Self::new(true, true, false)
    }

    /// Creates admin claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::admin().is_admin());
    /// ```
    #[must_use]
    pub const fn admin() -> Self {
        Self::new(true, true, true)
    }

    /// Returns whether joining a mix is allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::admin().can_participate());
    /// ```
    #[must_use]
    pub const fn can_participate(self) -> bool {
        self.participant || self.admin
    }

    /// Returns whether mixer operations are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::admin().can_mix());
    /// ```
    #[must_use]
    pub const fn can_mix(self) -> bool {
        self.mixer || self.admin
    }

    /// Returns whether administrative operations are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert!(AudiomixClaims::admin().is_admin());
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
    /// # use refract_app_audiomix::AudiomixClaims;
    /// assert_eq!(AudiomixClaims::participant().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Audiomix app error taxonomy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AudiomixError {
    /// Command exceeded the bounded input limit.
    #[error("audiomix command too large: {len} > {max}")]
    CommandTooLarge {
        /// Observed command length.
        len: usize,
        /// Maximum command length.
        max: usize,
    },
    /// Protocol version is unsupported.
    #[error("unsupported audiomix protocol version: {version}")]
    UnsupportedProtocolVersion {
        /// Requested protocol version.
        version: u16,
    },
    /// Mix identifier exceeded its bounded limit.
    #[error("mix id too large: {len} > {max}")]
    MixIdTooLarge {
        /// Observed mix identifier length.
        len: usize,
        /// Maximum mix identifier length.
        max: usize,
    },
    /// Gain value is outside the accepted clamp.
    #[error("gain out of range: {value}")]
    GainOutOfRange {
        /// Requested gain value.
        value: i16,
    },
    /// JSON decoding failed.
    #[error("invalid audiomix json: {0}")]
    Json(#[from] serde_json::Error),
}

impl AudiomixError {
    /// Returns the unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixError;
    /// let error = AudiomixError::UnsupportedProtocolVersion { version: 2 };
    /// assert_eq!(error.error_code(), "APP_AUDIOMIX_PROTOCOL_0001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::CommandTooLarge { .. } => "APP_AUDIOMIX_INPUT_0001",
            Self::UnsupportedProtocolVersion { .. } => "APP_AUDIOMIX_PROTOCOL_0001",
            Self::MixIdTooLarge { .. } => "APP_AUDIOMIX_INPUT_0002",
            Self::GainOutOfRange { .. } => "APP_AUDIOMIX_INPUT_0003",
            Self::Json(_) => "APP_AUDIOMIX_INPUT_0004",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app::Stability;
    /// # use refract_app_audiomix::AudiomixError;
    /// let error = AudiomixError::UnsupportedProtocolVersion { version: 2 };
    /// assert_eq!(error.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

type AudiomixResult<T> = Result<T, AudiomixError>;

/// Audiomix application factory.
#[derive(Clone, Debug, Default)]
pub struct AudiomixApp {
    state: Rc<RefCell<AudiomixState>>,
}

impl AudiomixApp {
    /// Creates an audiomix app.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixApp;
    /// let app = AudiomixApp::new();
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
    /// # use refract_app_audiomix::{AudiomixApp, AudiomixClaims};
    /// # use refract_core::SessionId;
    /// let app = AudiomixApp::new();
    /// app.set_claims(SessionId::from_raw(1), AudiomixClaims::participant());
    /// ```
    pub fn set_claims(&self, session_id: SessionId, claims: AudiomixClaims) {
        self.state.borrow_mut().claims.insert(session_id, claims);
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixApp;
    /// assert_eq!(
    ///     AudiomixApp::new().stability(),
    ///     refract_app::Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Application for AudiomixApp {
    type Session = AudiomixSession;

    fn name(&self) -> &'static str {
        "audiomix"
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
        Ok(AudiomixSession {
            context,
            claims,
            state: Rc::clone(&self.state),
        })
    }
}

/// Audiomix application session.
#[derive(Clone, Debug)]
pub struct AudiomixSession {
    context: SessionContext,
    claims: AudiomixClaims,
    state: Rc<RefCell<AudiomixState>>,
}

impl AudiomixSession {
    /// Returns the session claims.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::{AudiomixClaims, AudiomixSession};
    /// # fn assert_claims(session: &AudiomixSession) {
    /// let _claims: AudiomixClaims = session.claims();
    /// # }
    /// ```
    #[must_use]
    pub const fn claims(&self) -> AudiomixClaims {
        self.claims
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_app_audiomix::AudiomixSession;
    /// # fn assert_stability(session: &AudiomixSession) {
    /// assert_eq!(session.stability(), refract_app::Stability::Stage1);
    /// # }
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Session for AudiomixSession {
    async fn handle_message(
        &mut self,
        message: ClientMessage,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        match AudiomixCommand::parse(message.as_bytes()) {
            Ok(command) => self.apply_command(command, handle),
            Err(error) => send_error(handle, CURRENT_PROTOCOL_VERSION, error.error_code()),
        }
    }
}

impl AudiomixSession {
    fn apply_command(&self, command: AudiomixCommand, handle: &mut SessionHandle) -> AppResult<()> {
        let AudiomixCommand {
            protocol_version,
            kind,
        } = command;
        match kind {
            AudiomixKind::JoinMix { mix_id } => self.join_mix(protocol_version, &mix_id, handle),
            AudiomixKind::LeaveMix { mix_id } => {
                self.state
                    .borrow_mut()
                    .mix_mut(&mix_id)
                    .participants
                    .remove(&self.context.session_id());
                send_response(handle, &Response::ok(protocol_version, "left"))
            }
            AudiomixKind::SetGain {
                mix_id,
                session_id,
                gain_mb,
            } => self.mixer_only(protocol_version, handle, |state| {
                let target = SessionId::from_raw(session_id);
                if let Some(member) = state.mix_mut(&mix_id).participants.get_mut(&target) {
                    member.gain_mb = gain_mb;
                    Ok(Response::ok(protocol_version, "gain_set"))
                } else {
                    Ok(Response::error(
                        protocol_version,
                        "APP_AUDIOMIX_UNKNOWN_SESSION",
                    ))
                }
            }),
            AudiomixKind::Mute { mix_id, session_id } => {
                self.set_muted(protocol_version, &mix_id, session_id, true, handle)
            }
            AudiomixKind::Unmute { mix_id, session_id } => {
                self.set_muted(protocol_version, &mix_id, session_id, false, handle)
            }
            AudiomixKind::AudioLevel {
                mix_id,
                session_id,
                level,
            } => self.audio_level(protocol_version, &mix_id, session_id, level, handle),
            AudiomixKind::Status { mix_id } => {
                let response =
                    Response::status(protocol_version, &mix_id, self.state.borrow().mix(&mix_id));
                send_response(handle, &response)
            }
        }
    }

    fn join_mix(
        &self,
        protocol_version: u16,
        mix_id: &str,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        if !self.claims.can_participate() {
            return send_error(handle, protocol_version, "APP_AUDIOMIX_PERMISSION_JOIN");
        }
        self.state
            .borrow_mut()
            .mix_mut(mix_id)
            .participants
            .entry(self.context.session_id())
            .or_default();
        send_response(handle, &Response::ok(protocol_version, "joined"))
    }

    fn set_muted(
        &self,
        protocol_version: u16,
        mix_id: &str,
        session_id: u64,
        muted: bool,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        self.mixer_only(protocol_version, handle, |state| {
            let target = SessionId::from_raw(session_id);
            if let Some(member) = state.mix_mut(mix_id).participants.get_mut(&target) {
                member.muted = muted;
                Ok(Response::ok(
                    protocol_version,
                    if muted { "muted" } else { "unmuted" },
                ))
            } else {
                Ok(Response::error(
                    protocol_version,
                    "APP_AUDIOMIX_UNKNOWN_SESSION",
                ))
            }
        })
    }

    fn audio_level(
        &self,
        protocol_version: u16,
        mix_id: &str,
        session_id: u64,
        level: u8,
        handle: &mut SessionHandle,
    ) -> AppResult<()> {
        let target = SessionId::from_raw(session_id);
        if target != self.context.session_id() && !self.claims.can_mix() {
            return send_error(handle, protocol_version, "APP_AUDIOMIX_PERMISSION_LEVEL");
        }
        let mut state = self.state.borrow_mut();
        let mix = state.mix_mut(mix_id);
        let Some(member) = mix.participants.get_mut(&target) else {
            return send_error(handle, protocol_version, "APP_AUDIOMIX_UNKNOWN_SESSION");
        };
        member.audio_level = Some(level);
        mix.active_speaker = mix
            .participants
            .iter()
            .filter(|(_session, member)| !member.muted)
            .filter_map(|(session, member)| member.audio_level.map(|level| (*session, level)))
            .min_by_key(|(_session, level)| *level)
            .map(|(session, _level)| session);
        let active = mix.active_speaker.map(SessionId::raw);
        drop(state);
        send_response(handle, &Response::active_speaker(protocol_version, active))
    }

    fn mixer_only(
        &self,
        protocol_version: u16,
        handle: &mut SessionHandle,
        apply: impl FnOnce(&mut AudiomixState) -> AudiomixResult<Response>,
    ) -> AppResult<()> {
        if !self.claims.can_mix() {
            return send_error(handle, protocol_version, "APP_AUDIOMIX_PERMISSION_MIXER");
        }
        let response = apply(&mut self.state.borrow_mut())
            .unwrap_or_else(|error| Response::error(protocol_version, error.error_code()));
        send_response(handle, &response)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MemberState {
    muted: bool,
    gain_mb: i16,
    audio_level: Option<u8>,
}

#[derive(Clone, Debug, Default)]
struct MixState {
    participants: BTreeMap<SessionId, MemberState>,
    active_speaker: Option<SessionId>,
}

#[derive(Clone, Debug, Default)]
struct AudiomixState {
    claims: BTreeMap<SessionId, AudiomixClaims>,
    mixes: BTreeMap<String, MixState>,
}

impl AudiomixState {
    fn mix_mut(&mut self, mix_id: &str) -> &mut MixState {
        self.mixes.entry(mix_id.to_owned()).or_default()
    }

    fn mix(&self, mix_id: &str) -> Option<&MixState> {
        self.mixes.get(mix_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct AudiomixCommand {
    protocol_version: u16,
    #[serde(flatten)]
    kind: AudiomixKind,
}

impl AudiomixCommand {
    fn parse(bytes: &[u8]) -> AudiomixResult<Self> {
        if bytes.len() > MAX_AUDIOMIX_COMMAND_BYTES {
            return Err(AudiomixError::CommandTooLarge {
                len: bytes.len(),
                max: MAX_AUDIOMIX_COMMAND_BYTES,
            });
        }
        let command: Self = serde_json::from_slice(bytes)?;
        if command.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(AudiomixError::UnsupportedProtocolVersion {
                version: command.protocol_version,
            });
        }
        command.validate()?;
        Ok(command)
    }

    fn validate(&self) -> AudiomixResult<()> {
        let mix_id = match &self.kind {
            AudiomixKind::JoinMix { mix_id }
            | AudiomixKind::LeaveMix { mix_id }
            | AudiomixKind::SetGain { mix_id, .. }
            | AudiomixKind::Mute { mix_id, .. }
            | AudiomixKind::Unmute { mix_id, .. }
            | AudiomixKind::AudioLevel { mix_id, .. }
            | AudiomixKind::Status { mix_id } => mix_id,
        };
        if mix_id.len() > MAX_MIX_ID_BYTES {
            return Err(AudiomixError::MixIdTooLarge {
                len: mix_id.len(),
                max: MAX_MIX_ID_BYTES,
            });
        }
        if let AudiomixKind::SetGain { gain_mb, .. } = self.kind
            && !(MIN_GAIN_MB..=MAX_GAIN_MB).contains(&gain_mb)
        {
            return Err(AudiomixError::GainOutOfRange { value: gain_mb });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum AudiomixKind {
    JoinMix {
        mix_id: String,
    },
    LeaveMix {
        mix_id: String,
    },
    SetGain {
        mix_id: String,
        session_id: u64,
        gain_mb: i16,
    },
    Mute {
        mix_id: String,
        session_id: u64,
    },
    Unmute {
        mix_id: String,
        session_id: u64,
    },
    AudioLevel {
        mix_id: String,
        session_id: u64,
        level: u8,
    },
    Status {
        mix_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct Response {
    protocol_version: u16,
    status: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_speaker: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mix: Option<MixView>,
}

impl Response {
    const fn ok(protocol_version: u16, status: &'static str) -> Self {
        Self {
            protocol_version,
            status,
            code: "ok",
            active_speaker: None,
            mix: None,
        }
    }

    const fn active_speaker(protocol_version: u16, active_speaker: Option<u64>) -> Self {
        Self {
            protocol_version,
            status: "active_speaker",
            code: "ok",
            active_speaker,
            mix: None,
        }
    }

    fn status(protocol_version: u16, mix_id: &str, mix: Option<&MixState>) -> Self {
        Self {
            protocol_version,
            status: "status",
            code: "ok",
            active_speaker: None,
            mix: mix.map(|mix| MixView {
                mix_id: mix_id.to_owned(),
                active_speaker: mix.active_speaker.map(SessionId::raw),
                participants: mix
                    .participants
                    .iter()
                    .map(|(session, member)| ParticipantView {
                        session_id: session.raw(),
                        muted: member.muted,
                        gain_mb: member.gain_mb,
                        audio_level: member.audio_level,
                    })
                    .collect(),
            }),
        }
    }

    const fn error(protocol_version: u16, code: &'static str) -> Self {
        Self {
            protocol_version,
            status: "error",
            code,
            active_speaker: None,
            mix: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct MixView {
    mix_id: String,
    active_speaker: Option<u64>,
    participants: Vec<ParticipantView>,
}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
struct ParticipantView {
    session_id: u64,
    muted: bool,
    gain_mb: i16,
    audio_level: Option<u8>,
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
            component: "app_audiomix_response",
        })?;
    handle.send(ClientMessage::try_from_bytes(&bytes)?)
}

#[cfg(test)]
mod tests {
    use refract_app::{Application, RoomView, Session, SessionContext, SessionHandle};
    use refract_core::{PeerId, RoomId, SessionId};
    use serde_json::json;

    use super::{AudiomixApp, AudiomixClaims};

    fn context(session: u64) -> SessionContext {
        SessionContext::new(
            SessionId::from_raw(session),
            PeerId::from_raw(session + 100),
            RoomId::from_raw(30),
        )
    }

    fn handle(session: u64) -> (SessionHandle, refract_app::SessionIo) {
        SessionHandle::new(
            context(session),
            RoomView::empty(RoomId::from_raw(30)),
            16,
            16,
        )
        .unwrap()
    }

    fn message(value: &serde_json::Value) -> refract_app::ClientMessage {
        refract_app::ClientMessage::try_from_bytes(value.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn audiomix_join_active_speaker_under_churn() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = AudiomixApp::new();
            app.set_claims(SessionId::from_raw(1), AudiomixClaims::participant());
            app.set_claims(SessionId::from_raw(2), AudiomixClaims::participant());
            let mut first = app.create_session(context(1)).await.unwrap();
            let mut second = app.create_session(context(2)).await.unwrap();
            let (mut first_handle, mut first_io) = handle(1);
            let (mut second_handle, mut second_io) = handle(2);

            first
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "join_mix",
                        "mix_id": "main"
                    })),
                    &mut first_handle,
                )
                .await
                .unwrap();
            second
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "join_mix",
                        "mix_id": "main"
                    })),
                    &mut second_handle,
                )
                .await
                .unwrap();
            let _joined_first = first_io.client_outbox.pop().unwrap();
            let _joined_second = second_io.client_outbox.pop().unwrap();

            first
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "audio_level",
                        "mix_id": "main",
                        "session_id": 1,
                        "level": 80
                    })),
                    &mut first_handle,
                )
                .await
                .unwrap();
            let _first_level = first_io.client_outbox.pop().unwrap();
            second
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "audio_level",
                        "mix_id": "main",
                        "session_id": 2,
                        "level": 20
                    })),
                    &mut second_handle,
                )
                .await
                .unwrap();
            let response = second_io.client_outbox.pop().unwrap();
            assert!(String::from_utf8_lossy(response.as_bytes()).contains("\"active_speaker\":2"));
        });
    }

    #[test]
    fn audiomix_permission_enforced() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = AudiomixApp::new();
            app.set_claims(SessionId::from_raw(3), AudiomixClaims::participant());
            let mut session = app.create_session(context(3)).await.unwrap();
            let (mut handle, mut io) = handle(3);
            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 1,
                        "type": "mute",
                        "mix_id": "main",
                        "session_id": 3
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let response = io.client_outbox.pop().unwrap();
            assert!(
                String::from_utf8_lossy(response.as_bytes())
                    .contains("APP_AUDIOMIX_PERMISSION_MIXER")
            );
        });
    }

    #[test]
    fn audiomix_protocol_version_rejected() {
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let app = AudiomixApp::new();
            app.set_claims(SessionId::from_raw(4), AudiomixClaims::participant());
            let mut session = app.create_session(context(4)).await.unwrap();
            let (mut handle, mut io) = handle(4);
            session
                .handle_message(
                    message(&json!({
                        "protocol_version": 2,
                        "type": "status",
                        "mix_id": "main"
                    })),
                    &mut handle,
                )
                .await
                .unwrap();
            let response = io.client_outbox.pop().unwrap();
            assert!(
                String::from_utf8_lossy(response.as_bytes()).contains("APP_AUDIOMIX_PROTOCOL_0001")
            );
        });
    }
}
