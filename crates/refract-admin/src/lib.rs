//! Administrative API for drain, reload, diagnostics, and sessions.
//!
//! `refract-admin` is runtime independent: it defines UNIX-socket-only
//! configuration, peer-credential authorization, request routing, and the
//! graceful-drain state machine. The compio owner mounts this API on a UNIX
//! socket and passes verified peer credentials into [`AdminApi::handle`].
//!
//! # Examples
//!
//! ```
//! # use refract_admin::{AdminApi, AdminRequest, Method, PeerCredentials};
//! let mut api = AdminApi::default();
//! let response = api.handle(&AdminRequest::new(
//!     Method::Get,
//!     "/capabilities",
//!     "",
//!     PeerCredentials::root(),
//! ))?;
//! assert_eq!(response.status(), 200);
//! # Ok::<(), refract_admin::AdminError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

use refract_core::{NodeId, PeerId, RoomId, SessionId};
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

const DEFAULT_SOCKET_PATH: &str = "/run/refract/admin.sock";
const DEFAULT_GRACEFUL_DRAIN_TIMEOUT_SECS: u64 = 300;
const FAST_DRAIN_KILL_AFTER_SECS: u64 = 10;
const MAX_DRAIN_TIMEOUT_SECS: u64 = 300;
const DEFAULT_SESSION_PAGE_LIMIT: usize = 100;
const MAX_SESSION_PAGE_LIMIT: usize = 500;
const MAX_PROFILE_DURATION_SECS: u64 = 60;
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;
const REDACTED: &str = "<redacted>";

/// Result alias for admin operations.
pub type AdminResult<T> = Result<T, AdminError>;

/// Stage marker for public `refract-admin` APIs.
///
/// # Examples
///
/// ```
/// # use refract_admin::Stability;
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
    /// # use refract_admin::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Admin API errors with stable operator codes.
///
/// # Examples
///
/// ```
/// # use refract_admin::AdminError;
/// assert_eq!(AdminError::Unauthorized.error_code(), "ADMIN_AUTH_0001");
/// ```
#[derive(Debug, ThisError)]
pub enum AdminError {
    /// Peer credentials are not authorized.
    #[error("admin peer credentials rejected")]
    Unauthorized,
    /// Request method or path is not supported.
    #[error("admin endpoint not found")]
    NotFound,
    /// Request body exceeded the bounded admin limit.
    #[error("admin request body too large")]
    BodyTooLarge,
    /// Request JSON could not be parsed.
    #[error("admin request parse failed: {message}")]
    Parse {
        /// Clear parse failure message.
        message: String,
    },
    /// Request failed validation.
    #[error("admin request validation failed: {field}: {message}")]
    Validation {
        /// Rejected field path.
        field: &'static str,
        /// Clear validation message.
        message: &'static str,
    },
    /// Requested session does not exist.
    #[error("admin session not found")]
    SessionNotFound,
    /// Response serialization failed.
    #[error("admin response serialization failed")]
    Serialize,
}

impl AdminError {
    /// Returns the stable operator-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::AdminError;
    /// assert_eq!(
    ///     AdminError::SessionNotFound.error_code(),
    ///     "ADMIN_SESSION_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ADMIN_AUTH_0001",
            Self::NotFound => "ADMIN_ROUTE_0001",
            Self::BodyTooLarge => "ADMIN_INPUT_0001",
            Self::Parse { .. } => "ADMIN_INPUT_0002",
            Self::Validation { .. } => "ADMIN_INPUT_0003",
            Self::SessionNotFound => "ADMIN_SESSION_0001",
            Self::Serialize => "ADMIN_SERIALIZE_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::{AdminError, Stability};
    /// assert_eq!(AdminError::Unauthorized.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Admin bind configuration.
///
/// Stage 1 defaults to UNIX sockets only; there is intentionally no TCP bind
/// variant in this API.
///
/// # Examples
///
/// ```
/// # use refract_admin::AdminBind;
/// assert!(AdminBind::default().is_unix_socket());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminBind {
    /// UNIX domain socket bind path.
    UnixSocket {
        /// Socket filesystem path.
        path: PathBuf,
    },
}

impl Default for AdminBind {
    fn default() -> Self {
        Self::UnixSocket {
            path: PathBuf::from(DEFAULT_SOCKET_PATH),
        }
    }
}

impl AdminBind {
    /// Creates a UNIX socket bind configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::AdminBind;
    /// let bind = AdminBind::unix_socket("/tmp/refract-admin.sock");
    /// assert_eq!(bind.path(), std::path::Path::new("/tmp/refract-admin.sock"));
    /// ```
    #[must_use]
    pub fn unix_socket(path: impl Into<PathBuf>) -> Self {
        Self::UnixSocket { path: path.into() }
    }

    /// Returns whether this bind is a UNIX domain socket.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::AdminBind;
    /// assert!(AdminBind::default().is_unix_socket());
    /// ```
    #[must_use]
    pub const fn is_unix_socket(&self) -> bool {
        matches!(self, Self::UnixSocket { .. })
    }

    /// Returns the UNIX socket path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::AdminBind;
    /// assert_eq!(
    ///     AdminBind::default().path(),
    ///     std::path::Path::new("/run/refract/admin.sock")
    /// );
    /// ```
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::UnixSocket { path } => path,
        }
    }
}

/// Peer credentials collected from a UNIX socket acceptor.
///
/// # Examples
///
/// ```
/// # use refract_admin::PeerCredentials;
/// let credentials = PeerCredentials::new(0, 0);
/// assert!(credentials.is_root());
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerCredentials {
    uid: u32,
    gid: u32,
}

impl PeerCredentials {
    /// Creates peer credentials from UNIX uid/gid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::PeerCredentials;
    /// assert_eq!(PeerCredentials::new(7, 8).uid(), 7);
    /// ```
    #[must_use]
    pub const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    /// Creates root credentials for tests and local privileged callers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_admin::PeerCredentials;
    /// assert_eq!(PeerCredentials::root().uid(), 0);
    /// ```
    #[must_use]
    pub const fn root() -> Self {
        Self::new(0, 0)
    }

    /// Returns the UNIX uid.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the UNIX gid.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    /// Returns whether the peer is root.
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.uid == 0
    }
}

/// Peer-credential authorization policy.
///
/// # Examples
///
/// ```
/// # use refract_admin::{AdminAuth, PeerCredentials};
/// assert!(
///     AdminAuth::root_only()
///         .authorize(PeerCredentials::root())
///         .is_ok()
/// );
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAuth {
    allowed_uids: BTreeSet<u32>,
    allowed_gids: BTreeSet<u32>,
}

impl Default for AdminAuth {
    fn default() -> Self {
        Self::root_only()
    }
}

impl AdminAuth {
    /// Creates root-only admin auth.
    #[must_use]
    pub fn root_only() -> Self {
        Self {
            allowed_uids: BTreeSet::from([0]),
            allowed_gids: BTreeSet::new(),
        }
    }

    /// Creates admin auth from allowed uid/gid sets.
    #[must_use]
    pub fn new(
        uid_allowlist: impl IntoIterator<Item = u32>,
        group_allowlist: impl IntoIterator<Item = u32>,
    ) -> Self {
        Self {
            allowed_uids: uid_allowlist.into_iter().collect(),
            allowed_gids: group_allowlist.into_iter().collect(),
        }
    }

    /// Authorizes peer credentials.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::Unauthorized`] when neither uid nor gid is allowed.
    pub fn authorize(&self, credentials: PeerCredentials) -> AdminResult<()> {
        if self.allowed_uids.contains(&credentials.uid())
            || self.allowed_gids.contains(&credentials.gid())
        {
            Ok(())
        } else {
            Err(AdminError::Unauthorized)
        }
    }
}

/// HTTP-like method supported by the admin router.
///
/// # Examples
///
/// ```
/// # use refract_admin::Method;
/// assert_eq!(Method::Post.as_str(), "POST");
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// Returns the stable method label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One routed admin request.
///
/// # Examples
///
/// ```
/// # use refract_admin::{AdminRequest, Method, PeerCredentials};
/// let request = AdminRequest::new(Method::Get, "/stats", "", PeerCredentials::root());
/// assert_eq!(request.path(), "/stats");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRequest {
    method: Method,
    path: String,
    body: String,
    credentials: PeerCredentials,
}

impl AdminRequest {
    /// Creates an admin request.
    #[must_use]
    pub fn new(
        method: Method,
        path: impl Into<String>,
        body: impl Into<String>,
        credentials: PeerCredentials,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            body: body.into(),
            credentials,
        }
    }

    /// Returns the request method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Returns the path including any query string.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the request body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Returns peer credentials.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }
}

/// Admin response.
///
/// # Examples
///
/// ```
/// # use refract_admin::AdminResponse;
/// let response = AdminResponse::json(200, "{}");
/// assert_eq!(response.content_type(), "application/json");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminResponse {
    status: u16,
    content_type: &'static str,
    body: String,
}

impl AdminResponse {
    /// Creates a JSON response.
    #[must_use]
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into(),
        }
    }

    /// Returns the status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the content type.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.content_type
    }

    /// Returns the response body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// Drain mode.
///
/// # Examples
///
/// ```
/// # use refract_admin::DrainMode;
/// assert_eq!(DrainMode::Graceful.as_str(), "graceful");
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainMode {
    /// Refuse new sessions, signal existing sessions, wait up to timeout, then exit.
    Graceful,
    /// Refuse new sessions and kill existing sessions after 10 seconds.
    Fast,
}

impl DrainMode {
    /// Returns a stable mode label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Fast => "fast",
        }
    }
}

/// Drain request body.
///
/// # Examples
///
/// ```
/// # use refract_admin::{DrainMode, DrainRequest};
/// assert_eq!(
///     DrainRequest::new(DrainMode::Fast, None).mode(),
///     DrainMode::Fast
/// );
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrainRequest {
    mode: DrainMode,
    timeout_secs: Option<u64>,
}

impl DrainRequest {
    /// Creates a drain request.
    #[must_use]
    pub const fn new(mode: DrainMode, timeout_secs: Option<u64>) -> Self {
        Self { mode, timeout_secs }
    }

    /// Returns the drain mode.
    #[must_use]
    pub const fn mode(self) -> DrainMode {
        self.mode
    }

    /// Returns the optional timeout in seconds.
    #[must_use]
    pub const fn timeout_secs(self) -> Option<u64> {
        self.timeout_secs
    }
}

/// Drain lifecycle state.
///
/// # Examples
///
/// ```
/// # use refract_admin::DrainState;
/// assert_eq!(DrainState::Running.as_str(), "running");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainState {
    /// Not draining.
    Idle,
    /// Drain is active.
    Running,
    /// Drain finished and process may exit.
    Complete,
}

impl DrainState {
    /// Returns a stable state label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Complete => "complete",
        }
    }
}

/// Result of a drain operation.
///
/// # Examples
///
/// ```
/// # use refract_admin::{DrainMode, DrainOutcome, DrainState};
/// let outcome = DrainOutcome::new(DrainMode::Graceful, DrainState::Running, 1, 1, 0, 300);
/// assert_eq!(outcome.rehome_attempts(), 1);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DrainOutcome {
    mode: DrainMode,
    state: DrainState,
    signalled_sessions: usize,
    rehome_attempts: usize,
    killed_sessions: usize,
    timeout_secs: u64,
}

impl DrainOutcome {
    /// Creates a drain outcome.
    #[must_use]
    pub const fn new(
        mode: DrainMode,
        state: DrainState,
        signalled_sessions: usize,
        rehome_attempts: usize,
        killed_sessions: usize,
        timeout_secs: u64,
    ) -> Self {
        Self {
            mode,
            state,
            signalled_sessions,
            rehome_attempts,
            killed_sessions,
            timeout_secs,
        }
    }

    /// Returns re-home attempts caused by ICE restart.
    #[must_use]
    pub const fn rehome_attempts(self) -> usize {
        self.rehome_attempts
    }

    /// Returns killed sessions.
    #[must_use]
    pub const fn killed_sessions(self) -> usize {
        self.killed_sessions
    }
}

/// Session lifecycle state.
///
/// # Examples
///
/// ```
/// # use refract_admin::SessionState;
/// assert_eq!(SessionState::Active.as_str(), "active");
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Active media/control session.
    Active,
    /// Graceful drain signal sent to app-room.
    DrainSignalled,
    /// Session was kicked by an operator.
    Kicked,
    /// Session was killed by fast drain.
    Killed,
    /// Session completed voluntarily.
    Closed,
}

impl SessionState {
    /// Returns a stable state label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::DrainSignalled => "drain_signalled",
            Self::Kicked => "kicked",
            Self::Killed => "killed",
            Self::Closed => "closed",
        }
    }

    /// Returns whether the session is still live.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::DrainSignalled)
    }
}

/// Session record used by admin diagnostics.
///
/// # Examples
///
/// ```
/// # use refract_admin::SessionRecord;
/// # use refract_core::{NodeId, PeerId, RoomId, SessionId};
/// let session = SessionRecord::new(
///     SessionId::from_raw(1),
///     PeerId::from_raw(2),
///     RoomId::from_raw(3),
///     "room",
///     NodeId::from_raw(4),
/// );
/// assert_eq!(session.app(), "room");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    id: SessionId,
    peer_id: PeerId,
    room_id: RoomId,
    app: String,
    node_id: NodeId,
    state: SessionState,
    connected_ms: u64,
    rehome_attempts: usize,
}

impl SessionRecord {
    /// Creates a session record.
    #[must_use]
    pub fn new(
        id: SessionId,
        peer_id: PeerId,
        room_id: RoomId,
        app: impl Into<String>,
        node_id: NodeId,
    ) -> Self {
        Self {
            id,
            peer_id,
            room_id,
            app: app.into(),
            node_id,
            state: SessionState::Active,
            connected_ms: 0,
            rehome_attempts: 0,
        }
    }

    /// Returns the session id.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Returns the application name.
    #[must_use]
    pub fn app(&self) -> &str {
        &self.app
    }

    /// Returns the state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns re-home attempts.
    #[must_use]
    pub const fn rehome_attempts(&self) -> usize {
        self.rehome_attempts
    }

    const fn signal_drain(&mut self) {
        if self.state.is_live() {
            self.state = SessionState::DrainSignalled;
            self.rehome_attempts = self.rehome_attempts.saturating_add(1);
        }
    }

    const fn kick(&mut self) {
        self.state = SessionState::Kicked;
    }

    const fn kill(&mut self) {
        self.state = SessionState::Killed;
    }

    const fn close(&mut self) {
        self.state = SessionState::Closed;
    }
}

/// Privacy-redacted session view.
///
/// # Examples
///
/// ```
/// # use refract_admin::{RedactedSession, SessionRecord};
/// # use refract_core::{NodeId, PeerId, RoomId, SessionId};
/// let session = SessionRecord::new(
///     SessionId::from_raw(1),
///     PeerId::from_raw(2),
///     RoomId::from_raw(3),
///     "room",
///     NodeId::from_raw(1),
/// );
/// assert_eq!(RedactedSession::from(&session).peer_id(), "<redacted>");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedSession {
    id: u64,
    peer_id: &'static str,
    room_id: u64,
    app: String,
    node_id: u64,
    state: SessionState,
    connected_ms: u64,
    rehome_attempts: usize,
}

impl RedactedSession {
    /// Returns the redacted peer id placeholder.
    #[must_use]
    pub const fn peer_id(&self) -> &'static str {
        self.peer_id
    }
}

impl From<&SessionRecord> for RedactedSession {
    fn from(value: &SessionRecord) -> Self {
        Self {
            id: value.id.raw(),
            peer_id: REDACTED,
            room_id: value.room_id.raw(),
            app: value.app.clone(),
            node_id: value.node_id.raw(),
            state: value.state,
            connected_ms: value.connected_ms,
            rehome_attempts: value.rehome_attempts,
        }
    }
}

/// Paginated session list response.
///
/// # Examples
///
/// ```
/// # use refract_admin::SessionPage;
/// let page = SessionPage::new(Vec::new(), None, 0);
/// assert_eq!(page.total(), 0);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionPage {
    sessions: Vec<RedactedSession>,
    next_cursor: Option<u64>,
    total: usize,
}

impl SessionPage {
    /// Creates a session page.
    #[must_use]
    pub const fn new(
        sessions: Vec<RedactedSession>,
        next_cursor: Option<u64>,
        total: usize,
    ) -> Self {
        Self {
            sessions,
            next_cursor,
            total,
        }
    }

    /// Returns total sessions.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Returns sessions in this page.
    #[must_use]
    pub fn sessions(&self) -> &[RedactedSession] {
        &self.sessions
    }
}

/// Session directory owned by the admin slow path.
///
/// # Examples
///
/// ```
/// # use refract_admin::{SessionDirectory, SessionRecord};
/// # use refract_core::{NodeId, PeerId, RoomId, SessionId};
/// let mut directory = SessionDirectory::default();
/// directory.insert(SessionRecord::new(
///     SessionId::from_raw(1),
///     PeerId::from_raw(2),
///     RoomId::from_raw(3),
///     "room",
///     NodeId::from_raw(1),
/// ));
/// assert_eq!(directory.live_count(), 1);
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionDirectory {
    sessions: BTreeMap<SessionId, SessionRecord>,
}

impl SessionDirectory {
    /// Inserts or replaces a session.
    pub fn insert(&mut self, session: SessionRecord) {
        self.sessions.insert(session.id(), session);
    }

    /// Returns the live session count.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.state().is_live())
            .count()
    }

    /// Returns a redacted page of sessions.
    #[must_use]
    pub fn page(&self, cursor: Option<SessionId>, limit: usize) -> SessionPage {
        let limit = limit.clamp(1, MAX_SESSION_PAGE_LIMIT);
        let start = cursor.map_or(0, SessionId::raw);
        let mut selected = self
            .sessions
            .values()
            .filter(|session| session.id().raw() > start)
            .take(limit.saturating_add(1))
            .map(RedactedSession::from)
            .collect::<Vec<_>>();
        let next_cursor = if selected.len() > limit {
            selected.pop().map(|session| session.id)
        } else {
            None
        };
        SessionPage::new(selected, next_cursor, self.sessions.len())
    }

    /// Returns one redacted session.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::SessionNotFound`] if the id is unknown.
    pub fn get_redacted(&self, id: SessionId) -> AdminResult<RedactedSession> {
        self.sessions
            .get(&id)
            .map(RedactedSession::from)
            .ok_or(AdminError::SessionNotFound)
    }

    /// Kicks one session.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::SessionNotFound`] if the id is unknown.
    pub fn kick(&mut self, id: SessionId) -> AdminResult<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(AdminError::SessionNotFound)?;
        session.kick();
        Ok(())
    }

    /// Marks one session closed.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::SessionNotFound`] if the id is unknown.
    pub fn close(&mut self, id: SessionId) -> AdminResult<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(AdminError::SessionNotFound)?;
        session.close();
        Ok(())
    }

    fn signal_drain_all(&mut self) -> (usize, usize) {
        let mut signalled = 0usize;
        let mut rehome = 0usize;
        self.sessions
            .values_mut()
            .filter(|session| session.state().is_live())
            .for_each(|session| {
                session.signal_drain();
                signalled = signalled.saturating_add(1);
                rehome = rehome.saturating_add(1);
            });
        (signalled, rehome)
    }

    fn kill_live(&mut self) -> usize {
        let mut killed = 0usize;
        self.sessions
            .values_mut()
            .filter(|session| session.state().is_live())
            .for_each(|session| {
                session.kill();
                killed = killed.saturating_add(1);
            });
        killed
    }
}

/// Runtime stats exposed by `GET /stats`.
///
/// # Examples
///
/// ```
/// # use refract_admin::Stats;
/// let stats = Stats::new(1, false, 0, 0);
/// assert_eq!(stats.live_sessions(), 1);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Stats {
    live_sessions: usize,
    accepting_new_sessions: bool,
    drain_rehome_attempts: usize,
    kicked_sessions: usize,
}

impl Stats {
    /// Creates stats.
    #[must_use]
    pub const fn new(
        live_sessions: usize,
        accepting_new_sessions: bool,
        drain_rehome_attempts: usize,
        kicked_sessions: usize,
    ) -> Self {
        Self {
            live_sessions,
            accepting_new_sessions,
            drain_rehome_attempts,
            kicked_sessions,
        }
    }

    /// Returns live sessions.
    #[must_use]
    pub const fn live_sessions(self) -> usize {
        self.live_sessions
    }
}

/// Admin capabilities.
///
/// # Examples
///
/// ```
/// # use refract_admin::Capabilities;
/// assert!(Capabilities::stage1().unix_socket_only());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Capabilities {
    unix_socket_only: bool,
    peer_credentials_auth: bool,
    drain_modes: Vec<DrainMode>,
    profile_kinds: Vec<ProfileKind>,
}

impl Capabilities {
    /// Returns Stage 1 capabilities.
    #[must_use]
    pub fn stage1() -> Self {
        Self {
            unix_socket_only: true,
            peer_credentials_auth: true,
            drain_modes: vec![DrainMode::Graceful, DrainMode::Fast],
            profile_kinds: vec![ProfileKind::Cpu, ProfileKind::Heap, ProfileKind::Allocs],
        }
    }

    /// Returns whether admin bind is UNIX socket-only.
    #[must_use]
    pub const fn unix_socket_only(&self) -> bool {
        self.unix_socket_only
    }
}

/// Debug profile kind.
///
/// # Examples
///
/// ```
/// # use refract_admin::ProfileKind;
/// assert_eq!(ProfileKind::Cpu.as_str(), "cpu");
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// CPU profile.
    Cpu,
    /// Heap profile.
    Heap,
    /// Allocation profile.
    Allocs,
}

impl ProfileKind {
    /// Returns the stable profile label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Heap => "heap",
            Self::Allocs => "allocs",
        }
    }
}

/// Profile request body.
///
/// # Examples
///
/// ```
/// # use refract_admin::ProfileRequest;
/// assert_eq!(ProfileRequest::new(5).duration_secs(), 5);
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileRequest {
    duration_secs: u64,
}

impl ProfileRequest {
    /// Creates a profile request.
    #[must_use]
    pub const fn new(duration_secs: u64) -> Self {
        Self { duration_secs }
    }

    /// Returns requested duration.
    #[must_use]
    pub const fn duration_secs(self) -> u64 {
        self.duration_secs
    }
}

/// Profile start response.
///
/// # Examples
///
/// ```
/// # use refract_admin::{ProfileKind, ProfileStarted};
/// let started = ProfileStarted::new(ProfileKind::Cpu, 1);
/// assert_eq!(started.kind(), ProfileKind::Cpu);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileStarted {
    kind: ProfileKind,
    duration_secs: u64,
}

impl ProfileStarted {
    /// Creates a profile response.
    #[must_use]
    pub const fn new(kind: ProfileKind, duration_secs: u64) -> Self {
        Self {
            kind,
            duration_secs,
        }
    }

    /// Returns the profile kind.
    #[must_use]
    pub const fn kind(self) -> ProfileKind {
        self.kind
    }
}

/// Log level update request.
///
/// # Examples
///
/// ```
/// # use refract_admin::LogLevelRequest;
/// let request = LogLevelRequest::new("refract", "debug");
/// assert_eq!(request.level(), "debug");
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogLevelRequest {
    target: String,
    level: String,
}

impl LogLevelRequest {
    /// Creates a log-level request.
    #[must_use]
    pub fn new(target: impl Into<String>, level: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            level: level.into(),
        }
    }

    /// Returns the target.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the level.
    #[must_use]
    pub fn level(&self) -> &str {
        &self.level
    }
}

/// Admin API state and router.
///
/// # Examples
///
/// ```
/// # use refract_admin::AdminApi;
/// assert_eq!(AdminApi::default().stats().live_sessions(), 0);
/// ```
#[derive(Clone, Debug)]
pub struct AdminApi {
    bind: AdminBind,
    auth: AdminAuth,
    sessions: SessionDirectory,
    accepting_new_sessions: bool,
    drain_state: DrainState,
    drain_rehome_attempts: usize,
    kicked_sessions: usize,
    log_levels: BTreeMap<String, String>,
    reload_count: u64,
}

impl Default for AdminApi {
    fn default() -> Self {
        Self {
            bind: AdminBind::default(),
            auth: AdminAuth::default(),
            sessions: SessionDirectory::default(),
            accepting_new_sessions: true,
            drain_state: DrainState::Idle,
            drain_rehome_attempts: 0,
            kicked_sessions: 0,
            log_levels: BTreeMap::new(),
            reload_count: 0,
        }
    }
}

impl AdminApi {
    /// Creates an admin API with explicit bind and auth policy.
    #[must_use]
    pub fn new(bind: AdminBind, auth: AdminAuth) -> Self {
        Self {
            bind,
            auth,
            ..Self::default()
        }
    }

    /// Returns the bind configuration.
    #[must_use]
    pub const fn bind(&self) -> &AdminBind {
        &self.bind
    }

    /// Returns the current stats.
    #[must_use]
    pub fn stats(&self) -> Stats {
        Stats::new(
            self.sessions.live_count(),
            self.accepting_new_sessions,
            self.drain_rehome_attempts,
            self.kicked_sessions,
        )
    }

    /// Inserts a session into the admin directory.
    pub fn insert_session(&mut self, session: SessionRecord) {
        if self.accepting_new_sessions {
            self.sessions.insert(session);
        }
    }

    /// Returns a paginated session list.
    #[must_use]
    pub fn sessions(&self, cursor: Option<SessionId>, limit: usize) -> SessionPage {
        self.sessions.page(cursor, limit)
    }

    /// Returns one privacy-redacted session.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::SessionNotFound`] when the id is unknown.
    pub fn session(&self, id: SessionId) -> AdminResult<RedactedSession> {
        self.sessions.get_redacted(id)
    }

    /// Kicks one session.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::SessionNotFound`] when the id is unknown.
    pub fn kick_session(&mut self, id: SessionId) -> AdminResult<()> {
        self.sessions.kick(id)?;
        self.kicked_sessions = self.kicked_sessions.saturating_add(1);
        Ok(())
    }

    /// Marks one session closed by the application/runtime.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::SessionNotFound`] when the id is unknown.
    pub fn close_session(&mut self, id: SessionId) -> AdminResult<()> {
        self.sessions.close(id)
    }

    /// Performs graceful or fast drain.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::Validation`] when timeout is invalid.
    pub fn drain(&mut self, request: DrainRequest) -> AdminResult<DrainOutcome> {
        let timeout_secs = match request.mode() {
            DrainMode::Graceful => request
                .timeout_secs()
                .unwrap_or(DEFAULT_GRACEFUL_DRAIN_TIMEOUT_SECS),
            DrainMode::Fast => FAST_DRAIN_KILL_AFTER_SECS,
        };
        if timeout_secs == 0 || timeout_secs > MAX_DRAIN_TIMEOUT_SECS {
            return Err(AdminError::Validation {
                field: "timeout_secs",
                message: "must be in range 1..=300",
            });
        }

        self.accepting_new_sessions = false;
        self.drain_state = DrainState::Running;
        let (signalled, rehome_attempts) = self.sessions.signal_drain_all();
        self.drain_rehome_attempts = self.drain_rehome_attempts.saturating_add(rehome_attempts);
        let killed = if request.mode() == DrainMode::Fast {
            self.sessions.kill_live()
        } else {
            0
        };
        if self.sessions.live_count() == 0 {
            self.drain_state = DrainState::Complete;
        }

        Ok(DrainOutcome::new(
            request.mode(),
            self.drain_state,
            signalled,
            rehome_attempts,
            killed,
            timeout_secs,
        ))
    }

    /// Runs the reload hook.
    ///
    /// Stage 1 increments a reload counter; the embedding runtime performs the
    /// actual `refract-config` reload and calls this endpoint after success.
    #[must_use]
    pub const fn reload(&mut self) -> u64 {
        self.reload_count = self.reload_count.saturating_add(1);
        self.reload_count
    }

    /// Starts a bounded debug profile.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::Validation`] when duration is outside `1..=60`.
    pub const fn start_profile(
        &self,
        kind: ProfileKind,
        request: ProfileRequest,
    ) -> AdminResult<ProfileStarted> {
        if request.duration_secs() == 0 || request.duration_secs() > MAX_PROFILE_DURATION_SECS {
            return Err(AdminError::Validation {
                field: "duration_secs",
                message: "must be in range 1..=60",
            });
        }
        Ok(ProfileStarted::new(kind, request.duration_secs()))
    }

    /// Updates a slow-path log level.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::Validation`] when target or level is invalid.
    pub fn set_log_level(&mut self, request: &LogLevelRequest) -> AdminResult<()> {
        if request.target().is_empty() || request.target().len() > 128 {
            return Err(AdminError::Validation {
                field: "target",
                message: "must be non-empty and at most 128 bytes",
            });
        }
        if !matches!(
            request.level(),
            "error" | "warn" | "info" | "debug" | "trace"
        ) {
            return Err(AdminError::Validation {
                field: "level",
                message: "must be error, warn, info, debug, or trace",
            });
        }
        self.log_levels
            .insert(request.target().to_owned(), request.level().to_owned());
        Ok(())
    }

    /// Routes an admin request.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError`] for auth, route, parse, validation, session, or
    /// serialization failures.
    pub fn handle(&mut self, request: &AdminRequest) -> AdminResult<AdminResponse> {
        self.auth.authorize(request.credentials())?;
        if request.body().len() > MAX_REQUEST_BODY_BYTES {
            return Err(AdminError::BodyTooLarge);
        }

        let (path, query) = split_path_query(request.path());
        match (request.method(), path) {
            (Method::Post, "/drain") => {
                let drain_request = parse_body::<DrainRequest>(request.body())?;
                response(200, &self.drain(drain_request)?)
            }
            (Method::Post, "/reload") => response(200, &ReloadResponse::new(self.reload())),
            (Method::Get, "/stats") => response(200, &self.stats()),
            (Method::Get, "/sessions") => {
                let (cursor, limit) = parse_pagination(query)?;
                response(200, &self.sessions(cursor, limit))
            }
            (Method::Get, "/capabilities") => response(200, &Capabilities::stage1()),
            (Method::Post, "/debug/log-level") => {
                let log_request = parse_body::<LogLevelRequest>(request.body())?;
                self.set_log_level(&log_request)?;
                response(200, &SimpleStatus::ok())
            }
            (Method::Post, path) if path.starts_with("/debug/profile/") => {
                let kind = parse_profile_kind(path.trim_start_matches("/debug/profile/"))?;
                let profile_request = parse_body::<ProfileRequest>(request.body())?;
                response(200, &self.start_profile(kind, profile_request)?)
            }
            (Method::Get, path) if path.starts_with("/sessions/") => {
                let id = parse_session_path(path, "/sessions/")?;
                response(200, &self.session(id)?)
            }
            (Method::Post, path) if path.starts_with("/sessions/") && path.ends_with("/kick") => {
                let id = parse_session_path(path.trim_end_matches("/kick"), "/sessions/")?;
                self.kick_session(id)?;
                response(200, &SimpleStatus::ok())
            }
            _ => Err(AdminError::NotFound),
        }
    }
}

/// Reload endpoint response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ReloadResponse {
    reload_count: u64,
}

impl ReloadResponse {
    /// Creates a reload response.
    #[must_use]
    pub const fn new(reload_count: u64) -> Self {
        Self { reload_count }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct SimpleStatus {
    ok: bool,
}

impl SimpleStatus {
    const fn ok() -> Self {
        Self { ok: true }
    }
}

fn split_path_query(path: &str) -> (&str, Option<&str>) {
    path.split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)))
}

fn parse_body<T>(body: &str) -> AdminResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(body).map_err(|error| AdminError::Parse {
        message: error.to_string(),
    })
}

fn response<T>(status: u16, body: &T) -> AdminResult<AdminResponse>
where
    T: Serialize,
{
    serde_json::to_string(body)
        .map(|body| AdminResponse::json(status, body))
        .map_err(|_error| AdminError::Serialize)
}

fn parse_session_path(path: &str, prefix: &str) -> AdminResult<SessionId> {
    path.strip_prefix(prefix)
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(SessionId::from_raw)
        .ok_or(AdminError::Validation {
            field: "session_id",
            message: "must be a decimal session id",
        })
}

fn parse_profile_kind(raw: &str) -> AdminResult<ProfileKind> {
    match raw {
        "cpu" => Ok(ProfileKind::Cpu),
        "heap" => Ok(ProfileKind::Heap),
        "allocs" => Ok(ProfileKind::Allocs),
        _ => Err(AdminError::Validation {
            field: "profile_kind",
            message: "must be cpu, heap, or allocs",
        }),
    }
}

fn parse_pagination(query: Option<&str>) -> AdminResult<(Option<SessionId>, usize)> {
    let mut cursor = None;
    let mut limit = DEFAULT_SESSION_PAGE_LIMIT;
    for (key, value) in query
        .into_iter()
        .flat_map(|query| query.split('&').filter_map(|part| part.split_once('=')))
    {
        match key {
            "cursor" => {
                cursor = Some(SessionId::from_raw(value.parse::<u64>().map_err(
                    |_error| AdminError::Validation {
                        field: "cursor",
                        message: "must be a decimal session id",
                    },
                )?));
            }
            "limit" => {
                limit = value
                    .parse::<usize>()
                    .map_err(|_error| AdminError::Validation {
                        field: "limit",
                        message: "must be a decimal integer",
                    })?;
                if limit == 0 || limit > MAX_SESSION_PAGE_LIMIT {
                    return Err(AdminError::Validation {
                        field: "limit",
                        message: "must be in range 1..=500",
                    });
                }
            }
            _ => {}
        }
    }
    Ok((cursor, limit))
}

/// Returns the Stage 1 stability marker for this crate.
///
/// # Examples
///
/// ```
/// # use refract_admin::{stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> Stability {
    Stability::Stage1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(raw: u64) -> SessionRecord {
        SessionRecord::new(
            SessionId::from_raw(raw),
            PeerId::from_raw(raw + 10),
            RoomId::from_raw(1),
            "room",
            NodeId::from_raw(1),
        )
    }

    #[test]
    fn admin_auth_rejects_non_root_by_default() {
        let api = AdminApi::default();
        let error = api
            .auth
            .authorize(PeerCredentials::new(1_000, 1_000))
            .expect_err("non-root rejected");
        assert_eq!(error.error_code(), "ADMIN_AUTH_0001");
    }

    #[test]
    fn drain_with_active_sessions_measures_rehome_migration() -> AdminResult<()> {
        let mut api = AdminApi::default();
        api.insert_session(session(1));
        api.insert_session(session(2));

        let outcome = api.drain(DrainRequest::new(DrainMode::Graceful, None))?;

        assert_eq!(outcome.rehome_attempts(), 2);
        assert_eq!(api.stats().live_sessions(), 2);
        assert_eq!(api.session(SessionId::from_raw(1))?.peer_id(), REDACTED);
        api.insert_session(session(3));
        assert_eq!(api.sessions(None, 10).total(), 2);
        Ok(())
    }

    #[test]
    fn fast_drain_kills_live_sessions_after_stage1_window() -> AdminResult<()> {
        let mut api = AdminApi::default();
        api.insert_session(session(1));

        let outcome = api.drain(DrainRequest::new(DrainMode::Fast, Some(99)))?;

        assert_eq!(outcome.killed_sessions(), 1);
        assert_eq!(api.stats().live_sessions(), 0);
        Ok(())
    }

    #[test]
    fn router_handles_sessions_and_profile_endpoints() -> AdminResult<()> {
        let mut api = AdminApi::default();
        api.insert_session(session(1));

        let list = api.handle(&AdminRequest::new(
            Method::Get,
            "/sessions?limit=1",
            "",
            PeerCredentials::root(),
        ))?;
        assert_eq!(list.status(), 200);
        assert!(list.body().contains(REDACTED));

        let profile = api.handle(&AdminRequest::new(
            Method::Post,
            "/debug/profile/cpu",
            r#"{"duration_secs":1}"#,
            PeerCredentials::root(),
        ))?;
        assert_eq!(profile.status(), 200);
        assert!(profile.body().contains("cpu"));
        Ok(())
    }

    #[test]
    fn kick_endpoint_updates_session_state() -> AdminResult<()> {
        let mut api = AdminApi::default();
        api.insert_session(session(1));

        let response = api.handle(&AdminRequest::new(
            Method::Post,
            "/sessions/1/kick",
            "",
            PeerCredentials::root(),
        ))?;

        assert_eq!(response.status(), 200);
        assert_eq!(api.stats().live_sessions(), 0);
        Ok(())
    }

    #[test]
    fn capabilities_advertise_unix_peer_credentials() -> AdminResult<()> {
        let mut api = AdminApi::default();
        let response = api.handle(&AdminRequest::new(
            Method::Get,
            "/capabilities",
            "",
            PeerCredentials::root(),
        ))?;

        assert!(response.body().contains("unix_socket_only"));
        assert!(Capabilities::stage1().unix_socket_only());
        assert!(api.bind().is_unix_socket());
        Ok(())
    }

    #[test]
    fn every_error_variant_has_unique_code() {
        let errors = [
            AdminError::Unauthorized,
            AdminError::NotFound,
            AdminError::BodyTooLarge,
            AdminError::Parse {
                message: "x".to_owned(),
            },
            AdminError::Validation {
                field: "x",
                message: "x",
            },
            AdminError::SessionNotFound,
            AdminError::Serialize,
        ];
        let mut codes = errors
            .iter()
            .map(AdminError::error_code)
            .collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }
}
