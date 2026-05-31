//! Stateless signaling boundary for versioned WebSocket control messages.
//!
//! `refract-signal` owns the connection-local safety envelope around the
//! Stage 1 application boundary: transport selection, bounded handshakes,
//! defensive JSON parsing, JWT authentication, per-connection rate limiting,
//! connection ceilings, and bounded egress backpressure. It intentionally keeps
//! application and room state out of this crate; that state belongs in
//! `RoomStore` and Raft once those Stage 1 interfaces exist.
//!
//! # Examples
//!
//! ```
//! # use refract_signal::{parse_client_message, SignalConfig};
//! let config = SignalConfig::default();
//! let frame = br#"{"version":1,"app":"room","type":"ping","nonce":"n1"}"#;
//! let message = parse_client_message(frame, &config)?;
//! assert_eq!(message.version().as_u16(), 1);
//! # Ok::<(), refract_signal::SignalError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::{HashSet, VecDeque},
    fmt,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, errors::Error as JwtError,
};
use refract_app::{ClientMessage, MAX_APPLICATION_NAME_BYTES};
use refract_core::{PeerId, RoomId, SessionId};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use sockudo_ws::{
    Error as WsError, Message as WsMessage, OpCode, Role,
    frame::encode_frame,
    handshake::{build_response as build_ws_response, generate_accept_key, parse_request},
    protocol::Protocol as WsProtocol,
};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Current signaling JSON protocol version.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Oldest signaling JSON protocol version accepted by this crate.
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Default per-connection outbound queue budget in bytes.
pub const DEFAULT_SEND_QUEUE_BYTES: usize = 1024 * 1024;

/// Maximum accepted WebSocket message bytes.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Default slow-loris handshake deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default idle disconnect deadline.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Consecutive unanswered keepalive pings tolerated on an idle WebSocket
/// signaling connection before it is closed as dead.
///
/// A WebRTC signaling socket is legitimately idle between SDP/ICE exchanges
/// (media flows over UDP), so a single read timeout must not close it. Each
/// timeout sends a ping; a live peer auto-replies with a pong (resetting the
/// counter), so only a genuinely dead peer reaches this bound.
const MAX_IDLE_KEEPALIVES: u32 = 4;

/// Default process-wide connection ceiling.
pub const DEFAULT_CONNECTION_CEILING: usize = 100_000;

/// Default per-connection accepted message rate.
pub const DEFAULT_MESSAGES_PER_SECOND: u32 = 100;

/// Default burst for per-connection rate limiting.
pub const DEFAULT_MESSAGE_BURST: u32 = 200;

/// Maximum bearer token bytes accepted during handshake.
pub const DEFAULT_MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Maximum roles accepted from a JWT.
pub const MAX_JWT_ROLES: usize = 32;

/// Maximum JWT subject bytes copied into the authenticated identity.
pub const MAX_JWT_SUBJECT_BYTES: usize = 128;

/// Maximum JWT room hint bytes copied into the authenticated identity.
pub const MAX_JWT_ROOM_BYTES: usize = 128;

/// Maximum JWT role string bytes copied into the authenticated identity.
pub const MAX_JWT_ROLE_BYTES: usize = 64;

/// Maximum request identifier bytes accepted in signaling JSON.
pub const MAX_REQUEST_ID_BYTES: usize = 64;

/// Maximum room name bytes accepted in signaling JSON.
pub const MAX_ROOM_BYTES: usize = 128;

/// Maximum ping nonce bytes accepted in signaling JSON.
pub const MAX_NONCE_BYTES: usize = 128;

/// Maximum browser SDP bytes accepted in signaling JSON.
pub const MAX_RTC_SDP_BYTES: usize = 16 * 1024;

/// Maximum trickled ICE candidate bytes accepted in signaling JSON.
pub const MAX_RTC_ICE_CANDIDATE_BYTES: usize = 1_024;

/// HTTP status returned when the configured connection ceiling is reached.
pub const CONNECTION_CEILING_STATUS: u16 = 503;

const HTTP_HEADER_BYTES: usize = 8 * 1024;
const HTTP_READ_CHUNK_BYTES: usize = 4 * 1024;
const HTTP_STATUS_OK: u16 = 200;
const HTTP_STATUS_BAD_REQUEST: u16 = 400;
const HTTP_STATUS_NOT_FOUND: u16 = 404;
const HTTP_STATUS_METHOD_NOT_ALLOWED: u16 = 405;
const HTTP_STATUS_CONTENT_TOO_LARGE: u16 = 413;
const HTTP_STATUS_SERVICE_UNAVAILABLE: u16 = 503;
const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
const CONTENT_TYPE_TEXT: &str = "text/plain; charset=utf-8";
const SIGNAL_INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>refract WebRTC</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#101214;color:#f6f6f6}
main{max-width:980px;margin:0 auto;padding:28px}
label{display:block;font-size:13px;color:#cbd5e1;margin-bottom:6px}
input{font:inherit;padding:8px 10px;border:1px solid #334155;border-radius:6px;background:#171b20;color:#f8fafc}
button{font:inherit;padding:8px 12px;border:0;border-radius:6px;background:#2563eb;color:white}
button:disabled{background:#475569}
.toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-bottom:18px}
.videos{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
video{width:100%;aspect-ratio:16/9;background:#000;border-radius:6px}
pre{background:#171b20;border:1px solid #334155;border-radius:6px;padding:10px;white-space:pre-wrap}
</style>
</head>
<body>
<main>
<h1>refract WebRTC</h1>
<div class="toolbar">
  <div><label for="room">Room</label><input id="room" value="demo" maxlength="128"></div>
  <button id="join">Join</button>
</div>
<div class="videos">
  <div><label>Local</label><video id="local" autoplay playsinline muted></video></div>
  <div><label>Remote</label><video id="remote" autoplay playsinline></video></div>
</div>
<pre id="status">ready</pre>
</main>
<script>
const statusBox = document.getElementById('status');
let requestId = 0;
let ws;
let pc;
const log = message => { statusBox.textContent += `\n${message}`; };
const send = payload => ws.send(JSON.stringify({version:1, request_id:String(++requestId), app:'room', ...payload}));
function leaveRoom() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    send({type:'leave'});
  }
  if (pc) {
    pc.getSenders().forEach(sender => {
      if (sender.track) sender.track.stop();
    });
    pc.close();
    pc = undefined;
  }
  const local = document.getElementById('local').srcObject;
  if (local) local.getTracks().forEach(track => track.stop());
}
window.refractDebug = {
  remoteTrackCount: () => {
    const stream = document.getElementById('remote').srcObject;
    return stream ? stream.getTracks().length : 0;
  },
  inboundRtpPackets: async () => {
    if (!pc) return 0;
    const stats = await pc.getStats();
    let packets = 0;
    stats.forEach(report => {
      if (report.type === 'inbound-rtp') {
        packets += report.packetsReceived || 0;
      }
    });
    return packets;
  },
  outboundRtpPackets: async () => {
    if (!pc) return 0;
    const stats = await pc.getStats();
    let packets = 0;
    stats.forEach(report => {
      if (report.type === 'outbound-rtp') {
        packets += report.packetsSent || 0;
      }
    });
    return packets;
  },
  requestKeyframes: async () => {
    if (!pc) return;
    await Promise.all(pc.getSenders().map(sender => {
      if (sender.track && sender.track.kind === 'video' && sender.generateKeyFrame) {
        return sender.generateKeyFrame();
      }
      return Promise.resolve();
    }));
  },
  leaveRoom,
  connectionState: () => pc ? pc.connectionState : 'new',
  iceConnectionState: () => pc ? pc.iceConnectionState : 'new'
};
function syntheticStream(label) {
  const canvas = document.createElement('canvas');
  canvas.width = 640;
  canvas.height = 360;
  const context = canvas.getContext('2d');
  let frame = 0;
  const draw = () => {
    frame += 1;
    context.fillStyle = '#101214';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = '#22c55e';
    context.fillRect((frame * 5) % canvas.width, 96, 120, 120);
    context.fillStyle = '#f8fafc';
    context.font = '32px system-ui';
    context.fillText(label, 32, 64);
  };
  draw();
  setInterval(draw, 33);
  const stream = canvas.captureStream(30);
  const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
  if (AudioContextCtor) {
    const audio = new AudioContextCtor();
    const oscillator = audio.createOscillator();
    const gain = audio.createGain();
    const destination = audio.createMediaStreamDestination();
    gain.gain.value = 0.02;
    oscillator.frequency.value = 440;
    oscillator.connect(gain);
    gain.connect(destination);
    oscillator.start();
    destination.stream.getAudioTracks().forEach(track => stream.addTrack(track));
  }
  return stream;
}
async function localStream(room) {
  const query = new URLSearchParams(location.search);
  if (query.get('fake_media') === '1' || location.hash === '#fake_media') {
    return syntheticStream(room);
  }
  return navigator.mediaDevices.getUserMedia({audio:true, video:true});
}
async function joinRoom() {
  document.getElementById('join').disabled = true;
  const room = document.getElementById('room').value || 'demo';
  const stream = await localStream(room);
  document.getElementById('local').srcObject = stream;
  pc = new RTCPeerConnection({iceServers:[]});
  stream.getTracks().forEach(track => pc.addTrack(track, stream));
  pc.ontrack = event => { document.getElementById('remote').srcObject = event.streams[0]; };
  pc.onicecandidate = event => {
    if (event.candidate) send({type:'ice_candidate', room, candidate:event.candidate.candidate});
  };
  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = async () => {
    send({type:'join', room});
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    send({type:'rtc_offer', room, sdp:offer.sdp});
  };
  ws.onmessage = async event => {
    log(event.data);
    const message = JSON.parse(event.data);
    if (message.ok && message.type === 'rtc_answer' && message.sdp) {
      await pc.setRemoteDescription({type:'answer', sdp:message.sdp});
    }
  };
  ws.onerror = () => log('websocket error');
}
statusBox.textContent = 'loading capabilities';
fetch('/capabilities').then(r => r.json()).then(j => {
  statusBox.textContent = JSON.stringify(j, null, 2);
});
document.getElementById('join').onclick = () => {
  joinRoom().catch(error => {
    document.getElementById('join').disabled = false;
    log(error.message);
  });
};
window.addEventListener('pagehide', leaveRoom);
</script>
</body>
</html>
"#;

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns the stable marker label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Result alias for signaling operations.
pub type SignalResult<T> = Result<T, SignalError>;

/// Error taxonomy for signaling safety gates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignalError {
    /// A configuration field was outside the accepted bound.
    #[error("invalid configuration: {field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// Connection ceiling was reached.
    #[error("connection ceiling reached: {active} >= {ceiling}")]
    ConnectionCeiling {
        /// Active connection count.
        active: usize,
        /// Configured ceiling.
        ceiling: usize,
    },
    /// Handshake exceeded the deterministic slow-loris deadline.
    #[error("handshake timed out after {timeout:?}")]
    HandshakeTimeout {
        /// Timeout applied to the handshake.
        timeout: Duration,
    },
    /// Connection exceeded the deterministic idle deadline.
    #[error("connection idle timed out after {timeout:?}")]
    IdleTimeout {
        /// Timeout applied to idle connections.
        timeout: Duration,
    },
    /// WebSocket message exceeded the configured cap.
    #[error("message too large: {len} > {max}")]
    MessageTooLarge {
        /// Observed message length.
        len: usize,
        /// Configured maximum length.
        max: usize,
    },
    /// Message was not valid signaling JSON.
    #[error("invalid protocol json")]
    InvalidJson {
        /// Underlying JSON parser error.
        #[source]
        source: serde_json::Error,
    },
    /// Signaling protocol version was outside the accepted range.
    #[error("unsupported protocol version: {version}")]
    UnsupportedVersion {
        /// Received protocol version.
        version: u16,
    },
    /// Application name was empty, oversized, or contained an invalid byte.
    #[error("invalid application name")]
    InvalidApplicationName,
    /// Request identifier violated signaling bounds.
    #[error("invalid request id")]
    InvalidRequestId,
    /// Room identifier violated signaling bounds.
    #[error("invalid room")]
    InvalidRoom,
    /// Browser SDP violated signaling bounds or required WebRTC fields.
    #[error("invalid rtc sdp")]
    InvalidRtcSdp,
    /// Trickle ICE candidate violated signaling bounds.
    #[error("invalid ice candidate")]
    InvalidIceCandidate,
    /// RTC media forwarding is not wired for this signaling listener.
    #[error("rtc media forwarding unavailable")]
    RtcMediaUnavailable,
    /// Per-connection rate limit was exceeded.
    #[error("connection rate limit exceeded")]
    RateLimited,
    /// Bearer token exceeded the configured cap.
    #[error("token too large: {len} > {max}")]
    TokenTooLarge {
        /// Observed token length.
        len: usize,
        /// Configured maximum length.
        max: usize,
    },
    /// Bearer token failed authentication or claim validation.
    #[error("authentication failed")]
    Authentication {
        /// Authentication failure source.
        #[source]
        source: JwtError,
    },
    /// JWT claims were present but violated refract bounds.
    #[error("invalid jwt claim: {field}")]
    InvalidClaim {
        /// Invalid claim field.
        field: &'static str,
    },
    /// Bounded queue allocation failed.
    #[error("allocation failed in {component}")]
    Allocation {
        /// Component that failed to reserve memory.
        component: &'static str,
    },
    /// Per-connection send queue overflowed and the connection must close.
    #[error("send queue overflow: {queued_bytes} + {frame_bytes} > {limit_bytes}")]
    BackpressureOverflow {
        /// Bytes already queued.
        queued_bytes: usize,
        /// Candidate frame bytes.
        frame_bytes: usize,
        /// Configured queue budget.
        limit_bytes: usize,
    },
    /// Operation targeted a connection already closed by a safety gate.
    #[error("connection is closed: {reason}")]
    Disconnected {
        /// Close reason.
        reason: CloseReason,
    },
    /// HTTP fallback listener or connection I/O failed.
    #[error("signal http io failed: {source}")]
    Io {
        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },
    /// WebSocket handshake or framed message failed validation.
    #[error("websocket protocol failed: {source}")]
    WebSocket {
        /// Source WebSocket protocol error.
        #[source]
        source: WsError,
    },
}

impl SignalError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::SignalError;
    /// assert_eq!(
    ///     SignalError::InvalidApplicationName.error_code(),
    ///     "HSF-PROTO-003"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "HSF-CONFIG-001",
            Self::ConnectionCeiling { .. } => "HSF-CONN-001",
            Self::HandshakeTimeout { .. } => "HSF-SL-001",
            Self::IdleTimeout { .. } => "HSF-IDLE-001",
            Self::MessageTooLarge { .. } => "HSF-PROTO-001",
            Self::InvalidJson { .. } => "HSF-PROTO-002",
            Self::UnsupportedVersion { .. } => "HSF-PROTO-004",
            Self::InvalidApplicationName => "HSF-PROTO-003",
            Self::InvalidRequestId => "HSF-PROTO-005",
            Self::InvalidRoom => "HSF-RTC-ROOM-001",
            Self::InvalidRtcSdp => "HSF-RTC-SDP-001",
            Self::InvalidIceCandidate => "HSF-RTC-ICE-001",
            Self::RtcMediaUnavailable => "HSF-RTC-MEDIA-001",
            Self::RateLimited => "HSF-RATE-001",
            Self::TokenTooLarge { .. } => "HSF-AUTH-001",
            Self::Authentication { .. } => "HSF-AUTH-002",
            Self::InvalidClaim { .. } => "HSF-AUTH-003",
            Self::Allocation { .. } => "HSF-ALLOC-001",
            Self::BackpressureOverflow { .. } => "HSF-BP-001",
            Self::Disconnected { .. } => "HSF-CONN-002",
            Self::Io { .. } => "HSF-IO-001",
            Self::WebSocket { .. } => "HSF-WS-001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalError, Stability};
    /// assert_eq!(
    ///     SignalError::InvalidApplicationName.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Minimal browser-facing HTTP/1.1 signaling listener.
///
/// This listener is the Stage 1 fallback transport mounted by `refract-bin`.
/// It serves readiness/capability endpoints, a bounded diagnostic page, and a
/// JSON `/signal` endpoint backed by [`parse_client_message`]. The media SFU
/// path remains separate; this type only owns the slow signaling boundary.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::atomic::AtomicBool;
/// # use refract_signal::{SignalHttpServer, SignalHttpServerConfig};
/// let server = SignalHttpServer::bind(SignalHttpServerConfig::localhost(50000)?)?;
/// let stop = AtomicBool::new(false);
/// server.run_until(&stop)?;
/// # Ok::<(), refract_signal::SignalError>(())
/// ```
pub struct SignalHttpServer {
    listener: TcpListener,
    config: SignalHttpServerConfig,
    rtc_controller: Option<Arc<dyn RtcSignalingController>>,
}

impl fmt::Debug for SignalHttpServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalHttpServer")
            .field("config", &self.config)
            .field("rtc_controller", &self.rtc_controller.is_some())
            .finish_non_exhaustive()
    }
}

impl SignalHttpServer {
    /// Binds a browser-facing HTTP signaling listener.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] when the socket cannot be bound or moved to
    /// nonblocking mode.
    pub fn bind(config: SignalHttpServerConfig) -> SignalResult<Self> {
        let listener = bind_tcp_listener(config.bind())?;
        listener
            .set_nonblocking(true)
            .map_err(|source| SignalError::Io { source })?;
        Ok(Self {
            listener,
            config,
            rtc_controller: None,
        })
    }

    /// Binds a browser-facing HTTP signaling listener with RTC media control.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] when the socket cannot be bound or moved to
    /// nonblocking mode.
    pub fn bind_with_rtc(
        config: SignalHttpServerConfig,
        controller: Arc<dyn RtcSignalingController>,
    ) -> SignalResult<Self> {
        let mut server = Self::bind(config)?;
        server.rtc_controller = Some(controller);
        Ok(server)
    }

    /// Runs the listener until `stop` is raised.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] when the listener fails with an error other
    /// than nonblocking "would block".
    pub fn run_until(&self, stop: &AtomicBool) -> SignalResult<()> {
        let active = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    if active.load(Ordering::Acquire) >= self.config.signal().connection_ceiling() {
                        reject_connection(
                            stream,
                            &SignalError::ConnectionCeiling {
                                active: active.load(Ordering::Relaxed),
                                ceiling: self.config.signal().connection_ceiling(),
                            },
                        )?;
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let active_connection = active.clone();
                    let config = self.config;
                    let controller = self.rtc_controller.clone();
                    thread::Builder::new()
                        .name("refract-signal-connection".to_owned())
                        .spawn(move || {
                            if let Err(error) =
                                handle_http_stream(stream, config, controller.as_ref())
                            {
                                warn!(
                                    event = "signal_connection_failed",
                                    peer = %peer,
                                    error_code = error.error_code(),
                                    error = %error,
                                );
                            }
                            active_connection.fetch_sub(1, Ordering::AcqRel);
                        })
                        .map_err(|source| SignalError::Io { source })?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(source) => return Err(SignalError::Io { source }),
            }
        }
        Ok(())
    }

    /// Returns the bound local socket.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] when the OS cannot report the local address.
    pub fn local_addr(&self) -> SignalResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|source| SignalError::Io { source })
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalHttpServerConfig, Stability};
    /// assert_eq!(
    ///     SignalHttpServerConfig::default().stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

fn reject_connection(mut stream: TcpStream, error: &SignalError) -> SignalResult<()> {
    let response = error_response(error);
    stream
        .write_all(&response)
        .map_err(|source| SignalError::Io { source })
}

fn bind_tcp_listener(bind: SocketAddr) -> SignalResult<TcpListener> {
    let domain = if bind.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))
        .map_err(|source| SignalError::Io { source })?;
    socket
        .set_reuse_address(true)
        .map_err(|source| SignalError::Io { source })?;
    socket
        .bind(&bind.into())
        .map_err(|source| SignalError::Io { source })?;
    socket
        .listen(1024)
        .map_err(|source| SignalError::Io { source })?;
    Ok(socket.into())
}

/// Configuration for [`SignalHttpServer`].
///
/// # Examples
///
/// ```
/// # use refract_signal::SignalHttpServerConfig;
/// let config = SignalHttpServerConfig::localhost(50000)?;
/// assert_eq!(config.bind().port(), 50000);
/// # Ok::<(), refract_signal::SignalError>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalHttpServerConfig {
    bind: SocketAddr,
    signal: SignalConfig,
    capabilities: SignalCapabilities,
}

impl Default for SignalHttpServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 50_000)),
            signal: SignalConfig::default(),
            capabilities: SignalCapabilities::default(),
        }
    }
}

impl SignalHttpServerConfig {
    /// Creates a localhost configuration for the supplied port.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidConfig`] when the port is zero.
    pub fn localhost(port: u16) -> SignalResult<Self> {
        if port == 0 {
            return Err(SignalError::InvalidConfig { field: "bind.port" });
        }
        Ok(Self {
            bind: SocketAddr::from(([127, 0, 0, 1], port)),
            signal: SignalConfig::default(),
            capabilities: SignalCapabilities::default(),
        })
    }

    /// Creates an HTTP server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidConfig`] when `bind` has port zero or the
    /// nested signaling config is invalid.
    pub fn new(bind: SocketAddr, signal: SignalConfig) -> SignalResult<Self> {
        if bind.port() == 0 {
            return Err(SignalError::InvalidConfig { field: "bind.port" });
        }
        signal.validate()?;
        Ok(Self {
            bind,
            signal,
            capabilities: SignalCapabilities::default(),
        })
    }

    /// Returns this config with advertised runtime capabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalCapabilities, SignalHttpServerConfig};
    /// let config =
    ///     SignalHttpServerConfig::default().with_capabilities(SignalCapabilities::new(true, false));
    /// assert!(config.capabilities().sfu_media_sockets());
    /// ```
    #[must_use]
    pub const fn with_capabilities(mut self, capabilities: SignalCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Returns the socket address to bind.
    #[must_use]
    pub const fn bind(self) -> SocketAddr {
        self.bind
    }

    /// Returns the nested signaling bounds.
    #[must_use]
    pub const fn signal(self) -> SignalConfig {
        self.signal
    }

    /// Returns advertised runtime capabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::SignalHttpServerConfig;
    /// assert!(
    ///     !SignalHttpServerConfig::default()
    ///         .capabilities()
    ///         .webrtc_media_forwarding()
    /// );
    /// ```
    #[must_use]
    pub const fn capabilities(self) -> SignalCapabilities {
        self.capabilities
    }

    /// Returns the Stage 1 stability marker.
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Browser-facing capability flags exposed by `/capabilities`.
///
/// These flags are deliberately runtime-derived; they must not be flipped until
/// the corresponding subsystem is actually started.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalCapabilities {
    sfu_media_sockets: bool,
    webrtc_media_forwarding: bool,
}

impl SignalCapabilities {
    /// Creates advertised capabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::SignalCapabilities;
    /// let caps = SignalCapabilities::new(true, false);
    /// assert!(caps.sfu_media_sockets());
    /// ```
    #[must_use]
    pub const fn new(sfu_media_sockets: bool, webrtc_media_forwarding: bool) -> Self {
        Self {
            sfu_media_sockets,
            webrtc_media_forwarding,
        }
    }

    /// Returns whether live SFU media sockets are started.
    #[must_use]
    pub const fn sfu_media_sockets(self) -> bool {
        self.sfu_media_sockets
    }

    /// Returns whether browser WebRTC media forwarding is enabled.
    #[must_use]
    pub const fn webrtc_media_forwarding(self) -> bool {
        self.webrtc_media_forwarding
    }

    /// Returns the Stage 1 stability marker.
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Stable RTC metadata shared between signaling and the owning media core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcSessionMetadata {
    session_id: SessionId,
    peer_id: PeerId,
    room_id: RoomId,
    core_id: u16,
    media_addr: SocketAddr,
}

impl RtcSessionMetadata {
    /// Creates RTC session metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_signal::RtcSessionMetadata;
    /// let metadata = RtcSessionMetadata::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    ///     0,
    ///     "127.0.0.1:50000".parse::<SocketAddr>()?,
    /// );
    /// assert_eq!(metadata.core_id(), 0);
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        peer_id: PeerId,
        room_id: RoomId,
        core_id: u16,
        media_addr: SocketAddr,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            room_id,
            core_id,
            media_addr,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Returns the peer identifier.
    #[must_use]
    pub const fn peer_id(self) -> PeerId {
        self.peer_id
    }

    /// Returns the room identifier.
    #[must_use]
    pub const fn room_id(self) -> RoomId {
        self.room_id
    }

    /// Returns the owning core index.
    #[must_use]
    pub const fn core_id(self) -> u16 {
        self.core_id
    }

    /// Returns the advertised media socket address.
    #[must_use]
    pub const fn media_addr(self) -> SocketAddr {
        self.media_addr
    }
}

/// Join request passed to an RTC signaling controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcJoinRequest<'a> {
    room: &'a str,
}

impl<'a> RtcJoinRequest<'a> {
    /// Creates a join request.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::RtcJoinRequest;
    /// assert_eq!(RtcJoinRequest::new("demo").room(), "demo");
    /// ```
    #[must_use]
    pub const fn new(room: &'a str) -> Self {
        Self { room }
    }

    /// Returns the room string.
    #[must_use]
    pub const fn room(self) -> &'a str {
        self.room
    }
}

/// Offer request passed to an RTC signaling controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcOfferRequest<'a> {
    room: &'a str,
    sdp: &'a str,
    metadata: Option<RtcSessionMetadata>,
}

impl<'a> RtcOfferRequest<'a> {
    /// Creates an offer request.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::RtcOfferRequest;
    /// assert_eq!(RtcOfferRequest::new("demo", "v=0", None).sdp(), "v=0");
    /// ```
    #[must_use]
    pub const fn new(room: &'a str, sdp: &'a str, metadata: Option<RtcSessionMetadata>) -> Self {
        Self {
            room,
            sdp,
            metadata,
        }
    }

    /// Returns the room string.
    #[must_use]
    pub const fn room(self) -> &'a str {
        self.room
    }

    /// Returns the browser SDP offer.
    #[must_use]
    pub const fn sdp(self) -> &'a str {
        self.sdp
    }

    /// Returns existing session metadata, if the connection already joined.
    #[must_use]
    pub const fn metadata(self) -> Option<RtcSessionMetadata> {
        self.metadata
    }
}

/// ICE candidate request passed to an RTC signaling controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcIceCandidateRequest<'a> {
    session_id: SessionId,
    candidate: &'a str,
}

impl<'a> RtcIceCandidateRequest<'a> {
    /// Creates an ICE candidate request.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::SessionId;
    /// # use refract_signal::RtcIceCandidateRequest;
    /// let request = RtcIceCandidateRequest::new(SessionId::from_raw(1), "candidate:1");
    /// assert_eq!(request.session_id(), SessionId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn new(session_id: SessionId, candidate: &'a str) -> Self {
        Self {
            session_id,
            candidate,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Returns the ICE candidate text.
    #[must_use]
    pub const fn candidate(self) -> &'a str {
        self.candidate
    }
}

/// Answer returned by an RTC signaling controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtcAnswer {
    metadata: RtcSessionMetadata,
    sdp: Box<str>,
}

impl RtcAnswer {
    /// Creates a controller answer.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let answer = RtcAnswer::new(metadata, sdp);
    /// ```
    #[must_use]
    pub const fn new(metadata: RtcSessionMetadata, sdp: Box<str>) -> Self {
        Self { metadata, sdp }
    }

    /// Returns accepted session metadata.
    #[must_use]
    pub const fn metadata(&self) -> RtcSessionMetadata {
        self.metadata
    }

    /// Returns the SDP answer.
    #[must_use]
    pub fn sdp(&self) -> &str {
        &self.sdp
    }
}

/// Slow-path controller used by signaling to create and update RTC sessions.
pub trait RtcSignalingController: Send + Sync + fmt::Debug {
    /// Allocates or records a joined RTC session.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError`] when the controller cannot allocate the session.
    fn join(&self, request: RtcJoinRequest<'_>) -> SignalResult<RtcSessionMetadata>;

    /// Accepts one browser offer and returns a browser-ready SDP answer.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError`] when the media core rejects the offer.
    fn accept_offer(&self, request: RtcOfferRequest<'_>) -> SignalResult<RtcAnswer>;

    /// Adds one trickled ICE candidate to an existing RTC session.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError`] when the session is unknown or the candidate is
    /// invalid.
    fn add_ice_candidate(&self, request: RtcIceCandidateRequest<'_>) -> SignalResult<()>;

    /// Leaves and removes one RTC session.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError`] when the media core cannot complete cleanup.
    fn leave(&self, session_id: SessionId) -> SignalResult<()>;
}

/// Listener transport profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProfile {
    /// HTTP/3 listener using the `h3` protocol stack over Quinn QUIC.
    Http3H3Quinn,
    /// Fallback HTTP/1.1 WebSocket listener.
    Http11WebSocket,
}

impl TransportProfile {
    /// Returns the bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::TransportProfile;
    /// assert_eq!(TransportProfile::Http3H3Quinn.as_str(), "http3_h3_quinn");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http3H3Quinn => "http3_h3_quinn",
            Self::Http11WebSocket => "http11_websocket",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{Stability, TransportProfile};
    /// assert_eq!(
    ///     TransportProfile::Http11WebSocket.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for TransportProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One configured signaling listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    bind: SocketAddr,
    transport: TransportProfile,
}

impl ListenerConfig {
    /// Creates a listener configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_signal::{ListenerConfig, TransportProfile};
    /// let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    /// let listener = ListenerConfig::new(bind, TransportProfile::Http3H3Quinn);
    /// assert_eq!(listener.transport(), TransportProfile::Http3H3Quinn);
    /// ```
    #[must_use]
    pub const fn new(bind: SocketAddr, transport: TransportProfile) -> Self {
        Self { bind, transport }
    }

    /// Returns the socket address to bind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_signal::{ListenerConfig, TransportProfile};
    /// let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    /// assert_eq!(
    ///     ListenerConfig::new(bind, TransportProfile::Http11WebSocket).bind(),
    ///     bind
    /// );
    /// ```
    #[must_use]
    pub const fn bind(self) -> SocketAddr {
        self.bind
    }

    /// Returns the transport profile.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_signal::{ListenerConfig, TransportProfile};
    /// let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    /// assert_eq!(
    ///     ListenerConfig::new(bind, TransportProfile::Http11WebSocket).transport(),
    ///     TransportProfile::Http11WebSocket,
    /// );
    /// ```
    #[must_use]
    pub const fn transport(self) -> TransportProfile {
        self.transport
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_signal::{ListenerConfig, Stability, TransportProfile};
    /// let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    /// assert_eq!(
    ///     ListenerConfig::new(bind, TransportProfile::Http11WebSocket).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Signaling safety-envelope configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalConfig {
    send_queue_bytes: usize,
    max_message_bytes: usize,
    handshake_timeout: Duration,
    idle_timeout: Duration,
    connection_ceiling: usize,
    messages_per_second: u32,
    message_burst: u32,
    max_token_bytes: usize,
}

impl SignalConfig {
    /// Creates a validated signaling configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidConfig`] when any bound is zero or
    /// internally inconsistent.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_signal::SignalConfig;
    /// let config = SignalConfig::new(
    ///     1024,
    ///     512,
    ///     Duration::from_secs(5),
    ///     Duration::from_secs(30),
    ///     10,
    ///     50,
    ///     100,
    ///     1024,
    /// )?;
    /// assert_eq!(config.connection_ceiling(), 10);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        send_queue_bytes: usize,
        max_message_bytes: usize,
        handshake_timeout: Duration,
        idle_timeout: Duration,
        connection_ceiling: usize,
        messages_per_second: u32,
        message_burst: u32,
        max_token_bytes: usize,
    ) -> SignalResult<Self> {
        let config = Self {
            send_queue_bytes,
            max_message_bytes,
            handshake_timeout,
            idle_timeout,
            connection_ceiling,
            messages_per_second,
            message_burst,
            max_token_bytes,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates this configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidConfig`] when any bound is zero or
    /// internally inconsistent.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::SignalConfig;
    /// SignalConfig::default().validate()?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub const fn validate(self) -> SignalResult<()> {
        if self.send_queue_bytes == 0 {
            return Err(SignalError::InvalidConfig {
                field: "send_queue_bytes",
            });
        }
        if self.max_message_bytes == 0 {
            return Err(SignalError::InvalidConfig {
                field: "max_message_bytes",
            });
        }
        if self.max_message_bytes > self.send_queue_bytes {
            return Err(SignalError::InvalidConfig {
                field: "max_message_bytes",
            });
        }
        if self.handshake_timeout.is_zero() {
            return Err(SignalError::InvalidConfig {
                field: "handshake_timeout",
            });
        }
        if self.idle_timeout.is_zero() {
            return Err(SignalError::InvalidConfig {
                field: "idle_timeout",
            });
        }
        if self.connection_ceiling == 0 {
            return Err(SignalError::InvalidConfig {
                field: "connection_ceiling",
            });
        }
        if self.messages_per_second == 0 {
            return Err(SignalError::InvalidConfig {
                field: "messages_per_second",
            });
        }
        if self.message_burst == 0 {
            return Err(SignalError::InvalidConfig {
                field: "message_burst",
            });
        }
        if self.max_token_bytes == 0 {
            return Err(SignalError::InvalidConfig {
                field: "max_token_bytes",
            });
        }
        Ok(())
    }

    /// Returns the outbound queue byte budget.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_SEND_QUEUE_BYTES};
    /// assert_eq!(
    ///     SignalConfig::default().send_queue_bytes(),
    ///     DEFAULT_SEND_QUEUE_BYTES
    /// );
    /// ```
    #[must_use]
    pub const fn send_queue_bytes(self) -> usize {
        self.send_queue_bytes
    }

    /// Returns the maximum accepted message bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_MAX_MESSAGE_BYTES};
    /// assert_eq!(
    ///     SignalConfig::default().max_message_bytes(),
    ///     DEFAULT_MAX_MESSAGE_BYTES
    /// );
    /// ```
    #[must_use]
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes
    }

    /// Returns the handshake timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_HANDSHAKE_TIMEOUT};
    /// assert_eq!(
    ///     SignalConfig::default().handshake_timeout(),
    ///     DEFAULT_HANDSHAKE_TIMEOUT
    /// );
    /// ```
    #[must_use]
    pub const fn handshake_timeout(self) -> Duration {
        self.handshake_timeout
    }

    /// Returns the idle timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_IDLE_TIMEOUT};
    /// assert_eq!(SignalConfig::default().idle_timeout(), DEFAULT_IDLE_TIMEOUT);
    /// ```
    #[must_use]
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    /// Returns the connection ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_CONNECTION_CEILING};
    /// assert_eq!(
    ///     SignalConfig::default().connection_ceiling(),
    ///     DEFAULT_CONNECTION_CEILING
    /// );
    /// ```
    #[must_use]
    pub const fn connection_ceiling(self) -> usize {
        self.connection_ceiling
    }

    /// Returns the sustained per-connection message rate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_MESSAGES_PER_SECOND};
    /// assert_eq!(
    ///     SignalConfig::default().messages_per_second(),
    ///     DEFAULT_MESSAGES_PER_SECOND
    /// );
    /// ```
    #[must_use]
    pub const fn messages_per_second(self) -> u32 {
        self.messages_per_second
    }

    /// Returns the per-connection message burst.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_MESSAGE_BURST};
    /// assert_eq!(
    ///     SignalConfig::default().message_burst(),
    ///     DEFAULT_MESSAGE_BURST
    /// );
    /// ```
    #[must_use]
    pub const fn message_burst(self) -> u32 {
        self.message_burst
    }

    /// Returns the maximum accepted bearer token bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, DEFAULT_MAX_TOKEN_BYTES};
    /// assert_eq!(
    ///     SignalConfig::default().max_token_bytes(),
    ///     DEFAULT_MAX_TOKEN_BYTES
    /// );
    /// ```
    #[must_use]
    pub const fn max_token_bytes(self) -> usize {
        self.max_token_bytes
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, Stability};
    /// assert_eq!(SignalConfig::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            send_queue_bytes: DEFAULT_SEND_QUEUE_BYTES,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            connection_ceiling: DEFAULT_CONNECTION_CEILING,
            messages_per_second: DEFAULT_MESSAGES_PER_SECOND,
            message_burst: DEFAULT_MESSAGE_BURST,
            max_token_bytes: DEFAULT_MAX_TOKEN_BYTES,
        }
    }
}

/// Connection identifier local to a signaling worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Creates a connection identifier from a raw value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::ConnectionId;
    /// assert_eq!(ConnectionId::from_raw(7).raw(), 7);
    /// ```
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::ConnectionId;
    /// assert_eq!(ConnectionId::from_raw(9).raw(), 9);
    /// ```
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionId, Stability};
    /// assert_eq!(ConnectionId::from_raw(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "conn_{:016x}", self.0)
    }
}

/// Accepted connection permit tracked by the owning worker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionPermit {
    id: ConnectionId,
}

impl ConnectionPermit {
    /// Returns the connection identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionId, ConnectionPermit};
    /// let permit = ConnectionPermit::new(ConnectionId::from_raw(1));
    /// assert_eq!(permit.id().raw(), 1);
    /// ```
    #[must_use]
    pub const fn new(id: ConnectionId) -> Self {
        Self { id }
    }

    /// Returns the connection identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionId, ConnectionPermit};
    /// let permit = ConnectionPermit::new(ConnectionId::from_raw(2));
    /// assert_eq!(permit.id(), ConnectionId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn id(self) -> ConnectionId {
        self.id
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionId, ConnectionPermit, Stability};
    /// assert_eq!(
    ///     ConnectionPermit::new(ConnectionId::from_raw(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Shared-nothing connection ceiling ledger for one signaling worker.
#[derive(Debug)]
pub struct ConnectionLedger {
    ceiling: usize,
    active: usize,
    next_id: u64,
}

impl ConnectionLedger {
    /// Creates a connection ledger from validated configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionLedger, SignalConfig};
    /// let ledger = ConnectionLedger::new(SignalConfig::default());
    /// assert_eq!(ledger.active(), 0);
    /// ```
    #[must_use]
    pub const fn new(config: SignalConfig) -> Self {
        Self {
            ceiling: config.connection_ceiling(),
            active: 0,
            next_id: 1,
        }
    }

    /// Attempts to admit one connection.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::ConnectionCeiling`] once the ledger reaches its
    /// configured ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionLedger, SignalConfig};
    /// let mut ledger = ConnectionLedger::new(SignalConfig::default());
    /// let permit = ledger.try_open()?;
    /// assert_eq!(ledger.active(), 1);
    /// ledger.close(permit);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn try_open(&mut self) -> SignalResult<ConnectionPermit> {
        if self.active >= self.ceiling {
            warn!(
                event = "signal_connection_ceiling",
                active = self.active,
                ceiling = self.ceiling,
                status = CONNECTION_CEILING_STATUS,
            );
            return Err(SignalError::ConnectionCeiling {
                active: self.active,
                ceiling: self.ceiling,
            });
        }
        let permit = ConnectionPermit::new(ConnectionId::from_raw(self.next_id));
        self.next_id = self.next_id.saturating_add(1);
        self.active += 1;
        info!(
            event = "signal_connection_open",
            connection_id = %permit.id(),
            active = self.active,
        );
        Ok(permit)
    }

    /// Closes a previously opened connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionLedger, SignalConfig};
    /// let mut ledger = ConnectionLedger::new(SignalConfig::default());
    /// let permit = ledger.try_open()?;
    /// ledger.close(permit);
    /// assert_eq!(ledger.active(), 0);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn close(&mut self, permit: ConnectionPermit) {
        self.active = self.active.saturating_sub(1);
        info!(
            event = "signal_connection_close",
            connection_id = %permit.id(),
            active = self.active,
        );
    }

    /// Returns the active connection count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionLedger, SignalConfig};
    /// assert_eq!(ConnectionLedger::new(SignalConfig::default()).active(), 0);
    /// ```
    #[must_use]
    pub const fn active(&self) -> usize {
        self.active
    }

    /// Returns the configured ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionLedger, SignalConfig};
    /// assert_eq!(
    ///     ConnectionLedger::new(SignalConfig::default()).ceiling(),
    ///     SignalConfig::default().connection_ceiling(),
    /// );
    /// ```
    #[must_use]
    pub const fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ConnectionLedger, SignalConfig, Stability};
    /// assert_eq!(
    ///     ConnectionLedger::new(SignalConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Close reason emitted by a connection-local safety gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CloseReason {
    /// Backpressure overflow; maps to `HSF-BP-001`.
    Backpressure,
    /// Authentication failed.
    Authentication,
    /// Rate limit exceeded.
    RateLimited,
    /// Protocol input was invalid.
    Protocol,
    /// Slow-loris handshake timeout.
    HandshakeTimeout,
    /// Idle connection timeout.
    IdleTimeout,
}

impl CloseReason {
    /// Returns the unique close code used in logs and metrics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::CloseReason;
    /// assert_eq!(CloseReason::Backpressure.error_code(), "HSF-BP-001");
    /// ```
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::Backpressure => "HSF-BP-001",
            Self::Authentication => "HSF-AUTH-002",
            Self::RateLimited => "HSF-RATE-001",
            Self::Protocol => "HSF-PROTO-002",
            Self::HandshakeTimeout => "HSF-SL-001",
            Self::IdleTimeout => "HSF-IDLE-001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{CloseReason, Stability};
    /// assert_eq!(CloseReason::Protocol.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.error_code())
    }
}

/// Outbound WebSocket frame stored in a bounded send queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundFrame {
    bytes: Box<[u8]>,
}

impl OutboundFrame {
    /// Copies frame bytes after validating the per-frame cap.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::MessageTooLarge`] when `bytes` exceeds
    /// `max_message_bytes`, or [`SignalError::Allocation`] if bounded
    /// allocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::OutboundFrame;
    /// let frame = OutboundFrame::try_from_bytes(b"{}", 64)?;
    /// assert_eq!(frame.as_bytes(), b"{}");
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn try_from_bytes(bytes: &[u8], max_message_bytes: usize) -> SignalResult<Self> {
        if bytes.len() > max_message_bytes {
            return Err(SignalError::MessageTooLarge {
                len: bytes.len(),
                max: max_message_bytes,
            });
        }
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(bytes.len())
            .map_err(|_source| SignalError::Allocation {
                component: "outbound_frame",
            })?;
        copied.extend_from_slice(bytes);
        Ok(Self {
            bytes: copied.into_boxed_slice(),
        })
    }

    /// Returns frame bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::OutboundFrame;
    /// assert_eq!(OutboundFrame::try_from_bytes(b"x", 1)?.as_bytes(), b"x");
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns frame length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::OutboundFrame;
    /// assert_eq!(OutboundFrame::try_from_bytes(b"x", 1)?.len(), 1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this frame is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::OutboundFrame;
    /// assert!(OutboundFrame::try_from_bytes(b"", 1)?.is_empty());
    /// # Ok::<(), refract_signal::SignalError>(())
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
    /// # use refract_signal::{OutboundFrame, Stability};
    /// assert_eq!(
    ///     OutboundFrame::try_from_bytes(b"x", 1)?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Per-connection bounded outbound queue.
#[derive(Debug)]
pub struct SendQueue {
    limit_bytes: usize,
    max_message_bytes: usize,
    queued_bytes: usize,
    closed: Option<CloseReason>,
    frames: VecDeque<OutboundFrame>,
}

impl SendQueue {
    /// Creates an empty queue from validated configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig};
    /// let queue = SendQueue::new(SignalConfig::default());
    /// assert_eq!(queue.queued_bytes(), 0);
    /// ```
    #[must_use]
    pub const fn new(config: SignalConfig) -> Self {
        Self {
            limit_bytes: config.send_queue_bytes(),
            max_message_bytes: config.max_message_bytes(),
            queued_bytes: 0,
            closed: None,
            frames: VecDeque::new(),
        }
    }

    /// Enqueues one outbound frame or closes the connection on overflow.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::BackpressureOverflow`] when the enqueue would
    /// exceed the configured byte budget, [`SignalError::MessageTooLarge`] for
    /// oversized frames, [`SignalError::Disconnected`] after any safety close,
    /// or [`SignalError::Allocation`] if queue storage cannot be reserved.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig};
    /// let mut queue = SendQueue::new(SignalConfig::default());
    /// queue.enqueue(b"ok")?;
    /// assert_eq!(queue.queued_bytes(), 2);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn enqueue(&mut self, bytes: &[u8]) -> SignalResult<()> {
        if let Some(reason) = self.closed {
            return Err(SignalError::Disconnected { reason });
        }
        let frame = OutboundFrame::try_from_bytes(bytes, self.max_message_bytes)?;
        let candidate = self.queued_bytes.saturating_add(frame.len());
        if candidate > self.limit_bytes {
            self.closed = Some(CloseReason::Backpressure);
            warn!(
                event = "signal_backpressure_disconnect",
                error_code = CloseReason::Backpressure.error_code(),
                queued_bytes = self.queued_bytes,
                frame_bytes = frame.len(),
                limit_bytes = self.limit_bytes,
            );
            return Err(SignalError::BackpressureOverflow {
                queued_bytes: self.queued_bytes,
                frame_bytes: frame.len(),
                limit_bytes: self.limit_bytes,
            });
        }
        self.frames
            .try_reserve_exact(1)
            .map_err(|_source| SignalError::Allocation {
                component: "send_queue",
            })?;
        self.queued_bytes = candidate;
        self.frames.push_back(frame);
        Ok(())
    }

    /// Pops the next outbound frame.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig};
    /// let mut queue = SendQueue::new(SignalConfig::default());
    /// queue.enqueue(b"ok")?;
    /// assert_eq!(queue.pop().map(|frame| frame.len()), Some(2));
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn pop(&mut self) -> Option<OutboundFrame> {
        let frame = self.frames.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(frame.len());
        Some(frame)
    }

    /// Returns the queued byte count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig};
    /// assert_eq!(SendQueue::new(SignalConfig::default()).queued_bytes(), 0);
    /// ```
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Returns the configured byte limit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig};
    /// assert_eq!(
    ///     SendQueue::new(SignalConfig::default()).limit_bytes(),
    ///     SignalConfig::default().send_queue_bytes(),
    /// );
    /// ```
    #[must_use]
    pub const fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }

    /// Returns the close reason if the queue closed the connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig};
    /// assert_eq!(
    ///     SendQueue::new(SignalConfig::default()).closed_reason(),
    ///     None
    /// );
    /// ```
    #[must_use]
    pub const fn closed_reason(&self) -> Option<CloseReason> {
        self.closed
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SendQueue, SignalConfig, Stability};
    /// assert_eq!(
    ///     SendQueue::new(SignalConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Per-connection rate limiter backed by `governor`.
pub struct SignalRateLimiter {
    limiter: DefaultDirectRateLimiter,
}

impl SignalRateLimiter {
    /// Creates a rate limiter from signaling configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidConfig`] if the rate or burst fields are
    /// zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, SignalRateLimiter};
    /// let limiter = SignalRateLimiter::new(SignalConfig::default())?;
    /// limiter.check()?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn new(config: SignalConfig) -> SignalResult<Self> {
        let rate =
            NonZeroU32::new(config.messages_per_second()).ok_or(SignalError::InvalidConfig {
                field: "messages_per_second",
            })?;
        let burst = NonZeroU32::new(config.message_burst()).ok_or(SignalError::InvalidConfig {
            field: "message_burst",
        })?;
        let quota = Quota::per_second(rate).allow_burst(burst);
        Ok(Self {
            limiter: RateLimiter::direct(quota),
        })
    }

    /// Checks whether one incoming message may proceed.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::RateLimited`] when this connection exhausted its
    /// configured quota.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, SignalRateLimiter};
    /// let limiter = SignalRateLimiter::new(SignalConfig::default())?;
    /// limiter.check()?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn check(&self) -> SignalResult<()> {
        self.limiter.check().map_err(|_negative| {
            warn!(
                event = "signal_rate_limited",
                error_code = SignalError::RateLimited.error_code(),
            );
            SignalError::RateLimited
        })
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{SignalConfig, SignalRateLimiter, Stability};
    /// assert_eq!(
    ///     SignalRateLimiter::new(SignalConfig::default())?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Debug for SignalRateLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalRateLimiter")
            .field("backend", &"governor")
            .finish_non_exhaustive()
    }
}

/// Slow-loris handshake tracker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeTracker {
    started_at: Instant,
    deadline: Duration,
    received_bytes: usize,
    complete: bool,
}

impl HandshakeTracker {
    /// Starts a handshake tracker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig};
    /// let tracker = HandshakeTracker::start(Instant::now(), SignalConfig::default());
    /// assert!(!tracker.is_complete());
    /// ```
    #[must_use]
    pub const fn start(started_at: Instant, config: SignalConfig) -> Self {
        Self {
            started_at,
            deadline: config.handshake_timeout(),
            received_bytes: 0,
            complete: false,
        }
    }

    /// Records bytes received during handshake.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::MessageTooLarge`] if the handshake byte count
    /// exceeds `max_message_bytes`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig};
    /// let mut tracker = HandshakeTracker::start(Instant::now(), SignalConfig::default());
    /// tracker.record_bytes(12, SignalConfig::default())?;
    /// assert_eq!(tracker.received_bytes(), 12);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub const fn record_bytes(&mut self, len: usize, config: SignalConfig) -> SignalResult<()> {
        let candidate = self.received_bytes.saturating_add(len);
        if candidate > config.max_message_bytes() {
            return Err(SignalError::MessageTooLarge {
                len: candidate,
                max: config.max_message_bytes(),
            });
        }
        self.received_bytes = candidate;
        Ok(())
    }

    /// Marks the handshake complete.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig};
    /// let mut tracker = HandshakeTracker::start(Instant::now(), SignalConfig::default());
    /// tracker.mark_complete();
    /// assert!(tracker.is_complete());
    /// ```
    pub fn mark_complete(&mut self) {
        self.complete = true;
        debug!(event = "signal_handshake_complete");
    }

    /// Verifies the handshake deadline.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::HandshakeTimeout`] when the handshake is still
    /// incomplete past the configured deadline.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig};
    /// let tracker = HandshakeTracker::start(Instant::now(), SignalConfig::default());
    /// tracker.check_deadline(Instant::now())?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn check_deadline(self, now: Instant) -> SignalResult<()> {
        if !self.complete && now.duration_since(self.started_at) > self.deadline {
            warn!(
                event = "signal_handshake_timeout",
                error_code = CloseReason::HandshakeTimeout.error_code(),
                timeout_ms = self.deadline.as_millis(),
            );
            return Err(SignalError::HandshakeTimeout {
                timeout: self.deadline,
            });
        }
        Ok(())
    }

    /// Returns observed handshake bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig};
    /// assert_eq!(
    ///     HandshakeTracker::start(Instant::now(), SignalConfig::default()).received_bytes(),
    ///     0
    /// );
    /// ```
    #[must_use]
    pub const fn received_bytes(self) -> usize {
        self.received_bytes
    }

    /// Returns whether the handshake completed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig};
    /// assert!(!HandshakeTracker::start(Instant::now(), SignalConfig::default()).is_complete());
    /// ```
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.complete
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{HandshakeTracker, SignalConfig, Stability};
    /// assert_eq!(
    ///     HandshakeTracker::start(Instant::now(), SignalConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Idle timeout tracker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdleTracker {
    last_activity: Instant,
    timeout: Duration,
}

impl IdleTracker {
    /// Starts an idle tracker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{IdleTracker, SignalConfig};
    /// let tracker = IdleTracker::start(Instant::now(), SignalConfig::default());
    /// assert_eq!(tracker.timeout(), SignalConfig::default().idle_timeout());
    /// ```
    #[must_use]
    pub const fn start(now: Instant, config: SignalConfig) -> Self {
        Self {
            last_activity: now,
            timeout: config.idle_timeout(),
        }
    }

    /// Records connection activity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{IdleTracker, SignalConfig};
    /// let mut tracker = IdleTracker::start(Instant::now(), SignalConfig::default());
    /// let now = Instant::now();
    /// tracker.touch(now);
    /// assert_eq!(tracker.last_activity(), now);
    /// ```
    pub const fn touch(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Verifies the idle deadline.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::IdleTimeout`] when no activity was observed
    /// before the configured deadline.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{IdleTracker, SignalConfig};
    /// let tracker = IdleTracker::start(Instant::now(), SignalConfig::default());
    /// tracker.check_deadline(Instant::now())?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn check_deadline(self, now: Instant) -> SignalResult<()> {
        if now.duration_since(self.last_activity) > self.timeout {
            warn!(
                event = "signal_idle_timeout",
                error_code = CloseReason::IdleTimeout.error_code(),
                timeout_ms = self.timeout.as_millis(),
            );
            return Err(SignalError::IdleTimeout {
                timeout: self.timeout,
            });
        }
        Ok(())
    }

    /// Returns the last activity instant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{IdleTracker, SignalConfig};
    /// let now = Instant::now();
    /// assert_eq!(
    ///     IdleTracker::start(now, SignalConfig::default()).last_activity(),
    ///     now
    /// );
    /// ```
    #[must_use]
    pub const fn last_activity(self) -> Instant {
        self.last_activity
    }

    /// Returns the configured timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{IdleTracker, SignalConfig};
    /// assert_eq!(
    ///     IdleTracker::start(Instant::now(), SignalConfig::default()).timeout(),
    ///     SignalConfig::default().idle_timeout()
    /// );
    /// ```
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_signal::{IdleTracker, SignalConfig, Stability};
    /// assert_eq!(
    ///     IdleTracker::start(Instant::now(), SignalConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Signaling protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Creates and validates a protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::UnsupportedVersion`] when `value` is outside the
    /// accepted Stage 1 range.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::ProtocolVersion;
    /// assert_eq!(ProtocolVersion::try_new(1)?.as_u16(), 1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub const fn try_new(value: u16) -> SignalResult<Self> {
        if value < MIN_PROTOCOL_VERSION || value > CURRENT_PROTOCOL_VERSION {
            return Err(SignalError::UnsupportedVersion { version: value });
        }
        Ok(Self(value))
    }

    /// Returns the raw version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::ProtocolVersion;
    /// assert_eq!(ProtocolVersion::try_new(1)?.as_u16(), 1);
    /// # Ok::<(), refract_signal::SignalError>(())
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
    /// # use refract_signal::{ProtocolVersion, Stability};
    /// assert_eq!(ProtocolVersion::try_new(1)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}", self.0)
    }
}

/// Parsed client command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientCommand {
    /// Join an application room.
    Join {
        /// Room identifier from the application namespace.
        room: Box<str>,
    },
    /// Browser SDP offer for an RTC session.
    RtcOffer {
        /// Room identifier from the application namespace.
        room: Box<str>,
        /// Bounded browser SDP offer.
        sdp: Box<str>,
    },
    /// Browser SDP answer for renegotiation flows.
    RtcAnswer {
        /// Room identifier from the application namespace.
        room: Box<str>,
        /// Bounded browser SDP answer.
        sdp: Box<str>,
    },
    /// Trickle ICE candidate for an RTC session.
    IceCandidate {
        /// Room identifier from the application namespace.
        room: Box<str>,
        /// Bounded candidate attribute value.
        candidate: Box<str>,
    },
    /// Leave the current application session.
    Leave,
    /// Forward an application-defined payload to the selected app.
    App {
        /// Bounded application payload.
        payload: serde_json::Value,
    },
    /// Ping command for connection liveness.
    Ping {
        /// Optional bounded client nonce.
        nonce: Option<Box<str>>,
    },
}

impl ClientCommand {
    /// Returns the command label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::ClientCommand;
    /// assert_eq!(ClientCommand::Leave.as_str(), "leave");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Join { .. } => "join",
            Self::RtcOffer { .. } => "rtc_offer",
            Self::RtcAnswer { .. } => "rtc_answer",
            Self::IceCandidate { .. } => "ice_candidate",
            Self::Leave => "leave",
            Self::App { .. } => "app",
            Self::Ping { .. } => "ping",
        }
    }

    /// Serializes this command for delivery to an application session.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidJson`] if serialization fails, or
    /// application message validation errors mapped into [`SignalError`] when
    /// the serialized payload exceeds the application boundary.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::ClientCommand;
    /// let message = ClientCommand::Leave.to_app_message()?;
    /// assert!(!message.is_empty());
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn to_app_message(&self) -> SignalResult<ClientMessage> {
        let bytes =
            serde_json::to_vec(self).map_err(|source| SignalError::InvalidJson { source })?;
        ClientMessage::try_from_bytes(&bytes).map_err(map_app_message_error)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, Stability};
    /// assert_eq!(ClientCommand::Leave.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Parsed client envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientEnvelope {
    version: ProtocolVersion,
    request_id: Option<Box<str>>,
    app: Box<str>,
    command: ClientCommand,
}

impl ClientEnvelope {
    /// Creates a validated client envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::UnsupportedVersion`] or
    /// [`SignalError::InvalidApplicationName`] when inputs violate Stage 1
    /// bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope};
    /// let envelope = ClientEnvelope::new(1, None, "room".into(), ClientCommand::Leave)?;
    /// assert_eq!(envelope.app(), "room");
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn new(
        version: u16,
        request_id: Option<Box<str>>,
        app: Box<str>,
        command: ClientCommand,
    ) -> SignalResult<Self> {
        let version = ProtocolVersion::try_new(version)?;
        validate_request_id(request_id.as_deref())?;
        validate_application_name(&app)?;
        validate_client_command(&command)?;
        Ok(Self {
            version,
            request_id,
            app,
            command,
        })
    }

    /// Returns the protocol version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope, ProtocolVersion};
    /// let envelope = ClientEnvelope::new(1, None, "room".into(), ClientCommand::Leave)?;
    /// assert_eq!(envelope.version(), ProtocolVersion::try_new(1)?);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the optional request identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope};
    /// let envelope = ClientEnvelope::new(1, Some("r1".into()), "room".into(), ClientCommand::Leave)?;
    /// assert_eq!(envelope.request_id(), Some("r1"));
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Returns the application name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope};
    /// let envelope = ClientEnvelope::new(1, None, "room".into(), ClientCommand::Leave)?;
    /// assert_eq!(envelope.app(), "room");
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub fn app(&self) -> &str {
        &self.app
    }

    /// Returns the parsed client command.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope};
    /// let envelope = ClientEnvelope::new(1, None, "room".into(), ClientCommand::Leave)?;
    /// assert_eq!(envelope.command().as_str(), "leave");
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn command(&self) -> &ClientCommand {
        &self.command
    }

    /// Converts the command to a bounded application message.
    ///
    /// # Errors
    ///
    /// Returns JSON serialization errors or application message bound errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope};
    /// let envelope = ClientEnvelope::new(1, None, "room".into(), ClientCommand::Leave)?;
    /// assert!(!envelope.to_app_message()?.is_empty());
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn to_app_message(&self) -> SignalResult<ClientMessage> {
        self.command.to_app_message()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{ClientCommand, ClientEnvelope, Stability};
    /// let envelope = ClientEnvelope::new(1, None, "room".into(), ClientCommand::Leave)?;
    /// assert_eq!(envelope.stability(), Stability::Stage1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

#[derive(Debug, Deserialize)]
struct WireEnvelope {
    version: u16,
    #[serde(default)]
    request_id: Option<Box<str>>,
    app: Box<str>,
    #[serde(flatten)]
    command: ClientCommand,
}

/// Parses one bounded client WebSocket message.
///
/// # Errors
///
/// Returns [`SignalError::MessageTooLarge`], [`SignalError::InvalidJson`],
/// [`SignalError::UnsupportedVersion`], or
/// [`SignalError::InvalidApplicationName`] for malformed input.
///
/// # Examples
///
/// ```
/// # use refract_signal::{parse_client_message, SignalConfig};
/// let config = SignalConfig::default();
/// let message = parse_client_message(br#"{"version":1,"app":"room","type":"leave"}"#, &config)?;
/// assert_eq!(message.command().as_str(), "leave");
/// # Ok::<(), refract_signal::SignalError>(())
/// ```
pub fn parse_client_message(bytes: &[u8], config: &SignalConfig) -> SignalResult<ClientEnvelope> {
    if bytes.len() > config.max_message_bytes() {
        return Err(SignalError::MessageTooLarge {
            len: bytes.len(),
            max: config.max_message_bytes(),
        });
    }
    let wire: WireEnvelope =
        serde_json::from_slice(bytes).map_err(|source| SignalError::InvalidJson { source })?;
    ClientEnvelope::new(wire.version, wire.request_id, wire.app, wire.command)
}

fn handle_http_stream(
    mut stream: TcpStream,
    config: SignalHttpServerConfig,
    controller: Option<&Arc<dyn RtcSignalingController>>,
) -> SignalResult<()> {
    stream
        .set_nonblocking(false)
        .map_err(|source| SignalError::Io { source })?;
    stream
        .set_read_timeout(Some(config.signal().handshake_timeout()))
        .map_err(|source| SignalError::Io { source })?;
    stream
        .set_write_timeout(Some(config.signal().handshake_timeout()))
        .map_err(|source| SignalError::Io { source })?;
    let request = match read_http_request(&mut stream, config.signal()) {
        Ok(request) => request,
        Err(error) => {
            let response = error_response(&error);
            return stream
                .write_all(&response)
                .map_err(|source| SignalError::Io { source });
        }
    };
    if is_websocket_upgrade(&request) {
        return handle_websocket_stream(stream, &request, config.signal(), controller);
    }
    let response =
        route_http_request_with_controller(&request, config, controller.map(Arc::as_ref))
            .unwrap_or_else(|error| {
                warn!(
                    event = "signal_http_request_failed",
                    error_code = error.error_code(),
                    error = %error,
                );
                error_response(&error)
            });
    stream
        .write_all(&response)
        .map_err(|source| SignalError::Io { source })
}

fn read_http_request(stream: &mut TcpStream, config: SignalConfig) -> SignalResult<Vec<u8>> {
    let max_bytes = config.max_message_bytes().saturating_add(HTTP_HEADER_BYTES);
    let mut request = Vec::new();
    request
        .try_reserve_exact(max_bytes.min(HTTP_HEADER_BYTES))
        .map_err(|_source| SignalError::Allocation {
            component: "http_request",
        })?;
    let mut chunk = [0_u8; HTTP_READ_CHUNK_BYTES];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|source| SignalError::Io { source })?;
        if read == 0 {
            return Ok(request);
        }
        if request.len().saturating_add(read) > max_bytes {
            return Err(SignalError::MessageTooLarge {
                len: request.len().saturating_add(read),
                max: max_bytes,
            });
        }
        request.extend_from_slice(&chunk[..read]);
        if request_complete(&request, config.max_message_bytes())? {
            return Ok(request);
        }
    }
}

fn request_complete(bytes: &[u8], max_body_bytes: usize) -> SignalResult<bool> {
    let Some(header_end) = header_end(bytes) else {
        return Ok(false);
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|source| map_utf8_error(source, "http_header"))?;
    let length = content_length(header)?;
    if length > max_body_bytes {
        return Err(SignalError::MessageTooLarge {
            len: length,
            max: max_body_bytes,
        });
    }
    Ok(bytes.len().saturating_sub(header_end + 4) >= length)
}

#[cfg(test)]
fn route_http_request(bytes: &[u8], config: SignalHttpServerConfig) -> SignalResult<Vec<u8>> {
    route_http_request_with_controller(bytes, config, None)
}

fn route_http_request_with_controller(
    bytes: &[u8],
    config: SignalHttpServerConfig,
    controller: Option<&dyn RtcSignalingController>,
) -> SignalResult<Vec<u8>> {
    let Some(header_end) = header_end(bytes) else {
        return Ok(http_response(
            HTTP_STATUS_BAD_REQUEST,
            CONTENT_TYPE_TEXT,
            b"missing http header",
        ));
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|source| map_utf8_error(source, "http_header"))?;
    let mut lines = header.lines();
    let Some(request_line) = lines.next() else {
        return Ok(http_response(
            HTTP_STATUS_BAD_REQUEST,
            CONTENT_TYPE_TEXT,
            b"missing request line",
        ));
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let body = &bytes[header_end + 4..];
    match (method, path) {
        ("GET", "/" | "/index.html") => Ok(http_response(
            HTTP_STATUS_OK,
            CONTENT_TYPE_HTML,
            SIGNAL_INDEX_HTML.as_bytes(),
        )),
        ("GET", "/healthz") => Ok(http_response(
            HTTP_STATUS_OK,
            CONTENT_TYPE_JSON,
            br#"{"status":"ok"}"#,
        )),
        ("GET", "/readyz") => Ok(http_response(
            HTTP_STATUS_OK,
            CONTENT_TYPE_JSON,
            br#"{"ready":true}"#,
        )),
        ("GET", "/capabilities") => Ok(http_response(
            HTTP_STATUS_OK,
            CONTENT_TYPE_JSON,
            capabilities_body(config.capabilities()).as_bytes(),
        )),
        ("POST", "/signal") => signal_response(body, config.signal(), controller),
        ("OPTIONS", _) => Ok(http_response(HTTP_STATUS_OK, CONTENT_TYPE_TEXT, b"")),
        ("GET" | "POST", _) => Ok(http_response(
            HTTP_STATUS_NOT_FOUND,
            CONTENT_TYPE_JSON,
            br#"{"error":"not_found"}"#,
        )),
        _ => Ok(http_response(
            HTTP_STATUS_METHOD_NOT_ALLOWED,
            CONTENT_TYPE_JSON,
            br#"{"error":"method_not_allowed"}"#,
        )),
    }
}

fn signal_response(
    body: &[u8],
    config: SignalConfig,
    controller: Option<&dyn RtcSignalingController>,
) -> SignalResult<Vec<u8>> {
    let mut state = SignalConnectionState::default();
    let bytes = signal_response_payload_with_state(body, config, controller, &mut state)?;
    Ok(http_response(HTTP_STATUS_OK, CONTENT_TYPE_JSON, &bytes))
}

#[cfg(test)]
fn signal_response_payload(body: &[u8], config: SignalConfig) -> SignalResult<Vec<u8>> {
    let mut state = SignalConnectionState::default();
    signal_response_payload_with_state(body, config, None, &mut state)
}

fn signal_response_payload_with_state(
    body: &[u8],
    config: SignalConfig,
    controller: Option<&dyn RtcSignalingController>,
    state: &mut SignalConnectionState,
) -> SignalResult<Vec<u8>> {
    let envelope = parse_client_message(body, &config)?;
    let response = match envelope.command() {
        ClientCommand::Join { room } => {
            if let Some(controller) = controller {
                match controller.join(RtcJoinRequest::new(room)) {
                    Ok(metadata) => {
                        state.rtc = Some(metadata);
                        rtc_ok_response(&envelope, "join", metadata, None)
                    }
                    Err(error) => rtc_unavailable_response(&envelope, &error),
                }
            } else {
                generic_signal_response(&envelope)
            }
        }
        ClientCommand::RtcOffer { room, sdp } => {
            if let Some(controller) = controller {
                match controller.accept_offer(RtcOfferRequest::new(room, sdp, state.rtc)) {
                    Ok(answer) => {
                        let metadata = answer.metadata();
                        state.rtc = Some(metadata);
                        rtc_ok_response(&envelope, "rtc_answer", metadata, Some(answer.sdp()))
                    }
                    Err(error) => rtc_unavailable_response(&envelope, &error),
                }
            } else {
                rtc_unavailable_response(&envelope, &SignalError::RtcMediaUnavailable)
            }
        }
        ClientCommand::RtcAnswer { .. } => {
            rtc_unavailable_response(&envelope, &SignalError::RtcMediaUnavailable)
        }
        ClientCommand::IceCandidate { candidate, .. } => {
            if let (Some(controller), Some(metadata)) = (controller, state.rtc) {
                match controller.add_ice_candidate(RtcIceCandidateRequest::new(
                    metadata.session_id(),
                    candidate,
                )) {
                    Ok(()) => rtc_ok_response(&envelope, "ice_candidate", metadata, None),
                    Err(error) => rtc_unavailable_response(&envelope, &error),
                }
            } else {
                rtc_unavailable_response(&envelope, &SignalError::RtcMediaUnavailable)
            }
        }
        ClientCommand::Leave => {
            match controller.and_then(|controller| leave_rtc_session(controller, state)) {
                Some((metadata, Ok(()))) => rtc_ok_response(&envelope, "leave", metadata, None),
                Some((_metadata, Err(error))) => rtc_unavailable_response(&envelope, &error),
                None => generic_signal_response(&envelope),
            }
        }
        ClientCommand::App { .. } | ClientCommand::Ping { .. } => {
            generic_signal_response(&envelope)
        }
    };
    serde_json::to_vec(&response).map_err(|source| SignalError::InvalidJson { source })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SignalConnectionState {
    rtc: Option<RtcSessionMetadata>,
}

fn leave_rtc_session(
    controller: &dyn RtcSignalingController,
    state: &mut SignalConnectionState,
) -> Option<(RtcSessionMetadata, SignalResult<()>)> {
    let metadata = state.rtc.take()?;
    Some((metadata, controller.leave(metadata.session_id())))
}

fn cleanup_rtc_connection(
    controller: Option<&dyn RtcSignalingController>,
    state: &mut SignalConnectionState,
) {
    let Some(controller) = controller else {
        state.rtc = None;
        return;
    };
    let Some((metadata, result)) = leave_rtc_session(controller, state) else {
        return;
    };
    match result {
        Ok(()) => debug!(
            event = "signal_rtc_session_cleanup",
            session_id = %metadata.session_id(),
            peer_id = %metadata.peer_id(),
            room_id = %metadata.room_id(),
        ),
        Err(error) => warn!(
            event = "signal_rtc_session_cleanup_failed",
            error_code = error.error_code(),
            error = %error,
            session_id = %metadata.session_id(),
        ),
    }
}

fn generic_signal_response(envelope: &ClientEnvelope) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "version": envelope.version().as_u16(),
        "request_id": envelope.request_id(),
        "app": envelope.app(),
        "type": envelope.command().as_str(),
        "media_ready": false,
        "reason": "dtls_srtp_browser_sessions_not_wired"
    })
}

fn rtc_unavailable_response(envelope: &ClientEnvelope, error: &SignalError) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "version": envelope.version().as_u16(),
        "request_id": envelope.request_id(),
        "app": envelope.app(),
        "type": envelope.command().as_str(),
        "media_ready": false,
        "error_code": error.error_code(),
        "error": error.to_string(),
        "reason": "webrtc_media_forwarding_capability_false"
    })
}

fn rtc_ok_response(
    envelope: &ClientEnvelope,
    response_type: &'static str,
    metadata: RtcSessionMetadata,
    sdp: Option<&str>,
) -> serde_json::Value {
    let mut response = serde_json::json!({
        "ok": true,
        "version": envelope.version().as_u16(),
        "request_id": envelope.request_id(),
        "app": envelope.app(),
        "type": response_type,
        "media_ready": true,
        "session_id": metadata.session_id().to_string(),
        "peer_id": metadata.peer_id().to_string(),
        "room_id": metadata.room_id().to_string(),
        "core_id": metadata.core_id(),
        "media_addr": metadata.media_addr().to_string()
    });
    if let Some(sdp) = sdp {
        response["sdp"] = serde_json::Value::String(sdp.to_owned());
    }
    response
}

fn handle_websocket_stream(
    mut stream: TcpStream,
    request: &[u8],
    config: SignalConfig,
    controller: Option<&Arc<dyn RtcSignalingController>>,
) -> SignalResult<()> {
    let (response, consumed) = websocket_handshake_response(request)?;
    stream
        .write_all(&response)
        .map_err(|source| SignalError::Io { source })?;
    stream
        .set_read_timeout(Some(config.idle_timeout()))
        .map_err(|source| SignalError::Io { source })?;
    stream
        .set_write_timeout(Some(config.idle_timeout()))
        .map_err(|source| SignalError::Io { source })?;
    let mut buffer = BytesMut::new();
    if request.len() > consumed {
        buffer.extend_from_slice(&request[consumed..]);
    }
    let mut protocol = WsProtocol::new(
        Role::Server,
        config.max_message_bytes(),
        config.max_message_bytes(),
    );
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(4)
        .map_err(|_source| SignalError::Allocation {
            component: "websocket_messages",
        })?;
    let mut chunk = [0_u8; HTTP_READ_CHUNK_BYTES];
    let mut state = SignalConnectionState::default();
    let mut idle_keepalives: u32 = 0;
    let result = loop {
        if let Err(error) = process_websocket_messages(
            &mut stream,
            &mut protocol,
            &mut buffer,
            &mut messages,
            config,
            controller.map(Arc::as_ref),
            &mut state,
        ) {
            break Err(error);
        }
        if protocol.is_closed() {
            break Ok(());
        }
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            // A read timeout (`WouldBlock`/`TimedOut`) on this long-lived
            // signaling socket is NOT a failure. WebRTC peers go idle between
            // SDP/ICE exchanges while media flows over UDP, so the read deadline
            // routinely elapses on a perfectly healthy connection. Treating it as
            // fatal here previously closed the connection and ran
            // `cleanup_rtc_connection`, tearing down the live media session after
            // `idle_timeout`. Instead, send a keepalive ping (the peer auto-replies
            // with a pong, which arrives as data and resets the counter) and keep
            // the connection open. Only give up after several consecutive
            // unanswered keepalives, which indicates a genuinely dead peer.
            Err(ref source)
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                idle_keepalives = idle_keepalives.saturating_add(1);
                if idle_keepalives > MAX_IDLE_KEEPALIVES {
                    break Ok(());
                }
                if let Err(error) = write_websocket_frame(&mut stream, OpCode::Ping, &[]) {
                    break Err(error);
                }
                continue;
            }
            Err(source) => break Err(SignalError::Io { source }),
        };
        if read == 0 {
            break Ok(());
        }
        idle_keepalives = 0;
        if buffer.len().saturating_add(read) > config.max_message_bytes() {
            break Err(SignalError::MessageTooLarge {
                len: buffer.len().saturating_add(read),
                max: config.max_message_bytes(),
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    cleanup_rtc_connection(controller.map(Arc::as_ref), &mut state);
    result
}

fn websocket_handshake_response(request: &[u8]) -> SignalResult<(Vec<u8>, usize)> {
    let Some((handshake, consumed)) =
        parse_request(request).map_err(|source| SignalError::WebSocket { source })?
    else {
        return Err(SignalError::WebSocket {
            source: WsError::InvalidHttp("incomplete websocket handshake"),
        });
    };
    if handshake.path != "/ws" {
        return Err(SignalError::WebSocket {
            source: WsError::InvalidHttp("unsupported websocket path"),
        });
    }
    let accept = generate_accept_key(handshake.key);
    Ok((build_ws_response(&accept, None, None).to_vec(), consumed))
}

fn process_websocket_messages(
    stream: &mut TcpStream,
    protocol: &mut WsProtocol,
    buffer: &mut BytesMut,
    messages: &mut Vec<WsMessage>,
    config: SignalConfig,
    controller: Option<&dyn RtcSignalingController>,
    state: &mut SignalConnectionState,
) -> SignalResult<()> {
    protocol
        .process_into(buffer, messages)
        .map_err(|source| SignalError::WebSocket { source })?;
    for message in messages.iter() {
        match message {
            WsMessage::Text(bytes) => {
                let payload = signal_response_payload_with_state(bytes, config, controller, state)
                    .unwrap_or_else(|error| websocket_error_payload(&error));
                write_websocket_frame(stream, OpCode::Text, &payload)?;
            }
            WsMessage::Binary(_) => {
                let payload = websocket_error_payload(&SignalError::InvalidApplicationName);
                write_websocket_frame(stream, OpCode::Text, &payload)?;
            }
            WsMessage::Ping(bytes) => write_websocket_frame(stream, OpCode::Pong, bytes)?,
            WsMessage::Pong(_) => {}
            WsMessage::Close(_) => {
                write_websocket_frame(stream, OpCode::Close, &[])?;
                return Ok(());
            }
        }
    }
    messages.clear();
    Ok(())
}

fn write_websocket_frame(
    stream: &mut TcpStream,
    opcode: OpCode,
    payload: &[u8],
) -> SignalResult<()> {
    let mut frame = BytesMut::new();
    encode_frame(&mut frame, opcode, payload, true, None);
    stream
        .write_all(&frame)
        .map_err(|source| SignalError::Io { source })
}

fn websocket_error_payload(error: &SignalError) -> Vec<u8> {
    serde_json::json!({
        "ok": false,
        "error_code": error.error_code(),
        "error": error.to_string()
    })
    .to_string()
    .into_bytes()
}

fn capabilities_body(capabilities: SignalCapabilities) -> String {
    serde_json::json!({
        "service": "refract",
        "stage": "stage1",
        "signaling_http": true,
        "signaling_websocket": true,
        "webrtc_media_forwarding": capabilities.webrtc_media_forwarding(),
        "sfu_media_sockets": capabilities.sfu_media_sockets()
    })
    .to_string()
}

fn is_websocket_upgrade(bytes: &[u8]) -> bool {
    let Some(header_end) = header_end(bytes) else {
        return false;
    };
    std::str::from_utf8(&bytes[..header_end]).is_ok_and(|header| {
        header.lines().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case("websocket")
        })
    })
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(header: &str) -> SignalResult<usize> {
    header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
        .map_or(Ok(0), |value| {
            value
                .parse::<usize>()
                .map_err(|_source| SignalError::InvalidConfig {
                    field: "content-length",
                })
        })
}

fn http_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        HTTP_STATUS_OK => "OK",
        HTTP_STATUS_BAD_REQUEST => "Bad Request",
        HTTP_STATUS_NOT_FOUND => "Not Found",
        HTTP_STATUS_METHOD_NOT_ALLOWED => "Method Not Allowed",
        HTTP_STATUS_CONTENT_TOO_LARGE => "Content Too Large",
        HTTP_STATUS_SERVICE_UNAVAILABLE => "Service Unavailable",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\naccess-control-allow-origin: *\r\naccess-control-allow-methods: GET,POST,OPTIONS\r\naccess-control-allow-headers: content-type,authorization\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let mut response = header.into_bytes();
    response.extend_from_slice(body);
    response
}

fn error_response(error: &SignalError) -> Vec<u8> {
    let status = match error {
        SignalError::MessageTooLarge { .. } => HTTP_STATUS_CONTENT_TOO_LARGE,
        SignalError::ConnectionCeiling { .. } => HTTP_STATUS_SERVICE_UNAVAILABLE,
        _ => HTTP_STATUS_BAD_REQUEST,
    };
    let body = serde_json::json!({
        "ok": false,
        "error_code": error.error_code(),
        "error": error.to_string()
    })
    .to_string();
    http_response(status, CONTENT_TYPE_JSON, body.as_bytes())
}

fn map_utf8_error(source: std::str::Utf8Error, component: &'static str) -> SignalError {
    SignalError::InvalidJson {
        source: serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{component}: {source}"),
        )),
    }
}

fn validate_application_name(app: &str) -> SignalResult<()> {
    let valid = !app.is_empty()
        && app.len() <= MAX_APPLICATION_NAME_BYTES
        && app
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(SignalError::InvalidApplicationName)
    }
}

fn validate_request_id(request_id: Option<&str>) -> SignalResult<()> {
    let Some(request_id) = request_id else {
        return Ok(());
    };
    let valid = !request_id.is_empty()
        && request_id.len() <= MAX_REQUEST_ID_BYTES
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(SignalError::InvalidRequestId)
    }
}

fn validate_client_command(command: &ClientCommand) -> SignalResult<()> {
    match command {
        ClientCommand::Join { room } => validate_room(room),
        ClientCommand::RtcOffer { room, sdp } | ClientCommand::RtcAnswer { room, sdp } => {
            validate_room(room)?;
            validate_rtc_sdp(sdp)
        }
        ClientCommand::IceCandidate { room, candidate } => {
            validate_room(room)?;
            validate_ice_candidate(candidate)
        }
        ClientCommand::Leave | ClientCommand::App { .. } => Ok(()),
        ClientCommand::Ping { nonce } => validate_nonce(nonce.as_deref()),
    }
}

fn validate_room(room: &str) -> SignalResult<()> {
    let valid = !room.is_empty()
        && room.len() <= MAX_ROOM_BYTES
        && room
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(SignalError::InvalidRoom)
    }
}

const fn validate_nonce(nonce: Option<&str>) -> SignalResult<()> {
    let Some(nonce) = nonce else {
        return Ok(());
    };
    if nonce.len() <= MAX_NONCE_BYTES {
        Ok(())
    } else {
        Err(SignalError::InvalidClaim { field: "nonce" })
    }
}

fn validate_rtc_sdp(sdp: &str) -> SignalResult<()> {
    let has_required_lines = sdp.len() <= MAX_RTC_SDP_BYTES
        && sdp.lines().any(|line| line == "v=0")
        && sdp.lines().any(|line| line.starts_with("a=ice-ufrag:"))
        && sdp.lines().any(|line| line.starts_with("a=ice-pwd:"))
        && sdp
            .lines()
            .any(|line| line.starts_with("a=fingerprint:sha-256 "))
        && sdp.lines().any(|line| line.contains("UDP/TLS/RTP/SAVPF"))
        && sdp.lines().any(|line| line == "a=rtcp-mux");
    if has_required_lines {
        Ok(())
    } else {
        Err(SignalError::InvalidRtcSdp)
    }
}

fn validate_ice_candidate(candidate: &str) -> SignalResult<()> {
    let valid = !candidate.is_empty()
        && candidate.len() <= MAX_RTC_ICE_CANDIDATE_BYTES
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        && (candidate.starts_with("candidate:") || candidate.starts_with("a=candidate:"))
        && candidate.split_whitespace().count() >= 8;
    if valid {
        Ok(())
    } else {
        Err(SignalError::InvalidIceCandidate)
    }
}

fn map_app_message_error(error: refract_app::AppError) -> SignalError {
    match error {
        refract_app::AppError::MessageTooLarge { len, max } => {
            SignalError::MessageTooLarge { len, max }
        }
        _other => SignalError::InvalidClaim {
            field: "app_message",
        },
    }
}

/// JWT verification algorithm accepted by the signaling boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JwtAlgorithm {
    /// Edwards-curve Digital Signature Algorithm, preferred for Stage 1.
    EdDsa,
    /// RSA PKCS#1 SHA-256 fallback.
    Rs256,
}

impl JwtAlgorithm {
    /// Returns the `jsonwebtoken` algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::JwtAlgorithm;
    /// assert_eq!(JwtAlgorithm::EdDsa.as_str(), "EdDSA");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAlgorithm, Stability};
    /// assert_eq!(JwtAlgorithm::Rs256.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }

    const fn into_algorithm(self) -> Algorithm {
        match self {
            Self::EdDsa => Algorithm::EdDSA,
            Self::Rs256 => Algorithm::RS256,
        }
    }
}

impl fmt::Display for JwtAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// JWT verification key.
#[derive(Clone, Debug)]
pub struct JwtKey {
    key_id: Option<Box<str>>,
    algorithm: JwtAlgorithm,
    decoding_key: DecodingKey,
}

impl JwtKey {
    /// Creates an `EdDSA` verification key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Authentication`] when the PEM cannot be decoded.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let key = refract_signal::JwtKey::from_eddsa_pem(Some("kid1".into()), pem_bytes)?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn from_eddsa_pem(key_id: Option<Box<str>>, pem: &[u8]) -> SignalResult<Self> {
        let decoding_key = DecodingKey::from_ed_pem(pem)
            .map_err(|source| SignalError::Authentication { source })?;
        Ok(Self {
            key_id,
            algorithm: JwtAlgorithm::EdDsa,
            decoding_key,
        })
    }

    /// Creates an RS256 verification key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Authentication`] when the PEM cannot be decoded.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let key = refract_signal::JwtKey::from_rs256_pem(Some("kid1".into()), pem_bytes)?;
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn from_rs256_pem(key_id: Option<Box<str>>, pem: &[u8]) -> SignalResult<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(pem)
            .map_err(|source| SignalError::Authentication { source })?;
        Ok(Self {
            key_id,
            algorithm: JwtAlgorithm::Rs256,
            decoding_key,
        })
    }

    /// Creates an `EdDSA` verification key from public DER bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAlgorithm, JwtKey};
    /// let key = JwtKey::from_eddsa_der(None, &[0; 32]);
    /// assert_eq!(key.algorithm(), JwtAlgorithm::EdDsa);
    /// ```
    #[must_use]
    pub fn from_eddsa_der(key_id: Option<Box<str>>, der: &[u8]) -> Self {
        Self {
            key_id,
            algorithm: JwtAlgorithm::EdDsa,
            decoding_key: DecodingKey::from_ed_der(der),
        }
    }

    /// Returns the key identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::JwtKey;
    /// let key = JwtKey::from_eddsa_der(Some("kid".into()), &[0; 32]);
    /// assert_eq!(key.key_id(), Some("kid"));
    /// ```
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Returns the verification algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAlgorithm, JwtKey};
    /// assert_eq!(
    ///     JwtKey::from_eddsa_der(None, &[0; 32]).algorithm(),
    ///     JwtAlgorithm::EdDsa
    /// );
    /// ```
    #[must_use]
    pub const fn algorithm(&self) -> JwtAlgorithm {
        self.algorithm
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtKey, Stability};
    /// assert_eq!(
    ///     JwtKey::from_eddsa_der(None, &[0; 32]).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// JWT authenticator for per-connection handshakes.
#[derive(Clone, Debug)]
pub struct JwtAuthenticator {
    keys: Box<[JwtKey]>,
    audience: Option<Box<str>>,
    issuer: Option<Box<str>>,
    max_token_bytes: usize,
}

impl JwtAuthenticator {
    /// Creates a JWT authenticator.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::InvalidConfig`] when no keys are provided or the
    /// token byte cap is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAuthenticator, JwtKey, SignalConfig};
    /// let key = JwtKey::from_eddsa_der(None, &[0; 32]);
    /// let auth = JwtAuthenticator::new(vec![key], None, None, SignalConfig::default())?;
    /// assert_eq!(auth.key_count(), 1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn new(
        keys: Vec<JwtKey>,
        audience: Option<Box<str>>,
        issuer: Option<Box<str>>,
        config: SignalConfig,
    ) -> SignalResult<Self> {
        if keys.is_empty() {
            return Err(SignalError::InvalidConfig { field: "jwt_keys" });
        }
        if config.max_token_bytes() == 0 {
            return Err(SignalError::InvalidConfig {
                field: "max_token_bytes",
            });
        }
        Ok(Self {
            keys: keys.into_boxed_slice(),
            audience,
            issuer,
            max_token_bytes: config.max_token_bytes(),
        })
    }

    /// Authenticates a bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::TokenTooLarge`], [`SignalError::Authentication`],
    /// or [`SignalError::InvalidClaim`] for failed authentication.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAuthenticator, JwtKey, SignalConfig, SignalError};
    /// let key = JwtKey::from_eddsa_der(None, &[0; 32]);
    /// let auth = JwtAuthenticator::new(vec![key], None, None, SignalConfig::default())?;
    /// assert!(matches!(
    ///     auth.authenticate("not-a-jwt"),
    ///     Err(SignalError::Authentication { .. })
    /// ));
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    pub fn authenticate(&self, token: &str) -> SignalResult<AuthenticatedPeer> {
        if token.len() > self.max_token_bytes {
            return Err(SignalError::TokenTooLarge {
                len: token.len(),
                max: self.max_token_bytes,
            });
        }
        let header =
            decode_header(token).map_err(|source| SignalError::Authentication { source })?;
        let key = self
            .keys
            .iter()
            .find(|candidate| {
                candidate.algorithm.into_algorithm() == header.alg
                    && candidate
                        .key_id()
                        .is_none_or(|key_id| header.kid.as_deref() == Some(key_id))
            })
            .ok_or(SignalError::InvalidClaim { field: "kid" })?;
        let mut validation = Validation::new(key.algorithm.into_algorithm());
        validation.validate_nbf = true;
        if let Some(audience) = self.audience.as_deref() {
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }
        if let Some(issuer) = self.issuer.as_deref() {
            validation.set_issuer(&[issuer]);
        }
        validation.required_spec_claims = HashSet::from(["exp".to_owned(), "sub".to_owned()]);
        let token_data = decode::<SignalClaims>(token, &key.decoding_key, &validation)
            .map_err(|source| SignalError::Authentication { source })?;
        AuthenticatedPeer::try_from_claims(token_data.claims)
    }

    /// Returns the configured key count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAuthenticator, JwtKey, SignalConfig};
    /// let key = JwtKey::from_eddsa_der(None, &[0; 32]);
    /// let auth = JwtAuthenticator::new(vec![key], None, None, SignalConfig::default())?;
    /// assert_eq!(auth.key_count(), 1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_signal::{JwtAuthenticator, JwtKey, SignalConfig, Stability};
    /// let key = JwtKey::from_eddsa_der(None, &[0; 32]);
    /// let auth = JwtAuthenticator::new(vec![key], None, None, SignalConfig::default())?;
    /// assert_eq!(auth.stability(), Stability::Stage1);
    /// # Ok::<(), refract_signal::SignalError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

#[derive(Debug, Deserialize)]
struct SignalClaims {
    sub: String,
    #[serde(default)]
    room: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// Authenticated peer identity extracted from JWT claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    subject: Box<str>,
    room: Option<Box<str>>,
    roles: Box<[Box<str>]>,
}

impl AuthenticatedPeer {
    fn try_from_claims(claims: SignalClaims) -> SignalResult<Self> {
        let subject = bounded_boxed_str(claims.sub, MAX_JWT_SUBJECT_BYTES, "sub")?;
        let room = claims
            .room
            .map(|value| bounded_boxed_str(value, MAX_JWT_ROOM_BYTES, "room"))
            .transpose()?;
        if claims.roles.len() > MAX_JWT_ROLES {
            return Err(SignalError::InvalidClaim { field: "roles" });
        }
        let mut roles = Vec::new();
        roles
            .try_reserve_exact(claims.roles.len())
            .map_err(|_source| SignalError::Allocation {
                component: "jwt_roles",
            })?;
        for role in claims.roles {
            roles.push(bounded_boxed_str(role, MAX_JWT_ROLE_BYTES, "roles")?);
        }
        Ok(Self {
            subject,
            room,
            roles: roles.into_boxed_slice(),
        })
    }

    /// Returns the authenticated subject.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(peer.subject(), "user-1");
    /// ```
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the optional room claim.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(peer.room(), Some("room-1"));
    /// ```
    #[must_use]
    pub fn room(&self) -> Option<&str> {
        self.room.as_deref()
    }

    /// Returns authenticated roles.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert!(peer.roles().contains(&"publisher"));
    /// ```
    #[must_use]
    pub fn roles(&self) -> impl ExactSizeIterator<Item = &str> {
        self.roles.iter().map(Box::as_ref)
    }

    /// Returns whether the peer has a role.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert!(peer.has_role("subscriber"));
    /// ```
    #[must_use]
    pub fn has_role(&self, expected: &str) -> bool {
        self.roles().any(|role| role == expected)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(peer.stability(), refract_signal::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

fn bounded_boxed_str(value: String, max: usize, field: &'static str) -> SignalResult<Box<str>> {
    if value.is_empty() || value.len() > max {
        return Err(SignalError::InvalidClaim { field });
    }
    Ok(value.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use refract_app::Application;
    use refract_app_room::RoomApp;
    use refract_core::{PeerId, RoomId, SessionId};

    use super::{
        ClientCommand, CloseReason, ConnectionLedger, HandshakeTracker, JwtAuthenticator, JwtKey,
        MAX_ROOM_BYTES, MAX_RTC_ICE_CANDIDATE_BYTES, MAX_RTC_SDP_BYTES, ProtocolVersion, RtcAnswer,
        RtcIceCandidateRequest, RtcJoinRequest, RtcOfferRequest, RtcSessionMetadata,
        RtcSignalingController, SendQueue, SignalCapabilities, SignalConfig, SignalConnectionState,
        SignalError, SignalHttpServerConfig, SignalRateLimiter, SignalResult,
        cleanup_rtc_connection, is_websocket_upgrade, parse_client_message, route_http_request,
        signal_response_payload, websocket_handshake_response,
    };

    const VALID_BROWSER_SDP: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=ice-ufrag:abc\r\na=ice-pwd:abcdefghijklmnopqrstuvwxyz\r\na=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\na=setup:actpass\r\na=sendrecv\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n";

    const VALID_CANDIDATE: &str =
        "candidate:1 1 udp 1845494015 198.51.100.100 11100 typ host ufrag abc";

    #[derive(Debug, Default)]
    struct RecordingRtcController {
        left_session: AtomicU64,
    }

    impl RtcSignalingController for RecordingRtcController {
        fn join(&self, _request: RtcJoinRequest<'_>) -> SignalResult<RtcSessionMetadata> {
            Err(SignalError::RtcMediaUnavailable)
        }

        fn accept_offer(&self, _request: RtcOfferRequest<'_>) -> SignalResult<RtcAnswer> {
            Err(SignalError::RtcMediaUnavailable)
        }

        fn add_ice_candidate(&self, _request: RtcIceCandidateRequest<'_>) -> SignalResult<()> {
            Err(SignalError::RtcMediaUnavailable)
        }

        fn leave(&self, session_id: SessionId) -> SignalResult<()> {
            self.left_session.store(session_id.raw(), Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn multi_client_app_room_messages_parse() {
        let app = RoomApp::new();
        assert_eq!(app.name(), "room");

        let config = SignalConfig::default();
        let first = parse_client_message(
            br#"{"version":1,"request_id":"a","app":"room","type":"join","room":"stage"}"#,
            &config,
        )
        .expect("valid first room join");
        let second = parse_client_message(
            br#"{"version":1,"request_id":"b","app":"room","type":"join","room":"stage"}"#,
            &config,
        )
        .expect("valid second room join");

        assert_eq!(first.app(), app.name());
        assert_eq!(second.app(), app.name());
        assert_eq!(first.command().as_str(), "join");
        assert_eq!(second.command().as_str(), "join");
    }

    #[test]
    fn slow_loris_handshake_times_out() {
        let config = SignalConfig::default();
        let start = Instant::now();
        let mut tracker = HandshakeTracker::start(start, config);
        tracker
            .record_bytes(1, config)
            .expect("one byte is under the cap");
        let result =
            tracker.check_deadline(start + config.handshake_timeout() + Duration::from_millis(1));

        assert!(matches!(result, Err(SignalError::HandshakeTimeout { .. })));
    }

    #[test]
    fn completed_handshake_survives_deadline_check() {
        let config = SignalConfig::default();
        let start = Instant::now();
        let mut tracker = HandshakeTracker::start(start, config);
        tracker.mark_complete();

        assert!(
            tracker
                .check_deadline(start + config.handshake_timeout() * 2)
                .is_ok()
        );
    }

    #[test]
    fn backpressure_overflow_closes_queue() {
        let config = SignalConfig::new(
            8,
            8,
            Duration::from_secs(5),
            Duration::from_secs(30),
            10,
            10,
            10,
            128,
        )
        .expect("valid tiny queue config");
        let mut queue = SendQueue::new(config);

        queue.enqueue(b"12345678").expect("fills queue exactly");
        let result = queue.enqueue(b"1");

        assert!(matches!(
            result,
            Err(SignalError::BackpressureOverflow { .. })
        ));
        assert_eq!(queue.closed_reason(), Some(CloseReason::Backpressure));
    }

    #[test]
    fn connection_ceiling_returns_503_path() {
        let config = SignalConfig::new(
            1024,
            64,
            Duration::from_secs(5),
            Duration::from_secs(30),
            1,
            10,
            10,
            128,
        )
        .expect("valid one-connection config");
        let mut ledger = ConnectionLedger::new(config);

        let _permit = ledger.try_open().expect("first connection admitted");
        let result = ledger.try_open();

        assert!(matches!(
            result,
            Err(SignalError::ConnectionCeiling { ceiling: 1, .. })
        ));
    }

    #[test]
    fn auth_failure_paths_are_bounded() {
        let config = SignalConfig::new(
            1024,
            64,
            Duration::from_secs(5),
            Duration::from_secs(30),
            1,
            10,
            10,
            8,
        )
        .expect("valid auth config");
        let key = JwtKey::from_eddsa_der(None, &[0; 32]);
        let auth = JwtAuthenticator::new(vec![key], None, None, config).expect("auth config");

        assert!(matches!(
            auth.authenticate("this-token-is-too-large"),
            Err(SignalError::TokenTooLarge { .. })
        ));
        assert!(matches!(
            auth.authenticate("bad"),
            Err(SignalError::Authentication { .. })
        ));
    }

    #[test]
    fn rate_limiter_uses_governor_burst() {
        let config = SignalConfig::new(
            1024,
            64,
            Duration::from_secs(5),
            Duration::from_secs(30),
            1,
            1,
            1,
            128,
        )
        .expect("valid rate config");
        let limiter = SignalRateLimiter::new(config).expect("rate limiter");

        limiter.check().expect("first message within burst");
        assert!(matches!(limiter.check(), Err(SignalError::RateLimited)));
    }

    #[test]
    fn parser_rejects_oversized_messages_before_json() {
        let config = SignalConfig::new(
            1024,
            4,
            Duration::from_secs(5),
            Duration::from_secs(30),
            1,
            1,
            1,
            128,
        )
        .expect("valid parser config");

        assert!(matches!(
            parse_client_message(br#"{"version":1}"#, &config),
            Err(SignalError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn parser_rejects_unknown_version() {
        let config = SignalConfig::default();
        let result = parse_client_message(br#"{"version":2,"app":"room","type":"leave"}"#, &config);

        assert!(matches!(
            result,
            Err(SignalError::UnsupportedVersion { version: 2 })
        ));
        assert!(ProtocolVersion::try_new(1).is_ok());
    }

    #[test]
    fn command_to_app_message_is_bounded() {
        let command = ClientCommand::Ping {
            nonce: Some("n".into()),
        };
        let message = command.to_app_message().expect("small command serializes");

        assert!(!message.is_empty());
    }

    #[test]
    fn parser_accepts_bounded_rtc_commands() {
        let config = SignalConfig::default();
        let offer = format!(
            r#"{{"version":1,"request_id":"offer-1","app":"room","type":"rtc_offer","room":"stage","sdp":{}}}"#,
            serde_json::to_string(VALID_BROWSER_SDP).expect("sdp json")
        );
        let candidate = format!(
            r#"{{"version":1,"request_id":"ice-1","app":"room","type":"ice_candidate","room":"stage","candidate":{}}}"#,
            serde_json::to_string(VALID_CANDIDATE).expect("candidate json")
        );

        let parsed_offer =
            parse_client_message(offer.as_bytes(), &config).expect("valid rtc offer");
        let parsed_candidate =
            parse_client_message(candidate.as_bytes(), &config).expect("valid ice candidate");

        assert_eq!(parsed_offer.request_id(), Some("offer-1"));
        assert_eq!(parsed_offer.command().as_str(), "rtc_offer");
        assert_eq!(parsed_candidate.command().as_str(), "ice_candidate");
    }

    #[test]
    fn parser_rejects_rtc_bounds_and_malformed_inputs() {
        let config = SignalConfig::default();
        let long_room = "r".repeat(MAX_ROOM_BYTES + 1);
        let long_sdp = "v=0\n".repeat(MAX_RTC_SDP_BYTES / 4 + 1);
        let long_candidate = "c".repeat(MAX_RTC_ICE_CANDIDATE_BYTES + 1);
        let room_frame =
            format!(r#"{{"version":1,"app":"room","type":"join","room":"{long_room}"}}"#);
        let sdp_frame = format!(
            r#"{{"version":1,"app":"room","type":"rtc_offer","room":"stage","sdp":{}}}"#,
            serde_json::to_string(&long_sdp).expect("sdp json")
        );
        let candidate_frame = format!(
            r#"{{"version":1,"app":"room","type":"ice_candidate","room":"stage","candidate":{}}}"#,
            serde_json::to_string(&long_candidate).expect("candidate json")
        );

        assert!(matches!(
            parse_client_message(room_frame.as_bytes(), &config),
            Err(SignalError::InvalidRoom)
        ));
        assert!(matches!(
            parse_client_message(sdp_frame.as_bytes(), &config),
            Err(SignalError::InvalidRtcSdp)
        ));
        assert!(matches!(
            parse_client_message(candidate_frame.as_bytes(), &config),
            Err(SignalError::InvalidIceCandidate)
        ));
    }

    #[test]
    fn rtc_offer_response_keeps_media_forwarding_disabled_until_wired() {
        let config = SignalConfig::default();
        let offer = format!(
            r#"{{"version":1,"request_id":"offer-1","app":"room","type":"rtc_offer","room":"stage","sdp":{}}}"#,
            serde_json::to_string(VALID_BROWSER_SDP).expect("sdp json")
        );
        let payload =
            signal_response_payload(offer.as_bytes(), config).expect("rtc offer response");
        let text = String::from_utf8(payload).expect("response utf8");

        assert!(text.contains("\"ok\":false"));
        assert!(text.contains("\"request_id\":\"offer-1\""));
        assert!(text.contains("\"error_code\":\"HSF-RTC-MEDIA-001\""));
        assert!(text.contains("\"media_ready\":false"));
    }

    #[test]
    fn http_capabilities_reports_media_gap() {
        let request = b"GET /capabilities HTTP/1.1\r\nhost: localhost\r\n\r\n";
        let response = route_http_request(
            request,
            SignalHttpServerConfig::default()
                .with_capabilities(SignalCapabilities::new(true, false)),
        )
        .expect("capabilities response");
        let text = String::from_utf8(response).expect("http response utf8");

        assert!(text.contains("200 OK"));
        assert!(text.contains("\"signaling_http\":true"));
        assert!(text.contains("\"signaling_websocket\":true"));
        assert!(text.contains("\"sfu_media_sockets\":true"));
        assert!(text.contains("\"webrtc_media_forwarding\":false"));
    }

    #[test]
    fn http_signal_endpoint_uses_bounded_parser() {
        let body = br#"{"version":1,"app":"room","type":"ping","nonce":"n1"}"#;
        let request = format!(
            "POST /signal HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).expect("body utf8")
        );
        let response = route_http_request(request.as_bytes(), SignalHttpServerConfig::default())
            .expect("signal response");
        let text = String::from_utf8(response).expect("http response utf8");

        assert!(text.contains("200 OK"));
        assert!(text.contains("\"type\":\"ping\""));
        assert!(text.contains("\"media_ready\":false"));
        assert!(text.contains("dtls_srtp_browser_sessions_not_wired"));
    }

    #[test]
    fn websocket_upgrade_uses_sockudo_handshake() {
        let request = b"GET /ws HTTP/1.1\r\nhost: localhost\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n";

        assert!(is_websocket_upgrade(request));

        let (response, consumed) = websocket_handshake_response(request).expect("ws handshake");
        let text = String::from_utf8(response).expect("handshake utf8");

        assert_eq!(consumed, request.len());
        assert!(text.contains("101 Switching Protocols"));
        assert!(text.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    }

    #[test]
    fn websocket_cleanup_leaves_active_rtc_session() {
        let controller = RecordingRtcController::default();
        let media_addr = "127.0.0.1:50000"
            .parse::<SocketAddr>()
            .expect("valid media address");
        let metadata = RtcSessionMetadata::new(
            SessionId::from_raw(42),
            PeerId::from_raw(7),
            RoomId::from_raw(9),
            0,
            media_addr,
        );
        let mut state = SignalConnectionState {
            rtc: Some(metadata),
        };

        cleanup_rtc_connection(Some(&controller), &mut state);

        assert_eq!(state.rtc, None);
        assert_eq!(
            controller.left_session.load(Ordering::SeqCst),
            metadata.session_id().raw()
        );
    }
}
