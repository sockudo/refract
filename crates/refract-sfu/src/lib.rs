//! Per-core `SFU` forwarding engine for refract.
//!
//! The crate owns the per-pinned-core media loop boundary: demux, STUN/DTLS
//! handoff, SRTP ingress, RTP routing, jitter/loss accounting, header rewrite,
//! SRTP egress, pacing, and batch-send handoff. Construction performs bounded
//! warmup allocation; the media hot loop reuses preallocated buffers.
//!
//! # Examples
//!
//! ```
//! # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! # use refract_core::PeerId;
//! # use refract_router::SubscriberSessionId;
//! # use refract_sfu::{CoreId, FiveTuple, IpProtocol, SfuConfig, SfuCore};
//! let config = SfuConfig::new(CoreId::new(0), 16)?;
//! let mut core = SfuCore::new(config)?;
//! let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_000);
//! let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6_000);
//! core.register_plain_peer(
//!     PeerId::from_raw(1),
//!     FiveTuple::new(local, remote, IpProtocol::Udp),
//!     SubscriberSessionId::new(1),
//! )?;
//! # Ok::<(), refract_sfu::SfuError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use compio::{BufResult, net::UdpSocket, runtime::Runtime, time::timeout};
use refract_cc::PacketPriority;
use refract_core::{PeerId, RoomId, SessionId};
use refract_crypto::{CryptoError, DtlsAcceptor, DtlsConfig};
use refract_jitter::{
    JitterConfig, JitterError, LossDetector, NackAggregator, PublisherBuffer, RtpSequenceNumber,
};
use refract_net::stun::{MAGIC_COOKIE, StunMessage};
use refract_router::{
    IngressSsrc, RoutingTable, RoutingTableConfig, SubscriberSessionId, Subscription,
};
use refract_rtc::{
    RtcConfig, RtcError, RtcEvent, RtcIceState, RtcKeyframeRequestKind, RtcMid, RtcRid, RtcSession,
    Str0mRtpPacket as RtpPacket,
};
use refract_rtp::{
    RtpError,
    header::RtpHeader,
    rewriter::{RtpRewrite, RtpRewriter},
};
use refract_slab::{ArenaKind, ExhaustionPolicy, SlabConfig, SlabError, SlabPool};
use refract_srtp::{SrtpContext, SrtpError, SrtpKeys};
use refract_uring::{RecvTier, SqPoll, UringError};
use rtrb::{Consumer, PopError, Producer, PushError, RingBuffer};
use rustc_hash::{FxHashMap, FxHashSet};
use thiserror::Error;

/// Result alias for `refract-sfu` operations.
pub type SfuResult<T> = Result<T, SfuError>;

/// Maximum packet bytes retained in per-peer hot-loop scratch buffers.
pub const MAX_PACKET_BYTES: usize = 2_048;

/// Maximum fan-out routes processed for one ingress RTP packet.
pub const MAX_ROUTES_PER_PACKET: usize = 64;

/// Default number of packets retained in each peer's pacing queue.
pub const DEFAULT_OUTBOX_DEPTH: usize = 128;

/// Default upper bound for peer state on one core.
pub const DEFAULT_MAX_PEERS: usize = 10_000;

/// Maximum configured peer states accepted by one core constructor.
pub const MAX_PEERS_PER_CORE: usize = 65_536;

/// Maximum migration media blip accepted by the Stage 1 cross-core policy.
pub const MAX_MIGRATION_BLIP: Duration = Duration::from_millis(20);

/// Default bounded idle poll used by live media sockets.
pub const DEFAULT_MEDIA_IDLE_POLL: Duration = Duration::from_millis(50);

/// Default bounded control ring depth for one signaling-to-core lane.
pub const DEFAULT_CONTROL_RING_DEPTH: usize = 128;

/// Default deterministic timeout for slow-path RTC control operations.
pub const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_millis(500);

const RTP_FIXED_HEADER_LEN: usize = 12;
#[cfg(test)]
const RTP_VERSION: u8 = 2;
#[cfg(test)]
const RTP_VERSION_SHIFT: u8 = 6;
#[cfg(test)]
const RTP_SEQUENCE_OFFSET: usize = 2;
#[cfg(test)]
const RTP_SSRC_OFFSET: usize = 8;
const GCM_TAG_LEN: usize = 16;
const DTLS_CONTENT_TYPE_MIN: u8 = 20;
const DTLS_CONTENT_TYPE_MAX: u8 = 25;
const DTLS_MIN_HEADER_LEN: usize = 13;
const JITTER_RETAINED_PACKETS_PER_PEER: usize = 4;
const JITTER_BASELINE_BITRATE_BPS: u64 = 384_000;
const MAX_PENDING_RTC_PACKETS: usize = 128;
const MAX_RTC_RTP_DECRYPT_MISSES: u8 = 3;

/// WebRTC datagram class after RFC 7983-style UDP multiplexing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DatagramKind {
    /// STUN or ICE datagram.
    Stun,
    /// DTLS datagram.
    Dtls,
    /// RTP datagram.
    Rtp,
    /// RTCP datagram.
    Rtcp,
    /// Datagram did not match WebRTC multiplexing rules.
    Unknown,
}

impl DatagramKind {
    /// Returns the bounded datagram kind label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::DatagramKind;
    /// assert_eq!(DatagramKind::Rtp.as_str(), "rtp");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stun => "stun",
            Self::Dtls => "dtls",
            Self::Rtp => "rtp",
            Self::Rtcp => "rtcp",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{DatagramKind, Stability};
    /// assert_eq!(DatagramKind::Stun.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

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
    /// # use refract_sfu::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Per-core identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoreId(u16);

impl CoreId {
    /// Creates a core identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::CoreId;
    /// assert_eq!(CoreId::new(3).as_u16(), 3);
    /// ```
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw core index.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::CoreId;
    /// assert_eq!(CoreId::new(7).as_u16(), 7);
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
    /// # use refract_sfu::{CoreId, Stability};
    /// assert_eq!(CoreId::new(0).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for CoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "core_{}", self.0)
    }
}

/// IP protocol value in a media five-tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpProtocol {
    /// User Datagram Protocol.
    Udp,
}

impl IpProtocol {
    /// Returns the bounded protocol label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::IpProtocol;
    /// assert_eq!(IpProtocol::Udp.as_str(), "udp");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{IpProtocol, Stability};
    /// assert_eq!(IpProtocol::Udp.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Media socket five-tuple key used for hot-path demux.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FiveTuple {
    local: SocketAddr,
    remote: SocketAddr,
    protocol: IpProtocol,
}

impl FiveTuple {
    /// Creates a media socket five-tuple.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// assert_eq!(
    ///     FiveTuple::new(local, remote, IpProtocol::Udp).remote(),
    ///     remote
    /// );
    /// ```
    #[must_use]
    pub const fn new(local: SocketAddr, remote: SocketAddr, protocol: IpProtocol) -> Self {
        Self {
            local,
            remote,
            protocol,
        }
    }

    /// Returns the local media socket address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// assert_eq!(
    ///     FiveTuple::new(local, remote, IpProtocol::Udp).local(),
    ///     local
    /// );
    /// ```
    #[must_use]
    pub const fn local(self) -> SocketAddr {
        self.local
    }

    /// Returns the remote peer socket address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// assert_eq!(
    ///     FiveTuple::new(local, remote, IpProtocol::Udp).remote(),
    ///     remote
    /// );
    /// ```
    #[must_use]
    pub const fn remote(self) -> SocketAddr {
        self.remote
    }

    /// Returns the transport protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// assert_eq!(
    ///     FiveTuple::new(local, remote, IpProtocol::Udp).protocol(),
    ///     IpProtocol::Udp
    /// );
    /// ```
    #[must_use]
    pub const fn protocol(self) -> IpProtocol {
        self.protocol
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IpProtocol, Stability};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// assert_eq!(
    ///     FiveTuple::new(local, remote, IpProtocol::Udp).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Constructor configuration for one [`SfuCore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SfuConfig {
    core_id: CoreId,
    max_peers: usize,
    packet_capacity: usize,
    outbox_depth: usize,
    dtls_identity_path: Option<PathBuf>,
}

impl SfuConfig {
    /// Creates a bounded core configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::InvalidConfig`] when a bound is zero or exceeds the
    /// documented maximum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// let config = SfuConfig::new(CoreId::new(0), 128)?;
    /// assert_eq!(config.max_peers(), 128);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub const fn new(core_id: CoreId, max_peers: usize) -> SfuResult<Self> {
        if max_peers == 0 || max_peers > MAX_PEERS_PER_CORE {
            return Err(SfuError::InvalidConfig { field: "max_peers" });
        }
        Ok(Self {
            core_id,
            max_peers,
            packet_capacity: MAX_PACKET_BYTES,
            outbox_depth: DEFAULT_OUTBOX_DEPTH,
            dtls_identity_path: None,
        })
    }

    /// Sets the packet buffer capacity.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::InvalidConfig`] when `packet_capacity` is zero or
    /// larger than [`MAX_PACKET_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// let config = SfuConfig::new(CoreId::new(0), 16)?.with_packet_capacity(1500)?;
    /// assert_eq!(config.packet_capacity(), 1500);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn with_packet_capacity(mut self, packet_capacity: usize) -> SfuResult<Self> {
        if packet_capacity == 0 || packet_capacity > MAX_PACKET_BYTES {
            return Err(SfuError::InvalidConfig {
                field: "packet_capacity",
            });
        }
        self.packet_capacity = packet_capacity;
        Ok(self)
    }

    /// Sets the per-peer pacing queue depth.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::InvalidConfig`] when `outbox_depth` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// let config = SfuConfig::new(CoreId::new(0), 16)?.with_outbox_depth(32)?;
    /// assert_eq!(config.outbox_depth(), 32);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn with_outbox_depth(mut self, outbox_depth: usize) -> SfuResult<Self> {
        if outbox_depth == 0 {
            return Err(SfuError::InvalidConfig {
                field: "outbox_depth",
            });
        }
        self.outbox_depth = outbox_depth;
        Ok(self)
    }

    /// Enables a `DTLS` acceptor backed by the supplied identity path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// let config = SfuConfig::new(CoreId::new(0), 16)?.with_dtls_identity_path("identity.pem");
    /// assert!(config.dtls_identity_path().is_some());
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub fn with_dtls_identity_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.dtls_identity_path = Some(path.into());
        self
    }

    /// Returns the configured core identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// assert_eq!(
    ///     SfuConfig::new(CoreId::new(2), 16)?.core_id(),
    ///     CoreId::new(2)
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn core_id(&self) -> CoreId {
        self.core_id
    }

    /// Returns the peer-state bound.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// assert_eq!(SfuConfig::new(CoreId::new(0), 16)?.max_peers(), 16);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Returns the packet capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, MAX_PACKET_BYTES};
    /// assert_eq!(
    ///     SfuConfig::new(CoreId::new(0), 16)?.packet_capacity(),
    ///     MAX_PACKET_BYTES
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn packet_capacity(&self) -> usize {
        self.packet_capacity
    }

    /// Returns the per-peer pacing queue depth.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, DEFAULT_OUTBOX_DEPTH, SfuConfig};
    /// assert_eq!(
    ///     SfuConfig::new(CoreId::new(0), 16)?.outbox_depth(),
    ///     DEFAULT_OUTBOX_DEPTH
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn outbox_depth(&self) -> usize {
        self.outbox_depth
    }

    /// Returns the optional `DTLS` identity path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig};
    /// assert!(
    ///     SfuConfig::new(CoreId::new(0), 16)?
    ///         .dtls_identity_path()
    ///         .is_none()
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn dtls_identity_path(&self) -> Option<&PathBuf> {
        self.dtls_identity_path.as_ref()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, Stability};
    /// assert_eq!(
    ///     SfuConfig::new(CoreId::new(0), 16)?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Default for SfuConfig {
    fn default() -> Self {
        Self {
            core_id: CoreId::new(0),
            max_peers: DEFAULT_MAX_PEERS,
            packet_capacity: MAX_PACKET_BYTES,
            outbox_depth: DEFAULT_OUTBOX_DEPTH,
            dtls_identity_path: None,
        }
    }
}

/// Slow-path RTC offer command sent from signaling to one SFU core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SfuRtcOffer {
    session_id: SessionId,
    peer_id: PeerId,
    room_id: RoomId,
    sdp: Box<str>,
}

impl SfuRtcOffer {
    /// Creates an RTC offer command.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_sfu::SfuRtcOffer;
    /// let offer = SfuRtcOffer::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    ///     "v=0".into(),
    /// );
    /// assert_eq!(offer.session_id(), SessionId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        peer_id: PeerId,
        room_id: RoomId,
        sdp: Box<str>,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            room_id,
            sdp,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the peer identifier.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the room identifier.
    #[must_use]
    pub const fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Returns the browser SDP offer.
    #[must_use]
    pub fn sdp(&self) -> &str {
        &self.sdp
    }
}

/// Slow-path ICE candidate command sent from signaling to one SFU core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SfuIceCandidate {
    session_id: SessionId,
    candidate: Box<str>,
}

impl SfuIceCandidate {
    /// Creates an ICE candidate command.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::SessionId;
    /// # use refract_sfu::SfuIceCandidate;
    /// let candidate = SfuIceCandidate::new(SessionId::from_raw(1), "candidate:1".into());
    /// assert_eq!(candidate.session_id(), SessionId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn new(session_id: SessionId, candidate: Box<str>) -> Self {
        Self {
            session_id,
            candidate,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the ICE candidate text.
    #[must_use]
    pub fn candidate(&self) -> &str {
        &self.candidate
    }
}

/// Accepted RTC offer returned by the owning SFU core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtcOfferAccepted {
    session_id: SessionId,
    peer_id: PeerId,
    room_id: RoomId,
    core_id: CoreId,
    media_addr: SocketAddr,
    sdp: Box<str>,
}

impl RtcOfferAccepted {
    /// Creates accepted-offer metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_sfu::{CoreId, RtcOfferAccepted};
    /// let accepted = RtcOfferAccepted::new(
    ///     SessionId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     RoomId::from_raw(3),
    ///     CoreId::new(0),
    ///     "127.0.0.1:50000".parse::<SocketAddr>()?,
    ///     "v=0".into(),
    /// );
    /// assert_eq!(accepted.core_id(), CoreId::new(0));
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        peer_id: PeerId,
        room_id: RoomId,
        core_id: CoreId,
        media_addr: SocketAddr,
        sdp: Box<str>,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            room_id,
            core_id,
            media_addr,
            sdp,
        }
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the peer identifier.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the room identifier.
    #[must_use]
    pub const fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Returns the owning SFU core identifier.
    #[must_use]
    pub const fn core_id(&self) -> CoreId {
        self.core_id
    }

    /// Returns the UDP media address advertised in ICE.
    #[must_use]
    pub const fn media_addr(&self) -> SocketAddr {
        self.media_addr
    }

    /// Returns the SDP answer generated by `str0m`.
    #[must_use]
    pub fn sdp(&self) -> &str {
        &self.sdp
    }
}

/// Cloneable slow-path handle for signaling-to-core RTC control.
#[derive(Clone)]
pub struct SfuControlSender {
    producer: Arc<Mutex<Producer<SfuControlCommand>>>,
}

impl fmt::Debug for SfuControlSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SfuControlSender")
            .finish_non_exhaustive()
    }
}

impl SfuControlSender {
    /// Creates a bounded SPSC control ring pair.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::InvalidConfig`] when `depth` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{SfuControlSender, DEFAULT_CONTROL_RING_DEPTH};
    /// let (_tx, _rx) = SfuControlSender::pair(DEFAULT_CONTROL_RING_DEPTH)?;
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn pair(depth: usize) -> SfuResult<(Self, SfuControlConsumer)> {
        if depth == 0 {
            return Err(SfuError::InvalidConfig {
                field: "control_depth",
            });
        }
        let (producer, consumer) = RingBuffer::new(depth);
        Ok((
            Self {
                producer: Arc::new(Mutex::new(producer)),
            },
            SfuControlConsumer { consumer },
        ))
    }

    /// Sends an RTC offer to the owning SFU core and waits for the answer.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError`] when the bounded control ring is full, poisoned, times
    /// out, or the core rejects the offer.
    pub fn accept_rtc_offer(
        &self,
        offer: SfuRtcOffer,
        timeout: Duration,
    ) -> SfuResult<RtcOfferAccepted> {
        let (response, mut consumer) = RingBuffer::new(1);
        self.push(SfuControlCommand::AcceptRtcOffer { offer, response })?;
        wait_offer_response(&mut consumer, timeout)
    }

    /// Sends a trickled ICE candidate to the owning SFU core.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError`] when the bounded control ring is full, poisoned, times
    /// out, or the core rejects the candidate.
    pub fn add_ice_candidate(
        &self,
        candidate: SfuIceCandidate,
        timeout: Duration,
    ) -> SfuResult<()> {
        let (response, mut consumer) = RingBuffer::new(1);
        self.push(SfuControlCommand::AddIceCandidate {
            candidate,
            response,
        })?;
        wait_ack_response(&mut consumer, timeout)
    }

    /// Removes one RTC session from the owning SFU core.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError`] when the bounded control ring is full, poisoned, or
    /// times out.
    pub fn leave(&self, session_id: SessionId, timeout: Duration) -> SfuResult<()> {
        let (response, mut consumer) = RingBuffer::new(1);
        self.push(SfuControlCommand::Leave {
            session_id,
            response,
        })?;
        wait_ack_response(&mut consumer, timeout)
    }

    fn push(&self, command: SfuControlCommand) -> SfuResult<()> {
        self.producer
            .lock()
            .map_err(|_source| SfuError::ControlPoisoned)?
            .push(command)
            .map_err(|PushError::Full(_command)| SfuError::ControlQueueFull)
    }
}

/// Owning-core consumer for slow-path RTC control.
pub struct SfuControlConsumer {
    consumer: Consumer<SfuControlCommand>,
}

impl fmt::Debug for SfuControlConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SfuControlConsumer")
            .finish_non_exhaustive()
    }
}

enum SfuControlCommand {
    AcceptRtcOffer {
        offer: SfuRtcOffer,
        response: Producer<SfuControlResponse>,
    },
    AddIceCandidate {
        candidate: SfuIceCandidate,
        response: Producer<SfuControlResponse>,
    },
    Leave {
        session_id: SessionId,
        response: Producer<SfuControlResponse>,
    },
}

impl fmt::Debug for SfuControlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcceptRtcOffer { offer, .. } => formatter
                .debug_struct("AcceptRtcOffer")
                .field("session_id", &offer.session_id())
                .finish_non_exhaustive(),
            Self::AddIceCandidate { candidate, .. } => formatter
                .debug_struct("AddIceCandidate")
                .field("session_id", &candidate.session_id())
                .finish_non_exhaustive(),
            Self::Leave { session_id, .. } => formatter
                .debug_struct("Leave")
                .field("session_id", session_id)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug)]
enum SfuControlResponse {
    Offer(SfuResult<RtcOfferAccepted>),
    Ack(SfuResult<()>),
}

fn wait_offer_response(
    consumer: &mut Consumer<SfuControlResponse>,
    timeout: Duration,
) -> SfuResult<RtcOfferAccepted> {
    if timeout.is_zero() {
        return Err(SfuError::InvalidConfig {
            field: "control_timeout",
        });
    }
    let deadline = Instant::now() + timeout;
    loop {
        match consumer.pop() {
            Ok(SfuControlResponse::Offer(result)) => return result,
            Ok(SfuControlResponse::Ack(_result)) => return Err(SfuError::ControlResponseMismatch),
            Err(PopError::Empty) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(PopError::Empty) => return Err(SfuError::ControlTimeout),
        }
    }
}

fn wait_ack_response(
    consumer: &mut Consumer<SfuControlResponse>,
    timeout: Duration,
) -> SfuResult<()> {
    if timeout.is_zero() {
        return Err(SfuError::InvalidConfig {
            field: "control_timeout",
        });
    }
    let deadline = Instant::now() + timeout;
    loop {
        match consumer.pop() {
            Ok(SfuControlResponse::Ack(result)) => return result,
            Ok(SfuControlResponse::Offer(_result)) => {
                return Err(SfuError::ControlResponseMismatch);
            }
            Err(PopError::Empty) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(PopError::Empty) => return Err(SfuError::ControlTimeout),
        }
    }
}

/// One synthetic packet used by deterministic hot-loop tests and loadgen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressPacket<'a> {
    tuple: FiveTuple,
    payload: &'a [u8],
}

impl<'a> IngressPacket<'a> {
    /// Creates an ingress packet view.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IngressPacket, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// let tuple = FiveTuple::new(local, remote, IpProtocol::Udp);
    /// assert_eq!(IngressPacket::new(tuple, &[0_u8; 1]).payload().len(), 1);
    /// ```
    #[must_use]
    pub const fn new(tuple: FiveTuple, payload: &'a [u8]) -> Self {
        Self { tuple, payload }
    }

    /// Returns the source five-tuple.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IngressPacket, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// let tuple = FiveTuple::new(local, remote, IpProtocol::Udp);
    /// assert_eq!(IngressPacket::new(tuple, &[]).tuple(), tuple);
    /// ```
    #[must_use]
    pub const fn tuple(self) -> FiveTuple {
        self.tuple
    }

    /// Returns packet bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IngressPacket, IpProtocol};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// let tuple = FiveTuple::new(local, remote, IpProtocol::Udp);
    /// assert_eq!(IngressPacket::new(tuple, &[7]).payload(), &[7]);
    /// ```
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sfu::{FiveTuple, IngressPacket, IpProtocol, Stability};
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// let tuple = FiveTuple::new(local, remote, IpProtocol::Udp);
    /// assert_eq!(
    ///     IngressPacket::new(tuple, &[]).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Packet emitted by a peer pacer drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredPacket {
    destination: SocketAddr,
    len: usize,
    bytes: [u8; MAX_PACKET_BYTES],
}

impl DeliveredPacket {
    /// Creates an empty delivered packet slot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::DeliveredPacket;
    /// assert!(DeliveredPacket::empty().payload().is_empty());
    /// ```
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            destination: SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            )),
            len: 0,
            bytes: [0; MAX_PACKET_BYTES],
        }
    }

    /// Returns the destination socket address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::DeliveredPacket;
    /// assert_eq!(DeliveredPacket::empty().destination().port(), 0);
    /// ```
    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns delivered packet bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::DeliveredPacket;
    /// assert!(DeliveredPacket::empty().payload().is_empty());
    /// ```
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{DeliveredPacket, Stability};
    /// assert_eq!(DeliveredPacket::empty().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn copy_from(destination: SocketAddr, payload: &[u8]) -> SfuResult<Self> {
        if payload.len() > MAX_PACKET_BYTES {
            return Err(SfuError::PacketTooLarge {
                len: payload.len(),
                max: MAX_PACKET_BYTES,
            });
        }
        let mut packet = Self::empty();
        packet.destination = destination;
        packet.len = payload.len();
        packet.bytes[..payload.len()].copy_from_slice(payload);
        Ok(packet)
    }
}

impl Default for DeliveredPacket {
    fn default() -> Self {
        Self::empty()
    }
}

/// Snapshot of lock-free per-core counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatsSnapshot {
    /// Packets accepted from a media socket.
    pub ingress_packets: u64,
    /// RTP packets forwarded to at least one subscriber.
    pub forwarded_packets: u64,
    /// STUN packets handed to `refract-net`.
    pub stun_packets: u64,
    /// `DTLS` packets handed to `refract-crypto`.
    pub dtls_packets: u64,
    /// Packets dropped by parsing, demux, or queue bounds.
    pub dropped_packets: u64,
    /// Peer-local panics isolated by teardown.
    pub isolated_peer_panics: u64,
}

impl StatsSnapshot {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{Stability, StatsSnapshot};
    /// assert_eq!(StatsSnapshot::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Cross-core fan-out placement decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationDecision {
    /// Publisher and subscriber are already co-located.
    AlreadyLocal,
    /// Re-home a peer to the other core before sustained forwarding.
    Rehome {
        /// Peer selected for migration.
        peer: PeerId,
        /// Maximum media interruption budget.
        max_blip: Duration,
    },
}

impl MigrationDecision {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{MigrationDecision, Stability};
    /// assert_eq!(
    ///     MigrationDecision::AlreadyLocal.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Peer media protection mode.
#[derive(Debug)]
pub enum PeerCrypto {
    /// Plain RTP mode for deterministic synthetic tests and pre-DTLS warmup.
    Plaintext,
    /// SRTP mode using keys exported by `refract-crypto`.
    Srtp(Box<SrtpContext>),
}

impl PeerCrypto {
    /// Creates `SRTP` media protection from exported keys.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::Srtp`] when key setup fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::PeerCrypto;
    /// assert!(matches!(PeerCrypto::Plaintext, PeerCrypto::Plaintext));
    /// ```
    pub fn from_srtp_keys(keys: SrtpKeys) -> SfuResult<Self> {
        Ok(Self::Srtp(Box::new(SrtpContext::new(keys, 64)?)))
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{PeerCrypto, Stability};
    /// assert_eq!(PeerCrypto::Plaintext.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Errors returned by the per-core `SFU`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SfuError {
    /// Constructor or warmup configuration is invalid.
    #[error("invalid sfu config: field={field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// The per-core peer map is full.
    #[error("peer capacity exceeded: max={max}")]
    PeerCapacity {
        /// Configured peer bound.
        max: usize,
    },
    /// A peer was not registered.
    #[error("unknown peer")]
    UnknownPeer,
    /// A packet exceeded the bounded packet capacity.
    #[error("packet too large: len={len} max={max}")]
    PacketTooLarge {
        /// Observed length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// Too many routes were selected for one ingress packet.
    #[error("route fanout exceeded: routes={routes} max={max}")]
    RouteFanoutExceeded {
        /// Observed routes.
        routes: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A per-peer fixed pacing queue is full.
    #[error("pacer queue full")]
    PacerFull,
    /// `refract-router` rejected routing state.
    #[error("router failed: {0}")]
    Router(#[from] refract_router::RouterError),
    /// `refract-rtc` rejected WebRTC session input.
    #[error("rtc failed: {0}")]
    Rtc(#[from] RtcError),
    /// `refract-jitter` rejected ingress state.
    #[error("jitter failed: {0}")]
    Jitter(#[from] JitterError),
    /// `refract-rtp` rejected RTP bytes.
    #[error("rtp failed: {0}")]
    Rtp(#[from] RtpError),
    /// `refract-srtp` rejected media protection.
    #[error("srtp failed: {0}")]
    Srtp(#[from] SrtpError),
    /// `refract-net` rejected STUN bytes.
    #[error("net failed: {0}")]
    Net(#[from] refract_net::NetError),
    /// `refract-crypto` rejected `DTLS` bytes or policy.
    #[error("crypto failed: {0}")]
    Crypto(#[from] CryptoError),
    /// `refract-slab` failed during warmup.
    #[error("slab failed: {0}")]
    Slab(#[from] SlabError),
    /// `refract-uring` failed during queue setup.
    #[error("uring failed: {0}")]
    Uring(#[from] UringError),
    /// `compio` runtime construction failed.
    #[error("compio runtime failed: {0}")]
    Runtime(#[source] std::io::Error),
    /// Bounded warmup allocation failed.
    #[error("allocation failed: component={component}")]
    Allocation {
        /// Component being preallocated.
        component: &'static str,
    },
    /// Slow-path RTC control ring is full.
    #[error("rtc control queue full")]
    ControlQueueFull,
    /// Slow-path RTC control response was not received before the deadline.
    #[error("rtc control timeout")]
    ControlTimeout,
    /// Slow-path RTC control producer mutex was poisoned.
    #[error("rtc control producer poisoned")]
    ControlPoisoned,
    /// Slow-path RTC control response did not match the request.
    #[error("rtc control response mismatch")]
    ControlResponseMismatch,
}

impl SfuError {
    /// Returns the stable operator-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::SfuError;
    /// let error = SfuError::InvalidConfig { field: "max_peers" };
    /// assert_eq!(error.error_code(), "HSF-SFU-001");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "HSF-SFU-001",
            Self::PeerCapacity { .. } => "HSF-SFU-002",
            Self::UnknownPeer => "HSF-SFU-003",
            Self::PacketTooLarge { .. } => "HSF-SFU-004",
            Self::RouteFanoutExceeded { .. } => "HSF-SFU-005",
            Self::PacerFull => "HSF-SFU-006",
            Self::Router(_) => "HSF-SFU-007",
            Self::Rtc(_) => "HSF-SFU-008",
            Self::Jitter(_) => "HSF-SFU-009",
            Self::Rtp(_) => "HSF-SFU-010",
            Self::Srtp(_) => "HSF-SFU-011",
            Self::Net(_) => "HSF-SFU-012",
            Self::Crypto(_) => "HSF-SFU-013",
            Self::Slab(_) => "HSF-SFU-014",
            Self::Uring(_) => "HSF-SFU-015",
            Self::Runtime(_) => "HSF-SFU-016",
            Self::Allocation { .. } => "HSF-SFU-017",
            Self::ControlQueueFull => "HSF-SFU-018",
            Self::ControlTimeout => "HSF-SFU-019",
            Self::ControlPoisoned => "HSF-SFU-020",
            Self::ControlResponseMismatch => "HSF-SFU-021",
        }
    }
}

/// Per-core `SFU` owner.
pub struct SfuCore {
    config: SfuConfig,
    routing: RoutingTable,
    slab: SlabPool,
    io_queues: IoQueues,
    runtime: Runtime,
    dtls: Option<DtlsAcceptor>,
    peers: FxHashMap<PeerId, PeerState>,
    demux: FxHashMap<FiveTuple, PeerId>,
    subscribers: FxHashMap<SubscriberSessionId, PeerId>,
    rtc_sessions: FxHashMap<SessionId, RtcSession>,
    rtc_remote: FxHashMap<SocketAddr, RtcRemoteOwner>,
    rtc_ssrc: FxHashMap<u32, SessionId>,
    rtc_source_ssrc: FxHashMap<RtcSsrcKey, SessionId>,
    rtc_blocked_source_ssrc: FxHashSet<RtcSsrcKey>,
    rtc_rtp_decrypt_misses: FxHashMap<RtcSsrcKey, u8>,
    stats: CoreStats,
    route_scratch: [Option<SubscriberSessionId>; MAX_ROUTES_PER_PACKET],
    media_scratch: Vec<u8>,
    rtc_packet_scratch: VecDeque<RtpPacket>,
    rtc_keyframe_scratch: VecDeque<RtcKeyframeRequest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RtcRemoteOwner {
    Unique(SessionId),
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RtcSsrcKey {
    source: SocketAddr,
    ssrc: u32,
}

impl RtcSsrcKey {
    const fn new(source: SocketAddr, ssrc: u32) -> Self {
        Self { source, ssrc }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RtcKeyframeRequest {
    mid: RtcMid,
    rid: Option<RtcRid>,
    kind: RtcKeyframeRequestKind,
}

impl fmt::Debug for SfuCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SfuCore")
            .field("config", &self.config)
            .field("routing", &self.routing)
            .field("slab_stats", &self.slab.stats())
            .field("recv_tier", &self.io_queues.recv_tier)
            .field("sq_poll", &self.io_queues.sq_poll)
            .field("runtime", &self.runtime)
            .field("dtls_enabled", &self.dtls.is_some())
            .field("peers", &self.peers.len())
            .field("demux", &self.demux.len())
            .field("rtc_sessions", &self.rtc_sessions.len())
            .finish_non_exhaustive()
    }
}

impl SfuCore {
    /// Creates one per-core `SFU` with a `compio` runtime and warmed buffers.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime, slab, routing table, `DTLS` acceptor,
    /// or bounded warmup allocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// assert_eq!(core.core_id(), CoreId::new(0));
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn new(config: SfuConfig) -> SfuResult<Self> {
        let runtime = Runtime::new().map_err(SfuError::Runtime)?;
        let routing = RoutingTable::with_config(RoutingTableConfig::default())?;
        let slab = SlabPool::with_config(SlabConfig {
            slot_count: config.max_peers.saturating_mul(2).max(64),
            packet_capacity: config.packet_capacity,
            arena: ArenaKind::Heap,
            exhaustion: ExhaustionPolicy::FailFast,
        })?;
        let dtls = config
            .dtls_identity_path
            .as_ref()
            .map(|path| DtlsAcceptor::new(DtlsConfig::new(path)))
            .transpose()?;

        let mut peers = FxHashMap::default();
        let mut demux = FxHashMap::default();
        let mut subscribers = FxHashMap::default();
        let mut rtc_sessions = FxHashMap::default();
        let mut rtc_remote = FxHashMap::default();
        let mut rtc_ssrc = FxHashMap::default();
        let mut rtc_source_ssrc = FxHashMap::default();
        let mut rtc_blocked_source_ssrc = FxHashSet::default();
        let rtc_rtp_decrypt_misses = FxHashMap::default();
        peers
            .try_reserve(config.max_peers)
            .map_err(|_source| SfuError::Allocation { component: "peers" })?;
        demux
            .try_reserve(config.max_peers)
            .map_err(|_source| SfuError::Allocation { component: "demux" })?;
        subscribers
            .try_reserve(config.max_peers)
            .map_err(|_source| SfuError::Allocation {
                component: "subscribers",
            })?;
        rtc_sessions
            .try_reserve(config.max_peers)
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_sessions",
            })?;
        rtc_remote
            .try_reserve(config.max_peers)
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_remote",
            })?;
        rtc_ssrc
            .try_reserve(config.max_peers.saturating_mul(2))
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_ssrc",
            })?;
        rtc_source_ssrc
            .try_reserve(config.max_peers.saturating_mul(2))
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_source_ssrc",
            })?;
        rtc_blocked_source_ssrc
            .try_reserve(config.max_peers.saturating_mul(2))
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_blocked_source_ssrc",
            })?;
        let mut media_scratch = Vec::new();
        media_scratch
            .try_reserve_exact(config.packet_capacity)
            .map_err(|_source| SfuError::Allocation {
                component: "media_scratch",
            })?;
        let mut rtc_packet_scratch = VecDeque::new();
        rtc_packet_scratch
            .try_reserve_exact(MAX_PENDING_RTC_PACKETS)
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_packet_scratch",
            })?;
        let mut rtc_keyframe_scratch = VecDeque::new();
        rtc_keyframe_scratch
            .try_reserve_exact(MAX_PENDING_RTC_PACKETS)
            .map_err(|_source| SfuError::Allocation {
                component: "rtc_keyframe_scratch",
            })?;

        Ok(Self {
            config,
            routing,
            slab,
            io_queues: IoQueues::detect(),
            runtime,
            dtls,
            peers,
            demux,
            subscribers,
            rtc_sessions,
            rtc_remote,
            rtc_ssrc,
            rtc_source_ssrc,
            rtc_blocked_source_ssrc,
            rtc_rtp_decrypt_misses,
            stats: CoreStats::default(),
            route_scratch: [None; MAX_ROUTES_PER_PACKET],
            media_scratch,
            rtc_packet_scratch,
            rtc_keyframe_scratch,
        })
    }

    /// Returns the owning core identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(1), 16)?)?;
    /// assert_eq!(core.core_id(), CoreId::new(1));
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn core_id(&self) -> CoreId {
        self.config.core_id
    }

    /// Returns the selected I/O queue tier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// let _tier = core.recv_tier();
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn recv_tier(&self) -> RecvTier {
        self.io_queues.recv_tier
    }

    /// Returns mutable access to the per-core routing table.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// assert_eq!(core.routing_table_mut().subscription_count(), 0);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn routing_table_mut(&mut self) -> &mut RoutingTable {
        &mut self.routing
    }

    /// Adds a subscription to the per-core routing table.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::Router`] when the routing table rejects the
    /// subscription.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore, SubscriberSessionId, Subscription};
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// let sub = Subscription::new(
    ///     PublisherTrackId::new(1),
    ///     SubscriberSessionId::new(1),
    ///     IngressSsrc::new(42),
    ///     vec![Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?],
    /// )?;
    /// core.add_subscription(sub)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_subscription(&mut self, subscription: Subscription) -> SfuResult<bool> {
        Ok(self.routing.add_subscription(subscription)?)
    }

    /// Registers a plaintext peer for synthetic or pre-`DTLS` forwarding.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer map is full or warmup allocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_core::PeerId;
    /// # use refract_router::SubscriberSessionId;
    /// # use refract_sfu::{CoreId, FiveTuple, IpProtocol, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    /// let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    /// core.register_plain_peer(
    ///     PeerId::from_raw(1),
    ///     FiveTuple::new(local, remote, IpProtocol::Udp),
    ///     SubscriberSessionId::new(1),
    /// )?;
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn register_plain_peer(
        &mut self,
        peer_id: PeerId,
        tuple: FiveTuple,
        subscriber: SubscriberSessionId,
    ) -> SfuResult<()> {
        self.register_peer(peer_id, tuple, subscriber, PeerCrypto::Plaintext)
    }

    /// Registers an `SRTP` peer.
    ///
    /// # Errors
    ///
    /// Returns an error when key setup fails, the peer map is full, or warmup
    /// allocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{PeerCrypto, Stability};
    /// assert_eq!(PeerCrypto::Plaintext.stability(), Stability::Stage1);
    /// ```
    pub fn register_srtp_peer(
        &mut self,
        peer_id: PeerId,
        tuple: FiveTuple,
        subscriber: SubscriberSessionId,
        keys: SrtpKeys,
    ) -> SfuResult<()> {
        self.register_peer(
            peer_id,
            tuple,
            subscriber,
            PeerCrypto::from_srtp_keys(keys)?,
        )
    }

    /// Registers a browser `RtcSession` for `str0m` UDP demux.
    ///
    /// The session map is owned by this core and is warmed with the same
    /// per-core capacity as RTP peer state. Registration is a slow-path control
    /// operation; packet forwarding stays shared-nothing inside the core.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::PeerCapacity`] when the core already owns the
    /// configured maximum number of RTC sessions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId, SessionId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 4)?)?;
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// core.register_rtc_session(SessionId::from_raw(1), session)?;
    /// assert_eq!(core.rtc_session_count(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn register_rtc_session(
        &mut self,
        session_id: SessionId,
        session: RtcSession,
    ) -> SfuResult<()> {
        if !self.rtc_sessions.contains_key(&session_id)
            && self.rtc_sessions.len() == self.config.max_peers
        {
            return Err(SfuError::PeerCapacity {
                max: self.config.max_peers,
            });
        }
        self.rtc_sessions.insert(session_id, session);
        Ok(())
    }

    /// Removes an RTC session and its learned remote address mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::SessionId;
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 4)?)?;
    /// assert!(core.remove_rtc_session(SessionId::from_raw(9)).is_none());
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn remove_rtc_session(&mut self, session_id: SessionId) -> Option<RtcSession> {
        self.rtc_remote.retain(|_remote, owner| {
            !matches!(
                owner,
                RtcRemoteOwner::Unique(mapped) if *mapped == session_id
            ) && !matches!(owner, RtcRemoteOwner::Shared)
        });
        self.rtc_ssrc.retain(|_ssrc, mapped| *mapped != session_id);
        self.rtc_source_ssrc
            .retain(|_key, mapped| *mapped != session_id);
        self.rtc_blocked_source_ssrc.clear();
        self.rtc_rtp_decrypt_misses.clear();
        self.rtc_sessions.remove(&session_id)
    }

    /// Returns the number of registered RTC sessions on this core.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 4)?)?;
    /// assert_eq!(core.rtc_session_count(), 0);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub fn rtc_session_count(&self) -> usize {
        self.rtc_sessions.len()
    }

    /// Runs the exact per-core hot-loop body over a bounded synthetic batch.
    ///
    /// The method has no `.await` points. Cancellation safety is therefore
    /// trivial: callers either complete the current batch synchronously or tear
    /// down the whole owning core outside this method.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic parsing, demux, route, protection, or
    /// queue error after recording a drop counter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// core.process_synthetic_batch(&[], std::time::Duration::ZERO)?;
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn process_synthetic_batch(
        &mut self,
        batch: &[IngressPacket<'_>],
        now: Duration,
    ) -> SfuResult<()> {
        for packet in batch {
            let Some(peer_id) = self.demux.get(&packet.tuple()).copied() else {
                self.stats.dropped_packets.fetch_add(1);
                return Err(SfuError::UnknownPeer);
            };
            let result = catch_unwind(AssertUnwindSafe(|| {
                self.process_one_peer_packet(peer_id, packet.payload(), now)
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.stats.dropped_packets.fetch_add(1);
                    return Err(error);
                }
                Err(_panic) => {
                    self.teardown_peer(peer_id);
                    self.stats.isolated_peer_panics.fetch_add(1);
                }
            }
        }

        self.drain_pacers(now)
    }

    /// Runs a live UDP media socket on this core until `stop` is raised.
    ///
    /// The socket is driven by the crate-owned `compio` runtime. Each received
    /// datagram is converted into an [`IngressPacket`] and passed through the
    /// same peer panic isolation, demux, RTP parsing, routing, pacing, and
    /// delivery path as deterministic hot-loop tests. Packet-level errors are
    /// counted by the core and do not terminate the socket.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::InvalidConfig`] when `idle_poll` is zero, or
    /// [`SfuError::Net`] when the UDP socket cannot bind, receive, or send.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use std::sync::atomic::AtomicBool;
    /// # use std::time::Duration;
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// let stop = AtomicBool::new(true);
    /// let bound = core.run_udp_media_until(
    ///     "127.0.0.1:0".parse::<SocketAddr>()?,
    ///     &stop,
    ///     Duration::from_millis(1),
    ///     || {},
    /// )?;
    /// assert_ne!(bound.port(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn run_udp_media_until(
        &mut self,
        bind: SocketAddr,
        stop: &AtomicBool,
        idle_poll: Duration,
        mut on_tick: impl FnMut(),
    ) -> SfuResult<SocketAddr> {
        if idle_poll.is_zero() {
            return Err(SfuError::InvalidConfig { field: "idle_poll" });
        }
        let runtime = self.runtime.clone();
        runtime.block_on(self.run_udp_media_loop(bind, stop, idle_poll, &mut on_tick, None))
    }

    /// Runs a live UDP media socket while draining a slow-path RTC control ring.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::InvalidConfig`] when `idle_poll` is zero, or
    /// [`SfuError::Net`] when the UDP socket cannot bind, receive, or send.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::SocketAddr;
    /// # use std::sync::atomic::AtomicBool;
    /// # use std::time::Duration;
    /// # use refract_sfu::{CoreId, DEFAULT_CONTROL_RING_DEPTH, SfuConfig, SfuControlSender, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// let (_tx, mut rx) = SfuControlSender::pair(DEFAULT_CONTROL_RING_DEPTH)?;
    /// let stop = AtomicBool::new(true);
    /// let bound = core.run_udp_media_controlled_until(
    ///     "127.0.0.1:0".parse::<SocketAddr>()?,
    ///     &stop,
    ///     Duration::from_millis(1),
    ///     &mut rx,
    ///     || {},
    /// )?;
    /// assert_ne!(bound.port(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn run_udp_media_controlled_until(
        &mut self,
        bind: SocketAddr,
        stop: &AtomicBool,
        idle_poll: Duration,
        control: &mut SfuControlConsumer,
        mut on_tick: impl FnMut(),
    ) -> SfuResult<SocketAddr> {
        if idle_poll.is_zero() {
            return Err(SfuError::InvalidConfig { field: "idle_poll" });
        }
        let runtime = self.runtime.clone();
        runtime.block_on(self.run_udp_media_loop(
            bind,
            stop,
            idle_poll,
            &mut on_tick,
            Some(control),
        ))
    }

    /// Copies delivered packets for `peer_id` into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`SfuError::UnknownPeer`] when the peer has already been torn
    /// down or was never registered.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_sfu::{CoreId, DeliveredPacket, SfuConfig, SfuCore};
    /// let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// let mut out = [DeliveredPacket::empty()];
    /// assert!(
    ///     core.take_delivered(PeerId::from_raw(999), &mut out)
    ///         .is_err()
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    pub fn take_delivered(
        &mut self,
        peer_id: PeerId,
        out: &mut [DeliveredPacket],
    ) -> SfuResult<usize> {
        let peer = self.peers.get_mut(&peer_id).ok_or(SfuError::UnknownPeer)?;
        Ok(peer.delivered.drain_into(out))
    }

    /// Returns a lock-free stats snapshot for an aggregator core.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// assert_eq!(core.stats().ingress_packets, 0);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Chooses the Stage 1 cross-core fan-out action.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::PeerId;
    /// # use refract_sfu::{CoreId, MigrationDecision, SfuConfig, SfuCore};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// assert_eq!(
    ///     core.cross_core_decision(
    ///         PeerId::from_raw(1),
    ///         CoreId::new(0),
    ///         PeerId::from_raw(2),
    ///         CoreId::new(0)
    ///     ),
    ///     MigrationDecision::AlreadyLocal,
    /// );
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn cross_core_decision(
        &self,
        publisher: PeerId,
        publisher_core: CoreId,
        subscriber: PeerId,
        subscriber_core: CoreId,
    ) -> MigrationDecision {
        if publisher_core.0 == subscriber_core.0 {
            MigrationDecision::AlreadyLocal
        } else if publisher.raw() <= subscriber.raw() {
            MigrationDecision::Rehome {
                peer: subscriber,
                max_blip: MAX_MIGRATION_BLIP,
            }
        } else {
            MigrationDecision::Rehome {
                peer: publisher,
                max_blip: MAX_MIGRATION_BLIP,
            }
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sfu::{CoreId, SfuConfig, SfuCore, Stability};
    /// let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 16)?)?;
    /// assert_eq!(core.stability(), Stability::Stage1);
    /// # Ok::<(), refract_sfu::SfuError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn register_peer(
        &mut self,
        peer_id: PeerId,
        tuple: FiveTuple,
        subscriber: SubscriberSessionId,
        crypto: PeerCrypto,
    ) -> SfuResult<()> {
        if !self.peers.contains_key(&peer_id) && self.peers.len() == self.config.max_peers {
            return Err(SfuError::PeerCapacity {
                max: self.config.max_peers,
            });
        }
        let peer = PeerState::new(tuple, subscriber, crypto, &self.config)?;
        self.demux.insert(tuple, peer_id);
        self.subscribers.insert(subscriber, peer_id);
        self.peers.insert(peer_id, peer);
        Ok(())
    }

    fn process_one_peer_packet(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        now: Duration,
    ) -> SfuResult<()> {
        self.stats.ingress_packets.fetch_add(1);
        if payload.len() > self.config.packet_capacity {
            return Err(SfuError::PacketTooLarge {
                len: payload.len(),
                max: self.config.packet_capacity,
            });
        }
        if is_stun(payload) {
            StunMessage::parse(payload)?;
            self.stats.stun_packets.fetch_add(1);
            return Ok(());
        }
        if is_dtls(payload) {
            self.handle_dtls(payload)?;
            self.stats.dtls_packets.fetch_add(1);
            return Ok(());
        }

        let mut peer = self.peers.remove(&peer_id).ok_or(SfuError::UnknownPeer)?;
        let media = peer.ingress_media(payload, now)?;
        self.media_scratch.clear();
        self.media_scratch.extend_from_slice(media.payload);
        let ssrc = media.ssrc;
        self.peers.insert(peer_id, peer);

        let routes = self.routing.routes_for(IngressSsrc::new(ssrc));
        let route_slice = routes.as_slice();
        if route_slice.len() > MAX_ROUTES_PER_PACKET {
            return Err(SfuError::RouteFanoutExceeded {
                routes: route_slice.len(),
                max: MAX_ROUTES_PER_PACKET,
            });
        }
        self.route_scratch.fill(None);
        for (slot, route) in self.route_scratch.iter_mut().zip(route_slice.iter()) {
            *slot = Some(route.subscriber_session());
        }
        for subscriber in self.route_scratch.iter().flatten() {
            let Some(subscriber_peer) = self.subscribers.get(subscriber).copied() else {
                self.stats.dropped_packets.fetch_add(1);
                continue;
            };
            let Some(peer) = self.peers.get_mut(&subscriber_peer) else {
                self.stats.dropped_packets.fetch_add(1);
                continue;
            };
            peer.enqueue_egress(&self.media_scratch, now)?;
        }
        if !route_slice.is_empty() {
            self.stats.forwarded_packets.fetch_add(1);
        }
        Ok(())
    }

    fn handle_dtls(&self, payload: &[u8]) -> SfuResult<()> {
        if let Some(acceptor) = &self.dtls {
            let _outcome = acceptor.accept(Instant::now(), payload)?;
        }
        Ok(())
    }

    fn drain_pacers(&mut self, now: Duration) -> SfuResult<()> {
        for peer in self.peers.values_mut() {
            peer.drain_pacer(now)?;
        }
        Ok(())
    }

    #[allow(clippy::future_not_send)]
    async fn run_udp_media_loop(
        &mut self,
        bind: SocketAddr,
        stop: &AtomicBool,
        idle_poll: Duration,
        on_tick: &mut impl FnMut(),
        mut control: Option<&mut SfuControlConsumer>,
    ) -> SfuResult<SocketAddr> {
        let socket = UdpSocket::bind(bind).await.map_err(map_io)?;
        let local = socket.local_addr().map_err(map_io)?;
        let mut buffer = Self::media_buffer()?;
        let mut send_buffer = Self::media_buffer()?;
        let mut delivered: [DeliveredPacket; MAX_ROUTES_PER_PACKET] =
            std::array::from_fn(|_index| DeliveredPacket::empty());
        while !stop.load(Ordering::Acquire) {
            on_tick();
            if let Some(control) = control.as_deref_mut() {
                self.process_control(control, local, Instant::now());
            }
            let count = match timeout(idle_poll, socket.recv_from(buffer)).await {
                Ok(BufResult(Ok((len, remote)), returned)) => {
                    buffer = returned;
                    let packet = &buffer[..len];
                    let rtc_count = match self.process_rtc_receive(
                        Instant::now(),
                        remote,
                        local,
                        packet,
                        &mut delivered,
                    ) {
                        Ok(count) => count,
                        Err(_error) => {
                            self.stats.dropped_packets.fetch_add(1);
                            0
                        }
                    };
                    if rtc_count == 0 {
                        let tuple = FiveTuple::new(local, remote, IpProtocol::Udp);
                        let packet = IngressPacket::new(tuple, packet);
                        let now = Duration::ZERO;
                        let _result = self.process_synthetic_batch(&[packet], now);
                        self.drain_delivered(&mut delivered)
                    } else {
                        rtc_count
                    }
                }
                Ok(BufResult(Err(source), _returned)) => {
                    return Err(map_io(source));
                }
                Err(_elapsed) => {
                    buffer = Self::media_buffer()?;
                    self.process_rtc_timeouts(Instant::now(), &mut delivered)
                        .unwrap_or_else(|_error| {
                            self.stats.dropped_packets.fetch_add(1);
                            0
                        })
                }
            };
            for packet in delivered.iter().take(count) {
                send_buffer.clear();
                send_buffer.extend_from_slice(packet.payload());
                let destination = packet.destination();
                if !is_sendable_destination(local, destination) {
                    self.stats.dropped_packets.fetch_add(1);
                    continue;
                }
                let BufResult(result, returned) = socket.send_to(send_buffer, destination).await;
                send_buffer = returned;
                if result.is_err() {
                    self.stats.dropped_packets.fetch_add(1);
                }
            }
        }
        Ok(local)
    }

    fn process_control(
        &mut self,
        control: &mut SfuControlConsumer,
        media_addr: SocketAddr,
        now: Instant,
    ) {
        loop {
            let command = match control.consumer.pop() {
                Ok(command) => command,
                Err(PopError::Empty) => return,
            };
            match command {
                SfuControlCommand::AcceptRtcOffer {
                    offer,
                    mut response,
                } => {
                    let result = self.accept_controlled_rtc_offer(&offer, media_addr, now);
                    let _sent = response.push(SfuControlResponse::Offer(result)).is_ok();
                }
                SfuControlCommand::AddIceCandidate {
                    candidate,
                    mut response,
                } => {
                    let result = self.add_controlled_ice_candidate(&candidate);
                    let _sent = response.push(SfuControlResponse::Ack(result)).is_ok();
                }
                SfuControlCommand::Leave {
                    session_id,
                    mut response,
                } => {
                    let _removed = self.remove_rtc_session(session_id);
                    let _sent = response.push(SfuControlResponse::Ack(Ok(()))).is_ok();
                }
            }
        }
    }

    fn process_rtc_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        delivered: &mut [DeliveredPacket],
    ) -> SfuResult<usize> {
        let source_ssrc = rtp_ssrc(payload).map(|ssrc| RtcSsrcKey::new(source, ssrc));
        let session_id = self.rtc_session_for_datagram(now, source, destination, payload);
        let Some(session_id) = session_id else {
            return Ok(0);
        };
        let mut session = self
            .rtc_sessions
            .remove(&session_id)
            .ok_or(SfuError::UnknownPeer)?;
        let room_id = session.room_id();
        let connected_before_receive = session.ice_state() == RtcIceState::Connected;
        let rtp_packet_count_before_receive = session.pending_rtp_packet_count();
        if let Err(error) = session.handle_receive(now, source, destination, payload) {
            if let Some(key) = source_ssrc {
                self.rtc_source_ssrc.remove(&key);
                self.rtc_blocked_source_ssrc.insert(key);
                self.rtc_rtp_decrypt_misses.remove(&key);
            }
            self.rtc_sessions.insert(session_id, session);
            return Err(error.into());
        }
        self.record_rtc_remote(source, session_id);
        let emitted_rtp_packet =
            session.pending_rtp_packet_count() > rtp_packet_count_before_receive;
        if let Some(key) = source_ssrc {
            if emitted_rtp_packet {
                self.record_rtc_rtp_decrypt_success(key, session_id);
            } else if connected_before_receive {
                self.record_rtc_rtp_decrypt_miss(key);
            }
        }
        let mut count = match drain_rtc_transmits(&mut session, delivered) {
            Ok(count) => count,
            Err(error) => {
                self.rtc_sessions.insert(session_id, session);
                return Err(error);
            }
        };
        self.rtc_packet_scratch.clear();
        self.rtc_keyframe_scratch.clear();
        while let Some(packet) = session.pop_rtp_packet() {
            if self.rtc_packet_scratch.len() == MAX_PENDING_RTC_PACKETS {
                self.rtc_sessions.insert(session_id, session);
                return Err(SfuError::RouteFanoutExceeded {
                    routes: MAX_PENDING_RTC_PACKETS.saturating_add(1),
                    max: MAX_PENDING_RTC_PACKETS,
                });
            }
            self.rtc_ssrc.insert(*packet.header.ssrc, session_id);
            self.rtc_packet_scratch.push_back(packet);
        }
        while let Some(event) = session.pop_event() {
            if let RtcEvent::KeyframeRequest { mid, rid, kind } = event {
                if self.rtc_keyframe_scratch.len() == MAX_PENDING_RTC_PACKETS {
                    self.rtc_sessions.insert(session_id, session);
                    return Err(SfuError::RouteFanoutExceeded {
                        routes: MAX_PENDING_RTC_PACKETS.saturating_add(1),
                        max: MAX_PENDING_RTC_PACKETS,
                    });
                }
                self.rtc_keyframe_scratch
                    .push_back(RtcKeyframeRequest { mid, rid, kind });
            }
        }
        self.rtc_sessions.insert(session_id, session);
        while let Some(packet) = self.rtc_packet_scratch.pop_front() {
            count = self.forward_rtc_packet(session_id, room_id, &packet, delivered, count)?;
        }
        while let Some(request) = self.rtc_keyframe_scratch.pop_front() {
            count =
                self.forward_rtc_keyframe_request(session_id, room_id, request, delivered, count)?;
        }
        Ok(count)
    }

    fn rtc_session_for_datagram(
        &self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Option<SessionId> {
        let kind = classify_datagram(payload);
        let owner = self.rtc_remote.get(&source).copied();
        let source_ssrc = rtp_ssrc(payload).map(|ssrc| RtcSsrcKey::new(source, ssrc));
        let source_ssrc_session = source_ssrc
            .and_then(|key| self.rtc_source_ssrc.get(&key))
            .filter(|session_id| self.rtc_sessions.contains_key(session_id))
            .copied();
        let announced_ssrc_session = rtp_ssrc(payload)
            .and_then(|ssrc| self.rtc_ssrc.get(&ssrc))
            .filter(|session_id| self.rtc_sessions.contains_key(session_id))
            .copied();
        if kind == DatagramKind::Rtp {
            if source_ssrc.is_some_and(|key| self.rtc_blocked_source_ssrc.contains(&key)) {
                return None;
            }
            return match owner {
                Some(RtcRemoteOwner::Unique(session_id))
                    if self.rtc_sessions.contains_key(&session_id) =>
                {
                    Some(session_id)
                }
                Some(RtcRemoteOwner::Shared) => source_ssrc_session.or(announced_ssrc_session),
                Some(RtcRemoteOwner::Unique(_)) | None => None,
            };
        }
        if should_probe_rtc_sessions(kind)
            && let Some(session_id) = self.rtc_sessions.iter().find_map(|(session_id, session)| {
                session
                    .accepts_receive(now, source, destination, payload)
                    .then_some(*session_id)
            })
        {
            return Some(session_id);
        }
        // Only RTCP is allowed to use the unique remote-owner fallback.
        if !should_route_by_remote_owner(kind) {
            return None;
        }
        owner.and_then(|owner| match owner {
            RtcRemoteOwner::Unique(session_id) if self.rtc_sessions.contains_key(&session_id) => {
                Some(session_id)
            }
            RtcRemoteOwner::Unique(_) | RtcRemoteOwner::Shared => None,
        })
    }

    fn record_rtc_remote(&mut self, source: SocketAddr, session_id: SessionId) {
        match self.rtc_remote.get(&source).copied() {
            Some(RtcRemoteOwner::Unique(existing)) if existing != session_id => {
                tracing::warn!(
                    target: "refract_sfu::rtc_demux",
                    %source, existing = ?existing, new = ?session_id,
                    "rtc remote source now SHARED across sessions (single-socket demux collision)"
                );
                self.rtc_remote.insert(source, RtcRemoteOwner::Shared);
            }
            Some(RtcRemoteOwner::Unique(_) | RtcRemoteOwner::Shared) => {}
            None => {
                tracing::info!(
                    target: "refract_sfu::rtc_demux",
                    %source, session_id = ?session_id,
                    "rtc remote source bound (unique)"
                );
                self.rtc_remote
                    .insert(source, RtcRemoteOwner::Unique(session_id));
            }
        }
    }

    fn record_rtc_rtp_decrypt_success(&mut self, key: RtcSsrcKey, session_id: SessionId) {
        self.rtc_source_ssrc.insert(key, session_id);
        self.rtc_blocked_source_ssrc.remove(&key);
        self.rtc_rtp_decrypt_misses.remove(&key);
    }

    fn record_rtc_rtp_decrypt_miss(&mut self, key: RtcSsrcKey) {
        let misses = self.rtc_rtp_decrypt_misses.entry(key).or_insert(0);
        *misses = misses.saturating_add(1);
        if *misses >= MAX_RTC_RTP_DECRYPT_MISSES {
            self.rtc_source_ssrc.remove(&key);
            self.rtc_blocked_source_ssrc.insert(key);
            self.rtc_rtp_decrypt_misses.remove(&key);
        }
    }

    fn process_rtc_timeouts(
        &mut self,
        now: Instant,
        delivered: &mut [DeliveredPacket],
    ) -> SfuResult<usize> {
        let mut count = 0;
        for session in self.rtc_sessions.values_mut() {
            if session
                .next_timeout()
                .is_some_and(|deadline| deadline <= now)
            {
                session.handle_timeout(now)?;
                count += drain_rtc_transmits(session, &mut delivered[count..])?;
                if count == delivered.len() {
                    break;
                }
            }
        }
        Ok(count)
    }

    fn accept_controlled_rtc_offer(
        &mut self,
        offer: &SfuRtcOffer,
        media_addr: SocketAddr,
        now: Instant,
    ) -> SfuResult<RtcOfferAccepted> {
        let mut session = RtcSession::new(RtcConfig::new(offer.peer_id(), offer.room_id()), now)?;
        let answer = session.accept_browser_offer(offer.sdp(), media_addr)?;
        let accepted = RtcOfferAccepted::new(
            offer.session_id(),
            offer.peer_id(),
            offer.room_id(),
            self.core_id(),
            media_addr,
            answer.as_str().into(),
        );
        self.register_rtc_session(offer.session_id(), session)?;
        self.register_rtc_offer_ssrcs(offer.session_id(), offer.sdp());
        Ok(accepted)
    }

    fn register_rtc_offer_ssrcs(&mut self, session_id: SessionId, sdp: &str) {
        for ssrc in sdp.lines().filter_map(parse_sdp_ssrc) {
            self.rtc_ssrc.insert(ssrc, session_id);
            self.rtc_blocked_source_ssrc.retain(|key| key.ssrc != ssrc);
            self.rtc_rtp_decrypt_misses
                .retain(|key, _misses| key.ssrc != ssrc);
        }
    }

    fn add_controlled_ice_candidate(&mut self, candidate: &SfuIceCandidate) -> SfuResult<()> {
        let session = self
            .rtc_sessions
            .get_mut(&candidate.session_id())
            .ok_or(SfuError::UnknownPeer)?;
        session.add_remote_ice_candidate(candidate.candidate())?;
        Ok(())
    }

    fn forward_rtc_packet(
        &mut self,
        publisher: SessionId,
        room_id: RoomId,
        packet: &RtpPacket,
        delivered: &mut [DeliveredPacket],
        mut count: usize,
    ) -> SfuResult<usize> {
        let mut subscribers = [None; MAX_ROUTES_PER_PACKET];
        let mut route_count = 0_usize;
        for (session_id, subscriber) in &self.rtc_sessions {
            if *session_id == publisher || subscriber.room_id() != room_id {
                continue;
            }
            if route_count == subscribers.len() {
                return Err(SfuError::RouteFanoutExceeded {
                    routes: route_count.saturating_add(1),
                    max: subscribers.len(),
                });
            }
            subscribers[route_count] = Some(*session_id);
            route_count = route_count.saturating_add(1);
        }
        for subscriber_id in subscribers.into_iter().flatten() {
            let subscriber = self
                .rtc_sessions
                .get_mut(&subscriber_id)
                .ok_or(SfuError::UnknownPeer)?;
            subscriber.write_rtp_packet(packet)?;
            count += drain_rtc_transmits(subscriber, &mut delivered[count..])?;
        }
        Ok(count)
    }

    fn forward_rtc_keyframe_request(
        &mut self,
        requester: SessionId,
        room_id: RoomId,
        request: RtcKeyframeRequest,
        delivered: &mut [DeliveredPacket],
        mut count: usize,
    ) -> SfuResult<usize> {
        let publishers = self
            .rtc_sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (*session_id != requester && session.room_id() == room_id).then_some(*session_id)
            })
            .collect::<Vec<_>>();

        for publisher_id in publishers {
            let publisher = self
                .rtc_sessions
                .get_mut(&publisher_id)
                .ok_or(SfuError::UnknownPeer)?;
            let _requested = publisher.request_keyframe(request.mid, request.rid, request.kind)?;
            count += drain_rtc_transmits(publisher, &mut delivered[count..])?;
        }
        Ok(count)
    }

    fn media_buffer() -> SfuResult<Vec<u8>> {
        // The receive buffer MUST be sized to the largest datagram the SFU can
        // receive, NOT to the configured send-side MTU (`packet_capacity`). An
        // inbound SRTP packet is the sender's media MTU plus RTP header
        // extensions plus the AES-GCM auth tag, so it routinely exceeds the
        // 1200-byte media MTU. Sizing this buffer to the MTU truncates full-size
        // packets and strips the trailing GCM tag, making every such packet fail
        // SRTP authentication. Use the hard maximum instead.
        let capacity = MAX_PACKET_BYTES;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_source| SfuError::Allocation {
                component: "media_socket_buffer",
            })?;
        buffer.resize(capacity, 0);
        Ok(buffer)
    }

    fn drain_delivered(&mut self, out: &mut [DeliveredPacket]) -> usize {
        let mut total = 0;
        for peer in self.peers.values_mut() {
            if total == out.len() {
                break;
            }
            total += peer.delivered.drain_into(&mut out[total..]);
        }
        total
    }

    fn teardown_peer(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.peers.remove(&peer_id) {
            self.demux.remove(&peer.tuple);
            self.subscribers.remove(&peer.subscriber);
        }
    }
}

const fn map_io(source: std::io::Error) -> SfuError {
    SfuError::Net(refract_net::NetError::Io(source))
}

fn drain_rtc_transmits(
    session: &mut RtcSession,
    delivered: &mut [DeliveredPacket],
) -> SfuResult<usize> {
    let mut count = 0;
    while let Some(transmit) = session.pop_transmit() {
        if count == delivered.len() {
            return Err(SfuError::RouteFanoutExceeded {
                routes: count.saturating_add(1),
                max: delivered.len(),
            });
        }
        delivered[count] = DeliveredPacket::copy_from(transmit.destination, &transmit.contents)?;
        count += 1;
    }
    Ok(count)
}

fn rtp_ssrc(packet: &[u8]) -> Option<u32> {
    (classify_datagram(packet) == DatagramKind::Rtp && packet.len() >= RTP_FIXED_HEADER_LEN)
        .then(|| u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]))
}

fn parse_sdp_ssrc(line: &str) -> Option<u32> {
    line.strip_prefix("a=ssrc:")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|ssrc| ssrc.parse().ok())
}

const fn should_probe_rtc_sessions(kind: DatagramKind) -> bool {
    matches!(kind, DatagramKind::Stun | DatagramKind::Dtls)
}

const fn should_route_by_remote_owner(kind: DatagramKind) -> bool {
    matches!(kind, DatagramKind::Rtcp)
}

fn is_sendable_destination(local: SocketAddr, destination: SocketAddr) -> bool {
    destination != local && !destination.ip().is_unspecified() && destination.port() != 0
}

#[derive(Debug)]
struct IoQueues {
    recv_tier: RecvTier,
    sq_poll: SqPoll,
}

impl IoQueues {
    fn detect() -> Self {
        let capabilities = refract_uring::Capabilities::detect().unwrap_or_default();
        Self {
            recv_tier: RecvTier::select(capabilities),
            sq_poll: SqPoll::disabled(),
        }
    }
}

#[derive(Debug)]
struct PeerState {
    tuple: FiveTuple,
    subscriber: SubscriberSessionId,
    crypto: PeerCrypto,
    jitter: PublisherBuffer,
    loss: LossDetector,
    nacks: NackAggregator,
    ingress_scratch: Vec<u8>,
    egress_scratch: Vec<u8>,
    pacer: FixedPacer,
    delivered: DeliveredRing,
    panic_next_packet: bool,
}

impl PeerState {
    fn new(
        tuple: FiveTuple,
        subscriber: SubscriberSessionId,
        crypto: PeerCrypto,
        config: &SfuConfig,
    ) -> SfuResult<Self> {
        let jitter_memory_cap_bytes = config
            .packet_capacity
            .checked_mul(JITTER_RETAINED_PACKETS_PER_PEER)
            .ok_or(SfuError::InvalidConfig {
                field: "packet_capacity",
            })?;
        let jitter_config = JitterConfig {
            max_bitrate_bps: JITTER_BASELINE_BITRATE_BPS,
            average_packet_bytes: config.packet_capacity,
            max_packet_bytes: config.packet_capacity,
            memory_cap_bytes: jitter_memory_cap_bytes,
            ..JitterConfig::default()
        };
        let mut ingress_scratch = Vec::new();
        ingress_scratch
            .try_reserve_exact(config.packet_capacity + GCM_TAG_LEN)
            .map_err(|_source| SfuError::Allocation {
                component: "ingress_scratch",
            })?;
        let mut egress_scratch = Vec::new();
        egress_scratch
            .try_reserve_exact(config.packet_capacity + GCM_TAG_LEN)
            .map_err(|_source| SfuError::Allocation {
                component: "egress_scratch",
            })?;
        Ok(Self {
            tuple,
            subscriber,
            crypto,
            jitter: PublisherBuffer::with_config(jitter_config)?,
            loss: LossDetector::new(),
            nacks: NackAggregator::default(),
            ingress_scratch,
            egress_scratch,
            pacer: FixedPacer::new(config.outbox_depth)?,
            delivered: DeliveredRing::new(config.outbox_depth)?,
            panic_next_packet: false,
        })
    }

    fn ingress_media<'a>(
        &'a mut self,
        payload: &[u8],
        now: Duration,
    ) -> SfuResult<IngressMedia<'a>> {
        if self.panic_next_packet {
            self.panic_next_packet = false;
            panic!("injected peer panic");
        }
        self.ingress_scratch.clear();
        self.ingress_scratch.extend_from_slice(payload);
        let plaintext = match &mut self.crypto {
            PeerCrypto::Plaintext => self.ingress_scratch.as_slice(),
            PeerCrypto::Srtp(ctx) => ctx.ingress.unprotect_rtp(&mut self.ingress_scratch)?,
        };
        let header = RtpHeader::parse(plaintext)?;
        let sequence = RtpSequenceNumber::new(header.sequence());
        self.jitter.insert(sequence, plaintext)?;
        let _nacks = self.loss.observe(sequence, now, &mut self.nacks);
        Ok(IngressMedia {
            ssrc: header.ssrc(),
            payload: plaintext,
        })
    }

    fn enqueue_egress(&mut self, payload: &[u8], now: Duration) -> SfuResult<()> {
        self.egress_scratch.clear();
        self.egress_scratch.extend_from_slice(payload);
        RtpRewriter::new().rewrite(&mut self.egress_scratch, RtpRewrite::new())?;
        match &mut self.crypto {
            PeerCrypto::Plaintext => {}
            PeerCrypto::Srtp(ctx) => ctx.egress.protect_rtp(&mut self.egress_scratch)?,
        }
        let priority = packet_priority(&self.egress_scratch)?;
        self.pacer.enqueue(
            self.tuple.remote,
            priority,
            now,
            self.egress_scratch.as_slice(),
        )
    }

    fn drain_pacer(&mut self, now: Duration) -> SfuResult<()> {
        self.pacer.drain_into(now, &mut self.delivered)
    }
}

#[derive(Clone, Copy, Debug)]
struct IngressMedia<'a> {
    ssrc: u32,
    payload: &'a [u8],
}

#[derive(Debug)]
struct FixedPacer {
    queue: Vec<PacerSlot>,
    head: usize,
    len: usize,
    budget_bytes: usize,
}

impl FixedPacer {
    fn new(depth: usize) -> SfuResult<Self> {
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(depth)
            .map_err(|_source| SfuError::Allocation { component: "pacer" })?;
        for _slot in 0..depth {
            queue.push(PacerSlot::empty());
        }
        Ok(Self {
            queue,
            head: 0,
            len: 0,
            budget_bytes: MAX_PACKET_BYTES * depth,
        })
    }

    fn enqueue(
        &mut self,
        destination: SocketAddr,
        priority: PacketPriority,
        enqueued_at: Duration,
        payload: &[u8],
    ) -> SfuResult<()> {
        if self.len == self.queue.len() {
            return Err(SfuError::PacerFull);
        }
        let index = (self.head + self.len) % self.queue.len();
        self.queue[index].write(destination, priority, enqueued_at, payload)?;
        self.len += 1;
        Ok(())
    }

    fn drain_into(&mut self, now: Duration, delivered: &mut DeliveredRing) -> SfuResult<()> {
        while self.len != 0 {
            let slot = &self.queue[self.head];
            if slot.priority != PacketPriority::Audio && slot.len > self.budget_bytes {
                break;
            }
            delivered.push(slot.destination, slot.payload())?;
            self.budget_bytes = self.budget_bytes.saturating_sub(slot.len);
            if now.saturating_sub(slot.enqueued_at) >= Duration::from_millis(1) {
                self.budget_bytes = self.budget_bytes.saturating_add(MAX_PACKET_BYTES);
            }
            self.head = (self.head + 1) % self.queue.len();
            self.len -= 1;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PacerSlot {
    destination: SocketAddr,
    priority: PacketPriority,
    enqueued_at: Duration,
    len: usize,
    bytes: Box<[u8; MAX_PACKET_BYTES]>,
}

impl PacerSlot {
    fn empty() -> Self {
        Self {
            destination: SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            )),
            priority: PacketPriority::VideoDelta,
            enqueued_at: Duration::ZERO,
            len: 0,
            bytes: Box::new([0; MAX_PACKET_BYTES]),
        }
    }

    fn write(
        &mut self,
        destination: SocketAddr,
        priority: PacketPriority,
        enqueued_at: Duration,
        payload: &[u8],
    ) -> SfuResult<()> {
        if payload.len() > MAX_PACKET_BYTES {
            return Err(SfuError::PacketTooLarge {
                len: payload.len(),
                max: MAX_PACKET_BYTES,
            });
        }
        self.destination = destination;
        self.priority = priority;
        self.enqueued_at = enqueued_at;
        self.len = payload.len();
        self.bytes[..payload.len()].copy_from_slice(payload);
        Ok(())
    }

    fn payload(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Debug)]
struct DeliveredRing {
    queue: Vec<DeliveredPacket>,
    head: usize,
    len: usize,
}

impl DeliveredRing {
    fn new(depth: usize) -> SfuResult<Self> {
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(depth)
            .map_err(|_source| SfuError::Allocation {
                component: "delivered",
            })?;
        for _slot in 0..depth {
            queue.push(DeliveredPacket::empty());
        }
        Ok(Self {
            queue,
            head: 0,
            len: 0,
        })
    }

    fn push(&mut self, destination: SocketAddr, payload: &[u8]) -> SfuResult<()> {
        if self.len == self.queue.len() {
            return Err(SfuError::PacerFull);
        }
        let index = (self.head + self.len) % self.queue.len();
        self.queue[index] = DeliveredPacket::copy_from(destination, payload)?;
        self.len += 1;
        Ok(())
    }

    fn drain_into(&mut self, out: &mut [DeliveredPacket]) -> usize {
        let count = self.len.min(out.len());
        for slot in out.iter_mut().take(count) {
            *slot = self.queue[self.head].clone();
            self.head = (self.head + 1) % self.queue.len();
            self.len -= 1;
        }
        count
    }
}

#[derive(Debug, Default)]
struct CoreStats {
    ingress_packets: Counter,
    forwarded_packets: Counter,
    stun_packets: Counter,
    dtls_packets: Counter,
    dropped_packets: Counter,
    isolated_peer_panics: Counter,
}

impl CoreStats {
    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            ingress_packets: self.ingress_packets.load(),
            forwarded_packets: self.forwarded_packets.load(),
            stun_packets: self.stun_packets.load(),
            dtls_packets: self.dtls_packets.load(),
            dropped_packets: self.dropped_packets.load(),
            isolated_peer_panics: self.isolated_peer_panics.load(),
        }
    }
}

#[derive(Debug, Default)]
struct Counter(std::sync::atomic::AtomicU64);

impl Counter {
    fn fetch_add(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

fn packet_priority(packet: &[u8]) -> SfuResult<PacketPriority> {
    let header = RtpHeader::parse(packet)?;
    Ok(if header.payload_type() == 111 {
        PacketPriority::Audio
    } else if header.marker() {
        PacketPriority::VideoKeyframe
    } else {
        PacketPriority::VideoDelta
    })
}

/// Classifies a UDP datagram using WebRTC multiplexing byte ranges.
///
/// # Examples
///
/// ```
/// # use refract_sfu::{DatagramKind, classify_datagram};
/// assert_eq!(
///     classify_datagram(&[22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
///     DatagramKind::Dtls
/// );
/// ```
#[must_use]
pub fn classify_datagram(packet: &[u8]) -> DatagramKind {
    if packet.len() >= 20
        && packet[0] & 0xc0 == 0
        && u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) == MAGIC_COOKIE
    {
        return DatagramKind::Stun;
    }
    if packet.len() >= DTLS_MIN_HEADER_LEN
        && (DTLS_CONTENT_TYPE_MIN..=DTLS_CONTENT_TYPE_MAX).contains(&packet[0])
    {
        return DatagramKind::Dtls;
    }
    if packet.len() >= RTP_FIXED_HEADER_LEN && packet[0] & 0xc0 == 0x80 {
        let payload_type = packet[1] & 0x7f;
        if (64..96).contains(&payload_type) {
            DatagramKind::Rtcp
        } else {
            DatagramKind::Rtp
        }
    } else {
        DatagramKind::Unknown
    }
}

fn is_stun(packet: &[u8]) -> bool {
    classify_datagram(packet) == DatagramKind::Stun
}

fn is_dtls(packet: &[u8]) -> bool {
    classify_datagram(packet) == DatagramKind::Dtls
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Instant,
    };

    use refract_core::RoomId;
    use refract_router::{
        BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, Subscription,
    };
    use refract_rtc::{RtcConfig, RtcSession};
    use refract_slab::assert_no_alloc;

    use super::*;

    #[cfg(feature = "alloc-track")]
    const HOT_PATH_SOAK_BATCHES: u16 = 8_192;

    fn tuple(port: u16) -> FiveTuple {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        FiveTuple::new(local, remote, IpProtocol::Udp)
    }

    fn rtp(ssrc: u32, sequence: u16) -> [u8; 16] {
        let mut packet = [0_u8; 16];
        packet[..RTP_FIXED_HEADER_LEN].copy_from_slice(&[
            RTP_VERSION << RTP_VERSION_SHIFT,
            96,
            0,
            0,
            0,
            0,
            0,
            9,
            0,
            0,
            0,
            0,
        ]);
        packet[RTP_SEQUENCE_OFFSET..RTP_SEQUENCE_OFFSET + 2]
            .copy_from_slice(&sequence.to_be_bytes());
        packet[RTP_SSRC_OFFSET..RTP_SSRC_OFFSET + 4].copy_from_slice(&ssrc.to_be_bytes());
        packet[12..].copy_from_slice(&[1, 2, 3, 4]);
        packet
    }

    fn rtcp() -> [u8; 16] {
        let mut packet = rtp(42, 1);
        packet[1] = 72;
        packet
    }

    #[cfg(feature = "alloc-track")]
    fn audio_rtp(ssrc: u32, sequence: u16) -> [u8; 16] {
        let mut packet = rtp(ssrc, sequence);
        packet[1] = 111;
        packet
    }

    fn subscribed_core() -> SfuResult<SfuCore> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 4)?.with_outbox_depth(8)?)?;
        core.register_plain_peer(
            PeerId::from_raw(1),
            tuple(6_001),
            SubscriberSessionId::new(1),
        )?;
        core.register_plain_peer(
            PeerId::from_raw(2),
            tuple(6_002),
            SubscriberSessionId::new(2),
        )?;
        let subscription = Subscription::new(
            PublisherTrackId::new(1),
            SubscriberSessionId::new(2),
            IngressSsrc::new(42),
            vec![Layer::new(
                LayerId::new(0),
                BandwidthBps::new(100_000),
                QualityScore::new(1),
            )?],
        )?;
        core.add_subscription(subscription)?;
        Ok(core)
    }

    fn two_route_core() -> SfuResult<SfuCore> {
        let mut core = subscribed_core()?;
        core.register_plain_peer(
            PeerId::from_raw(3),
            tuple(6_003),
            SubscriberSessionId::new(3),
        )?;
        let subscription = Subscription::new(
            PublisherTrackId::new(2),
            SubscriberSessionId::new(3),
            IngressSsrc::new(42),
            vec![Layer::new(
                LayerId::new(0),
                BandwidthBps::new(100_000),
                QualityScore::new(1),
            )?],
        )?;
        core.add_subscription(subscription)?;
        Ok(core)
    }

    #[test]
    fn two_synthetic_peers_forward_byte_for_byte() -> SfuResult<()> {
        let mut core = subscribed_core()?;
        let packet = rtp(42, 1);
        let batch = [IngressPacket::new(tuple(6_001), &packet)];

        core.process_synthetic_batch(&batch, Duration::ZERO)?;

        let mut delivered = [DeliveredPacket::empty()];
        let count = core.take_delivered(PeerId::from_raw(2), &mut delivered)?;
        assert_eq!(count, 1);
        assert_eq!(delivered[0].payload(), packet);
        assert_eq!(core.stats().forwarded_packets, 1);
        Ok(())
    }

    #[test]
    fn one_thousand_simulated_peers_register_on_one_core() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 1_000)?)?;
        for index in 0_u16..1_000 {
            core.register_plain_peer(
                PeerId::from_raw(u64::from(index) + 1),
                tuple(10_000 + index),
                SubscriberSessionId::new(u64::from(index) + 1),
            )?;
        }
        assert_eq!(core.peers.len(), 1_000);
        assert_eq!(core.stats().dropped_packets, 0);
        Ok(())
    }

    #[test]
    fn ten_thousand_peer_core_baseline_sustains_forwarding() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 10_000)?.with_outbox_depth(1)?)?;
        for index in 0_u16..10_000 {
            core.register_plain_peer(
                PeerId::from_raw(u64::from(index) + 1),
                tuple(20_000 + index),
                SubscriberSessionId::new(u64::from(index) + 1),
            )?;
        }
        let subscription = Subscription::new(
            PublisherTrackId::new(1),
            SubscriberSessionId::new(2),
            IngressSsrc::new(42),
            vec![Layer::new(
                LayerId::new(0),
                BandwidthBps::new(100_000),
                QualityScore::new(1),
            )?],
        )?;
        core.add_subscription(subscription)?;
        let packet = rtp(42, 1);

        core.process_synthetic_batch(
            &[IngressPacket::new(tuple(20_000), &packet)],
            Duration::from_millis(1),
        )?;

        let mut delivered = [DeliveredPacket::empty()];
        assert_eq!(core.take_delivered(PeerId::from_raw(2), &mut delivered)?, 1);
        assert_eq!(delivered[0].payload(), packet);
        assert_eq!(core.peers.len(), 10_000);
        Ok(())
    }

    #[test]
    fn panic_injection_tears_down_only_malicious_peer() -> SfuResult<()> {
        let mut core = subscribed_core()?;
        let malicious = PeerId::from_raw(1);
        let benign = PeerId::from_raw(2);
        core.peers
            .get_mut(&malicious)
            .ok_or(SfuError::UnknownPeer)?
            .panic_next_packet = true;
        let packet = rtp(42, 1);
        let batch = [IngressPacket::new(tuple(6_001), &packet)];

        core.process_synthetic_batch(&batch, Duration::ZERO)?;

        assert!(!core.peers.contains_key(&malicious));
        assert!(core.peers.contains_key(&benign));
        assert_eq!(core.stats().isolated_peer_panics, 1);
        Ok(())
    }

    #[test]
    fn allocation_test_wraps_hot_loop_after_warmup() -> SfuResult<()> {
        let mut core = subscribed_core()?;
        let warmup = rtp(42, 0);
        core.process_synthetic_batch(&[IngressPacket::new(tuple(6_001), &warmup)], Duration::ZERO)?;
        let mut drain = [DeliveredPacket::empty()];
        let _count = core.take_delivered(PeerId::from_raw(2), &mut drain)?;

        let packet = rtp(42, 1);
        let batch = [IngressPacket::new(tuple(6_001), &packet)];
        assert_no_alloc!(|| core.process_synthetic_batch(&batch, Duration::from_millis(1)))?;
        Ok(())
    }

    #[test]
    fn allocation_test_wraps_per_route_fanout_after_warmup() -> SfuResult<()> {
        let mut core = two_route_core()?;
        let warmup = rtp(42, 0);
        core.process_synthetic_batch(&[IngressPacket::new(tuple(6_001), &warmup)], Duration::ZERO)?;
        let mut drain = [DeliveredPacket::empty()];
        let _first = core.take_delivered(PeerId::from_raw(2), &mut drain)?;
        let _second = core.take_delivered(PeerId::from_raw(3), &mut drain)?;

        let packet = rtp(42, 1);
        let batch = [IngressPacket::new(tuple(6_001), &packet)];
        assert_no_alloc!(|| core.process_synthetic_batch(&batch, Duration::from_millis(1)))?;

        assert_eq!(core.take_delivered(PeerId::from_raw(2), &mut drain)?, 1);
        assert_eq!(core.take_delivered(PeerId::from_raw(3), &mut drain)?, 1);
        Ok(())
    }

    #[cfg(feature = "alloc-track")]
    #[test]
    fn allocation_soak_wraps_per_route_fanout_after_warmup() -> SfuResult<()> {
        let mut core = two_route_core()?;
        let warmup = audio_rtp(42, 0);
        core.process_synthetic_batch(&[IngressPacket::new(tuple(6_001), &warmup)], Duration::ZERO)?;
        let mut drain = [DeliveredPacket::empty()];
        let _first = core.take_delivered(PeerId::from_raw(2), &mut drain)?;
        let _second = core.take_delivered(PeerId::from_raw(3), &mut drain)?;

        assert_no_alloc!(|| {
            (1..HOT_PATH_SOAK_BATCHES).try_for_each(|sequence| {
                let packet = audio_rtp(42, sequence);
                let batch = [IngressPacket::new(tuple(6_001), &packet)];
                core.process_synthetic_batch(&batch, Duration::from_millis(1))?;
                let _first = core.take_delivered(PeerId::from_raw(2), &mut drain)?;
                let _second = core.take_delivered(PeerId::from_raw(3), &mut drain)?;
                Ok::<(), SfuError>(())
            })
        })?;
        Ok(())
    }

    #[test]
    fn cross_core_fanout_prefers_rehome_with_twenty_ms_bound() -> SfuResult<()> {
        let core = SfuCore::new(SfuConfig::new(CoreId::new(0), 4)?)?;
        let decision = core.cross_core_decision(
            PeerId::from_raw(1),
            CoreId::new(0),
            PeerId::from_raw(2),
            CoreId::new(1),
        );
        assert_eq!(
            decision,
            MigrationDecision::Rehome {
                peer: PeerId::from_raw(2),
                max_blip: MAX_MIGRATION_BLIP,
            }
        );
        Ok(())
    }

    #[test]
    fn protocol_classification_is_bounded() {
        let mut stun = [0_u8; 20];
        stun[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        assert!(is_stun(&stun));
        let dtls = [22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(classify_datagram(&stun), DatagramKind::Stun);
        assert_eq!(classify_datagram(&dtls), DatagramKind::Dtls);
        assert_eq!(classify_datagram(&rtp(42, 1)), DatagramKind::Rtp);
        assert_eq!(classify_datagram(&rtcp()), DatagramKind::Rtcp);
        assert_eq!(classify_datagram(&[]), DatagramKind::Unknown);
        assert!(is_dtls(&dtls));
        assert!(!is_dtls(&rtp(42, 1)));
    }

    #[test]
    fn rtc_sessions_register_without_hot_path_locks() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let session = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;

        core.register_rtc_session(SessionId::from_raw(1), session)?;

        assert_eq!(core.rtc_session_count(), 1);
        assert!(core.remove_rtc_session(SessionId::from_raw(1)).is_some());
        assert_eq!(core.rtc_session_count(), 0);
        Ok(())
    }

    #[test]
    fn rtc_session_removal_clears_ambiguous_remote_owner() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.record_rtc_remote(source, first_id);
        core.record_rtc_remote(source, second_id);
        core.rtc_ssrc.insert(123_456, first_id);
        core.rtc_source_ssrc
            .insert(RtcSsrcKey::new(source, 123_456), first_id);
        core.rtc_blocked_source_ssrc
            .insert(RtcSsrcKey::new(source, 654_321));
        core.rtc_rtp_decrypt_misses
            .insert(RtcSsrcKey::new(source, 654_321), 1);

        assert_eq!(core.rtc_remote.get(&source), Some(&RtcRemoteOwner::Shared));
        assert!(core.remove_rtc_session(first_id).is_some());

        assert!(!core.rtc_remote.contains_key(&source));
        assert!(!core.rtc_ssrc.contains_key(&123_456));
        assert!(
            !core
                .rtc_source_ssrc
                .contains_key(&RtcSsrcKey::new(source, 123_456))
        );
        assert!(core.rtc_blocked_source_ssrc.is_empty());
        assert!(core.rtc_rtp_decrypt_misses.is_empty());
        Ok(())
    }

    #[test]
    fn rtc_demux_uses_learned_remote_mapping_for_rtcp() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.rtc_remote
            .insert(source, RtcRemoteOwner::Unique(second_id));

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtcp()),
            Some(second_id)
        );
        Ok(())
    }

    #[test]
    fn rtc_demux_routes_unknown_rtp_for_unique_remote() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.rtc_remote
            .insert(source, RtcRemoteOwner::Unique(second_id));

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(42, 1)),
            Some(second_id)
        );
        Ok(())
    }

    #[test]
    fn rtc_demux_prefers_unique_remote_over_announced_rtp_ssrc() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.rtc_remote
            .insert(source, RtcRemoteOwner::Unique(first_id));
        core.register_rtc_offer_ssrcs(
            second_id,
            "v=0\r\na=ssrc:123456 cname:camera\r\na=ssrc:123456 msid:stream track\r\n",
        );

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(123_456, 1)),
            Some(first_id)
        );
        Ok(())
    }

    #[test]
    fn rtc_demux_accepts_announced_rtp_ssrc_for_shared_remote() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.record_rtc_remote(source, first_id);
        core.record_rtc_remote(source, second_id);
        core.register_rtc_offer_ssrcs(
            second_id,
            "v=0\r\na=ssrc:123456 cname:camera\r\na=ssrc:123456 msid:stream track\r\n",
        );

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(123_456, 1)),
            Some(second_id)
        );
        Ok(())
    }

    #[test]
    fn rtc_demux_prefers_source_scoped_rtp_ssrc_for_shared_remote() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.record_rtc_remote(source, first_id);
        core.record_rtc_remote(source, second_id);
        core.rtc_ssrc.insert(123_456, first_id);
        core.rtc_source_ssrc
            .insert(RtcSsrcKey::new(source, 123_456), second_id);

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(123_456, 1)),
            Some(second_id)
        );
        Ok(())
    }

    #[test]
    fn rtc_demux_blocks_quarantined_source_scoped_rtp_ssrc() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let session = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let session_id = SessionId::from_raw(1);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(session_id, session)?;
        core.rtc_remote
            .insert(source, RtcRemoteOwner::Unique(session_id));
        core.rtc_blocked_source_ssrc
            .insert(RtcSsrcKey::new(source, 123_456));

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(123_456, 1)),
            None
        );
        Ok(())
    }

    #[test]
    fn rtc_decrypt_misses_quarantine_source_scoped_rtp_ssrc() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let session_id = SessionId::from_raw(1);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let key = RtcSsrcKey::new(source, 123_456);

        for _miss in 0..MAX_RTC_RTP_DECRYPT_MISSES {
            core.record_rtc_rtp_decrypt_miss(key);
        }

        assert!(core.rtc_blocked_source_ssrc.contains(&key));
        assert!(!core.rtc_rtp_decrypt_misses.contains_key(&key));

        core.record_rtc_rtp_decrypt_success(key, session_id);

        assert_eq!(core.rtc_source_ssrc.get(&key), Some(&session_id));
        assert!(!core.rtc_blocked_source_ssrc.contains(&key));
        Ok(())
    }

    #[test]
    fn rtc_demux_rejects_rtp_ssrc_without_learned_remote() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let session_id = SessionId::from_raw(1);
        let session = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(session_id, session)?;
        core.register_rtc_offer_ssrcs(
            session_id,
            "v=0\r\na=ssrc:123456 cname:camera\r\na=ssrc:123456 msid:stream track\r\n",
        );

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(123_456, 1)),
            None
        );
        Ok(())
    }

    #[test]
    fn rtc_demux_does_not_probe_sessions_for_unknown_rtp() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let session = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        core.register_rtc_session(SessionId::from_raw(1), session)?;

        assert_eq!(
            core.rtc_session_for_datagram(
                Instant::now(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000),
                &rtp(123_456, 1),
            ),
            None
        );
        assert!(!should_probe_rtc_sessions(DatagramKind::Rtp));
        assert!(!should_probe_rtc_sessions(DatagramKind::Rtcp));
        assert!(should_probe_rtc_sessions(DatagramKind::Stun));
        assert!(should_probe_rtc_sessions(DatagramKind::Dtls));
        Ok(())
    }

    #[test]
    fn rtc_demux_does_not_route_unknown_rtp_for_shared_remote() -> SfuResult<()> {
        let mut core = SfuCore::new(SfuConfig::new(CoreId::new(0), 2)?)?;
        let first = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let second = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(2), RoomId::from_raw(1)),
            Instant::now(),
        )?;
        let first_id = SessionId::from_raw(1);
        let second_id = SessionId::from_raw(2);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        core.register_rtc_session(first_id, first)?;
        core.register_rtc_session(second_id, second)?;
        core.record_rtc_remote(source, first_id);
        core.record_rtc_remote(source, second_id);

        assert_eq!(
            core.rtc_session_for_datagram(Instant::now(), source, destination, &rtp(123_456, 1)),
            None
        );
        Ok(())
    }

    #[test]
    fn sdp_ssrc_parser_ignores_non_ssrc_lines() {
        assert_eq!(parse_sdp_ssrc("a=ssrc:789 cname:camera"), Some(789));
        assert_eq!(parse_sdp_ssrc("a=ssrc-group:FID 1 2"), None);
        assert_eq!(parse_sdp_ssrc("m=video 9 UDP/TLS/RTP/SAVPF 96"), None);
    }

    #[test]
    fn sendable_destination_rejects_unspecified_or_zero_port() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        assert!(!is_sendable_destination(
            local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_000)
        ));
        assert!(!is_sendable_destination(
            local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        ));
        assert!(!is_sendable_destination(local, local));
        assert!(is_sendable_destination(
            local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_001)
        ));
    }
}
