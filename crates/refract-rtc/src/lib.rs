//! `str0m` sans-IO `WebRTC` integration for refract.
//!
//! `RtcSession` owns the `str0m::Rtc` state machine for ICE, SDP, DTLS timers,
//! and WebRTC events, while media-plane protection is explicitly routed through
//! `refract-srtp`. Construction uses `str0m` RTP mode so the SFU can keep RTP
//! packet ownership outside str0m's frame packetizer.
//!
//! # Examples
//!
//! ```
//! # use std::time::Instant;
//! # use refract_core::{PeerId, RoomId};
//! # use refract_rtc::{RtcConfig, RtcSession};
//! let mut session = RtcSession::new(
//!     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(7)),
//!     Instant::now(),
//! )?;
//! let offer = session.create_offer(&refract_rtc::SUPPORTED_CODECS)?;
//! assert!(offer.as_str().contains("UDP/TLS/RTP/SAVPF"));
//! # Ok::<(), refract_rtc::RtcError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    fmt::{self, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use refract_cc::{PacedPacket, Pacer, PacerConfig, PacketPriority};
use refract_core::{CodecKind, Error as CoreError, PeerId, RoomId, TrackId};
use refract_crypto::{
    SrtpKeys as ExportedSrtpKeys, SrtpProtectionProfile, SrtpProtectionProfile as CryptoProfile,
};
use refract_jitter::{
    JitterConfig, JitterError, LossDetector, NackAggregator, PublisherBuffer, RtpSequenceNumber,
};
use refract_router::{PublisherTrackId, RoutingTable, SubscriberSessionId};
use refract_srtp::{
    Egress, Ingress, SrtpContext, SrtpError, SrtpKeys as MediaSrtpKeys, SrtpProfile,
};
#[doc(hidden)]
pub use str0m::rtp::RtpPacket as Str0mRtpPacket;
use str0m::{
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
    change::SdpOffer,
    crypto::from_feature_flags,
    media::{KeyframeRequestKind as Str0mKeyframeRequestKind, Mid, Rid},
    net::{Receive, Transmit},
    rtp::RtpPacket,
};
use thiserror::Error;
use tracing::{debug, info};

/// `str0m` media identifier used by the RTC adapter.
pub type RtcMid = Mid;

/// `str0m` RTP stream identifier used by the RTC adapter.
pub type RtcRid = Rid;

/// Result alias for `refract-rtc`.
pub type RtcResult<T> = Result<T, RtcError>;

/// Maximum SDP bytes accepted by this crate.
pub const MAX_SDP_BYTES: usize = 16 * 1024;

/// Maximum RTP payload bytes copied through the test media path.
pub const MAX_RTP_BYTES: usize = 2_048;

/// Maximum pending output items retained per session.
pub const MAX_PENDING_OUTPUTS: usize = 128;

/// Maximum ICE candidate bytes accepted from signaling.
pub const MAX_ICE_CANDIDATE_BYTES: usize = 1_024;

const SDP_VERSION_LINE: &str = "v=0";
const RTP_CLOCK_VIDEO: u32 = 90_000;
const RTP_CLOCK_OPUS: u32 = 48_000;
const RTP_PAYLOAD_OPUS: u8 = 111;
const RTP_PAYLOAD_VP8: u8 = 96;
const RTP_PAYLOAD_VP9: u8 = 98;
const RTP_PAYLOAD_AV1: u8 = 100;
const RTP_PAYLOAD_H264: u8 = 102;
const RTP_PAYLOAD_H265: u8 = 104;
const DEFAULT_ICE_UFRAG: &str = "refract";
const DEFAULT_ICE_PWD: &str = "refract-production-ready-password";
const DEFAULT_FINGERPRINT: &str = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";
const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9);

/// Supported Stage 1 codec matrix.
pub const SUPPORTED_CODECS: [CodecKind; 6] = [
    CodecKind::Opus,
    CodecKind::Vp8,
    CodecKind::Vp9,
    CodecKind::Av1,
    CodecKind::H264,
    CodecKind::H265,
];

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
    /// # use refract_rtc::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// SRTP boundary selected for the `str0m` adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SrtpBoundary {
    /// `str0m` handles ICE/DTLS/SDP; `refract-srtp` handles RTP/SRTCP media.
    RefractSrtp,
}

impl SrtpBoundary {
    /// Returns the bounded boundary label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::SrtpBoundary;
    /// assert_eq!(SrtpBoundary::RefractSrtp.as_str(), "refract-srtp");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RefractSrtp => "refract-srtp",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::{SrtpBoundary, Stability};
    /// assert_eq!(SrtpBoundary::RefractSrtp.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// One codec entry in the SDP matrix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CodecSpec {
    kind: CodecKind,
    payload_type: u8,
    clock_rate: u32,
    channels: Option<u8>,
}

impl CodecSpec {
    /// Creates a codec spec from a supported codec kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(CodecSpec::for_kind(CodecKind::Opus).payload_type(), 111);
    /// ```
    #[must_use]
    pub const fn for_kind(kind: CodecKind) -> Self {
        match kind {
            CodecKind::Opus => Self::new(kind, RTP_PAYLOAD_OPUS, RTP_CLOCK_OPUS, Some(2)),
            CodecKind::Vp8 => Self::new(kind, RTP_PAYLOAD_VP8, RTP_CLOCK_VIDEO, None),
            CodecKind::Vp9 => Self::new(kind, RTP_PAYLOAD_VP9, RTP_CLOCK_VIDEO, None),
            CodecKind::Av1 => Self::new(kind, RTP_PAYLOAD_AV1, RTP_CLOCK_VIDEO, None),
            CodecKind::H264 => Self::new(kind, RTP_PAYLOAD_H264, RTP_CLOCK_VIDEO, None),
            CodecKind::H265 => Self::new(kind, RTP_PAYLOAD_H265, RTP_CLOCK_VIDEO, None),
        }
    }

    /// Creates a codec spec.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(
    ///     CodecSpec::new(CodecKind::Vp8, 96, 90_000, None).clock_rate(),
    ///     90_000
    /// );
    /// ```
    #[must_use]
    pub const fn new(
        kind: CodecKind,
        payload_type: u8,
        clock_rate: u32,
        channels: Option<u8>,
    ) -> Self {
        Self {
            kind,
            payload_type,
            clock_rate,
            channels,
        }
    }

    /// Returns the codec kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(CodecSpec::for_kind(CodecKind::Vp9).kind(), CodecKind::Vp9);
    /// ```
    #[must_use]
    pub const fn kind(self) -> CodecKind {
        self.kind
    }

    /// Returns the RTP payload type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(CodecSpec::for_kind(CodecKind::Av1).payload_type(), 100);
    /// ```
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        self.payload_type
    }

    /// Returns the codec RTP clock rate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(CodecSpec::for_kind(CodecKind::H264).clock_rate(), 90_000);
    /// ```
    #[must_use]
    pub const fn clock_rate(self) -> u32 {
        self.clock_rate
    }

    /// Returns the channel count when the codec declares one.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(CodecSpec::for_kind(CodecKind::Opus).channels(), Some(2));
    /// ```
    #[must_use]
    pub const fn channels(self) -> Option<u8> {
        self.channels
    }

    /// Returns the SDP codec token.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::CodecSpec;
    /// assert_eq!(CodecSpec::for_kind(CodecKind::H265).sdp_name(), "H265");
    /// ```
    #[must_use]
    pub const fn sdp_name(self) -> &'static str {
        match self.kind {
            CodecKind::Opus => "opus",
            CodecKind::Vp8 => "VP8",
            CodecKind::Vp9 => "VP9",
            CodecKind::Av1 => "AV1",
            CodecKind::H264 => "H264",
            CodecKind::H265 => "H265",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::{CodecSpec, Stability};
    /// assert_eq!(
    ///     CodecSpec::for_kind(CodecKind::Opus).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Session constructor configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtcConfig {
    peer_id: PeerId,
    room_id: RoomId,
    ice_lite: bool,
    rtp_mode: bool,
    srtp_boundary: SrtpBoundary,
}

impl RtcConfig {
    /// Creates a session configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert!(RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)).ice_lite());
    /// ```
    #[must_use]
    pub const fn new(peer_id: PeerId, room_id: RoomId) -> Self {
        Self {
            peer_id,
            room_id,
            ice_lite: true,
            rtp_mode: true,
            srtp_boundary: SrtpBoundary::RefractSrtp,
        }
    }

    /// Enables or disables ICE-Lite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert!(
    ///     !RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1))
    ///         .with_ice_lite(false)
    ///         .ice_lite()
    /// );
    /// ```
    #[must_use]
    pub const fn with_ice_lite(mut self, enabled: bool) -> Self {
        self.ice_lite = enabled;
        self
    }

    /// Enables or disables str0m RTP mode.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert!(
    ///     !RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1))
    ///         .with_rtp_mode(false)
    ///         .rtp_mode()
    /// );
    /// ```
    #[must_use]
    pub const fn with_rtp_mode(mut self, enabled: bool) -> Self {
        self.rtp_mode = enabled;
        self
    }

    /// Returns the peer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert_eq!(
    ///     RtcConfig::new(PeerId::from_raw(9), RoomId::from_raw(1)).peer_id(),
    ///     PeerId::from_raw(9)
    /// );
    /// ```
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the room identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert_eq!(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(9)).room_id(),
    ///     RoomId::from_raw(9)
    /// );
    /// ```
    #[must_use]
    pub const fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Returns whether ICE-Lite is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert!(RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)).ice_lite());
    /// ```
    #[must_use]
    pub const fn ice_lite(&self) -> bool {
        self.ice_lite
    }

    /// Returns whether str0m RTP mode is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::RtcConfig;
    /// assert!(RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)).rtp_mode());
    /// ```
    #[must_use]
    pub const fn rtp_mode(&self) -> bool {
        self.rtp_mode
    }

    /// Returns the SRTP boundary policy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, SrtpBoundary};
    /// assert_eq!(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)).srtp_boundary(),
    ///     SrtpBoundary::RefractSrtp
    /// );
    /// ```
    #[must_use]
    pub const fn srtp_boundary(&self) -> SrtpBoundary {
        self.srtp_boundary
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, Stability};
    /// assert_eq!(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// SDP document owned by the RTC adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdpDocument {
    role: SdpRole,
    codecs: Vec<CodecSpec>,
    text: String,
    ice_generation: u64,
}

impl SdpDocument {
    /// Creates an SDP offer for the supplied codec matrix.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] if the codec list is empty or the
    /// generated SDP exceeds [`MAX_SDP_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::{SdpDocument, SdpRole};
    /// let sdp = SdpDocument::offer(&[CodecKind::Opus], 0)?;
    /// assert_eq!(sdp.role(), SdpRole::Offer);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn offer(codecs: &[CodecKind], ice_generation: u64) -> RtcResult<Self> {
        Self::build(SdpRole::Offer, codecs, ice_generation)
    }

    /// Creates an SDP answer for the supplied codec matrix.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] if the codec list is empty or the
    /// generated SDP exceeds [`MAX_SDP_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::{SdpDocument, SdpRole};
    /// let sdp = SdpDocument::answer(&[CodecKind::Opus], 0)?;
    /// assert_eq!(sdp.role(), SdpRole::Answer);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn answer(codecs: &[CodecKind], ice_generation: u64) -> RtcResult<Self> {
        Self::build(SdpRole::Answer, codecs, ice_generation)
    }

    /// Parses and validates an SDP document generated by this crate.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] when required SDP fields are absent,
    /// unsupported, or exceed the bounded size.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::SdpDocument;
    /// let sdp = SdpDocument::offer(&[CodecKind::Opus], 0)?;
    /// assert_eq!(SdpDocument::parse(sdp.as_str())?.codecs(), sdp.codecs());
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn parse(text: &str) -> RtcResult<Self> {
        if text.len() > MAX_SDP_BYTES {
            return Err(RtcError::InvalidSdp { field: "len" });
        }
        if !text.lines().any(|line| line == SDP_VERSION_LINE) {
            return Err(RtcError::InvalidSdp { field: "version" });
        }
        if !text.lines().any(|line| line == "a=setup:actpass")
            && !text.lines().any(|line| line == "a=setup:passive")
        {
            return Err(RtcError::InvalidSdp { field: "setup" });
        }
        let role = if text.lines().any(|line| line == "a=setup:actpass") {
            SdpRole::Offer
        } else {
            SdpRole::Answer
        };
        let mut codecs = Vec::new();
        for line in text.lines().filter(|line| line.starts_with("a=rtpmap:")) {
            match parse_rtpmap(line) {
                Ok(spec) => codecs.push(spec),
                Err(RtcError::InvalidSdp { field: "codec" }) => {}
                Err(error) => return Err(error),
            }
        }
        if codecs.is_empty() {
            return Err(RtcError::InvalidSdp { field: "codecs" });
        }
        let ice_generation = parse_ice_generation(text)?;
        Ok(Self {
            role,
            codecs,
            text: text.to_owned(),
            ice_generation,
        })
    }

    /// Returns the SDP role.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::{SdpDocument, SdpRole};
    /// assert_eq!(
    ///     SdpDocument::offer(&[CodecKind::Opus], 1)?.role(),
    ///     SdpRole::Offer
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn role(&self) -> SdpRole {
        self.role
    }

    /// Returns the codec matrix.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::SdpDocument;
    /// assert_eq!(
    ///     SdpDocument::answer(&[CodecKind::Vp8], 1)?.codecs()[0].kind(),
    ///     CodecKind::Vp8
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub fn codecs(&self) -> &[CodecSpec] {
        &self.codecs
    }

    /// Returns the ICE restart generation embedded in the SDP.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::SdpDocument;
    /// assert_eq!(
    ///     SdpDocument::offer(&[CodecKind::Opus], 3)?.ice_generation(),
    ///     3
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn ice_generation(&self) -> u64 {
        self.ice_generation
    }

    /// Returns SDP text.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::SdpDocument;
    /// assert!(
    ///     SdpDocument::offer(&[CodecKind::Opus], 0)?
    ///         .as_str()
    ///         .contains("m=audio")
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::CodecKind;
    /// # use refract_rtc::{SdpDocument, Stability};
    /// assert_eq!(
    ///     SdpDocument::offer(&[CodecKind::Opus], 0)?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn build(role: SdpRole, codecs: &[CodecKind], ice_generation: u64) -> RtcResult<Self> {
        if codecs.is_empty() {
            return Err(RtcError::InvalidSdp { field: "codecs" });
        }
        let specs = codecs
            .iter()
            .copied()
            .map(CodecSpec::for_kind)
            .collect::<Vec<_>>();
        let text = render_sdp(role, &specs, ice_generation)?;
        if text.len() > MAX_SDP_BYTES {
            return Err(RtcError::InvalidSdp { field: "len" });
        }
        Ok(Self {
            role,
            codecs: specs,
            text,
            ice_generation,
        })
    }
}

impl fmt::Display for SdpDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// SDP offer/answer role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SdpRole {
    /// SDP offer.
    Offer,
    /// SDP answer.
    Answer,
}

impl SdpRole {
    /// Returns the bounded SDP role label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::SdpRole;
    /// assert_eq!(SdpRole::Answer.as_str(), "answer");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::{SdpRole, Stability};
    /// assert_eq!(SdpRole::Offer.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// ICE restart state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IceRestartState {
    generation: u64,
    pending: bool,
}

impl IceRestartState {
    /// Returns the current restart generation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::IceRestartState;
    /// assert_eq!(IceRestartState::default().generation(), 0);
    /// ```
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns whether a restart is pending connectivity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::IceRestartState;
    /// assert!(!IceRestartState::default().is_pending());
    /// ```
    #[must_use]
    pub const fn is_pending(self) -> bool {
        self.pending
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::{IceRestartState, Stability};
    /// assert_eq!(IceRestartState::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Media packet accepted by the refract SRTP boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRtp {
    len: usize,
    bytes: [u8; MAX_RTP_BYTES],
}

impl ProtectedRtp {
    /// Copies a bounded RTP packet.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::PacketTooLarge`] when `packet` exceeds
    /// [`MAX_RTP_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::ProtectedRtp;
    /// assert_eq!(ProtectedRtp::copy_from(&[1, 2])?.as_slice(), &[1, 2]);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn copy_from(packet: &[u8]) -> RtcResult<Self> {
        if packet.len() > MAX_RTP_BYTES {
            return Err(RtcError::PacketTooLarge {
                len: packet.len(),
                max: MAX_RTP_BYTES,
            });
        }
        let mut bytes = [0; MAX_RTP_BYTES];
        bytes[..packet.len()].copy_from_slice(packet);
        Ok(Self {
            len: packet.len(),
            bytes,
        })
    }

    /// Returns packet bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::ProtectedRtp;
    /// assert_eq!(ProtectedRtp::copy_from(&[9])?.as_slice(), &[9]);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::{ProtectedRtp, Stability};
    /// assert_eq!(
    ///     ProtectedRtp::copy_from(&[9])?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Events normalized by the RTC adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtcEvent {
    /// ICE state changed.
    IceConnectionStateChanged(RtcIceState),
    /// A media frame was emitted by `str0m`.
    MediaData {
        /// Media byte length.
        len: usize,
    },
    /// RTCP feedback was emitted.
    RtcpFeedback {
        /// Bounded feedback kind label.
        kind: &'static str,
    },
    /// A downstream receiver requested a keyframe for one outbound stream.
    KeyframeRequest {
        /// Media section identifier.
        mid: RtcMid,
        /// Optional simulcast stream identifier.
        rid: Option<RtcRid>,
        /// Keyframe request kind.
        kind: RtcKeyframeRequestKind,
    },
    /// `str0m` reported full connection.
    Connected,
}

impl RtcEvent {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::{RtcEvent, RtcIceState, Stability};
    /// assert_eq!(
    ///     RtcEvent::IceConnectionStateChanged(RtcIceState::New).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Keyframe request kind normalized across the RTC adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtcKeyframeRequestKind {
    /// Picture Loss Indication.
    Pli,
    /// Full Intra Request.
    Fir,
}

impl RtcKeyframeRequestKind {
    /// Returns a bounded label for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pli => "pli",
            Self::Fir => "fir",
        }
    }

    const fn from_str0m(value: Str0mKeyframeRequestKind) -> Self {
        match value {
            Str0mKeyframeRequestKind::Pli => Self::Pli,
            Str0mKeyframeRequestKind::Fir => Self::Fir,
        }
    }

    const fn into_str0m(self) -> Str0mKeyframeRequestKind {
        match self {
            Self::Pli => Str0mKeyframeRequestKind::Pli,
            Self::Fir => Str0mKeyframeRequestKind::Fir,
        }
    }
}

/// Adapter-level ICE state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RtcIceState {
    /// New or not yet checking.
    New,
    /// Connectivity checks are in progress.
    Checking,
    /// ICE is connected.
    Connected,
    /// ICE is disconnected.
    Disconnected,
}

impl RtcIceState {
    /// Returns the bounded ICE state label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::RtcIceState;
    /// assert_eq!(RtcIceState::Connected.as_str(), "connected");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Checking => "checking",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::{RtcIceState, Stability};
    /// assert_eq!(RtcIceState::New.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Errors returned by `refract-rtc`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RtcError {
    /// SDP was invalid.
    #[error("invalid sdp: field={field}")]
    InvalidSdp {
        /// Invalid field name.
        field: &'static str,
    },
    /// Packet exceeded the configured bound.
    #[error("packet too large: len={len} max={max}")]
    PacketTooLarge {
        /// Packet length.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// str0m rejected an operation.
    #[error("str0m failed: {0}")]
    Str0m(#[from] str0m::RtcError),
    /// str0m network parsing rejected an input datagram.
    #[error("str0m net failed: {0}")]
    Str0mNet(#[from] str0m::error::NetError),
    /// ICE candidate text was invalid.
    #[error("invalid ice candidate: field={field}")]
    InvalidCandidate {
        /// Invalid field name.
        field: &'static str,
    },
    /// RTP-mode packet forwarding failed.
    #[error("rtp packet write failed: field={field}")]
    PacketWrite {
        /// Invalid field name.
        field: &'static str,
    },
    /// `refract-srtp` rejected packet protection.
    #[error("srtp failed: {0}")]
    Srtp(#[from] SrtpError),
    /// `refract-jitter` rejected packet retention.
    #[error("jitter failed: {0}")]
    Jitter(#[from] JitterError),
    /// `refract-cc` rejected pacing.
    #[error("cc failed: {0}")]
    Cc(#[from] refract_cc::CcError),
    /// `refract-core` rejected a semantic value.
    #[error("core failed: {0}")]
    Core(#[from] CoreError),
    /// Bounded allocation failed.
    #[error("allocation failed: component={component}")]
    Allocation {
        /// Component name.
        component: &'static str,
    },
}

impl RtcError {
    /// Returns the stable operator-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtc::RtcError;
    /// assert_eq!(
    ///     RtcError::InvalidSdp { field: "version" }.error_code(),
    ///     "HSF-RTC-001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidSdp { .. } => "HSF-RTC-001",
            Self::PacketTooLarge { .. } => "HSF-RTC-002",
            Self::Str0m(_) => "HSF-RTC-003",
            Self::Str0mNet(_) => "HSF-RTC-004",
            Self::InvalidCandidate { .. } => "HSF-RTC-005",
            Self::PacketWrite { .. } => "HSF-RTC-006",
            Self::Srtp(_) => "HSF-RTC-007",
            Self::Jitter(_) => "HSF-RTC-008",
            Self::Cc(_) => "HSF-RTC-009",
            Self::Core(_) => "HSF-RTC-010",
            Self::Allocation { .. } => "HSF-RTC-011",
        }
    }
}

/// One WebRTC session on a per-core SFU lane.
pub struct RtcSession {
    rtc: Rtc,
    config: RtcConfig,
    routing: RoutingHandles,
    srtp: Option<PeerSrtp>,
    media: MediaState,
    ice_restart: IceRestartState,
    ice_state: RtcIceState,
    next_timeout: Option<Instant>,
    pending_events: Vec<RtcEvent>,
    pending_transmits: Vec<Transmit>,
    pending_rtp_packets: Vec<RtpPacket>,
}

impl fmt::Debug for RtcSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtcSession")
            .field("peer_id", &self.config.peer_id)
            .field("room_id", &self.config.room_id)
            .field("srtp_boundary", &self.config.srtp_boundary)
            .field("ice_restart", &self.ice_restart)
            .field("ice_state", &self.ice_state)
            .field("routing", &self.routing)
            .finish_non_exhaustive()
    }
}

impl RtcSession {
    /// Creates a `str0m`-backed RTC session.
    ///
    /// # Errors
    ///
    /// Returns an error when bounded warmup allocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert!(session.rtp_mode());
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn new(config: RtcConfig, now: Instant) -> RtcResult<Self> {
        let provider = Arc::new(from_feature_flags());
        let rtc = str0m::RtcConfig::new()
            .set_crypto_provider(provider)
            .set_ice_lite(config.ice_lite)
            .set_rtp_mode(config.rtp_mode)
            .build(now);
        let mut pending_events = Vec::new();
        pending_events
            .try_reserve_exact(MAX_PENDING_OUTPUTS)
            .map_err(|_source| RtcError::Allocation {
                component: "pending_events",
            })?;
        let mut pending_transmits = Vec::new();
        pending_transmits
            .try_reserve_exact(MAX_PENDING_OUTPUTS)
            .map_err(|_source| RtcError::Allocation {
                component: "pending_transmits",
            })?;
        let mut pending_rtp_packets = Vec::new();
        pending_rtp_packets
            .try_reserve_exact(MAX_PENDING_OUTPUTS)
            .map_err(|_source| RtcError::Allocation {
                component: "pending_rtp_packets",
            })?;
        Ok(Self {
            rtc,
            config,
            routing: RoutingHandles::default(),
            srtp: None,
            media: MediaState::new()?,
            ice_restart: IceRestartState::default(),
            ice_state: RtcIceState::New,
            next_timeout: None,
            pending_events,
            pending_transmits,
            pending_rtp_packets,
        })
    }

    /// Returns whether str0m RTP mode is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// assert!(
    ///     RtcSession::new(
    ///         RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///         Instant::now()
    ///     )?
    ///     .rtp_mode()
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn rtp_mode(&self) -> bool {
        self.config.rtp_mode
    }

    /// Returns the peer identifier owned by this RTC session.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(7), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.peer_id(), PeerId::from_raw(7));
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.config.peer_id
    }

    /// Returns the room identifier owned by this RTC session.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(9)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.room_id(), RoomId::from_raw(9));
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn room_id(&self) -> RoomId {
        self.config.room_id
    }

    /// Returns the SRTP boundary policy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession, SrtpBoundary};
    /// assert_eq!(
    ///     RtcSession::new(
    ///         RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///         Instant::now()
    ///     )?
    ///     .srtp_boundary(),
    ///     SrtpBoundary::RefractSrtp
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn srtp_boundary(&self) -> SrtpBoundary {
        self.config.srtp_boundary
    }

    /// Returns mutable access to the wrapped `str0m::Rtc`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let _rtc = session.str0m_rtc_mut();
    /// ```
    #[must_use]
    pub const fn str0m_rtc_mut(&mut self) -> &mut Rtc {
        &mut self.rtc
    }

    /// Installs SRTP state exported by the DTLS layer.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::Srtp`] if `refract-srtp` rejects the key material.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.install_srtp(keys)?;
    /// ```
    pub fn install_srtp(&mut self, keys: &ExportedSrtpKeys) -> RtcResult<()> {
        self.srtp = Some(PeerSrtp::from_exported(keys)?);
        Ok(())
    }

    /// Adds a local UDP host candidate to the wrapped `str0m` session.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidCandidate`] when `str0m` rejects the socket
    /// address as an ICE host candidate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{net::SocketAddr, time::Instant};
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// session.add_local_udp_candidate("127.0.0.1:50000".parse::<SocketAddr>()?)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_local_udp_candidate(&mut self, addr: SocketAddr) -> RtcResult<()> {
        let candidate =
            Candidate::host(addr, "udp").map_err(|_source| RtcError::InvalidCandidate {
                field: "local_host",
            })?;
        self.rtc
            .add_local_candidate(candidate)
            .ok_or(RtcError::InvalidCandidate {
                field: "local_duplicate",
            })?;
        Ok(())
    }

    /// Accepts a browser SDP offer and returns the `str0m` generated answer.
    ///
    /// This is the browser-interoperable SDP path. It uses the remote offer
    /// produced by `RTCPeerConnection.createOffer()`, installs a real host
    /// candidate for the bound media socket, delegates offer validation to
    /// `str0m`, and returns an answer with `str0m` ICE credentials, DTLS
    /// fingerprint, BUNDLE, `rtcp-mux`, and negotiated codecs.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] for oversized or syntactically invalid
    /// offers, [`RtcError::InvalidCandidate`] when `local_addr` cannot be used
    /// as a host candidate, or [`RtcError::Str0m`] when `str0m` rejects the
    /// SDP semantics.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let answer = session.accept_browser_offer(browser_offer, media_addr)?;
    /// ```
    pub fn accept_browser_offer(
        &mut self,
        offer_sdp: &str,
        local_addr: SocketAddr,
    ) -> RtcResult<SdpDocument> {
        if offer_sdp.len() > MAX_SDP_BYTES {
            return Err(RtcError::InvalidSdp { field: "len" });
        }
        self.add_local_udp_candidate(local_addr)?;
        let offer = SdpOffer::from_sdp_string(offer_sdp)
            .map_err(|_source| RtcError::InvalidSdp { field: "offer" })?;
        let answer = self.rtc.sdp_api().accept_offer(offer)?;
        let answer_sdp = answer.to_sdp_string();
        let document = SdpDocument::parse(&answer_sdp)?;
        self.drain_str0m_outputs()?;
        Ok(document)
    }

    /// Adds a trickled remote ICE candidate from signaling.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidCandidate`] when the candidate is empty,
    /// oversized, or malformed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.add_remote_ice_candidate("candidate:1 1 udp ...")?;
    /// ```
    pub fn add_remote_ice_candidate(&mut self, candidate: &str) -> RtcResult<()> {
        if candidate.is_empty() {
            return Err(RtcError::InvalidCandidate { field: "empty" });
        }
        if candidate.len() > MAX_ICE_CANDIDATE_BYTES {
            return Err(RtcError::InvalidCandidate { field: "len" });
        }
        let candidate = candidate
            .strip_prefix("a=")
            .unwrap_or(candidate)
            .trim_end_matches("\r\n")
            .trim_end_matches('\n');
        let candidate = match Candidate::from_sdp_string(candidate) {
            Ok(candidate) => candidate,
            Err(_source) if is_browser_mdns_candidate(candidate) => {
                return self.drain_str0m_outputs();
            }
            Err(_source) => return Err(RtcError::InvalidCandidate { field: "parse" }),
        };
        self.rtc.add_remote_candidate(candidate);
        self.drain_str0m_outputs()
    }

    /// Creates an SDP offer for the supported codec matrix.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] when SDP generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession, SUPPORTED_CODECS};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(
    ///     session.create_offer(&SUPPORTED_CODECS)?.role().as_str(),
    ///     "offer"
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn create_offer(&mut self, codecs: &[CodecKind]) -> RtcResult<SdpDocument> {
        SdpDocument::offer(codecs, self.ice_restart.generation)
    }

    /// Creates an SDP answer for the supported codec matrix.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] when SDP generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession, SUPPORTED_CODECS};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(
    ///     session.create_answer(&SUPPORTED_CODECS)?.role().as_str(),
    ///     "answer"
    /// );
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn create_answer(&mut self, codecs: &[CodecKind]) -> RtcResult<SdpDocument> {
        SdpDocument::answer(codecs, self.ice_restart.generation)
    }

    /// Validates a remote SDP and records the codec matrix.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] when SDP parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession, SUPPORTED_CODECS};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// let offer = session.create_offer(&SUPPORTED_CODECS)?;
    /// session.accept_remote_sdp(offer.as_str())?;
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn accept_remote_sdp(&mut self, sdp: &str) -> RtcResult<SdpDocument> {
        let document = SdpDocument::parse(sdp)?;
        if document.ice_generation > self.ice_restart.generation {
            self.ice_restart.generation = document.ice_generation;
            self.ice_restart.pending = true;
        }
        Ok(document)
    }

    /// Starts an ICE restart and returns an offer with new ICE credentials.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] when SDP generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession, SUPPORTED_CODECS};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// let before = session.ice_restart().generation();
    /// let _offer = session.restart_ice(&SUPPORTED_CODECS)?;
    /// assert_eq!(session.ice_restart().generation(), before + 1);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn restart_ice(&mut self, codecs: &[CodecKind]) -> RtcResult<SdpDocument> {
        self.ice_restart.generation = self.ice_restart.generation.saturating_add(1);
        self.ice_restart.pending = true;
        SdpDocument::offer(codecs, self.ice_restart.generation)
    }

    /// Returns ICE restart state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.ice_restart().generation(), 0);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn ice_restart(&self) -> IceRestartState {
        self.ice_restart
    }

    /// Handles `str0m::Input::Receive` or `str0m::Input::Timeout` and drains
    /// events and transmits.
    ///
    /// This method has no `.await` points. Cancellation safety is therefore
    /// trivial: one call drives a bounded sans-IO step synchronously.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::Str0m`] if `str0m` rejects the input or output poll.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.handle_input(Input::Timeout(Instant::now()))?;
    /// ```
    pub fn handle_input(&mut self, input: Input<'_>) -> RtcResult<()> {
        self.rtc.handle_input(input)?;
        self.drain_str0m_outputs()
    }

    /// Handles a UDP receive by constructing `str0m::Input::Receive`.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::Str0mNet`] if str0m cannot classify the datagram, or
    /// [`RtcError::Str0m`] if the state machine rejects it.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.handle_receive(now, source, destination, packet)?;
    /// ```
    pub fn handle_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        packet: &[u8],
    ) -> RtcResult<()> {
        let receive = Receive::new(str0m::net::Protocol::Udp, source, destination, packet)?;
        self.handle_input(Input::Receive(now, receive))
    }

    /// Handles a deterministic `str0m` timeout.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::Str0m`] if `str0m` rejects the timeout or generated
    /// outputs.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// session.handle_timeout(std::time::Instant::now())?;
    /// ```
    pub fn handle_timeout(&mut self, now: Instant) -> RtcResult<()> {
        self.handle_input(Input::Timeout(now))
    }

    /// Returns whether this session accepts a UDP datagram.
    ///
    /// This wraps `str0m::Rtc::accepts` for per-core SFU demux. Malformed
    /// datagrams return `false` and do not mutate the session.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if session.accepts_receive(now, remote, local, packet) {
    ///     session.handle_receive(now, remote, local, packet)?;
    /// }
    /// ```
    #[must_use]
    pub fn accepts_receive(
        &self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        packet: &[u8],
    ) -> bool {
        Receive::new(str0m::net::Protocol::Udp, source, destination, packet).is_ok_and(|receive| {
            let input = Input::Receive(now, receive);
            self.rtc.accepts(&input)
        })
    }

    /// Handles already-unprotected RTP through the refract media plane.
    ///
    /// # Errors
    ///
    /// Returns an error when packet bounds, SRTP authentication, jitter, or
    /// pacing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::{Duration, Instant};
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// # let mut session = RtcSession::new(RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)), Instant::now())?;
    /// let packet = [0x80, 96, 0, 1, 0, 0, 0, 9, 0, 0, 0, 7];
    /// session.handle_refract_rtp(&packet, Duration::ZERO)?;
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn handle_refract_rtp(&mut self, packet: &[u8], now: Duration) -> RtcResult<()> {
        let protected = ProtectedRtp::copy_from(packet)?;
        self.media
            .ingress_rtp(protected.as_slice(), now, self.srtp.as_mut())
    }

    /// Pops one normalized event.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert!(session.pop_event().is_none());
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn pop_event(&mut self) -> Option<RtcEvent> {
        self.pending_events.pop()
    }

    /// Pops one pending transmit generated by `str0m`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert!(session.pop_transmit().is_none());
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn pop_transmit(&mut self) -> Option<Transmit> {
        self.pending_transmits.pop()
    }

    /// Pops one received RTP-mode packet emitted by `str0m`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let mut session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert!(session.pop_rtp_packet().is_none());
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    pub fn pop_rtp_packet(&mut self) -> Option<RtpPacket> {
        self.pending_rtp_packets.pop()
    }

    /// Returns the number of decrypted RTP-mode packets waiting to be drained.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.pending_rtp_packet_count(), 0);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn pending_rtp_packet_count(&self) -> usize {
        self.pending_rtp_packets.len()
    }

    /// Writes one RTP-mode packet to this session's outgoing `str0m` stream.
    ///
    /// # Errors
    ///
    /// Returns [`RtcError::InvalidSdp`] when the packet cannot be associated with
    /// a negotiated media section, or [`RtcError::PacketWrite`] when `str0m`
    /// rejects the RTP packet.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// subscriber.write_rtp_packet(&publisher_packet)?;
    /// ```
    pub fn write_rtp_packet(&mut self, packet: &RtpPacket) -> RtcResult<()> {
        let header = &packet.header;
        let payload_type = header.payload_type;
        let mid = header
            .ext_vals
            .mid
            .unwrap_or_else(|| mid_for_payload_type(*payload_type));
        if self.rtc.media(mid).is_none() {
            return Err(RtcError::InvalidSdp { field: "mid" });
        }

        let ssrc = header.ssrc;
        let rid = header.ext_vals.rid;
        let mut api = self.rtc.direct_api();
        let has_negotiated_stream = api.stream_tx_by_mid(mid, rid).is_some();
        let stream = if has_negotiated_stream {
            api.stream_tx_by_mid(mid, rid)
        } else {
            if api.stream_tx(&ssrc).is_none() {
                api.declare_stream_tx(ssrc, None, mid, rid);
            }
            api.stream_tx(&ssrc)
        }
        .ok_or(RtcError::PacketWrite { field: "stream_tx" })?;
        stream
            .write_rtp(
                payload_type,
                packet.seq_no,
                header.timestamp,
                packet.timestamp,
                header.marker,
                header.ext_vals.clone(),
                false,
                packet.payload.clone(),
            )
            .map_err(|_source| RtcError::PacketWrite { field: "write_rtp" })?;
        self.drain_str0m_outputs()
    }

    /// Requests a keyframe from an incoming RTP-mode stream.
    ///
    /// Returns `Ok(false)` when this session has not learned a matching
    /// receive stream yet.
    ///
    /// # Errors
    ///
    /// Returns an error when `str0m` rejects generated RTCP feedback.
    pub fn request_keyframe(
        &mut self,
        mid: RtcMid,
        rid: Option<RtcRid>,
        kind: RtcKeyframeRequestKind,
    ) -> RtcResult<bool> {
        let mut api = self.rtc.direct_api();
        let Some(stream) = api.stream_rx_by_mid(mid, rid) else {
            return Ok(false);
        };
        stream.request_keyframe(kind.into_str0m());
        self.drain_str0m_outputs()?;
        Ok(true)
    }

    /// Returns the next `str0m` timeout deadline, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert!(session.next_timeout().is_none());
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn next_timeout(&self) -> Option<Instant> {
        self.next_timeout
    }

    /// Returns the current ICE state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcIceState, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.ice_state(), RtcIceState::New);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn ice_state(&self) -> RtcIceState {
        self.ice_state
    }

    /// Returns the current routing snapshot route count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.route_count(), 0);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routing.table.snapshot().route_count()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Instant;
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_rtc::{RtcConfig, RtcSession, Stability};
    /// let session = RtcSession::new(
    ///     RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(1)),
    ///     Instant::now(),
    /// )?;
    /// assert_eq!(session.stability(), Stability::Stage1);
    /// # Ok::<(), refract_rtc::RtcError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn drain_str0m_outputs(&mut self) -> RtcResult<()> {
        loop {
            match self.rtc.poll_output()? {
                Output::Timeout(deadline) => {
                    self.next_timeout = Some(deadline);
                    return Ok(());
                }
                Output::Transmit(transmit) => {
                    if self.pending_transmits.len() == MAX_PENDING_OUTPUTS {
                        return Err(RtcError::Allocation {
                            component: "pending_transmits",
                        });
                    }
                    self.pending_transmits.push(transmit);
                }
                Output::Event(event) => self.handle_str0m_event(event)?,
            }
        }
    }

    fn handle_str0m_event(&mut self, event: Event) -> RtcResult<()> {
        match event {
            Event::Connected => {
                info!(
                    target: "refract_rtc::dtls",
                    peer_id = ?self.config.peer_id,
                    room_id = ?self.config.room_id,
                    "str0m session Connected (DTLS+SRTP keys installed)"
                );
                self.ice_restart.pending = false;
                self.push_event(RtcEvent::Connected)?;
            }
            Event::IceConnectionStateChange(state) => {
                let state = RtcIceState::from(state);
                info!(
                    target: "refract_rtc::ice",
                    peer_id = ?self.config.peer_id,
                    room_id = ?self.config.room_id,
                    ice_state = ?state,
                    "ICE state changed"
                );
                if state == RtcIceState::Connected {
                    self.ice_restart.pending = false;
                }
                self.ice_state = state;
                self.push_event(RtcEvent::IceConnectionStateChanged(state))?;
            }
            Event::MediaData(data) => {
                self.push_event(RtcEvent::MediaData {
                    len: data.data.len(),
                })?;
            }
            Event::RtpPacket(packet) => {
                debug!(
                    target: "refract_rtc::rtp",
                    peer_id = ?self.config.peer_id,
                    ssrc = ?packet.header.ssrc,
                    seq = ?packet.header.sequence_number,
                    pt = ?packet.header.payload_type,
                    "decrypted RtpPacket from str0m"
                );
                if self.pending_rtp_packets.len() == MAX_PENDING_OUTPUTS {
                    return Err(RtcError::Allocation {
                        component: "pending_rtp_packets",
                    });
                }
                self.pending_rtp_packets.push(packet);
            }
            Event::KeyframeRequest(request) => {
                self.push_event(RtcEvent::KeyframeRequest {
                    mid: request.mid,
                    rid: request.rid,
                    kind: RtcKeyframeRequestKind::from_str0m(request.kind),
                })?;
            }
            Event::SenderFeedback(_feedback) => {
                self.push_event(RtcEvent::RtcpFeedback {
                    kind: "sender_report",
                })?;
            }
            _other => {}
        }
        Ok(())
    }

    fn push_event(&mut self, event: RtcEvent) -> RtcResult<()> {
        if self.pending_events.len() == MAX_PENDING_OUTPUTS {
            return Err(RtcError::Allocation {
                component: "pending_events",
            });
        }
        self.pending_events.push(event);
        Ok(())
    }
}

impl From<IceConnectionState> for RtcIceState {
    fn from(value: IceConnectionState) -> Self {
        match value {
            IceConnectionState::New => Self::New,
            IceConnectionState::Checking => Self::Checking,
            IceConnectionState::Connected | IceConnectionState::Completed => Self::Connected,
            IceConnectionState::Disconnected => Self::Disconnected,
        }
    }
}

fn mid_for_payload_type(payload_type: u8) -> Mid {
    if payload_type == RTP_PAYLOAD_OPUS {
        Mid::from("0")
    } else {
        Mid::from("1")
    }
}

fn is_browser_mdns_candidate(candidate: &str) -> bool {
    let mut parts = candidate.split_whitespace();
    let Some(foundation) = parts
        .next()
        .and_then(|value| value.strip_prefix("candidate:"))
    else {
        return false;
    };
    let Some(component) = parts.next() else {
        return false;
    };
    let Some(protocol) = parts.next() else {
        return false;
    };
    let Some(priority) = parts.next() else {
        return false;
    };
    let Some(address) = parts.next() else {
        return false;
    };
    let Some(port) = parts.next() else {
        return false;
    };
    let Some(type_marker) = parts.next() else {
        return false;
    };
    let Some(kind) = parts.next() else {
        return false;
    };
    !foundation.is_empty()
        && component.parse::<u16>().is_ok()
        && (protocol.eq_ignore_ascii_case("udp") || protocol.eq_ignore_ascii_case("tcp"))
        && priority.parse::<u32>().is_ok()
        && is_mdns_hostname(address)
        && port.parse::<u16>().is_ok()
        && type_marker == "typ"
        && matches!(kind, "host" | "prflx" | "srflx" | "relay")
}

fn is_mdns_hostname(address: &str) -> bool {
    let address = address.strip_suffix('.').unwrap_or(address);
    address.contains('.')
        && address
            .rsplit('.')
            .next()
            .is_some_and(|label| label.eq_ignore_ascii_case("local"))
}

#[derive(Default)]
struct RoutingHandles {
    table: RoutingTable,
    publisher: Option<PublisherTrackId>,
    subscriber: Option<SubscriberSessionId>,
    track: Option<TrackId>,
}

impl fmt::Debug for RoutingHandles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingHandles")
            .field("route_count", &self.table.snapshot().route_count())
            .field("publisher", &self.publisher)
            .field("subscriber", &self.subscriber)
            .field("track", &self.track)
            .finish()
    }
}

#[derive(Debug)]
struct PeerSrtp {
    context: SrtpContext,
}

impl PeerSrtp {
    fn from_exported(keys: &ExportedSrtpKeys) -> RtcResult<Self> {
        Ok(Self {
            context: SrtpContext::new(convert_srtp_keys(keys)?, 64)?,
        })
    }

    const fn ingress(&mut self) -> &mut Ingress {
        &mut self.context.ingress
    }

    const fn egress(&mut self) -> &mut Egress {
        &mut self.context.egress
    }
}

#[derive(Debug)]
struct MediaState {
    jitter: PublisherBuffer,
    loss: LossDetector,
    nacks: NackAggregator,
    pacer: Pacer,
    scratch: Vec<u8>,
}

impl MediaState {
    fn new() -> RtcResult<Self> {
        let jitter = PublisherBuffer::with_config(JitterConfig {
            max_packet_bytes: MAX_RTP_BYTES,
            average_packet_bytes: MAX_RTP_BYTES,
            memory_cap_bytes: MAX_RTP_BYTES * 8,
            ..JitterConfig::default()
        })?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(MAX_RTP_BYTES + 16)
            .map_err(|_source| RtcError::Allocation { component: "media" })?;
        Ok(Self {
            jitter,
            loss: LossDetector::new(),
            nacks: NackAggregator::default(),
            pacer: Pacer::new(PacerConfig::default()),
            scratch,
        })
    }

    fn ingress_rtp(
        &mut self,
        packet: &[u8],
        now: Duration,
        mut srtp: Option<&mut PeerSrtp>,
    ) -> RtcResult<()> {
        self.scratch.clear();
        self.scratch.extend_from_slice(packet);
        let (sequence, len, priority) = {
            let plain = if let Some(peer_srtp) = srtp.as_mut() {
                peer_srtp.ingress().unprotect_rtp(&mut self.scratch)?
            } else {
                self.scratch.as_slice()
            };
            let sequence = if plain.len() >= 4 {
                RtpSequenceNumber::new(u16::from_be_bytes([plain[2], plain[3]]))
            } else {
                return Err(RtcError::PacketTooLarge {
                    len: plain.len(),
                    max: MAX_RTP_BYTES,
                });
            };
            self.jitter.insert(sequence, plain)?;
            (sequence, plain.len(), packet_priority(plain))
        };
        let _nacks = self.loss.observe(sequence, now, &mut self.nacks);
        self.pacer.enqueue(PacedPacket::new(
            u64::from(sequence.as_u16()),
            len,
            priority,
            now,
        ))?;
        if let Some(peer_srtp) = srtp.as_mut() {
            peer_srtp.egress().protect_rtp(&mut self.scratch)?;
        }
        Ok(())
    }
}

fn packet_priority(packet: &[u8]) -> PacketPriority {
    if packet.get(1).copied() == Some(RTP_PAYLOAD_OPUS) {
        PacketPriority::Audio
    } else if packet.get(1).is_some_and(|byte| byte & 0x80 == 0x80) {
        PacketPriority::VideoKeyframe
    } else {
        PacketPriority::VideoDelta
    }
}

fn convert_srtp_keys(keys: &ExportedSrtpKeys) -> RtcResult<MediaSrtpKeys> {
    match keys.profile() {
        CryptoProfile::AeadAes128Gcm => {
            let mut combined_keys = [0; 32];
            combined_keys[..16].copy_from_slice(keys.client_key());
            combined_keys[16..].copy_from_slice(keys.server_key());
            let mut salts = [0; 24];
            salts[..12].copy_from_slice(keys.client_salt());
            salts[12..].copy_from_slice(keys.server_salt());
            Ok(MediaSrtpKeys::new(
                SrtpProfile::AeadAes128Gcm,
                combined_keys,
                salts,
            )?)
        }
        SrtpProtectionProfile::AeadAes256Gcm => {
            let mut combined_keys = [0; 64];
            combined_keys[..32].copy_from_slice(keys.client_key());
            combined_keys[32..].copy_from_slice(keys.server_key());
            let mut salts = [0; 24];
            salts[..12].copy_from_slice(keys.client_salt());
            salts[12..].copy_from_slice(keys.server_salt());
            Ok(MediaSrtpKeys::new(
                SrtpProfile::AeadAes256Gcm,
                combined_keys,
                salts,
            )?)
        }
    }
}

fn render_sdp(role: SdpRole, codecs: &[CodecSpec], ice_generation: u64) -> RtcResult<String> {
    let mut text = String::new();
    let setup = match role {
        SdpRole::Offer => "actpass",
        SdpRole::Answer => "passive",
    };
    text.try_reserve_exact(2048)
        .map_err(|_source| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "v=0").map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "o=- {ice_generation} 2 IN IP4 127.0.0.1")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "s=refract").map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "t=0 0").map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=group:BUNDLE 0 1")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    write_media_section(&mut text, "audio", codecs, ice_generation, setup)?;
    write_media_section(&mut text, "video", codecs, ice_generation, setup)?;
    Ok(text)
}

fn write_media_section(
    text: &mut String,
    kind: &str,
    codecs: &[CodecSpec],
    ice_generation: u64,
    setup: &str,
) -> RtcResult<()> {
    use std::fmt::Write;
    let selected = codecs
        .iter()
        .copied()
        .filter(|codec| (kind == "audio") == (codec.kind == CodecKind::Opus))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(());
    }
    write!(text, "m={kind} 9 UDP/TLS/RTP/SAVPF")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    for codec in &selected {
        write!(text, " {}", codec.payload_type)
            .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    }
    writeln!(text).map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "c=IN IP4 {}", DEFAULT_ADDR.ip())
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=mid:{}", u8::from(kind == "video"))
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=ice-ufrag:{DEFAULT_ICE_UFRAG}{ice_generation}")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=ice-pwd:{DEFAULT_ICE_PWD}{ice_generation}")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=ice-options:trickle")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=fingerprint:sha-256 {DEFAULT_FINGERPRINT}")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=setup:{setup}")
        .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=sendrecv").map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    writeln!(text, "a=rtcp-mux").map_err(|_error| RtcError::Allocation { component: "sdp" })?;
    for codec in selected {
        if let Some(channels) = codec.channels {
            writeln!(
                text,
                "a=rtpmap:{} {}/{}/{}",
                codec.payload_type,
                codec.sdp_name(),
                codec.clock_rate,
                channels
            )
            .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
        } else {
            writeln!(
                text,
                "a=rtpmap:{} {}/{}",
                codec.payload_type,
                codec.sdp_name(),
                codec.clock_rate
            )
            .map_err(|_error| RtcError::Allocation { component: "sdp" })?;
        }
    }
    Ok(())
}

fn parse_rtpmap(line: &str) -> RtcResult<CodecSpec> {
    let Some(rest) = line.strip_prefix("a=rtpmap:") else {
        return Err(RtcError::InvalidSdp { field: "rtpmap" });
    };
    let Some((pt, codec)) = rest.split_once(' ') else {
        return Err(RtcError::InvalidSdp { field: "rtpmap" });
    };
    let payload_type = pt
        .parse::<u8>()
        .map_err(|_source| RtcError::InvalidSdp { field: "payload" })?;
    let mut parts = codec.split('/');
    let Some(name) = parts.next() else {
        return Err(RtcError::InvalidSdp { field: "codec" });
    };
    let Some(clock) = parts.next() else {
        return Err(RtcError::InvalidSdp { field: "clock" });
    };
    let clock_rate = clock
        .parse::<u32>()
        .map_err(|_source| RtcError::InvalidSdp { field: "clock" })?;
    let channels = parts
        .next()
        .map(str::parse::<u8>)
        .transpose()
        .map_err(|_source| RtcError::InvalidSdp { field: "channels" })?;
    let kind = match name.to_ascii_lowercase().as_str() {
        "opus" => CodecKind::Opus,
        "vp8" => CodecKind::Vp8,
        "vp9" => CodecKind::Vp9,
        "av1" => CodecKind::Av1,
        "h264" => CodecKind::H264,
        "h265" => CodecKind::H265,
        _other => return Err(RtcError::InvalidSdp { field: "codec" }),
    };
    Ok(CodecSpec::new(kind, payload_type, clock_rate, channels))
}

fn parse_ice_generation(text: &str) -> RtcResult<u64> {
    let Some(line) = text.lines().find(|line| line.starts_with("a=ice-ufrag:")) else {
        return Err(RtcError::InvalidSdp { field: "ice-ufrag" });
    };
    let value = line.trim_start_matches("a=ice-ufrag:");
    if let Some(generation) = value.strip_prefix(DEFAULT_ICE_UFRAG) {
        return generation
            .parse::<u64>()
            .map_err(|_source| RtcError::InvalidSdp { field: "ice-ufrag" });
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use str0m::{
        Candidate, Rtc as Str0mRtc,
        media::{Direction as Str0mDirection, MediaKind as Str0mMediaKind},
    };

    use super::*;

    fn session() -> RtcResult<RtcSession> {
        RtcSession::new(
            RtcConfig::new(PeerId::from_raw(1), RoomId::from_raw(7)),
            Instant::now(),
        )
    }

    #[test]
    fn sdp_roundtrips_every_codec_combo() -> RtcResult<()> {
        for mask in 1_u8..(1_u8 << SUPPORTED_CODECS.len()) {
            let codecs = SUPPORTED_CODECS
                .iter()
                .enumerate()
                .filter_map(|(index, codec)| ((mask & (1 << index)) != 0).then_some(*codec))
                .collect::<Vec<_>>();
            let offer = SdpDocument::offer(&codecs, 0)?;
            let parsed_offer = SdpDocument::parse(offer.as_str())?;
            assert_eq!(parsed_offer.codecs(), offer.codecs());
            let answer = SdpDocument::answer(&codecs, 0)?;
            let parsed_answer = SdpDocument::parse(answer.as_str())?;
            assert_eq!(parsed_answer.codecs(), answer.codecs());
        }
        Ok(())
    }

    #[test]
    fn ice_restart_preserves_session_and_changes_generation() -> RtcResult<()> {
        let mut session = session()?;
        let original_peer = session.config.peer_id();
        let original_room = session.config.room_id();
        let first = session.create_offer(&SUPPORTED_CODECS)?;

        let restart = session.restart_ice(&SUPPORTED_CODECS)?;

        assert_eq!(session.config.peer_id(), original_peer);
        assert_eq!(session.config.room_id(), original_room);
        assert!(session.ice_restart().is_pending());
        assert_eq!(restart.ice_generation(), first.ice_generation() + 1);
        assert_ne!(
            parse_ice_generation(first.as_str())?,
            parse_ice_generation(restart.as_str())?
        );
        Ok(())
    }

    #[test]
    fn refract_srtp_boundary_is_selected() -> RtcResult<()> {
        let session = session()?;

        assert_eq!(session.srtp_boundary(), SrtpBoundary::RefractSrtp);
        assert!(session.rtp_mode());
        Ok(())
    }

    #[test]
    fn media_path_accepts_plain_rtp_for_pre_srtp_tests() -> RtcResult<()> {
        let mut session = session()?;
        let packet = [0x80, 96, 0, 1, 0, 0, 0, 9, 0, 0, 0, 7];

        session.handle_refract_rtp(&packet, Duration::ZERO)?;

        Ok(())
    }

    #[test]
    fn webrtc_rs_interop_sdp_contract_is_browser_compatible() -> RtcResult<()> {
        let mut session = session()?;
        let offer = session.create_offer(&SUPPORTED_CODECS)?;
        let sdp = offer.as_str();

        assert!(sdp.contains("a=ice-options:trickle"));
        assert!(sdp.contains("a=rtcp-mux"));
        assert!(sdp.contains("a=fingerprint:sha-256"));
        assert!(sdp.contains("UDP/TLS/RTP/SAVPF"));
        Ok(())
    }

    #[test]
    fn str0m_offer_acceptance_returns_real_browser_answer() -> RtcResult<()> {
        let now = Instant::now();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);
        let mut browser = Str0mRtc::new(now);
        let candidate =
            Candidate::host(remote_addr, "udp").map_err(|_source| RtcError::InvalidCandidate {
                field: "test_remote",
            })?;
        browser
            .add_local_candidate(candidate)
            .ok_or(RtcError::InvalidCandidate {
                field: "test_remote",
            })?;
        let mut changes = browser.sdp_api();
        changes.add_media(
            Str0mMediaKind::Audio,
            Str0mDirection::SendRecv,
            None,
            None,
            None,
        );
        changes.add_media(
            Str0mMediaKind::Video,
            Str0mDirection::SendRecv,
            None,
            None,
            None,
        );
        let (offer, _pending) = changes
            .apply()
            .ok_or(RtcError::InvalidSdp { field: "offer" })?;

        let mut session = RtcSession::new(
            RtcConfig::new(PeerId::from_raw(9), RoomId::from_raw(3)),
            now,
        )?;
        let answer = session.accept_browser_offer(&offer.to_sdp_string(), local_addr)?;
        let sdp = answer.as_str();

        assert_eq!(answer.role(), SdpRole::Answer);
        assert!(sdp.contains("a=setup:passive"));
        assert!(sdp.contains("a=rtcp-mux"));
        assert!(sdp.contains("a=fingerprint:sha-256"));
        assert!(!sdp.contains(DEFAULT_FINGERPRINT));
        assert!(!sdp.contains(DEFAULT_ICE_UFRAG));
        Ok(())
    }

    #[test]
    fn trickled_ice_candidate_is_bounded_and_parsed() -> RtcResult<()> {
        let mut session = session()?;

        session.add_remote_ice_candidate(
            "candidate:1 1 udp 1845494015 198.51.100.100 11100 typ host ufrag abc",
        )?;
        session.add_remote_ice_candidate(
            "candidate:2 1 udp 2113937151 d6c6c942-72be-41ec-90c4-2ea25df4c676.local 55102 typ host generation 0 ufrag abc network-cost 999",
        )?;

        assert!(matches!(
            session.add_remote_ice_candidate(""),
            Err(RtcError::InvalidCandidate { field: "empty" })
        ));
        Ok(())
    }

    #[test]
    fn accepts_receive_rejects_malformed_datagram_without_mutation() -> RtcResult<()> {
        let session = session()?;
        let now = Instant::now();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);

        assert!(!session.accepts_receive(now, source, destination, &[]));
        assert_eq!(session.ice_state(), RtcIceState::New);
        Ok(())
    }
}
