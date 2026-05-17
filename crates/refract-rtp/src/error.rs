//! Error taxonomy for defensive RTP and RTCP parsing.
//!
//! Every variant has a stable operations-facing error code.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::RtpError;
//! assert_eq!(RtpError::PacketTooShort { len: 2 }.error_code(), "RTP_PARSE_0001");
//! ```

use std::fmt;
use thiserror::Error;

/// Result alias for `refract-rtp` operations.
pub type RtpResult<T> = Result<T, RtpError>;

/// RTP and RTCP parse, validation, and rewrite errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RtpError {
    /// The packet is shorter than the fixed RTP header.
    #[error("rtp packet too short: len={len}")]
    PacketTooShort {
        /// Observed packet length in bytes.
        len: usize,
    },
    /// The RTP version is not two.
    #[error("invalid rtp version: version={version}")]
    InvalidVersion {
        /// Observed RTP version.
        version: u8,
    },
    /// The CSRC list does not fit inside the packet.
    #[error("csrc list exceeds packet: cc={cc} remaining={remaining}")]
    CsrcListTruncated {
        /// CSRC count from the RTP header.
        cc: u8,
        /// Remaining bytes after the fixed header.
        remaining: usize,
    },
    /// The RTP extension header is missing or truncated.
    #[error("extension header truncated: remaining={remaining}")]
    ExtensionHeaderTruncated {
        /// Remaining bytes before reading the extension header.
        remaining: usize,
    },
    /// The RTP extension payload length exceeds the remaining packet bytes.
    #[error("extension payload truncated: words={words} remaining={remaining}")]
    ExtensionPayloadTruncated {
        /// Extension payload length in 32-bit words.
        words: u16,
        /// Remaining bytes after the extension header.
        remaining: usize,
    },
    /// The RTP padding byte is zero when the padding bit is set.
    #[error("zero rtp padding length")]
    ZeroPadding,
    /// The RTP padding length exceeds the bytes after the header.
    #[error("rtp padding exceeds packet: padding={padding} remaining={remaining}")]
    PaddingTooLarge {
        /// Padding byte value.
        padding: usize,
        /// Bytes remaining after the RTP header and extension block.
        remaining: usize,
    },
    /// The packet exceeds the crate's bounded parse size.
    #[error("rtp packet exceeds maximum length: len={len} max={max}")]
    PacketTooLarge {
        /// Observed packet length.
        len: usize,
        /// Maximum accepted packet length.
        max: usize,
    },
    /// An RFC 8285 extension entry is malformed but later entries may still parse.
    #[error("malformed rtp extension entry: id={id} reason={reason}")]
    MalformedExtension {
        /// Extension identifier.
        id: u8,
        /// Stable reason code for the malformed entry.
        reason: ExtensionErrorReason,
    },
    /// A requested rewrite cannot be represented in the existing packet bytes.
    #[error("rtp rewrite cannot fit: needed={needed} available={available}")]
    RewriteNoSpace {
        /// Required bytes.
        needed: usize,
        /// Available bytes.
        available: usize,
    },
    /// A requested RTP rewrite is incompatible with the packet layout.
    #[error("rtp rewrite target is absent: target={target}")]
    RewriteTargetMissing {
        /// Stable target label.
        target: &'static str,
    },
    /// The RTCP packet is shorter than the fixed common header.
    #[error("rtcp packet too short: len={len}")]
    RtcpPacketTooShort {
        /// Observed packet length.
        len: usize,
    },
    /// An RTCP packet length field exceeds the remaining compound packet.
    #[error("rtcp packet length exceeds compound: declared={declared} remaining={remaining}")]
    RtcpLengthTooLarge {
        /// Declared packet length in bytes.
        declared: usize,
        /// Remaining compound bytes.
        remaining: usize,
    },
    /// A compound RTCP packet exceeds the bounded MTU budget.
    #[error("rtcp compound exceeds maximum length: len={len} max={max}")]
    RtcpCompoundTooLarge {
        /// Observed compound length.
        len: usize,
        /// Maximum accepted compound length.
        max: usize,
    },
    /// An RTCP packet type-specific body is malformed.
    #[error("malformed rtcp packet: packet_type={packet_type} reason={reason}")]
    MalformedRtcp {
        /// RTCP packet type number.
        packet_type: u8,
        /// Stable reason code.
        reason: RtcpErrorReason,
    },
}

/// Stable malformed extension reason labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionErrorReason {
    /// One-byte extension ID 15 is reserved by RFC 8285.
    ReservedOneByteId,
    /// The extension entry length exceeds the remaining extension block.
    EntryLengthExceedsBlock,
    /// A known extension was present with an invalid payload length.
    InvalidKnownLength,
    /// The two-byte extension entry omits its payload.
    EmptyTwoByteEntry,
}

impl ExtensionErrorReason {
    /// Returns a stable reason label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::error::ExtensionErrorReason;
    /// assert_eq!(ExtensionErrorReason::InvalidKnownLength.as_str(), "invalid_known_length");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservedOneByteId => "reserved_one_byte_id",
            Self::EntryLengthExceedsBlock => "entry_length_exceeds_block",
            Self::InvalidKnownLength => "invalid_known_length",
            Self::EmptyTwoByteEntry => "empty_two_byte_entry",
        }
    }
}

impl fmt::Display for ExtensionErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable malformed RTCP reason labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RtcpErrorReason {
    /// The packet is shorter than the minimum body for its type.
    BodyTooShort,
    /// The report count does not match the packet body length.
    CountLengthMismatch,
    /// The packet has an unsupported feedback format.
    UnsupportedFeedbackFormat,
    /// The packet has an unsupported payload-specific feedback format.
    UnsupportedPayloadFeedbackFormat,
}

impl RtcpErrorReason {
    /// Returns a stable reason label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::error::RtcpErrorReason;
    /// assert_eq!(RtcpErrorReason::BodyTooShort.as_str(), "body_too_short");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooShort => "body_too_short",
            Self::CountLengthMismatch => "count_length_mismatch",
            Self::UnsupportedFeedbackFormat => "unsupported_feedback_format",
            Self::UnsupportedPayloadFeedbackFormat => "unsupported_payload_feedback_format",
        }
    }
}

impl fmt::Display for RtcpErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RtpError {
    /// Returns the unique stable error code for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::RtpError;
    /// assert_eq!(RtpError::InvalidVersion { version: 1 }.error_code(), "RTP_PARSE_0002");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::PacketTooShort { .. } => "RTP_PARSE_0001",
            Self::InvalidVersion { .. } => "RTP_PARSE_0002",
            Self::CsrcListTruncated { .. } => "RTP_PARSE_0003",
            Self::ExtensionHeaderTruncated { .. } => "RTP_PARSE_0004",
            Self::ExtensionPayloadTruncated { .. } => "RTP_PARSE_0005",
            Self::ZeroPadding => "RTP_PARSE_0006",
            Self::PaddingTooLarge { .. } => "RTP_PARSE_0007",
            Self::PacketTooLarge { .. } => "RTP_PARSE_0008",
            Self::MalformedExtension { .. } => "RTP_EXT_0001",
            Self::RewriteNoSpace { .. } => "RTP_REWRITE_0001",
            Self::RewriteTargetMissing { .. } => "RTP_REWRITE_0002",
            Self::RtcpPacketTooShort { .. } => "RTCP_PARSE_0001",
            Self::RtcpLengthTooLarge { .. } => "RTCP_PARSE_0002",
            Self::RtcpCompoundTooLarge { .. } => "RTCP_PARSE_0003",
            Self::MalformedRtcp { .. } => "RTCP_PARSE_0004",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{RtpError, Stability};
    /// assert_eq!(RtpError::ZeroPadding.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}
