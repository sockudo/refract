//! Media descriptor enums and bounded RTP payload types.

use core::{fmt, str::FromStr};

use strum::{Display, EnumString};

use crate::{Error, Layer, Result, limits};

/// Media section kind.
#[derive(Clone, Copy, Debug, Display, EnumString, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum MediaKind {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Data-channel media.
    Data,
}

/// SDP media direction.
#[derive(Clone, Copy, Debug, Display, EnumString, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum Direction {
    /// Send and receive media.
    SendRecv,
    /// Send media only.
    SendOnly,
    /// Receive media only.
    RecvOnly,
    /// Do not send or receive media.
    Inactive,
}

/// Codec kind used in SDP and RTP payload descriptors.
#[derive(Clone, Copy, Debug, Display, EnumString, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CodecKind {
    /// Opus audio codec.
    #[strum(serialize = "opus", ascii_case_insensitive)]
    Opus,
    /// VP8 video codec.
    #[strum(to_string = "VP8", serialize = "vp8", ascii_case_insensitive)]
    Vp8,
    /// VP9 video codec.
    #[strum(to_string = "VP9", serialize = "vp9", ascii_case_insensitive)]
    Vp9,
    /// AV1 video codec.
    #[strum(to_string = "AV1", serialize = "av1", ascii_case_insensitive)]
    Av1,
    /// H.264 video codec.
    #[strum(to_string = "H264", serialize = "h264", ascii_case_insensitive)]
    H264,
    /// H.265 video codec.
    #[strum(to_string = "H265", serialize = "h265", ascii_case_insensitive)]
    H265,
}

/// Seven-bit RTP payload type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PayloadType(u8);

impl PayloadType {
    /// Creates a payload type after validating the seven-bit RTP bound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] when `value` is larger than the RTP seven-bit
    /// payload type bound.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::PayloadType;
    ///
    /// let payload_type = PayloadType::new(111)?;
    /// assert_eq!(payload_type.get(), 111);
    /// # Ok::<(), refract_core::Error>(())
    /// ```
    pub const fn new(value: u8) -> Result<Self> {
        if value <= limits::PAYLOAD_TYPE_MAX {
            Ok(Self(value))
        } else {
            Err(Error::Parse {
                context: "payload_type",
                message: "payload type exceeds seven-bit bound",
            })
        }
    }

    /// Returns the numeric payload type value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for PayloadType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        value.get()
    }
}

impl fmt::Display for PayloadType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for PayloadType {
    type Err = Error;

    fn from_str(source: &str) -> Result<Self> {
        let value = source.parse::<u8>().map_err(|_source| Error::Parse {
            context: "payload_type",
            message: "payload type is not an unsigned byte",
        })?;

        Self::new(value)
    }
}

/// Validated metadata extracted from one codec RTP payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecPacket {
    kind: CodecKind,
    keyframe: bool,
    layer: Option<Layer>,
}

impl CodecPacket {
    /// Creates codec packet metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::{CodecKind, CodecPacket};
    ///
    /// let packet = CodecPacket::new(CodecKind::Opus, true, None);
    /// assert!(packet.is_keyframe());
    /// ```
    #[must_use]
    pub const fn new(kind: CodecKind, keyframe: bool, layer: Option<Layer>) -> Self {
        Self {
            kind,
            keyframe,
            layer,
        }
    }

    /// Returns the codec kind.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::{CodecKind, CodecPacket};
    ///
    /// assert_eq!(
    ///     CodecPacket::new(CodecKind::Vp8, false, None).kind(),
    ///     CodecKind::Vp8
    /// );
    /// ```
    #[must_use]
    pub const fn kind(self) -> CodecKind {
        self.kind
    }

    /// Returns whether this payload begins or represents a keyframe.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::{CodecKind, CodecPacket};
    ///
    /// assert!(CodecPacket::new(CodecKind::Opus, true, None).is_keyframe());
    /// ```
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        self.keyframe
    }

    /// Returns the spatial/temporal quality layer if the codec exposes one.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::{CodecKind, CodecPacket};
    ///
    /// assert!(
    ///     CodecPacket::new(CodecKind::H264, false, None)
    ///         .layer()
    ///         .is_none()
    /// );
    /// ```
    #[must_use]
    pub const fn layer(self) -> Option<Layer> {
        self.layer
    }
}

/// Common codec RTP payload analysis contract.
pub trait Codec {
    /// Returns the codec kind implemented by this parser.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(codec.kind(), refract_core::CodecKind::Vp8);
    /// ```
    #[must_use]
    fn kind(&self) -> CodecKind;

    /// Parses one RTP payload into validated codec metadata.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] when the payload is empty, truncated, malformed,
    /// or exceeds codec-specific bounded fields.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let packet = codec.parse(payload)?;
    /// assert_eq!(packet.kind(), codec.kind());
    /// # Ok::<(), refract_core::Error>(())
    /// ```
    fn parse(&self, payload: &[u8]) -> Result<CodecPacket>;

    /// Returns whether a payload is a keyframe.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Codec::parse`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let keyframe = codec.is_keyframe(payload)?;
    /// # Ok::<(), refract_core::Error>(())
    /// ```
    fn is_keyframe(&self, payload: &[u8]) -> Result<bool> {
        Ok(self.parse(payload)?.is_keyframe())
    }

    /// Returns the quality layer extracted from a payload, if present.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Codec::parse`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let layer = codec.layer(payload)?;
    /// # Ok::<(), refract_core::Error>(())
    /// ```
    fn layer(&self, payload: &[u8]) -> Result<Option<Layer>> {
        Ok(self.parse(payload)?.layer())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{CodecKind, CodecPacket, Direction, MediaKind, PayloadType};
    use crate::limits;

    #[test]
    fn media_enums_parse_sdp_tokens() {
        assert_eq!(MediaKind::from_str("audio"), Ok(MediaKind::Audio));
        assert_eq!(Direction::from_str("sendrecv"), Ok(Direction::SendRecv));
        assert_eq!(CodecKind::from_str("opus"), Ok(CodecKind::Opus));
        assert_eq!(CodecKind::from_str("VP8"), Ok(CodecKind::Vp8));
    }

    #[test]
    fn media_enums_display_sdp_tokens() {
        assert_eq!(MediaKind::Video.to_string(), "video");
        assert_eq!(Direction::RecvOnly.to_string(), "recvonly");
        assert_eq!(CodecKind::Av1.to_string(), "AV1");
    }

    #[test]
    fn payload_type_accepts_only_u7_values() {
        let payload_type = PayloadType::new(limits::PAYLOAD_TYPE_MAX);

        assert!(matches!(payload_type, Ok(value) if value.get() == limits::PAYLOAD_TYPE_MAX));
        assert!(PayloadType::new(limits::PAYLOAD_TYPE_MAX.saturating_add(1)).is_err());
    }

    #[test]
    fn codec_packet_exposes_metadata() {
        let packet = CodecPacket::new(CodecKind::Vp9, true, None);

        assert_eq!(packet.kind(), CodecKind::Vp9);
        assert!(packet.is_keyframe());
        assert!(packet.layer().is_none());
    }
}
