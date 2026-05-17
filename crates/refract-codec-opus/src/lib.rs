//! Opus RTP payload parsing for RFC 7587.
//!
//! The parser validates the TOC byte and frame-packing code without allocating.
//! It also exposes RFC 6464 audio-level parsing and bounded `fmtp` parameters.
//!
//! # Examples
//!
//! ```
//! use refract_codec_opus::{OpusCodec, parse};
//! use refract_core::Codec;
//!
//! let payload = [0x78, 0x55];
//! let packet = parse(&payload)?;
//! assert!(packet.is_keyframe());
//! assert!(OpusCodec.parse(&payload).is_ok());
//! # Ok::<(), refract_codec_opus::OpusError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use core::fmt;

use refract_core::{Codec, CodecKind, CodecPacket, Error as CoreError, Result as CoreResult};
use thiserror::Error;

/// Opus codec implementation for the shared core [`Codec`] trait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpusCodec;

/// Parsed Opus RTP payload metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpusPacket {
    toc: OpusToc,
    frame_count: u8,
    dtx: bool,
}

/// Parsed Opus TOC byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpusToc {
    config: u8,
    stereo: bool,
    frame_code: u8,
}

/// Parsed RFC 6464 audio-level extension value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioLevel {
    voice_activity: bool,
    level: u8,
}

/// Bounded Opus FMTP parameters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpusFmtp {
    max_playback_rate: Option<u32>,
    stereo: Option<bool>,
    useinbandfec: Option<bool>,
    usedtx: Option<bool>,
    cbr: Option<bool>,
}

/// Opus parser errors with stable operator-facing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OpusError {
    /// Payload is empty and therefore has no TOC byte.
    #[error("opus payload is empty")]
    EmptyPayload,
    /// Code 1 frame packing requires an even byte count after the TOC.
    #[error("opus code 1 payload has odd frame bytes: len={len}")]
    OddCodeOneFrameBytes {
        /// Number of frame bytes after the TOC.
        len: usize,
    },
    /// Code 2 frame packing is missing the second frame length byte.
    #[error("opus code 2 payload is truncated")]
    TruncatedCodeTwo,
    /// Code 2 first frame length exceeds the remaining payload.
    #[error("opus code 2 first frame exceeds payload: first={first} remaining={remaining}")]
    CodeTwoFrameTooLarge {
        /// First frame byte length.
        first: usize,
        /// Remaining bytes after the length byte.
        remaining: usize,
    },
    /// Code 3 frame packing has no count byte.
    #[error("opus code 3 payload is truncated")]
    TruncatedCodeThree,
    /// Code 3 declares zero frames.
    #[error("opus code 3 declares zero frames")]
    ZeroCodeThreeFrames,
    /// Code 3 declares a frame count that cannot fit in the payload.
    #[error("opus code 3 frame count exceeds payload: frames={frames} remaining={remaining}")]
    CodeThreeFrameCountTooLarge {
        /// Declared frame count.
        frames: u8,
        /// Remaining payload bytes after the count byte.
        remaining: usize,
    },
    /// FMTP parameter is malformed.
    #[error("opus fmtp parameter is malformed")]
    MalformedFmtp,
    /// Audio level extension has the wrong length.
    #[error("opus audio-level extension length is invalid: len={len}")]
    InvalidAudioLevelLength {
        /// Extension value length.
        len: usize,
    },
}

impl OpusError {
    /// Returns the stable error code for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_codec_opus::OpusError;
    ///
    /// assert_eq!(OpusError::EmptyPayload.error_code(), "OPUS_PARSE_0001");
    /// ```
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::EmptyPayload => "OPUS_PARSE_0001",
            Self::OddCodeOneFrameBytes { .. } => "OPUS_PARSE_0002",
            Self::TruncatedCodeTwo => "OPUS_PARSE_0003",
            Self::CodeTwoFrameTooLarge { .. } => "OPUS_PARSE_0004",
            Self::TruncatedCodeThree => "OPUS_PARSE_0005",
            Self::ZeroCodeThreeFrames => "OPUS_PARSE_0006",
            Self::CodeThreeFrameCountTooLarge { .. } => "OPUS_PARSE_0007",
            Self::MalformedFmtp => "OPUS_PARSE_0008",
            Self::InvalidAudioLevelLength { .. } => "OPUS_PARSE_0009",
        }
    }
}

impl From<OpusError> for CoreError {
    fn from(value: OpusError) -> Self {
        Self::Parse {
            context: "opus",
            message: value.error_code(),
        }
    }
}

impl Codec for OpusCodec {
    fn kind(&self) -> CodecKind {
        CodecKind::Opus
    }

    fn parse(&self, payload: &[u8]) -> CoreResult<CodecPacket> {
        parse(payload)
            .map(|packet| CodecPacket::new(CodecKind::Opus, packet.is_keyframe(), None))
            .map_err(CoreError::from)
    }
}

/// Parses one Opus RTP payload.
///
/// # Errors
///
/// Returns an error when the payload is empty or its frame-packing fields are
/// truncated or inconsistent with the remaining payload length.
///
/// # Examples
///
/// ```
/// use refract_codec_opus::parse;
///
/// assert_eq!(parse(&[0x78, 0xaa])?.frame_count(), 1);
/// # Ok::<(), refract_codec_opus::OpusError>(())
/// ```
pub fn parse(payload: &[u8]) -> Result<OpusPacket, OpusError> {
    let Some((&toc_byte, body)) = payload.split_first() else {
        let error = OpusError::EmptyPayload;
        record_parse_error(error);
        return Err(error);
    };
    let toc = OpusToc::new(toc_byte);
    let frame_count = match toc.frame_code() {
        0 => 1,
        1 => parse_code_one(body)?,
        2 => parse_code_two(body)?,
        _ => parse_code_three(body)?,
    };
    let packet = OpusPacket {
        toc,
        frame_count,
        dtx: payload.len() <= 2 && toc.config() == 0,
    };
    if packet.is_keyframe() {
        metrics::counter!("refract.codec.opus.keyframes").increment(1);
    }
    Ok(packet)
}

/// Parses an RFC 6464 one-byte audio-level extension value.
///
/// # Errors
///
/// Returns an error unless `value` contains exactly one byte.
///
/// # Examples
///
/// ```
/// use refract_codec_opus::parse_audio_level;
///
/// let level = parse_audio_level(&[0b1000_1010])?;
/// assert!(level.voice_activity());
/// assert_eq!(level.level(), 10);
/// # Ok::<(), refract_codec_opus::OpusError>(())
/// ```
pub fn parse_audio_level(value: &[u8]) -> Result<AudioLevel, OpusError> {
    if value.len() != 1 {
        let error = OpusError::InvalidAudioLevelLength { len: value.len() };
        record_parse_error(error);
        return Err(error);
    }
    Ok(AudioLevel {
        voice_activity: value[0] & 0x80 == 0x80,
        level: value[0] & 0x7f,
    })
}

/// Parses semicolon-separated Opus FMTP parameters.
///
/// # Errors
///
/// Returns an error when a parameter lacks `=` or an integer/boolean value is
/// outside the accepted grammar.
///
/// # Examples
///
/// ```
/// use refract_codec_opus::parse_fmtp;
///
/// let fmtp = parse_fmtp("stereo=1;usedtx=0;maxplaybackrate=48000")?;
/// assert_eq!(fmtp.stereo(), Some(true));
/// # Ok::<(), refract_codec_opus::OpusError>(())
/// ```
pub fn parse_fmtp(source: &str) -> Result<OpusFmtp, OpusError> {
    let mut fmtp = OpusFmtp::default();
    for part in source
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some((key, value)) = part.split_once('=') else {
            return Err(OpusError::MalformedFmtp);
        };
        match key {
            "maxplaybackrate" => {
                fmtp.max_playback_rate = Some(parse_u32(value)?);
            }
            "stereo" => fmtp.stereo = Some(parse_bool(value)?),
            "useinbandfec" => fmtp.useinbandfec = Some(parse_bool(value)?),
            "usedtx" => fmtp.usedtx = Some(parse_bool(value)?),
            "cbr" => fmtp.cbr = Some(parse_bool(value)?),
            _ => {}
        }
    }
    Ok(fmtp)
}

impl OpusPacket {
    /// Returns the parsed TOC byte.
    #[must_use]
    pub const fn toc(self) -> OpusToc {
        self.toc
    }

    /// Returns the validated Opus frame count.
    #[must_use]
    pub const fn frame_count(self) -> u8 {
        self.frame_count
    }

    /// Returns whether the packet is classified as DTX comfort-noise style.
    #[must_use]
    pub const fn is_dtx(self) -> bool {
        self.dtx
    }

    /// Returns whether the packet is a keyframe. Opus is always keyframe-like.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        true
    }
}

impl OpusToc {
    /// Parses an Opus TOC byte.
    #[must_use]
    pub const fn new(byte: u8) -> Self {
        Self {
            config: byte >> 3,
            stereo: byte & 0x04 == 0x04,
            frame_code: byte & 0x03,
        }
    }

    /// Returns the five-bit Opus configuration number.
    #[must_use]
    pub const fn config(self) -> u8 {
        self.config
    }

    /// Returns whether the TOC signals stereo.
    #[must_use]
    pub const fn stereo(self) -> bool {
        self.stereo
    }

    /// Returns the two-bit frame packing code.
    #[must_use]
    pub const fn frame_code(self) -> u8 {
        self.frame_code
    }
}

impl AudioLevel {
    /// Returns whether RFC 6464 voice activity is set.
    #[must_use]
    pub const fn voice_activity(self) -> bool {
        self.voice_activity
    }

    /// Returns the seven-bit audio level.
    #[must_use]
    pub const fn level(self) -> u8 {
        self.level
    }
}

impl OpusFmtp {
    /// Returns `maxplaybackrate`.
    #[must_use]
    pub const fn max_playback_rate(self) -> Option<u32> {
        self.max_playback_rate
    }

    /// Returns `stereo`.
    #[must_use]
    pub const fn stereo(self) -> Option<bool> {
        self.stereo
    }

    /// Returns `useinbandfec`.
    #[must_use]
    pub const fn useinbandfec(self) -> Option<bool> {
        self.useinbandfec
    }

    /// Returns `usedtx`.
    #[must_use]
    pub const fn usedtx(self) -> Option<bool> {
        self.usedtx
    }

    /// Returns `cbr`.
    #[must_use]
    pub const fn cbr(self) -> Option<bool> {
        self.cbr
    }
}

fn parse_code_one(body: &[u8]) -> Result<u8, OpusError> {
    if body.len().is_multiple_of(2) {
        Ok(2)
    } else {
        let error = OpusError::OddCodeOneFrameBytes { len: body.len() };
        record_parse_error(error);
        Err(error)
    }
}

fn parse_code_two(body: &[u8]) -> Result<u8, OpusError> {
    let Some((&first_len, frames)) = body.split_first() else {
        let error = OpusError::TruncatedCodeTwo;
        record_parse_error(error);
        return Err(error);
    };
    let first = usize::from(first_len);
    if first > frames.len() {
        let error = OpusError::CodeTwoFrameTooLarge {
            first,
            remaining: frames.len(),
        };
        record_parse_error(error);
        return Err(error);
    }
    Ok(2)
}

fn parse_code_three(body: &[u8]) -> Result<u8, OpusError> {
    let Some((&count_byte, frames)) = body.split_first() else {
        let error = OpusError::TruncatedCodeThree;
        record_parse_error(error);
        return Err(error);
    };
    let frames_declared = count_byte & 0x3f;
    if frames_declared == 0 {
        let error = OpusError::ZeroCodeThreeFrames;
        record_parse_error(error);
        return Err(error);
    }
    if usize::from(frames_declared) > frames.len().saturating_add(1) {
        let error = OpusError::CodeThreeFrameCountTooLarge {
            frames: frames_declared,
            remaining: frames.len(),
        };
        record_parse_error(error);
        return Err(error);
    }
    Ok(frames_declared)
}

fn parse_bool(value: &str) -> Result<bool, OpusError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(OpusError::MalformedFmtp),
    }
}

fn parse_u32(value: &str) -> Result<u32, OpusError> {
    value
        .parse::<u32>()
        .map_err(|_source| OpusError::MalformedFmtp)
}

fn record_parse_error(error: OpusError) {
    metrics::counter!(
        "refract.codec.opus.parse_errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

impl fmt::Display for OpusPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "opus frames={} config={} stereo={} dtx={}",
            self.frame_count,
            self.toc.config(),
            self.toc.stereo(),
            self.dtx
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toc_and_code_one() {
        let packet = parse(&[0x79, 1, 2, 3, 4]).expect("valid code one");
        assert_eq!(packet.toc().frame_code(), 1);
        assert_eq!(packet.frame_count(), 2);
        assert!(packet.is_keyframe());
    }

    #[test]
    fn rejects_malformed_lengths() {
        assert!(matches!(
            parse(&[0x79, 1]),
            Err(OpusError::OddCodeOneFrameBytes { len: 1 })
        ));
        assert!(matches!(parse(&[0x7a]), Err(OpusError::TruncatedCodeTwo)));
        assert!(matches!(parse(&[0x7b]), Err(OpusError::TruncatedCodeThree)));
    }

    #[test]
    fn parses_fmtp_and_audio_level() {
        let fmtp = parse_fmtp("maxplaybackrate=48000;stereo=1;useinbandfec=1;usedtx=0;cbr=1")
            .expect("valid fmtp");
        assert_eq!(fmtp.max_playback_rate(), Some(48_000));
        assert_eq!(fmtp.stereo(), Some(true));
        assert_eq!(fmtp.usedtx(), Some(false));
        let level = parse_audio_level(&[0x85]).expect("valid audio level");
        assert!(level.voice_activity());
        assert_eq!(level.level(), 5);
    }

    #[test]
    fn implements_core_codec() {
        let packet = OpusCodec.parse(&[0x78, 0]).expect("valid opus");
        assert_eq!(packet.kind(), CodecKind::Opus);
        assert!(packet.is_keyframe());
    }
}
