//! H.264 RTP payload parsing for RFC 6184.
//!
//! The parser validates single NAL units, STAP-A/B, MTAP16/24, and FU-A/B
//! packetization enough to classify keyframes and cache SPS/PPS parameter sets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use refract_core::{Codec, CodecKind, CodecPacket, Error as CoreError, Result as CoreResult};
use thiserror::Error;

/// H.264 codec implementation for the shared core [`Codec`] trait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H264Codec;

/// Parsed H.264 RTP payload metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H264Packet {
    nal_type: u8,
    keyframe: bool,
    has_sps: bool,
    has_pps: bool,
}

/// Bounded H.264 FMTP parameters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H264Fmtp {
    profile_level_id: Option<u32>,
    packetization_mode: Option<u8>,
    has_sprop_parameter_sets: bool,
}

/// Per-publisher SPS/PPS cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParameterSetCache {
    has_sps: bool,
    has_pps: bool,
}

/// H.264 parse errors with stable operator-facing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum H264Error {
    /// Payload is empty.
    #[error("h264 payload is empty")]
    EmptyPayload,
    /// Aggregation packet length field is truncated.
    #[error("h264 aggregation length is truncated")]
    TruncatedAggregationLength,
    /// Aggregated NAL exceeds remaining payload bytes.
    #[error("h264 aggregation nal is truncated")]
    TruncatedAggregationNal,
    /// FU indicator/header is truncated.
    #[error("h264 fragmentation unit is truncated")]
    TruncatedFu,
    /// FMTP parameter is malformed.
    #[error("h264 fmtp parameter is malformed")]
    MalformedFmtp,
}

impl H264Error {
    /// Returns the stable error code for this variant.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::EmptyPayload => "H264_PARSE_0001",
            Self::TruncatedAggregationLength => "H264_PARSE_0002",
            Self::TruncatedAggregationNal => "H264_PARSE_0003",
            Self::TruncatedFu => "H264_PARSE_0004",
            Self::MalformedFmtp => "H264_PARSE_0005",
        }
    }
}

impl From<H264Error> for CoreError {
    fn from(value: H264Error) -> Self {
        Self::Parse {
            context: "h264",
            message: value.error_code(),
        }
    }
}

impl Codec for H264Codec {
    fn kind(&self) -> CodecKind {
        CodecKind::H264
    }

    fn parse(&self, payload: &[u8]) -> CoreResult<CodecPacket> {
        parse(payload)
            .map(|packet| CodecPacket::new(CodecKind::H264, packet.is_keyframe(), None))
            .map_err(CoreError::from)
    }
}

/// Parses one H.264 RTP payload.
///
/// # Errors
///
/// Returns an error when aggregation or fragmentation lengths exceed the
/// remaining payload bytes.
pub fn parse(payload: &[u8]) -> Result<H264Packet, H264Error> {
    let Some((&first, rest)) = payload.split_first() else {
        let error = H264Error::EmptyPayload;
        record_parse_error(error);
        return Err(error);
    };
    let nal_type = first & 0x1f;
    let mut packet = H264Packet {
        nal_type,
        keyframe: nal_type == 5,
        has_sps: nal_type == 7,
        has_pps: nal_type == 8,
    };
    match nal_type {
        24..=27 => parse_aggregation(
            rest,
            &mut packet,
            nal_type == 25 || nal_type == 26 || nal_type == 27,
        )?,
        28 | 29 => parse_fu(rest, &mut packet)?,
        _ => {}
    }
    if packet.is_keyframe() {
        metrics::counter!("refract.codec.h264.keyframes").increment(1);
    }
    Ok(packet)
}

/// Parses H.264 FMTP parameters.
///
/// # Errors
///
/// Returns an error when numeric parameters are malformed.
pub fn parse_fmtp(source: &str) -> Result<H264Fmtp, H264Error> {
    let mut fmtp = H264Fmtp::default();
    for part in source
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some((key, value)) = part.split_once('=') else {
            return Err(H264Error::MalformedFmtp);
        };
        match key {
            "profile-level-id" => {
                fmtp.profile_level_id = Some(
                    u32::from_str_radix(value, 16).map_err(|_source| H264Error::MalformedFmtp)?,
                );
            }
            "packetization-mode" => {
                fmtp.packetization_mode = Some(
                    value
                        .parse::<u8>()
                        .map_err(|_source| H264Error::MalformedFmtp)?,
                );
            }
            "sprop-parameter-sets" => fmtp.has_sprop_parameter_sets = true,
            _ => {}
        }
    }
    Ok(fmtp)
}

impl H264Packet {
    /// Returns the top-level NAL type.
    #[must_use]
    pub const fn nal_type(self) -> u8 {
        self.nal_type
    }

    /// Returns whether an IDR NAL is present.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        self.keyframe
    }

    /// Returns whether SPS is present.
    #[must_use]
    pub const fn has_sps(self) -> bool {
        self.has_sps
    }

    /// Returns whether PPS is present.
    #[must_use]
    pub const fn has_pps(self) -> bool {
        self.has_pps
    }
}

impl H264Fmtp {
    /// Returns `profile-level-id`.
    #[must_use]
    pub const fn profile_level_id(self) -> Option<u32> {
        self.profile_level_id
    }

    /// Returns `packetization-mode`.
    #[must_use]
    pub const fn packetization_mode(self) -> Option<u8> {
        self.packetization_mode
    }

    /// Returns whether `sprop-parameter-sets` was present.
    #[must_use]
    pub const fn has_sprop_parameter_sets(self) -> bool {
        self.has_sprop_parameter_sets
    }
}

impl ParameterSetCache {
    /// Observes a parsed packet and updates SPS/PPS presence.
    pub const fn observe(&mut self, packet: H264Packet) {
        self.has_sps |= packet.has_sps();
        self.has_pps |= packet.has_pps();
    }

    /// Returns whether both SPS and PPS have been cached.
    #[must_use]
    pub const fn can_inject_before_keyframe(self) -> bool {
        self.has_sps && self.has_pps
    }
}

fn parse_aggregation(rest: &[u8], packet: &mut H264Packet, has_don: bool) -> Result<(), H264Error> {
    let mut offset = if has_don { 2 } else { 0 };
    if offset > rest.len() {
        let error = H264Error::TruncatedAggregationLength;
        record_parse_error(error);
        return Err(error);
    }
    while offset < rest.len() {
        let size_bytes = rest
            .get(offset..offset + 2)
            .ok_or(H264Error::TruncatedAggregationLength)?;
        let size = usize::from(u16::from_be_bytes([size_bytes[0], size_bytes[1]]));
        offset += 2;
        let nal = rest
            .get(offset..offset + size)
            .ok_or(H264Error::TruncatedAggregationNal)?;
        if let Some(&header) = nal.first() {
            let nal_type = header & 0x1f;
            packet.keyframe |= nal_type == 5;
            packet.has_sps |= nal_type == 7;
            packet.has_pps |= nal_type == 8;
        }
        offset += size;
    }
    Ok(())
}

fn parse_fu(rest: &[u8], packet: &mut H264Packet) -> Result<(), H264Error> {
    let fu_header = *rest.get(1).ok_or(H264Error::TruncatedFu)?;
    let start = fu_header & 0x80 == 0x80;
    let original_type = fu_header & 0x1f;
    packet.keyframe = start && original_type == 5;
    packet.has_sps = start && original_type == 7;
    packet.has_pps = start && original_type == 8;
    Ok(())
}

fn record_parse_error(error: H264Error) {
    metrics::counter!(
        "refract.codec.h264.parse_errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_single_nal_keyframe_and_parameter_sets() {
        assert!(parse(&[0x65]).expect("idr").is_keyframe());
        assert!(parse(&[0x67]).expect("sps").has_sps());
        assert!(parse(&[0x68]).expect("pps").has_pps());
    }

    #[test]
    fn parses_stap_a() {
        let packet = parse(&[24, 0, 1, 0x67, 0, 1, 0x65]).expect("stap-a");
        assert!(packet.has_sps());
        assert!(packet.is_keyframe());
    }

    #[test]
    fn parses_fmtp_and_cache() {
        let fmtp =
            parse_fmtp("profile-level-id=42e01f;packetization-mode=1;sprop-parameter-sets=Z0I=")
                .expect("fmtp");
        assert_eq!(fmtp.profile_level_id(), Some(0x0042_e01f));
        let mut cache = ParameterSetCache::default();
        cache.observe(parse(&[0x67]).expect("sps"));
        cache.observe(parse(&[0x68]).expect("pps"));
        assert!(cache.can_inject_before_keyframe());
    }
}
