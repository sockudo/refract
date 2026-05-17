//! H.265 RTP payload parsing for RFC 7798.
//!
//! The parser validates single NAL units, aggregation packets, and
//! fragmentation units, then classifies IDR and VPS/SPS/PPS presence.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::struct_excessive_bools)]

use refract_core::{Codec, CodecKind, CodecPacket, Error as CoreError, Result as CoreResult};
use thiserror::Error;

/// H.265 codec implementation for the shared core [`Codec`] trait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H265Codec;

/// Parsed H.265 RTP payload metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H265Packet {
    nal_type: u8,
    keyframe: bool,
    has_vps: bool,
    has_sps: bool,
    has_pps: bool,
}

/// Bounded H.265 FMTP parameters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H265Fmtp {
    profile_id: Option<u8>,
    tier_flag: Option<bool>,
    level_id: Option<u8>,
    has_sprop_vps: bool,
    has_sprop_sps: bool,
    has_sprop_pps: bool,
}

/// H.265 parser errors with stable operator-facing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum H265Error {
    /// Payload is shorter than the two-byte H.265 NAL header.
    #[error("h265 payload is too short")]
    PayloadTooShort,
    /// Aggregation packet length field is truncated.
    #[error("h265 aggregation length is truncated")]
    TruncatedAggregationLength,
    /// Aggregated NAL exceeds remaining payload bytes.
    #[error("h265 aggregation nal is truncated")]
    TruncatedAggregationNal,
    /// Fragmentation unit header is truncated.
    #[error("h265 fragmentation unit is truncated")]
    TruncatedFu,
    /// FMTP parameter is malformed.
    #[error("h265 fmtp parameter is malformed")]
    MalformedFmtp,
}

impl H265Error {
    /// Returns the stable error code for this variant.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::PayloadTooShort => "H265_PARSE_0001",
            Self::TruncatedAggregationLength => "H265_PARSE_0002",
            Self::TruncatedAggregationNal => "H265_PARSE_0003",
            Self::TruncatedFu => "H265_PARSE_0004",
            Self::MalformedFmtp => "H265_PARSE_0005",
        }
    }
}

impl From<H265Error> for CoreError {
    fn from(value: H265Error) -> Self {
        Self::Parse {
            context: "h265",
            message: value.error_code(),
        }
    }
}

impl Codec for H265Codec {
    fn kind(&self) -> CodecKind {
        CodecKind::H265
    }

    fn parse(&self, payload: &[u8]) -> CoreResult<CodecPacket> {
        parse(payload)
            .map(|packet| CodecPacket::new(CodecKind::H265, packet.is_keyframe(), None))
            .map_err(CoreError::from)
    }
}

/// Parses one H.265 RTP payload.
///
/// # Errors
///
/// Returns an error when the NAL header or declared AP/FU fields are truncated.
pub fn parse(payload: &[u8]) -> Result<H265Packet, H265Error> {
    if payload.len() < 2 {
        let error = H265Error::PayloadTooShort;
        record_parse_error(error);
        return Err(error);
    }
    let nal_type = (payload[0] >> 1) & 0x3f;
    let mut packet = classify_nal(nal_type);
    match nal_type {
        48 => parse_ap(&payload[2..], &mut packet)?,
        49 => parse_fu(&payload[2..], &mut packet)?,
        _ => {}
    }
    if packet.is_keyframe() {
        metrics::counter!("refract.codec.h265.keyframes").increment(1);
    }
    Ok(packet)
}

/// Parses H.265 FMTP parameters.
///
/// # Errors
///
/// Returns an error when numeric/boolean parameters are malformed.
pub fn parse_fmtp(source: &str) -> Result<H265Fmtp, H265Error> {
    let mut fmtp = H265Fmtp::default();
    for part in source
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some((key, value)) = part.split_once('=') else {
            return Err(H265Error::MalformedFmtp);
        };
        match key {
            "profile-id" => {
                fmtp.profile_id = Some(
                    value
                        .parse::<u8>()
                        .map_err(|_source| H265Error::MalformedFmtp)?,
                );
            }
            "tier-flag" => fmtp.tier_flag = Some(parse_bool(value)?),
            "level-id" => {
                fmtp.level_id = Some(
                    value
                        .parse::<u8>()
                        .map_err(|_source| H265Error::MalformedFmtp)?,
                );
            }
            "sprop-vps" => fmtp.has_sprop_vps = true,
            "sprop-sps" => fmtp.has_sprop_sps = true,
            "sprop-pps" => fmtp.has_sprop_pps = true,
            _ => {}
        }
    }
    Ok(fmtp)
}

impl H265Packet {
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

    /// Returns whether VPS is present.
    #[must_use]
    pub const fn has_vps(self) -> bool {
        self.has_vps
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

impl H265Fmtp {
    /// Returns `profile-id`.
    #[must_use]
    pub const fn profile_id(self) -> Option<u8> {
        self.profile_id
    }

    /// Returns `tier-flag`.
    #[must_use]
    pub const fn tier_flag(self) -> Option<bool> {
        self.tier_flag
    }

    /// Returns `level-id`.
    #[must_use]
    pub const fn level_id(self) -> Option<u8> {
        self.level_id
    }
}

const fn classify_nal(nal_type: u8) -> H265Packet {
    H265Packet {
        nal_type,
        keyframe: nal_type == 19 || nal_type == 20 || nal_type == 21,
        has_vps: nal_type == 32,
        has_sps: nal_type == 33,
        has_pps: nal_type == 34,
    }
}

fn parse_ap(mut rest: &[u8], packet: &mut H265Packet) -> Result<(), H265Error> {
    while !rest.is_empty() {
        if rest.len() < 2 {
            let error = H265Error::TruncatedAggregationLength;
            record_parse_error(error);
            return Err(error);
        }
        let size = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
        let nal = rest.get(..size).ok_or(H265Error::TruncatedAggregationNal)?;
        if nal.len() >= 2 {
            let nested = classify_nal((nal[0] >> 1) & 0x3f);
            packet.keyframe |= nested.keyframe;
            packet.has_vps |= nested.has_vps;
            packet.has_sps |= nested.has_sps;
            packet.has_pps |= nested.has_pps;
        }
        rest = &rest[size..];
    }
    Ok(())
}

fn parse_fu(rest: &[u8], packet: &mut H265Packet) -> Result<(), H265Error> {
    let fu_header = *rest.first().ok_or(H265Error::TruncatedFu)?;
    let start = fu_header & 0x80 == 0x80;
    let nested = classify_nal(fu_header & 0x3f);
    packet.keyframe = start && nested.keyframe;
    packet.has_vps = start && nested.has_vps;
    packet.has_sps = start && nested.has_sps;
    packet.has_pps = start && nested.has_pps;
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, H265Error> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(H265Error::MalformedFmtp),
    }
}

fn record_parse_error(error: H265Error) {
    metrics::counter!(
        "refract.codec.h265.parse_errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_single_nal_types() {
        assert!(parse(&[19 << 1, 1]).expect("idr").is_keyframe());
        assert!(parse(&[32 << 1, 1]).expect("vps").has_vps());
        assert!(parse(&[33 << 1, 1]).expect("sps").has_sps());
        assert!(parse(&[34 << 1, 1]).expect("pps").has_pps());
    }

    #[test]
    fn parses_ap_and_fu() {
        let ap = [48 << 1, 1, 0, 2, 19 << 1, 1];
        assert!(parse(&ap).expect("ap").is_keyframe());
        let fu = [49 << 1, 1, 0x80 | 0x13, 0];
        assert!(parse(&fu).expect("fu").is_keyframe());
    }

    #[test]
    fn parses_fmtp() {
        let fmtp =
            parse_fmtp("profile-id=1;tier-flag=0;level-id=120;sprop-vps=a;sprop-sps=b;sprop-pps=c")
                .expect("fmtp");
        assert_eq!(fmtp.profile_id(), Some(1));
        assert_eq!(fmtp.tier_flag(), Some(false));
        assert_eq!(fmtp.level_id(), Some(120));
    }
}
