//! VP9 RTP payload parsing for draft-ietf-payload-vp9-16.
//!
//! This parser validates the descriptor control bits, `PictureID`, layer fields,
//! flexible-mode references, and scalability-structure length before exposing
//! keyframe and layer metadata.
//!
//! # Examples
//!
//! ```
//! use refract_codec_vp9::{Vp9Codec, parse};
//! use refract_core::Codec;
//!
//! let payload = [0x08, 0x00];
//! assert!(parse(&payload)?.is_keyframe());
//! assert!(Vp9Codec.parse(&payload).is_ok());
//! # Ok::<(), refract_codec_vp9::Vp9Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::struct_excessive_bools)]

use refract_core::{
    Codec, CodecKind, CodecPacket, Error as CoreError, Layer, Result as CoreResult,
};
use thiserror::Error;

/// VP9 codec implementation for the shared core [`Codec`] trait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Vp9Codec;

/// Parsed VP9 RTP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp9Packet {
    descriptor: Vp9Descriptor,
    keyframe: bool,
}

/// Parsed VP9 RTP payload descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp9Descriptor {
    picture_id: Option<u16>,
    inter_picture_predicted: bool,
    flexible_mode: bool,
    beginning_of_frame: bool,
    end_of_frame: bool,
    scalability_structure: bool,
    tl0picidx: Option<u8>,
    temporal_id: Option<u8>,
    switching_up_point: bool,
    spatial_id: Option<u8>,
    inter_layer_dependency: bool,
    payload_offset: usize,
}

/// VP9 transparent layer-drop state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp9Rewriter {
    max_spatial_id: u8,
    max_temporal_id: u8,
}

/// VP9 parser errors with stable operator-facing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Vp9Error {
    /// Payload is empty.
    #[error("vp9 payload is empty")]
    EmptyPayload,
    /// Descriptor field is truncated.
    #[error("vp9 descriptor is truncated")]
    TruncatedDescriptor,
    /// Payload bytes after the descriptor are missing.
    #[error("vp9 frame payload is missing")]
    MissingFramePayload,
    /// Reference index bytes are truncated.
    #[error("vp9 flexible-mode references are truncated")]
    TruncatedReferences,
    /// Scalability structure is truncated.
    #[error("vp9 scalability structure is truncated")]
    TruncatedScalabilityStructure,
}

impl Vp9Error {
    /// Returns the stable error code for this variant.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::EmptyPayload => "VP9_PARSE_0001",
            Self::TruncatedDescriptor => "VP9_PARSE_0002",
            Self::MissingFramePayload => "VP9_PARSE_0003",
            Self::TruncatedReferences => "VP9_PARSE_0004",
            Self::TruncatedScalabilityStructure => "VP9_PARSE_0005",
        }
    }
}

impl From<Vp9Error> for CoreError {
    fn from(value: Vp9Error) -> Self {
        Self::Parse {
            context: "vp9",
            message: value.error_code(),
        }
    }
}

impl Codec for Vp9Codec {
    fn kind(&self) -> CodecKind {
        CodecKind::Vp9
    }

    fn parse(&self, payload: &[u8]) -> CoreResult<CodecPacket> {
        parse(payload)
            .map(|packet| CodecPacket::new(CodecKind::Vp9, packet.is_keyframe(), packet.layer()))
            .map_err(CoreError::from)
    }
}

/// Parses one VP9 RTP payload.
///
/// # Errors
///
/// Returns an error when descriptor-controlled fields are truncated or when no
/// encoded VP9 payload bytes remain.
pub fn parse(payload: &[u8]) -> Result<Vp9Packet, Vp9Error> {
    let descriptor = parse_descriptor(payload)?;
    let frame = payload
        .get(descriptor.payload_offset()..)
        .ok_or(Vp9Error::MissingFramePayload)?;
    if frame.is_empty() {
        let error = Vp9Error::MissingFramePayload;
        record_parse_error(error);
        return Err(error);
    }
    let keyframe = !descriptor.inter_picture_predicted() && descriptor.beginning_of_frame();
    if keyframe {
        metrics::counter!("refract.codec.vp9.keyframes").increment(1);
    }
    Ok(Vp9Packet {
        descriptor,
        keyframe,
    })
}

/// Parses the VP9 RTP payload descriptor.
///
/// # Errors
///
/// Returns an error when any declared descriptor field is truncated.
pub fn parse_descriptor(payload: &[u8]) -> Result<Vp9Descriptor, Vp9Error> {
    let Some((&first, _)) = payload.split_first() else {
        let error = Vp9Error::EmptyPayload;
        record_parse_error(error);
        return Err(error);
    };
    let i = first & 0x80 == 0x80;
    let inter_picture_predicted = first & 0x40 == 0x40;
    let l = first & 0x20 == 0x20;
    let flexible_mode = first & 0x10 == 0x10;
    let beginning_of_frame = first & 0x08 == 0x08;
    let end_of_frame = first & 0x04 == 0x04;
    let scalability_structure = first & 0x02 == 0x02;
    let mut offset = 1;
    let mut picture_id = None;
    let mut tl0picidx = None;
    let mut temporal_id = None;
    let mut switching_up_point = false;
    let mut spatial_id = None;
    let mut inter_layer_dependency = false;

    if i {
        let id = *payload.get(offset).ok_or(Vp9Error::TruncatedDescriptor)?;
        offset += 1;
        if id & 0x80 == 0x80 {
            let low = *payload.get(offset).ok_or(Vp9Error::TruncatedDescriptor)?;
            offset += 1;
            picture_id = Some((u16::from(id & 0x7f) << 8) | u16::from(low));
        } else {
            picture_id = Some(u16::from(id & 0x7f));
        }
    }
    if l {
        let layer = *payload.get(offset).ok_or(Vp9Error::TruncatedDescriptor)?;
        offset += 1;
        temporal_id = Some((layer >> 5) & 0x07);
        switching_up_point = layer & 0x10 == 0x10;
        spatial_id = Some((layer >> 1) & 0x07);
        inter_layer_dependency = layer & 0x01 == 0x01;
        if !flexible_mode {
            tl0picidx = Some(*payload.get(offset).ok_or(Vp9Error::TruncatedDescriptor)?);
            offset += 1;
        }
    }
    if flexible_mode && inter_picture_predicted {
        loop {
            let reference = *payload.get(offset).ok_or(Vp9Error::TruncatedReferences)?;
            offset += 1;
            if reference & 0x01 == 0 {
                break;
            }
        }
    }
    if scalability_structure {
        let ss = *payload
            .get(offset)
            .ok_or(Vp9Error::TruncatedScalabilityStructure)?;
        offset += 1;
        let spatial_layers = usize::from((ss >> 5) & 0x07) + 1;
        if ss & 0x10 == 0x10 {
            let needed = spatial_layers.saturating_mul(4);
            if payload.len().saturating_sub(offset) < needed {
                let error = Vp9Error::TruncatedScalabilityStructure;
                record_parse_error(error);
                return Err(error);
            }
            offset += needed;
        }
        let group_count = usize::from(ss & 0x0f);
        for _ in 0..group_count {
            let group = *payload
                .get(offset)
                .ok_or(Vp9Error::TruncatedScalabilityStructure)?;
            offset += 1;
            let refs = usize::from(group & 0x03);
            if payload.len().saturating_sub(offset) < refs {
                let error = Vp9Error::TruncatedScalabilityStructure;
                record_parse_error(error);
                return Err(error);
            }
            offset += refs;
        }
    }

    Ok(Vp9Descriptor {
        picture_id,
        inter_picture_predicted,
        flexible_mode,
        beginning_of_frame,
        end_of_frame,
        scalability_structure,
        tl0picidx,
        temporal_id,
        switching_up_point,
        spatial_id,
        inter_layer_dependency,
        payload_offset: offset,
    })
}

impl Vp9Packet {
    /// Returns the parsed VP9 descriptor.
    #[must_use]
    pub const fn descriptor(self) -> Vp9Descriptor {
        self.descriptor
    }

    /// Returns whether this payload starts a keyframe.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        self.keyframe
    }

    /// Returns spatial and temporal layer metadata.
    #[must_use]
    pub fn layer(self) -> Option<Layer> {
        match (self.descriptor.spatial_id(), self.descriptor.temporal_id()) {
            (Some(spatial), Some(temporal)) => Layer::new(spatial, temporal).ok(),
            (Some(spatial), None) => Layer::new(spatial, 0).ok(),
            (None, Some(temporal)) => Layer::new(0, temporal).ok(),
            (None, None) => None,
        }
    }
}

impl Vp9Descriptor {
    /// Returns the optional `PictureID`.
    #[must_use]
    pub const fn picture_id(self) -> Option<u16> {
        self.picture_id
    }

    /// Returns whether inter-picture prediction is set.
    #[must_use]
    pub const fn inter_picture_predicted(self) -> bool {
        self.inter_picture_predicted
    }

    /// Returns whether flexible mode is set.
    #[must_use]
    pub const fn flexible_mode(self) -> bool {
        self.flexible_mode
    }

    /// Returns whether the payload begins a frame.
    #[must_use]
    pub const fn beginning_of_frame(self) -> bool {
        self.beginning_of_frame
    }

    /// Returns whether the payload ends a frame.
    #[must_use]
    pub const fn end_of_frame(self) -> bool {
        self.end_of_frame
    }

    /// Returns whether a scalability structure is present.
    #[must_use]
    pub const fn scalability_structure(self) -> bool {
        self.scalability_structure
    }

    /// Returns the optional TL0PICIDX.
    #[must_use]
    pub const fn tl0picidx(self) -> Option<u8> {
        self.tl0picidx
    }

    /// Returns the optional temporal layer ID.
    #[must_use]
    pub const fn temporal_id(self) -> Option<u8> {
        self.temporal_id
    }

    /// Returns whether switching-up-point is set.
    #[must_use]
    pub const fn switching_up_point(self) -> bool {
        self.switching_up_point
    }

    /// Returns the optional spatial layer ID.
    #[must_use]
    pub const fn spatial_id(self) -> Option<u8> {
        self.spatial_id
    }

    /// Returns whether inter-layer dependency is set.
    #[must_use]
    pub const fn inter_layer_dependency(self) -> bool {
        self.inter_layer_dependency
    }

    /// Returns the offset where encoded VP9 payload bytes begin.
    #[must_use]
    pub const fn payload_offset(self) -> usize {
        self.payload_offset
    }
}

impl Vp9Rewriter {
    /// Creates a transparent layer-drop helper.
    #[must_use]
    pub const fn new(max_spatial_id: u8, max_temporal_id: u8) -> Self {
        Self {
            max_spatial_id,
            max_temporal_id,
        }
    }

    /// Returns whether a parsed packet should be forwarded for the configured layer subset.
    #[must_use]
    pub fn should_forward(self, packet: Vp9Packet) -> bool {
        let spatial_ok = packet
            .descriptor()
            .spatial_id()
            .is_none_or(|spatial| spatial <= self.max_spatial_id);
        let temporal_ok = packet
            .descriptor()
            .temporal_id()
            .is_none_or(|temporal| temporal <= self.max_temporal_id);
        spatial_ok && temporal_ok
    }
}

fn record_parse_error(error: Vp9Error) {
    metrics::counter!(
        "refract.codec.vp9.parse_errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keyframe_and_layers() {
        let packet = parse(&[0x28, 0b0101_0010, 7, 0]).expect("valid vp9");
        assert!(packet.is_keyframe());
        assert_eq!(packet.descriptor().temporal_id(), Some(2));
        assert_eq!(packet.descriptor().spatial_id(), Some(1));
    }

    #[test]
    fn parses_picture_id_and_flexible_refs() {
        let descriptor =
            parse_descriptor(&[0xd8, 0x80, 0x01, 0x02, 0]).expect("flexible ref descriptor");
        assert_eq!(descriptor.picture_id(), Some(1));
        assert!(descriptor.flexible_mode());
    }

    #[test]
    fn rejects_truncated_scalability_structure() {
        assert!(matches!(
            parse_descriptor(&[0x0a, 0xf0]),
            Err(Vp9Error::TruncatedScalabilityStructure)
        ));
    }

    #[test]
    fn rewriter_drops_above_target_layer() {
        let packet = parse(&[0x28, 0b0101_0010, 7, 0]).expect("valid vp9");
        assert!(!Vp9Rewriter::new(0, 2).should_forward(packet));
        assert!(Vp9Rewriter::new(1, 2).should_forward(packet));
    }
}
