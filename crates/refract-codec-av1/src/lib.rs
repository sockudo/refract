//! AV1 RTP payload parsing for RFC 9420 and Dependency Descriptor metadata.
//!
//! This crate validates aggregation headers, OBU headers and LEB128 sizes, and
//! provides a bounded Dependency Descriptor template store/writer for forwarded
//! layer subsets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use refract_core::{
    Codec, CodecKind, CodecPacket, Error as CoreError, Layer, Result as CoreResult,
};
use thiserror::Error;

/// AV1 codec implementation for the shared core [`Codec`] trait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Av1Codec;

/// Parsed AV1 RTP payload metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Av1Packet {
    aggregation: AggregationHeader,
    sequence_header: bool,
}

/// AV1 RTP aggregation header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationHeader {
    z: bool,
    y: bool,
    w: u8,
    n: bool,
}

/// Parsed AV1 OBU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObuHeader {
    obu_type: u8,
    has_extension: bool,
    has_size_field: bool,
}

/// Minimal parsed AV1 Dependency Descriptor metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyDescriptor {
    template_id: u8,
    spatial_id: u8,
    temporal_id: u8,
    start_of_coded_video_sequence: bool,
    active_decode_targets_bitmask: u32,
}

/// Bounded per-publisher Dependency Descriptor template store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateStore {
    templates: [Option<DependencyDescriptor>; 64],
}

/// Dependency Descriptor writer for forwarded layer subsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdWriter {
    max_spatial_id: u8,
    max_temporal_id: u8,
}

/// AV1 parser errors with stable operator-facing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Av1Error {
    /// Payload is empty.
    #[error("av1 payload is empty")]
    EmptyPayload,
    /// OBU header is truncated.
    #[error("av1 obu header is truncated")]
    TruncatedObu,
    /// LEB128 OBU size is truncated or too large.
    #[error("av1 obu size is malformed")]
    MalformedObuSize,
    /// OBU payload exceeds remaining bytes.
    #[error("av1 obu payload is truncated")]
    TruncatedObuPayload,
    /// Dependency Descriptor is truncated.
    #[error("av1 dependency descriptor is truncated")]
    TruncatedDependencyDescriptor,
}

impl Av1Error {
    /// Returns the stable error code for this variant.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::EmptyPayload => "AV1_PARSE_0001",
            Self::TruncatedObu => "AV1_PARSE_0002",
            Self::MalformedObuSize => "AV1_PARSE_0003",
            Self::TruncatedObuPayload => "AV1_PARSE_0004",
            Self::TruncatedDependencyDescriptor => "AV1_PARSE_0005",
        }
    }
}

impl From<Av1Error> for CoreError {
    fn from(value: Av1Error) -> Self {
        Self::Parse {
            context: "av1",
            message: value.error_code(),
        }
    }
}

impl Codec for Av1Codec {
    fn kind(&self) -> CodecKind {
        CodecKind::Av1
    }

    fn parse(&self, payload: &[u8]) -> CoreResult<CodecPacket> {
        parse(payload)
            .map(|packet| CodecPacket::new(CodecKind::Av1, packet.is_keyframe(), None))
            .map_err(CoreError::from)
    }
}

/// Parses one AV1 RTP payload.
///
/// # Errors
///
/// Returns an error when aggregation, OBU header, size, or payload fields are
/// truncated.
pub fn parse(payload: &[u8]) -> Result<Av1Packet, Av1Error> {
    let Some((&header, mut rest)) = payload.split_first() else {
        let error = Av1Error::EmptyPayload;
        record_parse_error(error);
        return Err(error);
    };
    let aggregation = AggregationHeader::new(header);
    let mut sequence_header = false;
    let mut remaining_obus = aggregation.w();
    while !rest.is_empty() && remaining_obus != 0 {
        let (obu, consumed) = parse_obu(rest)?;
        sequence_header |= obu.obu_type() == 1;
        rest = &rest[consumed..];
        remaining_obus = remaining_obus.saturating_sub(1);
    }
    let packet = Av1Packet {
        aggregation,
        sequence_header,
    };
    if packet.is_keyframe() {
        metrics::counter!("refract.codec.av1.keyframes").increment(1);
    }
    Ok(packet)
}

/// Parses one AV1 OBU from a payload fragment.
///
/// # Errors
///
/// Returns an error when the OBU header or size-delimited payload is truncated.
pub fn parse_obu(bytes: &[u8]) -> Result<(ObuHeader, usize), Av1Error> {
    let Some((&header, rest)) = bytes.split_first() else {
        return Err(Av1Error::TruncatedObu);
    };
    let obu = ObuHeader {
        obu_type: (header >> 3) & 0x0f,
        has_extension: header & 0x04 == 0x04,
        has_size_field: header & 0x02 == 0x02,
    };
    let mut offset = 1;
    if obu.has_extension() {
        if rest.is_empty() {
            return Err(Av1Error::TruncatedObu);
        }
        offset += 1;
    }
    if obu.has_size_field() {
        let (size, size_len) = read_leb128(&bytes[offset..])?;
        offset += size_len;
        let size_usize = usize::try_from(size).map_err(|_source| Av1Error::MalformedObuSize)?;
        if bytes.len().saturating_sub(offset) < size_usize {
            return Err(Av1Error::TruncatedObuPayload);
        }
        offset += size_usize;
    } else {
        offset = bytes.len();
    }
    Ok((obu, offset))
}

/// Parses a compact Dependency Descriptor representation used by this crate.
///
/// The format is template id, layer byte, flags byte, and a 32-bit active decode
/// target mask. SDP-cached template resolution is represented by
/// [`TemplateStore::resolve`].
///
/// # Errors
///
/// Returns an error when fewer than seven bytes are present.
pub fn parse_dependency_descriptor(bytes: &[u8]) -> Result<DependencyDescriptor, Av1Error> {
    if bytes.len() < 7 {
        return Err(Av1Error::TruncatedDependencyDescriptor);
    }
    Ok(DependencyDescriptor {
        template_id: bytes[0] & 0x3f,
        spatial_id: (bytes[1] >> 5) & 0x07,
        temporal_id: (bytes[1] >> 2) & 0x07,
        start_of_coded_video_sequence: bytes[2] & 0x80 == 0x80,
        active_decode_targets_bitmask: u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]),
    })
}

impl Av1Packet {
    /// Returns the aggregation header.
    #[must_use]
    pub const fn aggregation(self) -> AggregationHeader {
        self.aggregation
    }

    /// Returns whether a sequence header OBU was present.
    #[must_use]
    pub const fn has_sequence_header(self) -> bool {
        self.sequence_header
    }

    /// Returns whether this payload is an AV1 keyframe candidate.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        self.sequence_header && self.aggregation.n()
    }
}

impl AggregationHeader {
    /// Parses an AV1 aggregation header byte.
    #[must_use]
    pub const fn new(byte: u8) -> Self {
        Self {
            z: byte & 0x80 == 0x80,
            y: byte & 0x40 == 0x40,
            w: (byte >> 4) & 0x03,
            n: byte & 0x08 == 0x08,
        }
    }

    /// Returns the Z continuation flag.
    #[must_use]
    pub const fn z(self) -> bool {
        self.z
    }

    /// Returns the Y continuation flag.
    #[must_use]
    pub const fn y(self) -> bool {
        self.y
    }

    /// Returns the W OBU count hint.
    #[must_use]
    pub const fn w(self) -> u8 {
        if self.w == 0 { u8::MAX } else { self.w }
    }

    /// Returns the N coded video sequence flag.
    #[must_use]
    pub const fn n(self) -> bool {
        self.n
    }
}

impl ObuHeader {
    /// Returns the OBU type.
    #[must_use]
    pub const fn obu_type(self) -> u8 {
        self.obu_type
    }

    /// Returns whether an OBU extension byte is present.
    #[must_use]
    pub const fn has_extension(self) -> bool {
        self.has_extension
    }

    /// Returns whether a size field is present.
    #[must_use]
    pub const fn has_size_field(self) -> bool {
        self.has_size_field
    }
}

impl DependencyDescriptor {
    /// Returns the template ID.
    #[must_use]
    pub const fn template_id(self) -> u8 {
        self.template_id
    }

    /// Returns the spatial ID.
    #[must_use]
    pub const fn spatial_id(self) -> u8 {
        self.spatial_id
    }

    /// Returns the temporal ID.
    #[must_use]
    pub const fn temporal_id(self) -> u8 {
        self.temporal_id
    }

    /// Returns whether this starts a coded video sequence.
    #[must_use]
    pub const fn start_of_coded_video_sequence(self) -> bool {
        self.start_of_coded_video_sequence
    }

    /// Returns the active decode targets bitmask.
    #[must_use]
    pub const fn active_decode_targets_bitmask(self) -> u32 {
        self.active_decode_targets_bitmask
    }

    /// Returns a core layer.
    #[must_use]
    pub fn layer(self) -> Option<Layer> {
        Layer::new(self.spatial_id, self.temporal_id).ok()
    }
}

impl TemplateStore {
    /// Creates an empty template store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            templates: [None; 64],
        }
    }

    /// Caches a dependency descriptor template by ID.
    pub fn insert(&mut self, descriptor: DependencyDescriptor) {
        self.templates[usize::from(descriptor.template_id())] = Some(descriptor);
    }

    /// Resolves a descriptor against the cached SDP template store.
    #[must_use]
    pub fn resolve(self, template_id: u8) -> Option<DependencyDescriptor> {
        self.templates
            .get(usize::from(template_id & 0x3f))
            .copied()
            .flatten()
    }
}

impl Default for TemplateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DdWriter {
    /// Creates a DD writer for a forwarded layer subset.
    #[must_use]
    pub const fn new(max_spatial_id: u8, max_temporal_id: u8) -> Self {
        Self {
            max_spatial_id,
            max_temporal_id,
        }
    }

    /// Regenerates the compact Dependency Descriptor into `out`.
    ///
    /// # Errors
    ///
    /// Returns an error when `out` is shorter than seven bytes.
    pub fn write(
        self,
        descriptor: DependencyDescriptor,
        out: &mut [u8],
    ) -> Result<usize, Av1Error> {
        if out.len() < 7 {
            return Err(Av1Error::TruncatedDependencyDescriptor);
        }
        let active_mask = descriptor.active_decode_targets_bitmask()
            & layer_mask(self.max_spatial_id, self.max_temporal_id);
        out[0] = descriptor.template_id();
        out[1] = (descriptor.spatial_id().min(self.max_spatial_id) << 5)
            | (descriptor.temporal_id().min(self.max_temporal_id) << 2);
        out[2] = if descriptor.start_of_coded_video_sequence() {
            0x80
        } else {
            0
        };
        out[3..7].copy_from_slice(&active_mask.to_be_bytes());
        Ok(7)
    }
}

fn read_leb128(bytes: &[u8]) -> Result<(u64, usize), Av1Error> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for (index, byte) in bytes.iter().copied().take(8).enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
    }
    Err(Av1Error::MalformedObuSize)
}

const fn layer_mask(max_spatial_id: u8, max_temporal_id: u8) -> u32 {
    let mut mask = 0_u32;
    let mut spatial = 0_u8;
    while spatial <= max_spatial_id {
        let mut temporal = 0_u8;
        while temporal <= max_temporal_id {
            let bit = spatial as u32 * 8 + temporal as u32;
            mask |= 1_u32 << bit;
            temporal += 1;
        }
        spatial += 1;
    }
    mask
}

fn record_parse_error(error: Av1Error) {
    metrics::counter!(
        "refract.codec.av1.parse_errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sequence_header_keyframe() {
        let payload = [0x18, 0x0a, 0x00];
        let packet = parse(&payload).expect("valid av1");
        assert!(packet.has_sequence_header());
        assert!(packet.is_keyframe());
    }

    #[test]
    fn parses_dependency_descriptor_and_rewrites_mask() {
        let descriptor =
            parse_dependency_descriptor(&[3, 0b0010_1000, 0x80, 0xff, 0xff, 0xff, 0xff])
                .expect("dd");
        assert_eq!(descriptor.spatial_id(), 1);
        assert_eq!(descriptor.temporal_id(), 2);
        let mut out = [0_u8; 7];
        let written = DdWriter::new(0, 1)
            .write(descriptor, &mut out)
            .expect("write");
        assert_eq!(written, 7);
        assert_eq!(
            u32::from_be_bytes([out[3], out[4], out[5], out[6]]),
            0x0000_0003
        );
    }

    #[test]
    fn template_store_resolves() {
        let descriptor = parse_dependency_descriptor(&[1, 0, 0, 0, 0, 0, 1]).expect("descriptor");
        let mut store = TemplateStore::new();
        store.insert(descriptor);
        assert_eq!(store.resolve(1), Some(descriptor));
    }
}
