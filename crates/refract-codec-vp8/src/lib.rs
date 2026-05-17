//! VP8 RTP payload parsing for RFC 7741.
//!
//! The parser validates the payload descriptor before exposing `PictureID`,
//! TL0PICIDX, temporal-layer, and keyframe metadata.
//!
//! # Examples
//!
//! ```
//! use refract_codec_vp8::{parse, Vp8Codec};
//! use refract_core::Codec;
//!
//! let payload = [0x10, 0x00, 0x9d, 0x01, 0x2a];
//! assert!(parse(&payload)?.is_keyframe());
//! assert!(Vp8Codec.parse(&payload).is_ok());
//! # Ok::<(), refract_codec_vp8::Vp8Error>(())
//! ```

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

/// VP8 codec implementation for the shared core [`Codec`] trait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Vp8Codec;

/// Parsed VP8 RTP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp8Packet {
    descriptor: Vp8Descriptor,
    keyframe: bool,
}

/// Parsed VP8 payload descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp8Descriptor {
    start_of_partition: bool,
    partition_id: u8,
    picture_id: Option<u16>,
    tl0picidx: Option<u8>,
    temporal_id: Option<u8>,
    layer_sync: bool,
    keyidx: Option<u8>,
    payload_offset: usize,
}

/// VP8 `PictureID` continuity rewriter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp8Rewriter {
    next_picture_id: u16,
}

/// VP8 parser errors with stable operator-facing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Vp8Error {
    /// Payload is empty.
    #[error("vp8 payload is empty")]
    EmptyPayload,
    /// Descriptor extension bits require more bytes than are present.
    #[error("vp8 descriptor is truncated")]
    TruncatedDescriptor,
    /// VP8 payload bytes after the descriptor are missing.
    #[error("vp8 frame payload is missing")]
    MissingFramePayload,
    /// `PictureID` field is truncated.
    #[error("vp8 picture id is truncated")]
    TruncatedPictureId,
    /// Layer extension field is truncated.
    #[error("vp8 layer extension is truncated")]
    TruncatedLayer,
}

impl Vp8Error {
    /// Returns the stable error code for this variant.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::EmptyPayload => "VP8_PARSE_0001",
            Self::TruncatedDescriptor => "VP8_PARSE_0002",
            Self::MissingFramePayload => "VP8_PARSE_0003",
            Self::TruncatedPictureId => "VP8_PARSE_0004",
            Self::TruncatedLayer => "VP8_PARSE_0005",
        }
    }
}

impl From<Vp8Error> for CoreError {
    fn from(value: Vp8Error) -> Self {
        Self::Parse {
            context: "vp8",
            message: value.error_code(),
        }
    }
}

impl Codec for Vp8Codec {
    fn kind(&self) -> CodecKind {
        CodecKind::Vp8
    }

    fn parse(&self, payload: &[u8]) -> CoreResult<CodecPacket> {
        parse(payload)
            .map(|packet| CodecPacket::new(CodecKind::Vp8, packet.is_keyframe(), packet.layer()))
            .map_err(CoreError::from)
    }
}

/// Parses one VP8 RTP payload.
///
/// # Errors
///
/// Returns an error when descriptor bits require bytes not present in the
/// payload or when the encoded frame payload is absent.
pub fn parse(payload: &[u8]) -> Result<Vp8Packet, Vp8Error> {
    let descriptor = parse_descriptor(payload)?;
    let frame = payload
        .get(descriptor.payload_offset()..)
        .ok_or(Vp8Error::MissingFramePayload)?;
    if frame.is_empty() {
        let error = Vp8Error::MissingFramePayload;
        record_parse_error(error);
        return Err(error);
    }
    let keyframe = descriptor.start_of_partition()
        && descriptor.partition_id() == 0
        && frame.first().is_some_and(|byte| byte & 0x01 == 0);
    if keyframe {
        metrics::counter!("refract.codec.vp8.keyframes").increment(1);
    }
    Ok(Vp8Packet {
        descriptor,
        keyframe,
    })
}

/// Parses only the VP8 payload descriptor.
///
/// # Errors
///
/// Returns an error when any declared extension byte is truncated.
pub fn parse_descriptor(payload: &[u8]) -> Result<Vp8Descriptor, Vp8Error> {
    let Some((&first, rest)) = payload.split_first() else {
        let error = Vp8Error::EmptyPayload;
        record_parse_error(error);
        return Err(error);
    };
    let extended = first & 0x80 == 0x80;
    let start_of_partition = first & 0x10 == 0x10;
    let partition_id = first & 0x0f;
    let mut offset = 1;
    let mut picture_id = None;
    let mut tl0picidx = None;
    let mut temporal_id = None;
    let mut layer_sync = false;
    let mut keyidx = None;

    if extended {
        let Some((&extension, _)) = rest.split_first() else {
            let error = Vp8Error::TruncatedDescriptor;
            record_parse_error(error);
            return Err(error);
        };
        offset += 1;
        if extension & 0x80 == 0x80 {
            let id_byte = *payload.get(offset).ok_or(Vp8Error::TruncatedPictureId)?;
            offset += 1;
            if id_byte & 0x80 == 0x80 {
                let low = *payload.get(offset).ok_or(Vp8Error::TruncatedPictureId)?;
                offset += 1;
                picture_id = Some((u16::from(id_byte & 0x7f) << 8) | u16::from(low));
            } else {
                picture_id = Some(u16::from(id_byte & 0x7f));
            }
        }
        if extension & 0x40 == 0x40 {
            tl0picidx = Some(*payload.get(offset).ok_or(Vp8Error::TruncatedDescriptor)?);
            offset += 1;
        }
        if extension & 0x20 == 0x20 || extension & 0x10 == 0x10 {
            let layer = *payload.get(offset).ok_or(Vp8Error::TruncatedLayer)?;
            offset += 1;
            if extension & 0x20 == 0x20 {
                temporal_id = Some((layer >> 6) & 0x03);
                layer_sync = layer & 0x20 == 0x20;
            }
            if extension & 0x10 == 0x10 {
                keyidx = Some(layer & 0x1f);
            }
        }
    }

    Ok(Vp8Descriptor {
        start_of_partition,
        partition_id,
        picture_id,
        tl0picidx,
        temporal_id,
        layer_sync,
        keyidx,
        payload_offset: offset,
    })
}

impl Vp8Packet {
    /// Returns the parsed descriptor.
    #[must_use]
    pub const fn descriptor(self) -> Vp8Descriptor {
        self.descriptor
    }

    /// Returns whether this payload starts a keyframe.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        self.keyframe
    }

    /// Returns the temporal-only layer.
    #[must_use]
    pub fn layer(self) -> Option<Layer> {
        self.descriptor
            .temporal_id()
            .and_then(|temporal| Layer::new(0, temporal).ok())
    }
}

impl Vp8Descriptor {
    /// Returns whether the payload starts a partition.
    #[must_use]
    pub const fn start_of_partition(self) -> bool {
        self.start_of_partition
    }

    /// Returns the partition ID.
    #[must_use]
    pub const fn partition_id(self) -> u8 {
        self.partition_id
    }

    /// Returns the optional `PictureID`.
    #[must_use]
    pub const fn picture_id(self) -> Option<u16> {
        self.picture_id
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

    /// Returns whether layer sync is set.
    #[must_use]
    pub const fn layer_sync(self) -> bool {
        self.layer_sync
    }

    /// Returns the optional KEYIDX.
    #[must_use]
    pub const fn keyidx(self) -> Option<u8> {
        self.keyidx
    }

    /// Returns the offset where VP8 frame bytes begin.
    #[must_use]
    pub const fn payload_offset(self) -> usize {
        self.payload_offset
    }
}

impl Vp8Rewriter {
    /// Creates a `PictureID` continuity rewriter.
    #[must_use]
    pub const fn new(first_picture_id: u16) -> Self {
        Self {
            next_picture_id: first_picture_id,
        }
    }

    /// Returns the next subscriber `PictureID` and advances with 15-bit wrap.
    #[must_use]
    pub const fn map_next(&mut self) -> u16 {
        let mapped = self.next_picture_id & 0x7fff;
        self.next_picture_id = self.next_picture_id.wrapping_add(1) & 0x7fff;
        mapped
    }
}

fn record_parse_error(error: Vp8Error) {
    metrics::counter!(
        "refract.codec.vp8.parse_errors",
        "error_code" => error.error_code()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keyframe_and_temporal_layer() {
        let packet = parse(&[0x90, 0x20, 0x00, 0x00]).expect("valid vp8");
        assert!(packet.is_keyframe());
        assert_eq!(packet.descriptor().temporal_id(), Some(0));
    }

    #[test]
    fn parses_picture_id_variants() {
        assert_eq!(
            parse_descriptor(&[0x80, 0x80, 0x7f, 0])
                .expect("7 bit")
                .picture_id(),
            Some(0x7f)
        );
        assert_eq!(
            parse_descriptor(&[0x80, 0x80, 0x80, 0x01, 0])
                .expect("15 bit")
                .picture_id(),
            Some(1)
        );
    }

    #[test]
    fn rejects_truncated_descriptor() {
        assert!(matches!(
            parse_descriptor(&[0x80]),
            Err(Vp8Error::TruncatedDescriptor)
        ));
        assert!(matches!(parse(&[0x10]), Err(Vp8Error::MissingFramePayload)));
    }

    #[test]
    fn picture_id_rewriter_wraps() {
        let mut rewriter = Vp8Rewriter::new(0x7ffe);
        assert_eq!(rewriter.map_next(), 0x7ffe);
        assert_eq!(rewriter.map_next(), 0x7fff);
        assert_eq!(rewriter.map_next(), 0);
    }
}
