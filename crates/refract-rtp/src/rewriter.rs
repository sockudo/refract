//! Allocation-free RTP header rewriting.
//!
//! The rewriter mutates caller-owned packet bytes after validating the packet
//! header. Sequence and timestamp remappers are stateful value types intended
//! to live inside a per-subscriber, per-core forwarding lane.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::rewriter::{RtpRewrite, RtpRewriter};
//! let mut packet = [0x80, 96, 0, 1, 0, 0, 0, 10, 0, 0, 0, 7];
//! RtpRewriter::new().rewrite(&mut packet, RtpRewrite::new().with_ssrc(9))?;
//! assert_eq!(&packet[8..12], &[0, 0, 0, 9]);
//! # Ok::<(), refract_rtp::RtpError>(())
//! ```

use crate::header::{RtpHeader, read_u16, read_u32, write_u16, write_u32};
use crate::metrics::record_rewrite;
use crate::{RtpError, RtpResult, Stability};

const RTP_SEQUENCE_OFFSET: usize = 2;
const RTP_TIMESTAMP_OFFSET: usize = 4;
const RTP_SSRC_OFFSET: usize = 8;
const ONE_BYTE_PROFILE: u16 = 0xbede;

/// In-place RTP rewrite request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtpRewrite {
    ssrc: Option<u32>,
    sequence: Option<u16>,
    timestamp: Option<u32>,
    remove_extension_id: Option<u8>,
    add_extension: Option<OneByteExtension>,
}

/// One-byte RFC 8285 extension value that can be inserted into existing padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneByteExtension {
    id: u8,
    len: u8,
    value: [u8; 16],
}

impl RtpRewrite {
    /// Creates an empty rewrite request.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new(), RtpRewrite::default());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ssrc: None,
            sequence: None,
            timestamp: None,
            remove_extension_id: None,
            add_extension: None,
        }
    }

    /// Adds an SSRC rewrite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// let rewrite = RtpRewrite::new().with_ssrc(42);
    /// assert_eq!(rewrite.ssrc(), Some(42));
    /// ```
    #[must_use]
    pub const fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = Some(ssrc);
        self
    }

    /// Adds a sequence-number rewrite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().with_sequence(7).sequence(), Some(7));
    /// ```
    #[must_use]
    pub const fn with_sequence(mut self, sequence: u16) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Adds a timestamp rewrite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().with_timestamp(7).timestamp(), Some(7));
    /// ```
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Adds a one-byte extension removal request.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().remove_one_byte_extension(3).remove_extension_id(), Some(3));
    /// ```
    #[must_use]
    pub const fn remove_one_byte_extension(mut self, id: u8) -> Self {
        self.remove_extension_id = Some(id);
        self
    }

    /// Adds a one-byte extension insertion request.
    ///
    /// # Errors
    ///
    /// Returns an error when the ID is zero or reserved, or the value is longer
    /// than the one-byte RFC 8285 limit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert!(RtpRewrite::new().add_one_byte_extension(1, &[9]).is_ok());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    pub fn add_one_byte_extension(mut self, id: u8, value: &[u8]) -> RtpResult<Self> {
        self.add_extension = Some(OneByteExtension::new(id, value)?);
        Ok(self)
    }

    /// Returns the configured SSRC rewrite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().with_ssrc(1).ssrc(), Some(1));
    /// ```
    #[must_use]
    pub const fn ssrc(self) -> Option<u32> {
        self.ssrc
    }

    /// Returns the configured sequence rewrite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().with_sequence(1).sequence(), Some(1));
    /// ```
    #[must_use]
    pub const fn sequence(self) -> Option<u16> {
        self.sequence
    }

    /// Returns the configured timestamp rewrite.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().with_timestamp(1).timestamp(), Some(1));
    /// ```
    #[must_use]
    pub const fn timestamp(self) -> Option<u32> {
        self.timestamp
    }

    /// Returns the one-byte extension ID selected for removal.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewrite;
    /// assert_eq!(RtpRewrite::new().remove_one_byte_extension(1).remove_extension_id(), Some(1));
    /// ```
    #[must_use]
    pub const fn remove_extension_id(self) -> Option<u8> {
        self.remove_extension_id
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{rewriter::RtpRewrite, Stability};
    /// assert_eq!(RtpRewrite::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl OneByteExtension {
    /// Builds a bounded one-byte RFC 8285 extension insertion payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the ID is zero or reserved, or the value exceeds
    /// sixteen bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::OneByteExtension;
    /// assert_eq!(OneByteExtension::new(1, &[9])?.wire_len(), 2);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    pub fn new(id: u8, value: &[u8]) -> RtpResult<Self> {
        if id == 0 || id == 15 || value.is_empty() || value.len() > 16 {
            return Err(RtpError::RewriteTargetMissing {
                target: "one_byte_extension_id_or_len",
            });
        }
        let mut bytes = [0_u8; 16];
        bytes[..value.len()].copy_from_slice(value);
        let len = u8::try_from(value.len()).map_err(|_| RtpError::RewriteTargetMissing {
            target: "one_byte_extension_len",
        })?;
        Ok(Self {
            id,
            len,
            value: bytes,
        })
    }

    /// Returns the wire length including the one-byte header.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::OneByteExtension;
    /// assert_eq!(OneByteExtension::new(1, &[9, 8])?.wire_len(), 3);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub fn wire_len(self) -> usize {
        usize::from(self.len) + 1
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{rewriter::OneByteExtension, Stability};
    /// assert_eq!(OneByteExtension::new(1, &[9])?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Stateless in-place RTP packet rewriter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtpRewriter;

impl RtpRewriter {
    /// Creates an RTP rewriter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::RtpRewriter;
    /// let rewriter = RtpRewriter::new();
    /// assert_eq!(rewriter.stability(), refract_rtp::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Rewrites RTP header fields and selected one-byte extensions in place.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is invalid, the requested extension block
    /// is absent, or the insertion cannot fit in existing extension padding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::{RtpRewrite, RtpRewriter};
    /// let mut packet = [0x80, 96, 0, 1, 0, 0, 0, 10, 0, 0, 0, 7];
    /// RtpRewriter::new().rewrite(&mut packet, RtpRewrite::new().with_sequence(9))?;
    /// assert_eq!(&packet[2..4], &[0, 9]);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    pub fn rewrite(self, packet: &mut [u8], rewrite: RtpRewrite) -> RtpResult<()> {
        RtpHeader::parse(packet)?;

        if let Some(ssrc) = rewrite.ssrc {
            write_u32(&mut packet[RTP_SSRC_OFFSET..RTP_SSRC_OFFSET + 4], ssrc);
        }
        if let Some(sequence) = rewrite.sequence {
            write_u16(
                &mut packet[RTP_SEQUENCE_OFFSET..RTP_SEQUENCE_OFFSET + 2],
                sequence,
            );
        }
        if let Some(timestamp) = rewrite.timestamp {
            write_u32(
                &mut packet[RTP_TIMESTAMP_OFFSET..RTP_TIMESTAMP_OFFSET + 4],
                timestamp,
            );
        }
        if let Some(id) = rewrite.remove_extension_id {
            remove_one_byte_extension(packet, id)?;
        }
        if let Some(extension) = rewrite.add_extension {
            add_one_byte_extension(packet, extension)?;
        }

        record_rewrite();
        Ok(())
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{rewriter::RtpRewriter, Stability};
    /// assert_eq!(RtpRewriter::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Sequence number remapper with a rolling wrapping offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqRemap {
    offset: u16,
}

impl SeqRemap {
    /// Creates a remapper from the first publisher and subscriber sequence pair.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::SeqRemap;
    /// let remap = SeqRemap::new(65_535, 7);
    /// assert_eq!(remap.map(0), 8);
    /// ```
    #[must_use]
    pub const fn new(publisher_start: u16, subscriber_start: u16) -> Self {
        Self {
            offset: subscriber_start.wrapping_sub(publisher_start),
        }
    }

    /// Maps a publisher sequence number to the subscriber sequence space.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::SeqRemap;
    /// let remap = SeqRemap::new(10, 100);
    /// assert_eq!(remap.map(12), 102);
    /// ```
    #[must_use]
    pub const fn map(self, pub_sequence: u16) -> u16 {
        pub_sequence.wrapping_add(self.offset)
    }

    /// Returns the rolling offset.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::SeqRemap;
    /// assert_eq!(SeqRemap::new(10, 15).offset(), 5);
    /// ```
    #[must_use]
    pub const fn offset(self) -> u16 {
        self.offset
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{rewriter::SeqRemap, Stability};
    /// assert_eq!(SeqRemap::new(1, 2).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// RTP timestamp remapper with codec clock-rate awareness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsRemap {
    clock_rate_hz: u32,
    offset: u32,
}

impl TsRemap {
    /// Creates a timestamp remapper.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::TsRemap;
    /// let remap = TsRemap::new(90_000, 10, 100);
    /// assert_eq!(remap.map(12), 102);
    /// ```
    #[must_use]
    pub const fn new(clock_rate_hz: u32, publisher_start: u32, subscriber_start: u32) -> Self {
        Self {
            clock_rate_hz,
            offset: subscriber_start.wrapping_sub(publisher_start),
        }
    }

    /// Maps a publisher RTP timestamp to the subscriber timestamp space.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::TsRemap;
    /// let remap = TsRemap::new(48_000, 10, 20);
    /// assert_eq!(remap.map(12), 22);
    /// ```
    #[must_use]
    pub const fn map(self, pub_timestamp: u32) -> u32 {
        pub_timestamp.wrapping_add(self.offset)
    }

    /// Converts a duration in microseconds into codec clock ticks.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::TsRemap;
    /// assert_eq!(TsRemap::new(48_000, 0, 0).ticks_from_micros(20_000), 960);
    /// ```
    #[must_use]
    pub fn ticks_from_micros(self, micros: u64) -> u64 {
        micros.saturating_mul(u64::from(self.clock_rate_hz)) / 1_000_000
    }

    /// Returns the codec clock rate in hertz.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::rewriter::TsRemap;
    /// assert_eq!(TsRemap::new(90_000, 0, 0).clock_rate_hz(), 90_000);
    /// ```
    #[must_use]
    pub const fn clock_rate_hz(self) -> u32 {
        self.clock_rate_hz
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{rewriter::TsRemap, Stability};
    /// assert_eq!(TsRemap::new(90_000, 0, 0).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

fn extension_payload_range(packet: &[u8]) -> RtpResult<(usize, usize)> {
    let header = RtpHeader::parse(packet)?;
    let Some(extension) = header.extension() else {
        return Err(RtpError::RewriteTargetMissing {
            target: "rtp_extension",
        });
    };
    if extension.profile() != ONE_BYTE_PROFILE {
        return Err(RtpError::RewriteTargetMissing {
            target: "one_byte_extension_profile",
        });
    }
    let start = header.header_len() - extension.payload().len();
    Ok((start, header.header_len()))
}

fn remove_one_byte_extension(packet: &mut [u8], id: u8) -> RtpResult<()> {
    let (start, end) = extension_payload_range(packet)?;
    let mut cursor = start;
    while cursor < end {
        let header = packet[cursor];
        if header == 0 {
            cursor += 1;
            continue;
        }
        let entry_id = header >> 4;
        let len = usize::from(header & 0x0f) + 1;
        let entry_end = cursor.saturating_add(1).saturating_add(len);
        if entry_end > end {
            return Err(RtpError::RewriteTargetMissing {
                target: "malformed_one_byte_extension",
            });
        }
        if entry_id == id {
            packet[cursor..entry_end].fill(0);
            return Ok(());
        }
        cursor = entry_end;
    }
    Err(RtpError::RewriteTargetMissing {
        target: "one_byte_extension_id",
    })
}

fn add_one_byte_extension(packet: &mut [u8], extension: OneByteExtension) -> RtpResult<()> {
    let (start, end) = extension_payload_range(packet)?;
    let needed = extension.wire_len();
    let mut cursor = start;
    while cursor < end {
        if packet[cursor] != 0 {
            let len = usize::from(packet[cursor] & 0x0f) + 1;
            cursor = cursor.saturating_add(1).saturating_add(len);
            continue;
        }
        let run_start = cursor;
        while cursor < end && packet[cursor] == 0 {
            cursor += 1;
        }
        let available = cursor - run_start;
        if available >= needed {
            packet[run_start] = (extension.id << 4) | (extension.len - 1);
            let value_len = usize::from(extension.len);
            packet[run_start + 1..run_start + 1 + value_len]
                .copy_from_slice(&extension.value[..value_len]);
            return Ok(());
        }
    }
    Err(RtpError::RewriteNoSpace {
        needed,
        available: end - start,
    })
}

/// Reads the RTP sequence number from a validated packet.
///
/// # Errors
///
/// Returns an error if the packet is not a valid bounded RTP packet.
///
/// # Examples
///
/// ```
/// # use refract_rtp::rewriter::read_sequence;
/// let packet = [0x80, 96, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1];
/// assert_eq!(read_sequence(&packet)?, 8);
/// # Ok::<(), refract_rtp::RtpError>(())
/// ```
pub fn read_sequence(packet: &[u8]) -> RtpResult<u16> {
    RtpHeader::parse(packet)?;
    Ok(read_u16(
        &packet[RTP_SEQUENCE_OFFSET..RTP_SEQUENCE_OFFSET + 2],
    ))
}

/// Reads the RTP timestamp from a validated packet.
///
/// # Errors
///
/// Returns an error if the packet is not a valid bounded RTP packet.
///
/// # Examples
///
/// ```
/// # use refract_rtp::rewriter::read_timestamp;
/// let packet = [0x80, 96, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1];
/// assert_eq!(read_timestamp(&packet)?, 8);
/// # Ok::<(), refract_rtp::RtpError>(())
/// ```
pub fn read_timestamp(packet: &[u8]) -> RtpResult<u32> {
    RtpHeader::parse(packet)?;
    Ok(read_u32(
        &packet[RTP_TIMESTAMP_OFFSET..RTP_TIMESTAMP_OFFSET + 4],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_fixed_header_fields() {
        let mut packet = [0x80, 96, 0, 1, 0, 0, 0, 10, 0, 0, 0, 7];
        let rewrite = RtpRewrite::new()
            .with_ssrc(9)
            .with_sequence(2)
            .with_timestamp(11);
        RtpRewriter::new()
            .rewrite(&mut packet, rewrite)
            .expect("rewrite succeeds");
        assert_eq!(read_sequence(&packet).expect("sequence"), 2);
        assert_eq!(read_timestamp(&packet).expect("timestamp"), 11);
        assert_eq!(&packet[8..12], &[0, 0, 0, 9]);
    }

    #[test]
    fn removes_and_adds_one_byte_extensions_without_allocation() {
        let mut packet = [
            0x90, 96, 0, 1, 0, 0, 0, 10, 0, 0, 0, 7, 0xbe, 0xde, 0, 1, 0x10, 0xaa, 0, 0,
        ];
        RtpRewriter::new()
            .rewrite(&mut packet, RtpRewrite::new().remove_one_byte_extension(1))
            .expect("remove succeeds");
        assert_eq!(&packet[16..18], &[0, 0]);
        let rewrite = RtpRewrite::new()
            .add_one_byte_extension(2, &[0xbb])
            .expect("extension fits request");
        RtpRewriter::new()
            .rewrite(&mut packet, rewrite)
            .expect("add succeeds");
        assert_eq!(&packet[16..18], &[0x20, 0xbb]);
    }

    #[test]
    fn seq_remap_has_no_drift_across_rollover() {
        let remap = SeqRemap::new(65_530, 10);
        let expected_offset = remap.offset();
        for step in 0_u16..128 {
            let pub_sequence = 65_530_u16.wrapping_add(step);
            assert_eq!(
                remap.map(pub_sequence).wrapping_sub(pub_sequence),
                expected_offset
            );
        }
    }

    #[test]
    fn decade_long_synthetic_sequences_do_not_drift() {
        let remap = SeqRemap::new(12_345, 54_321);
        let mut pub_sequence = 12_345_u16;
        let mut sub_sequence = 54_321_u16;
        for _ in 0_u32..1_000_000 {
            assert_eq!(remap.map(pub_sequence), sub_sequence);
            pub_sequence = pub_sequence.wrapping_add(37);
            sub_sequence = sub_sequence.wrapping_add(37);
        }
    }
}
