//! RFC 8888 transport-wide congestion-control feedback encode/decode.
//!
//! The encoder records ingress RTP transport-wide sequence arrivals and emits a
//! bounded RTCP RTPFB transport-cc body. The parser decodes the same body on
//! egress for bandwidth estimation.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_cc::{TwccRecorder, TwccSequenceNumber};
//! let mut recorder = TwccRecorder::new(1, 2);
//! recorder.record(TwccSequenceNumber::new(7), Duration::from_millis(100))?;
//! let feedback = recorder.build_feedback(1)?;
//! assert_eq!(feedback.records().len(), 1);
//! # Ok::<(), refract_cc::CcError>(())
//! ```

use std::time::Duration;

use crate::{CcError, CcResult};

/// Maximum packet statuses in one generated transport-cc feedback packet.
pub const MAX_TWCC_PACKETS: usize = 512;
/// Maximum bytes accepted or generated for one transport-cc body.
pub const MAX_TWCC_FEEDBACK_BYTES: usize = 1_500;

const HEADER_LEN: usize = 12;
const FCI_FIXED_LEN: usize = 8;
const CHUNK_LEN: usize = 2;
const SMALL_DELTA_TICK_US: i64 = 250;
const SMALL_DELTA_MIN_TICKS: i16 = 0;
const SMALL_DELTA_MAX_TICKS: i16 = u8::MAX as i16;
const LARGE_DELTA_MIN_TICKS: i16 = i16::MIN;
const LARGE_DELTA_MAX_TICKS: i16 = i16::MAX;
const REF_TIME_TICK_US: u128 = 64_000;
const RTCP_VERSION: u8 = 2;
const RTPFB_PACKET_TYPE: u8 = 205;
const TRANSPORT_CC_FMT: u8 = 15;
const STATUS_NOT_RECEIVED: u16 = 0;
const STATUS_SMALL_DELTA: u16 = 1;
const STATUS_LARGE_DELTA: u16 = 2;

/// Transport-wide RTP sequence number.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TwccSequenceNumber(u16);

impl TwccSequenceNumber {
    /// Creates a sequence number from its raw RTP transport-wide value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccSequenceNumber;
    /// assert_eq!(TwccSequenceNumber::new(9).as_u16(), 9);
    /// ```
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw sequence number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccSequenceNumber;
    /// assert_eq!(TwccSequenceNumber::new(3).as_u16(), 3);
    /// ```
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Adds a wrapping offset.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccSequenceNumber;
    /// assert_eq!(
    ///     TwccSequenceNumber::new(u16::MAX).wrapping_add(2).as_u16(),
    ///     1
    /// );
    /// ```
    #[must_use]
    pub const fn wrapping_add(self, offset: u16) -> Self {
        Self(self.0.wrapping_add(offset))
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Stability, TwccSequenceNumber};
    /// assert_eq!(TwccSequenceNumber::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

impl From<u16> for TwccSequenceNumber {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

/// Decoded transport-cc packet status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketStatus {
    /// Packet was not received.
    NotReceived,
    /// Packet was received with a small positive delta.
    SmallDelta,
    /// Packet was received with a signed large delta.
    LargeDelta,
}

impl PacketStatus {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::PacketStatus;
    /// assert_eq!(PacketStatus::SmallDelta.as_str(), "small_delta");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReceived => "not_received",
            Self::SmallDelta => "small_delta",
            Self::LargeDelta => "large_delta",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{PacketStatus, Stability};
    /// assert_eq!(PacketStatus::NotReceived.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// One transport-cc packet record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwccPacketRecord {
    /// Transport-wide sequence number.
    pub sequence: TwccSequenceNumber,
    /// Packet status.
    pub status: PacketStatus,
    /// Receive timestamp when the packet was received.
    pub received_at: Option<Duration>,
}

impl TwccPacketRecord {
    /// Creates a received packet record.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccPacketRecord, TwccSequenceNumber};
    /// let record = TwccPacketRecord::received(TwccSequenceNumber::new(1), Duration::ZERO);
    /// assert!(record.received_at.is_some());
    /// ```
    #[must_use]
    pub const fn received(sequence: TwccSequenceNumber, received_at: Duration) -> Self {
        Self {
            sequence,
            status: PacketStatus::SmallDelta,
            received_at: Some(received_at),
        }
    }

    /// Creates a missing packet record.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{PacketStatus, TwccPacketRecord, TwccSequenceNumber};
    /// let record = TwccPacketRecord::missing(TwccSequenceNumber::new(1));
    /// assert_eq!(record.status, PacketStatus::NotReceived);
    /// ```
    #[must_use]
    pub const fn missing(sequence: TwccSequenceNumber) -> Self {
        Self {
            sequence,
            status: PacketStatus::NotReceived,
            received_at: None,
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Stability, TwccPacketRecord, TwccSequenceNumber};
    /// assert_eq!(
    ///     TwccPacketRecord::missing(TwccSequenceNumber::new(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Parsed or generated transport-wide congestion-control feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwccFeedback {
    sender_ssrc: u32,
    media_ssrc: u32,
    base_sequence: TwccSequenceNumber,
    feedback_count: u8,
    reference_time: Duration,
    records: Vec<TwccPacketRecord>,
}

impl TwccFeedback {
    /// Parses a complete RTCP RTPFB transport-cc packet.
    ///
    /// # Errors
    ///
    /// Returns [`CcError`] when RTCP or RFC 8888 FCI fields are malformed, the
    /// packet count exceeds [`MAX_TWCC_PACKETS`], or status/delta bytes are
    /// truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccFeedback, TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(9), Duration::from_millis(64))?;
    /// let feedback = recorder.build_feedback(3)?;
    /// let mut bytes = [0_u8; refract_cc::MAX_TWCC_FEEDBACK_BYTES];
    /// let len = feedback.encode(&mut bytes)?;
    /// assert_eq!(TwccFeedback::parse(&bytes[..len])?.feedback_count(), 3);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    pub fn parse(bytes: &[u8]) -> CcResult<Self> {
        validate_rtcp_packet(bytes)?;
        let header = ParsedTwccHeader::parse(bytes);
        let packet_count = header.packet_count;
        if packet_count > MAX_TWCC_PACKETS {
            return Err(CcError::MalformedTwcc {
                reason: "packet_count_too_large",
            });
        }
        let mut cursor = 20;
        let statuses = decode_statuses(bytes, packet_count, &mut cursor)?;
        let records = decode_records(
            bytes,
            header.base_sequence,
            header.reference_time,
            statuses,
            cursor,
        )?;

        Ok(Self {
            sender_ssrc: header.sender_ssrc,
            media_ssrc: header.media_ssrc,
            base_sequence: header.base_sequence,
            feedback_count: header.feedback_count,
            reference_time: header.reference_time,
            records,
        })
    }

    /// Encodes a complete RTCP RTPFB transport-cc packet into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`CcError`] when `out` is too small, the feedback has too many
    /// records, or delta arithmetic cannot be represented in RFC 8888 fields.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(1), Duration::from_millis(1))?;
    /// let feedback = recorder.build_feedback(1)?;
    /// let mut out = [0_u8; refract_cc::MAX_TWCC_FEEDBACK_BYTES];
    /// assert!(feedback.encode(&mut out)? > 0);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    pub fn encode(&self, out: &mut [u8]) -> CcResult<usize> {
        if self.records.len() > MAX_TWCC_PACKETS {
            return Err(CcError::MalformedTwcc {
                reason: "packet_count_too_large",
            });
        }

        let mut cursor = HEADER_LEN + FCI_FIXED_LEN;
        if out.len() < cursor {
            return Err(CcError::PacketTooLarge {
                len: cursor,
                max: out.len(),
            });
        }

        for run in status_runs(self.records.as_slice()) {
            ensure_room(cursor + CHUNK_LEN, out.len())?;
            let chunk = encode_run_chunk(run.status, run.len)?;
            write_u16(&mut out[cursor..cursor + CHUNK_LEN], chunk);
            cursor += CHUNK_LEN;
        }

        let mut previous = self.reference_time;
        for record in &self.records {
            if let Some(received_at) = record.received_at {
                let delta_ticks = delta_ticks(previous, received_at)?;
                match delta_status(delta_ticks)? {
                    PacketStatus::SmallDelta => {
                        ensure_room(cursor + 1, out.len())?;
                        out[cursor] =
                            u8::try_from(delta_ticks).map_err(|_error| CcError::MalformedTwcc {
                                reason: "small_delta_out_of_range",
                            })?;
                        cursor += 1;
                    }
                    PacketStatus::LargeDelta => {
                        ensure_room(cursor + 2, out.len())?;
                        out[cursor..cursor + 2].copy_from_slice(&delta_ticks.to_be_bytes());
                        cursor += 2;
                    }
                    PacketStatus::NotReceived => {}
                }
                previous = received_at;
            }
        }

        while !cursor.is_multiple_of(4) {
            ensure_room(cursor + 1, out.len())?;
            out[cursor] = 0;
            cursor += 1;
        }

        out[0] = (RTCP_VERSION << 6) | TRANSPORT_CC_FMT;
        out[1] = RTPFB_PACKET_TYPE;
        let words_minus_one =
            u16::try_from(cursor / 4 - 1).map_err(|_error| CcError::PacketTooLarge {
                len: cursor,
                max: MAX_TWCC_FEEDBACK_BYTES,
            })?;
        write_u16(&mut out[2..4], words_minus_one);
        write_u32(&mut out[4..8], self.sender_ssrc);
        write_u32(&mut out[8..12], self.media_ssrc);
        write_u16(&mut out[12..14], self.base_sequence.as_u16());
        write_u16(
            &mut out[14..16],
            u16::try_from(self.records.len()).map_err(|_error| CcError::MalformedTwcc {
                reason: "packet_count_too_large",
            })?,
        );
        write_reference_time(&mut out[16..19], self.reference_time)?;
        out[19] = self.feedback_count;
        Ok(cursor)
    }

    /// Returns the sender SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert_eq!(TwccRecorder::new(1, 2).sender_ssrc(), 1);
    /// ```
    #[must_use]
    pub const fn sender_ssrc(&self) -> u32 {
        self.sender_ssrc
    }

    /// Returns the media SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert_eq!(TwccRecorder::new(1, 2).media_ssrc(), 2);
    /// ```
    #[must_use]
    pub const fn media_ssrc(&self) -> u32 {
        self.media_ssrc
    }

    /// Returns the feedback packet count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(1), Duration::ZERO)?;
    /// assert_eq!(recorder.build_feedback(7)?.feedback_count(), 7);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    #[must_use]
    pub const fn feedback_count(&self) -> u8 {
        self.feedback_count
    }

    /// Returns decoded packet records.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(1), Duration::ZERO)?;
    /// assert_eq!(recorder.build_feedback(0)?.records().len(), 1);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    #[must_use]
    pub const fn records(&self) -> &[TwccPacketRecord] {
        self.records.as_slice()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{Stability, TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(1), Duration::ZERO)?;
    /// assert_eq!(recorder.build_feedback(0)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Ingress recorder for transport-cc sequence arrivals.
#[derive(Debug, Clone)]
pub struct TwccRecorder {
    sender_ssrc: u32,
    media_ssrc: u32,
    records: Vec<TwccPacketRecord>,
}

impl TwccRecorder {
    /// Creates an empty recorder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert_eq!(TwccRecorder::new(1, 2).sender_ssrc(), 1);
    /// ```
    #[must_use]
    pub const fn new(sender_ssrc: u32, media_ssrc: u32) -> Self {
        Self {
            sender_ssrc,
            media_ssrc,
            records: Vec::new(),
        }
    }

    /// Records one received packet arrival.
    ///
    /// # Errors
    ///
    /// Returns [`CcError::MalformedTwcc`] when more than [`MAX_TWCC_PACKETS`]
    /// would be retained, or [`CcError::Allocation`] if bounded preallocation
    /// fails outside the packet hot path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(4), Duration::ZERO)?;
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    pub fn record(&mut self, sequence: TwccSequenceNumber, received_at: Duration) -> CcResult<()> {
        if self.records.len() == MAX_TWCC_PACKETS {
            return Err(CcError::MalformedTwcc {
                reason: "packet_count_too_large",
            });
        }
        if self.records.capacity() == self.records.len() {
            self.records
                .try_reserve_exact(1)
                .map_err(|source| CcError::Allocation {
                    component: "twcc_recorder",
                    source,
                })?;
        }
        self.records
            .push(TwccPacketRecord::received(sequence, received_at));
        Ok(())
    }

    /// Builds feedback from retained records and clears the recorder.
    ///
    /// # Errors
    ///
    /// Returns [`CcError`] when no records are available.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{TwccRecorder, TwccSequenceNumber};
    /// let mut recorder = TwccRecorder::new(1, 2);
    /// recorder.record(TwccSequenceNumber::new(1), Duration::ZERO)?;
    /// assert_eq!(recorder.build_feedback(0)?.records().len(), 1);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    pub fn build_feedback(&mut self, feedback_count: u8) -> CcResult<TwccFeedback> {
        if self.records.is_empty() {
            return Err(CcError::MalformedTwcc {
                reason: "no_records",
            });
        }
        self.records.sort_by_key(|record| record.sequence.as_u16());
        let base_sequence = self.records[0].sequence;
        let reference_time = reference_time_for(self.records.as_slice())?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.records.len())
            .map_err(|source| CcError::Allocation {
                component: "twcc_feedback",
                source,
            })?;
        records.extend(self.records.iter().copied());
        self.records.clear();

        Ok(TwccFeedback {
            sender_ssrc: self.sender_ssrc,
            media_ssrc: self.media_ssrc,
            base_sequence,
            feedback_count,
            reference_time,
            records,
        })
    }

    /// Returns the sender SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert_eq!(TwccRecorder::new(9, 10).sender_ssrc(), 9);
    /// ```
    #[must_use]
    pub const fn sender_ssrc(&self) -> u32 {
        self.sender_ssrc
    }

    /// Returns the media SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert_eq!(TwccRecorder::new(9, 10).media_ssrc(), 10);
    /// ```
    #[must_use]
    pub const fn media_ssrc(&self) -> u32 {
        self.media_ssrc
    }

    /// Returns retained record count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert_eq!(TwccRecorder::new(1, 2).len(), 0);
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether the recorder is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::TwccRecorder;
    /// assert!(TwccRecorder::new(1, 2).is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Stability, TwccRecorder};
    /// assert_eq!(TwccRecorder::new(1, 2).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusRun {
    status: PacketStatus,
    len: usize,
}

fn status_runs(records: &[TwccPacketRecord]) -> impl Iterator<Item = StatusRun> + '_ {
    let mut index = 0;
    std::iter::from_fn(move || {
        let first = records.get(index)?;
        let status = status_for_record(first);
        let mut len = 1;
        while index + len < records.len()
            && status_for_record(&records[index + len]) == status
            && len < 0x1fff
        {
            len += 1;
        }
        index += len;
        Some(StatusRun { status, len })
    })
}

const fn status_for_record(record: &TwccPacketRecord) -> PacketStatus {
    if record.received_at.is_none() {
        return PacketStatus::NotReceived;
    }
    record.status
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedTwccHeader {
    sender_ssrc: u32,
    media_ssrc: u32,
    base_sequence: TwccSequenceNumber,
    packet_count: usize,
    reference_time: Duration,
    feedback_count: u8,
}

impl ParsedTwccHeader {
    fn parse(bytes: &[u8]) -> Self {
        Self {
            sender_ssrc: read_u32(&bytes[4..8]),
            media_ssrc: read_u32(&bytes[8..12]),
            base_sequence: TwccSequenceNumber::new(read_u16(&bytes[12..14])),
            packet_count: usize::from(read_u16(&bytes[14..16])),
            reference_time: read_reference_time(&bytes[16..19]),
            feedback_count: bytes[19],
        }
    }
}

fn validate_rtcp_packet(bytes: &[u8]) -> CcResult<()> {
    if bytes.len() > MAX_TWCC_FEEDBACK_BYTES {
        return Err(CcError::PacketTooLarge {
            len: bytes.len(),
            max: MAX_TWCC_FEEDBACK_BYTES,
        });
    }
    if bytes.len() < HEADER_LEN + FCI_FIXED_LEN {
        return Err(CcError::MalformedTwcc {
            reason: "packet_too_short",
        });
    }
    if bytes[0] >> 6 != RTCP_VERSION
        || bytes[1] != RTPFB_PACKET_TYPE
        || bytes[0] & 0x1f != TRANSPORT_CC_FMT
    {
        return Err(CcError::MalformedTwcc {
            reason: "unexpected_rtcp_header",
        });
    }
    let declared_len = (usize::from(read_u16(&bytes[2..4])) + 1) * 4;
    if declared_len != bytes.len() {
        return Err(CcError::MalformedTwcc {
            reason: "length_mismatch",
        });
    }
    Ok(())
}

fn decode_statuses(
    bytes: &[u8],
    packet_count: usize,
    cursor: &mut usize,
) -> CcResult<Vec<PacketStatus>> {
    let mut statuses = Vec::new();
    statuses
        .try_reserve_exact(packet_count)
        .map_err(|source| CcError::Allocation {
            component: "twcc_statuses",
            source,
        })?;

    while statuses.len() < packet_count {
        if *cursor + CHUNK_LEN > bytes.len() {
            return Err(CcError::MalformedTwcc {
                reason: "status_chunk_truncated",
            });
        }
        let chunk = read_u16(&bytes[*cursor..*cursor + CHUNK_LEN]);
        *cursor += CHUNK_LEN;
        decode_status_chunk(chunk, packet_count, &mut statuses)?;
    }

    Ok(statuses)
}

fn decode_records(
    bytes: &[u8],
    base_sequence: TwccSequenceNumber,
    reference_time: Duration,
    statuses: Vec<PacketStatus>,
    mut cursor: usize,
) -> CcResult<Vec<TwccPacketRecord>> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(statuses.len())
        .map_err(|source| CcError::Allocation {
            component: "twcc_records",
            source,
        })?;
    let mut arrival = reference_time;

    for (index, status) in statuses.into_iter().enumerate() {
        let received_at = decode_delta(bytes, status, &mut cursor, &mut arrival)?;
        let sequence = base_sequence.wrapping_add(u16::try_from(index).map_err(|_error| {
            CcError::MalformedTwcc {
                reason: "sequence_offset_overflow",
            }
        })?);
        records.push(TwccPacketRecord {
            sequence,
            status,
            received_at,
        });
    }

    Ok(records)
}

fn decode_delta(
    bytes: &[u8],
    status: PacketStatus,
    cursor: &mut usize,
    arrival: &mut Duration,
) -> CcResult<Option<Duration>> {
    match status {
        PacketStatus::NotReceived => Ok(None),
        PacketStatus::SmallDelta => {
            if *cursor >= bytes.len() {
                return Err(CcError::MalformedTwcc {
                    reason: "small_delta_truncated",
                });
            }
            let ticks = i16::from(bytes[*cursor]);
            *cursor += 1;
            *arrival = add_delta(*arrival, ticks);
            Ok(Some(*arrival))
        }
        PacketStatus::LargeDelta => {
            if *cursor + 2 > bytes.len() {
                return Err(CcError::MalformedTwcc {
                    reason: "large_delta_truncated",
                });
            }
            let ticks = i16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
            *cursor += 2;
            *arrival = add_delta(*arrival, ticks);
            Ok(Some(*arrival))
        }
    }
}

fn encode_run_chunk(status: PacketStatus, len: usize) -> CcResult<u16> {
    let symbol = match status {
        PacketStatus::NotReceived => STATUS_NOT_RECEIVED,
        PacketStatus::SmallDelta => STATUS_SMALL_DELTA,
        PacketStatus::LargeDelta => STATUS_LARGE_DELTA,
    };
    let run_len = u16::try_from(len).map_err(|_error| CcError::MalformedTwcc {
        reason: "run_too_large",
    })?;
    Ok((symbol << 13) | (run_len & 0x1fff))
}

fn decode_status_chunk(
    chunk: u16,
    packet_count: usize,
    statuses: &mut Vec<PacketStatus>,
) -> CcResult<()> {
    if chunk & 0x8000 != 0 {
        return decode_vector_chunk(chunk, packet_count, statuses);
    }
    let symbol = (chunk >> 13) & 0x03;
    let len = usize::from(chunk & 0x1fff);
    let status = decode_status_symbol(symbol)?;
    let remaining = packet_count.saturating_sub(statuses.len());
    statuses.extend(std::iter::repeat_n(status, len.min(remaining)));
    Ok(())
}

fn decode_vector_chunk(
    chunk: u16,
    packet_count: usize,
    statuses: &mut Vec<PacketStatus>,
) -> CcResult<()> {
    if chunk & 0x4000 == 0 {
        for bit in (0..14).rev() {
            if statuses.len() == packet_count {
                return Ok(());
            }
            let symbol = (chunk >> bit) & 0x01;
            statuses.push(decode_status_symbol(symbol)?);
        }
        return Ok(());
    }

    for index in 0..7 {
        if statuses.len() == packet_count {
            return Ok(());
        }
        let shift = 12 - index * 2;
        let symbol = (chunk >> shift) & 0x03;
        statuses.push(decode_status_symbol(symbol)?);
    }
    Ok(())
}

const fn decode_status_symbol(symbol: u16) -> CcResult<PacketStatus> {
    match symbol {
        STATUS_NOT_RECEIVED => Ok(PacketStatus::NotReceived),
        STATUS_SMALL_DELTA => Ok(PacketStatus::SmallDelta),
        STATUS_LARGE_DELTA => Ok(PacketStatus::LargeDelta),
        _ => Err(CcError::MalformedTwcc {
            reason: "reserved_status_symbol",
        }),
    }
}

fn reference_time_for(records: &[TwccPacketRecord]) -> CcResult<Duration> {
    let Some(first) = records.iter().find_map(|record| record.received_at) else {
        return Err(CcError::MalformedTwcc {
            reason: "no_received_packets",
        });
    };
    let micros = first.as_micros();
    let ref_micros = (micros / REF_TIME_TICK_US) * REF_TIME_TICK_US;
    let ref_u64 = u64::try_from(ref_micros).map_err(|_error| CcError::MalformedTwcc {
        reason: "reference_time_overflow",
    })?;
    Ok(Duration::from_micros(ref_u64))
}

fn delta_ticks(previous: Duration, current: Duration) -> CcResult<i16> {
    let previous_us =
        i128::try_from(previous.as_micros()).map_err(|_error| CcError::MalformedTwcc {
            reason: "delta_overflow",
        })?;
    let current_us =
        i128::try_from(current.as_micros()).map_err(|_error| CcError::MalformedTwcc {
            reason: "delta_overflow",
        })?;
    let ticks = (current_us - previous_us) / i128::from(SMALL_DELTA_TICK_US);
    i16::try_from(ticks).map_err(|_error| CcError::MalformedTwcc {
        reason: "delta_out_of_range",
    })
}

fn delta_status(ticks: i16) -> CcResult<PacketStatus> {
    if (SMALL_DELTA_MIN_TICKS..=SMALL_DELTA_MAX_TICKS).contains(&ticks) {
        return Ok(PacketStatus::SmallDelta);
    }
    if (LARGE_DELTA_MIN_TICKS..=LARGE_DELTA_MAX_TICKS).contains(&ticks) {
        return Ok(PacketStatus::LargeDelta);
    }
    Err(CcError::MalformedTwcc {
        reason: "delta_out_of_range",
    })
}

fn add_delta(base: Duration, ticks: i16) -> Duration {
    let micros = i128::try_from(base.as_micros()).unwrap_or(i128::MAX)
        + i128::from(ticks) * i128::from(SMALL_DELTA_TICK_US);
    Duration::from_micros(u64::try_from(micros.max(0)).unwrap_or(u64::MAX))
}

fn ensure_room(needed: usize, capacity: usize) -> CcResult<()> {
    if needed > capacity || needed > MAX_TWCC_FEEDBACK_BYTES {
        return Err(CcError::PacketTooLarge {
            len: needed,
            max: capacity.min(MAX_TWCC_FEEDBACK_BYTES),
        });
    }
    Ok(())
}

fn read_reference_time(bytes: &[u8]) -> Duration {
    let ticks = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    Duration::from_micros(u64::from(ticks) * 64_000)
}

fn write_reference_time(bytes: &mut [u8], time: Duration) -> CcResult<()> {
    let ticks = time.as_micros() / REF_TIME_TICK_US;
    if ticks > 0x00ff_ffff {
        return Err(CcError::MalformedTwcc {
            reason: "reference_time_out_of_range",
        });
    }
    let ticks_u32 = u32::try_from(ticks).map_err(|_error| CcError::MalformedTwcc {
        reason: "reference_time_out_of_range",
    })?;
    bytes[0] = u8::try_from((ticks_u32 >> 16) & 0xff).map_err(|_error| CcError::MalformedTwcc {
        reason: "reference_time_out_of_range",
    })?;
    bytes[1] = u8::try_from((ticks_u32 >> 8) & 0xff).map_err(|_error| CcError::MalformedTwcc {
        reason: "reference_time_out_of_range",
    })?;
    bytes[2] = u8::try_from(ticks_u32 & 0xff).map_err(|_error| CcError::MalformedTwcc {
        reason: "reference_time_out_of_range",
    })?;
    Ok(())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

const fn write_u16(bytes: &mut [u8], value: u16) {
    let [high, low] = value.to_be_bytes();
    bytes[0] = high;
    bytes[1] = low;
}

const fn write_u32(bytes: &mut [u8], value: u32) {
    let [first, second, third, fourth] = value.to_be_bytes();
    bytes[0] = first;
    bytes[1] = second;
    bytes[2] = third;
    bytes[3] = fourth;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_parses_transport_cc_feedback() {
        let mut recorder = TwccRecorder::new(0x1111_1111, 0x2222_2222);
        recorder
            .record(TwccSequenceNumber::new(100), Duration::from_millis(64))
            .unwrap();
        recorder
            .record(TwccSequenceNumber::new(101), Duration::from_millis(65))
            .unwrap();
        let feedback = recorder.build_feedback(9).unwrap();
        let mut bytes = [0_u8; MAX_TWCC_FEEDBACK_BYTES];
        let len = feedback.encode(&mut bytes).unwrap();

        let parsed = TwccFeedback::parse(&bytes[..len]).unwrap();
        assert_eq!(parsed.sender_ssrc(), 0x1111_1111);
        assert_eq!(parsed.media_ssrc(), 0x2222_2222);
        assert_eq!(parsed.feedback_count(), 9);
        assert_eq!(parsed.records().len(), 2);
        assert_eq!(
            parsed.records()[1].received_at,
            Some(Duration::from_millis(65))
        );
    }

    #[test]
    fn rejects_malformed_feedback() {
        assert!(matches!(
            TwccFeedback::parse(&[0; 3]),
            Err(CcError::MalformedTwcc {
                reason: "packet_too_short"
            })
        ));
    }

    #[test]
    fn parses_one_bit_status_vector_chunk() {
        let bytes = [
            0x8f, 205, 0, 5, 0, 0, 0, 1, 0, 0, 0, 2, 0, 7, 0, 3, 0, 0, 0, 1, 0xa8, 0, 0, 4,
        ];

        let parsed = TwccFeedback::parse(&bytes).unwrap();

        assert_eq!(parsed.sender_ssrc(), 1);
        assert_eq!(parsed.media_ssrc(), 2);
        assert_eq!(parsed.records().len(), 3);
        assert_eq!(parsed.records()[0].status, PacketStatus::SmallDelta);
        assert_eq!(parsed.records()[1].status, PacketStatus::NotReceived);
        assert_eq!(parsed.records()[2].status, PacketStatus::SmallDelta);
        assert_eq!(
            parsed.records()[2].received_at,
            Some(Duration::from_millis(1))
        );
    }
}
