//! Borrowed RTP header views with defensive length validation.
//!
//! `RtpHeader` borrows a caller-owned packet and exposes raw-bit RTP header
//! fields without allocating.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::header::RtpHeader;
//! let packet = [
//!     0x80, 0xe0, 0, 1, 0, 0, 0, 42, 0x11, 0x22, 0x33, 0x44,
//!     0xaa, 0xbb,
//! ];
//! let header = RtpHeader::parse(&packet)?;
//! assert!(header.marker());
//! assert_eq!(header.payload(), &[0xaa, 0xbb]);
//! # Ok::<(), refract_rtp::RtpError>(())
//! ```

use crate::error::RtpResult;
use crate::{RtpError, Stability};

/// Fixed RTP header length in bytes.
pub const FIXED_HEADER_LEN: usize = 12;

/// Maximum bounded RTP packet length accepted by this crate.
pub const MAX_RTP_PACKET_LEN: usize = 1_500;

const RTP_VERSION: u8 = 2;
const VERSION_SHIFT: u8 = 6;
const PADDING_MASK: u8 = 0x20;
const EXTENSION_MASK: u8 = 0x10;
const CC_MASK: u8 = 0x0f;
const MARKER_MASK: u8 = 0x80;
const PAYLOAD_TYPE_MASK: u8 = 0x7f;
const CSRC_LEN: usize = 4;
const EXTENSION_HEADER_LEN: usize = 4;

/// Borrowed view over a validated RTP packet.
#[derive(Debug, Clone, Copy)]
pub struct RtpHeader<'a> {
    packet: &'a [u8],
    header_len: usize,
    payload_end: usize,
    extension: Option<RtpExtensionBlock<'a>>,
}

/// Owned RTP header snapshot for code that must keep fields after packet reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRtpHeader {
    version: u8,
    padding: bool,
    extension: bool,
    cc: u8,
    marker: bool,
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    csrcs: Vec<u32>,
    header_len: usize,
    payload_len: usize,
}

/// Borrowed RTP header extension block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpExtensionBlock<'a> {
    profile: u16,
    payload: &'a [u8],
}

impl<'a> RtpHeader<'a> {
    /// Parses and validates a borrowed RTP packet.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet is oversized, too short, uses a
    /// non-RTP-v2 version, has truncated CSRC or extension data, or carries
    /// invalid padding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 7, 0, 0, 0, 1, 0, 0, 0, 2];
    /// assert_eq!(RtpHeader::parse(&packet)?.ssrc(), 2);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use = "parsing validates attacker-controlled RTP bytes"]
    pub fn parse(packet: &'a [u8]) -> RtpResult<Self> {
        if packet.len() > MAX_RTP_PACKET_LEN {
            return Err(RtpError::PacketTooLarge {
                len: packet.len(),
                max: MAX_RTP_PACKET_LEN,
            });
        }
        if packet.len() < FIXED_HEADER_LEN {
            return Err(RtpError::PacketTooShort { len: packet.len() });
        }

        let version = packet[0] >> VERSION_SHIFT;
        if version != RTP_VERSION {
            return Err(RtpError::InvalidVersion { version });
        }

        let cc = packet[0] & CC_MASK;
        let csrc_len = usize::from(cc) * CSRC_LEN;
        let remaining_after_fixed = packet.len() - FIXED_HEADER_LEN;
        if csrc_len > remaining_after_fixed {
            return Err(RtpError::CsrcListTruncated {
                cc,
                remaining: remaining_after_fixed,
            });
        }

        let mut cursor = FIXED_HEADER_LEN + csrc_len;
        let extension = if packet[0] & EXTENSION_MASK == EXTENSION_MASK {
            let remaining = packet.len() - cursor;
            if remaining < EXTENSION_HEADER_LEN {
                return Err(RtpError::ExtensionHeaderTruncated { remaining });
            }
            let profile = read_u16(&packet[cursor..cursor + 2]);
            let words = read_u16(&packet[cursor + 2..cursor + 4]);
            cursor += EXTENSION_HEADER_LEN;
            let payload_len = usize::from(words) * CSRC_LEN;
            let remaining = packet.len() - cursor;
            if payload_len > remaining {
                return Err(RtpError::ExtensionPayloadTruncated { words, remaining });
            }
            let payload = &packet[cursor..cursor + payload_len];
            cursor += payload_len;
            Some(RtpExtensionBlock { profile, payload })
        } else {
            None
        };

        let padding_len = if packet[0] & PADDING_MASK == PADDING_MASK {
            let Some(&last) = packet.last() else {
                return Err(RtpError::PacketTooShort { len: packet.len() });
            };
            let padding = usize::from(last);
            if padding == 0 {
                return Err(RtpError::ZeroPadding);
            }
            let remaining = packet.len() - cursor;
            if padding > remaining {
                return Err(RtpError::PaddingTooLarge { padding, remaining });
            }
            padding
        } else {
            0
        };

        Ok(Self {
            packet,
            header_len: cursor,
            payload_end: packet.len() - padding_len,
            extension,
        })
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{header::RtpHeader, Stability};
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    /// Copies the validated header fields into an owned snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 5, 0, 0, 0, 0, 0, 0, 0, 9];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().sequence(), 5);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub fn to_owned(self) -> OwnedRtpHeader {
        OwnedRtpHeader {
            version: self.version(),
            padding: self.padding(),
            extension: self.has_extension(),
            cc: self.cc(),
            marker: self.marker(),
            payload_type: self.payload_type(),
            sequence: self.sequence(),
            timestamp: self.timestamp(),
            ssrc: self.ssrc(),
            csrcs: self.csrcs().collect(),
            header_len: self.header_len,
            payload_len: self.payload().len(),
        }
    }

    /// Returns the RTP version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.version(), 2);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn version(self) -> u8 {
        self.packet[0] >> VERSION_SHIFT
    }

    /// Returns whether RTP padding is set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(!RtpHeader::parse(&packet)?.padding());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn padding(self) -> bool {
        self.packet[0] & PADDING_MASK == PADDING_MASK
    }

    /// Returns whether the RTP header extension bit is set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(!RtpHeader::parse(&packet)?.has_extension());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn has_extension(self) -> bool {
        self.packet[0] & EXTENSION_MASK == EXTENSION_MASK
    }

    /// Returns the CSRC count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.cc(), 0);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn cc(self) -> u8 {
        self.packet[0] & CC_MASK
    }

    /// Returns the marker bit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(RtpHeader::parse(&packet)?.marker());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn marker(self) -> bool {
        self.packet[1] & MARKER_MASK == MARKER_MASK
    }

    /// Returns the RTP payload type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.payload_type(), 111);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        self.packet[1] & PAYLOAD_TYPE_MASK
    }

    /// Returns the RTP sequence number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.sequence(), 0x1234);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn sequence(self) -> u16 {
        read_u16_const(self.packet, 2)
    }

    /// Returns the RTP timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 42, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.timestamp(), 42);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn timestamp(self) -> u32 {
        read_u32_const(self.packet, 4)
    }

    /// Returns the RTP SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
    /// assert_eq!(RtpHeader::parse(&packet)?.ssrc(), 0xaabbccdd);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn ssrc(self) -> u32 {
        read_u32_const(self.packet, 8)
    }

    /// Iterates over CSRC identifiers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x81, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9];
    /// assert_eq!(RtpHeader::parse(&packet)?.csrcs().collect::<Vec<_>>(), vec![9]);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub fn csrcs(self) -> CsrcIter<'a> {
        CsrcIter {
            bytes: &self.packet
                [FIXED_HEADER_LEN..FIXED_HEADER_LEN + usize::from(self.cc()) * CSRC_LEN],
        }
    }

    /// Returns the optional RTP extension block.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(RtpHeader::parse(&packet)?.extension().is_none());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn extension(self) -> Option<RtpExtensionBlock<'a>> {
        self.extension
    }

    /// Returns the complete validated packet bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.packet(), packet);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn packet(self) -> &'a [u8] {
        self.packet
    }

    /// Returns payload bytes after RTP header extensions and before padding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 8];
    /// assert_eq!(RtpHeader::parse(&packet)?.payload(), &[7, 8]);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.packet[self.header_len..self.payload_end]
    }

    /// Returns the validated RTP header length including CSRC and extensions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::{RtpHeader, FIXED_HEADER_LEN};
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.header_len(), FIXED_HEADER_LEN);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn header_len(self) -> usize {
        self.header_len
    }
}

impl OwnedRtpHeader {
    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{header::RtpHeader, Stability};
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().stability(), Stability::Stage1);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    /// Returns the copied RTP version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().version(), 2);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns whether the copied RTP header had padding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(!RtpHeader::parse(&packet)?.to_owned().padding());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn padding(&self) -> bool {
        self.padding
    }

    /// Returns whether the copied RTP header had an extension.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(!RtpHeader::parse(&packet)?.to_owned().has_extension());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn has_extension(&self) -> bool {
        self.extension
    }

    /// Returns the copied CSRC count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().cc(), 0);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn cc(&self) -> u8 {
        self.cc
    }

    /// Returns the copied marker bit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(RtpHeader::parse(&packet)?.to_owned().marker());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn marker(&self) -> bool {
        self.marker
    }

    /// Returns the copied RTP payload type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().payload_type(), 111);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns the copied sequence number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 9, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().sequence(), 9);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn sequence(&self) -> u16 {
        self.sequence
    }

    /// Returns the copied timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().timestamp(), 7);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the copied SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().ssrc(), 8);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Returns copied CSRC identifiers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert!(RtpHeader::parse(&packet)?.to_owned().csrcs().is_empty());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub fn csrcs(&self) -> &[u32] {
        &self.csrcs
    }

    /// Returns copied header length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::{RtpHeader, FIXED_HEADER_LEN};
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().header_len(), FIXED_HEADER_LEN);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns copied payload length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 99];
    /// assert_eq!(RtpHeader::parse(&packet)?.to_owned().payload_len(), 1);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }
}

impl<'a> RtpExtensionBlock<'a> {
    /// Returns the RTP extension profile identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x90, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe, 0xde, 0, 0];
    /// assert_eq!(RtpHeader::parse(&packet)?.extension().map(|e| e.profile()), Some(0xbede));
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn profile(self) -> u16 {
        self.profile
    }

    /// Returns the extension payload bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::header::RtpHeader;
    /// let packet = [0x90, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe, 0xde, 0, 0];
    /// assert_eq!(RtpHeader::parse(&packet)?.extension().map(|e| e.payload()), Some(&[][..]));
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{header::RtpHeader, Stability};
    /// let packet = [0x90, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe, 0xde, 0, 0];
    /// assert_eq!(RtpHeader::parse(&packet)?.extension().map(|e| e.stability()), Some(Stability::Stage1));
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Iterator over validated CSRC identifiers.
#[derive(Debug, Clone)]
pub struct CsrcIter<'a> {
    bytes: &'a [u8],
}

impl Iterator for CsrcIter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < CSRC_LEN {
            return None;
        }
        let value = read_u32(&self.bytes[..CSRC_LEN]);
        self.bytes = &self.bytes[CSRC_LEN..];
        Some(value)
    }
}

impl ExactSizeIterator for CsrcIter<'_> {
    fn len(&self) -> usize {
        self.bytes.len() / CSRC_LEN
    }
}

#[inline]
pub(crate) fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[inline]
pub(crate) fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[inline]
pub(crate) const fn write_u16(bytes: &mut [u8], value: u16) {
    let encoded = value.to_be_bytes();
    bytes[0] = encoded[0];
    bytes[1] = encoded[1];
}

#[inline]
pub(crate) const fn write_u32(bytes: &mut [u8], value: u32) {
    let encoded = value.to_be_bytes();
    bytes[0] = encoded[0];
    bytes[1] = encoded[1];
    bytes[2] = encoded[2];
    bytes[3] = encoded[3];
}

#[inline]
const fn read_u16_const(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[inline]
const fn read_u32_const(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csrc_extension_and_padding() {
        let packet = [
            0xb1, 0xe0, 0x12, 0x34, 0, 0, 0, 9, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 7, 0xbe, 0xde, 0,
            1, 0x10, 0xaa, 0, 0, 1, 2, 0, 2,
        ];
        let header = RtpHeader::parse(&packet).expect("valid rtp packet");
        assert_eq!(header.version(), 2);
        assert!(header.padding());
        assert!(header.has_extension());
        assert_eq!(header.cc(), 1);
        assert!(header.marker());
        assert_eq!(header.payload_type(), 96);
        assert_eq!(header.sequence(), 0x1234);
        assert_eq!(header.timestamp(), 9);
        assert_eq!(header.ssrc(), 0xaabb_ccdd);
        assert_eq!(header.csrcs().collect::<Vec<_>>(), vec![7]);
        assert_eq!(
            header.extension().map(RtpExtensionBlock::profile),
            Some(0xbede)
        );
        assert_eq!(header.payload(), &[1, 2]);
    }

    #[test]
    fn rejects_padding_exceeding_remaining() {
        let packet = [0xa0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 13];
        assert!(matches!(
            RtpHeader::parse(&packet),
            Err(RtpError::PaddingTooLarge {
                padding: 13,
                remaining: 1
            })
        ));
    }

    #[test]
    fn rejects_truncated_extension() {
        let packet = [0x90, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe];
        assert!(matches!(
            RtpHeader::parse(&packet),
            Err(RtpError::ExtensionHeaderTruncated { remaining: 1 })
        ));
    }
}
