//! UDP payload classification for WebRTC demultiplexing at the XDP boundary.
//!
//! The classifier follows the RFC 7983 first-byte ranges used to demultiplex
//! STUN, DTLS, RTP, and RTCP over one UDP 5-tuple.
//!
//! # Examples
//!
//! ```
//! use refract_xdp::{PacketClass, classify_udp_payload};
//!
//! assert_eq!(classify_udp_payload(&[22, 0xfe, 0xfd]), PacketClass::Dtls);
//! assert_eq!(classify_udp_payload(&[0x80, 0, 0, 0]), PacketClass::Srtp);
//! ```

use crate::wire::STUN_MAGIC_COOKIE;

const STUN_HEADER_LEN: usize = 20;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_METHOD_MASK: u16 = 0x3eef;

/// UDP payload class accepted or rejected by the XDP filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketClass {
    /// STUN binding request subject to per-source rate limiting.
    StunBinding,
    /// STUN packet that is not a binding request.
    StunOther,
    /// DTLS packet.
    Dtls,
    /// SRTP or SRTCP packet.
    Srtp,
    /// UDP payload that does not belong on the media port.
    Unsupported,
}

/// Classifies a UDP payload before the SFU socket receives it.
///
/// # Examples
///
/// ```
/// use refract_xdp::{PacketClass, classify_udp_payload};
///
/// assert_eq!(classify_udp_payload(&[0xff]), PacketClass::Unsupported);
/// ```
#[must_use]
pub fn classify_udp_payload(payload: &[u8]) -> PacketClass {
    match payload.first().copied() {
        Some(0..=3) if is_stun(payload) => classify_stun(payload),
        Some(20..=63) => PacketClass::Dtls,
        Some(128..=191) => PacketClass::Srtp,
        _ => PacketClass::Unsupported,
    }
}

fn classify_stun(payload: &[u8]) -> PacketClass {
    let message_type = u16::from_be_bytes([payload[0], payload[1]]);
    if message_type & STUN_METHOD_MASK == STUN_BINDING_REQUEST {
        PacketClass::StunBinding
    } else {
        PacketClass::StunOther
    }
}

fn is_stun(payload: &[u8]) -> bool {
    payload.len() >= STUN_HEADER_LEN
        && u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) == STUN_MAGIC_COOKIE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun_packet(message_type: u16) -> [u8; STUN_HEADER_LEN] {
        let mut packet = [0_u8; STUN_HEADER_LEN];
        packet[0..2].copy_from_slice(&message_type.to_be_bytes());
        packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet
    }

    #[test]
    fn classifies_binding_request() {
        assert_eq!(
            classify_udp_payload(&stun_packet(STUN_BINDING_REQUEST)),
            PacketClass::StunBinding
        );
    }

    #[test]
    fn classifies_non_binding_stun() {
        assert_eq!(
            classify_udp_payload(&stun_packet(0x0003)),
            PacketClass::StunOther
        );
    }

    #[test]
    fn rejects_short_stun_like_packet() {
        assert_eq!(
            classify_udp_payload(&[0, 1, 0, 0]),
            PacketClass::Unsupported
        );
    }

    #[test]
    fn classifies_dtls_and_srtp_ranges() {
        assert_eq!(classify_udp_payload(&[20]), PacketClass::Dtls);
        assert_eq!(classify_udp_payload(&[63]), PacketClass::Dtls);
        assert_eq!(classify_udp_payload(&[128]), PacketClass::Srtp);
        assert_eq!(classify_udp_payload(&[191]), PacketClass::Srtp);
    }
}
