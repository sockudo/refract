//! RTP padding validation and stripping for pacer-owned buffers.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::pad_strip::strip_padding;
//! let mut packet = [0xa0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 9, 0, 2];
//! let len = strip_padding(&packet)?;
//! assert_eq!(len, 13);
//! # Ok::<(), refract_rtp::RtpError>(())
//! ```

use crate::{RtpError, RtpResult, Stability, header::RtpHeader};

/// Returns the packet length after removing RTP padding.
///
/// This function validates the full RTP header first so attacker-controlled
/// padding bytes cannot underflow or strip header bytes.
///
/// # Errors
///
/// Returns the same parse errors as [`RtpHeader::parse`].
///
/// # Examples
///
/// ```
/// # use refract_rtp::pad_strip::strip_padding;
/// let packet = [0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7];
/// assert_eq!(strip_padding(&packet)?, packet.len());
/// # Ok::<(), refract_rtp::RtpError>(())
/// ```
pub fn strip_padding(packet: &[u8]) -> RtpResult<usize> {
    let header = RtpHeader::parse(packet)?;
    if !header.padding() {
        return Ok(packet.len());
    }
    let Some(&last) = packet.last() else {
        return Err(RtpError::PacketTooShort { len: packet.len() });
    };
    Ok(packet.len() - usize::from(last))
}

/// Adds RTP padding in place and returns the new packet length.
///
/// The caller owns the backing buffer and supplies the currently valid packet
/// length. Padding bytes are set to zero except the final RTP padding count.
///
/// # Errors
///
/// Returns an error when the current packet is invalid, `padding_len` is zero,
/// or the buffer has insufficient remaining capacity.
///
/// # Examples
///
/// ```
/// # use refract_rtp::pad_strip::add_padding;
/// let mut packet = [0_u8; 16];
/// packet[..12].copy_from_slice(&[0x80, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
/// assert_eq!(add_padding(&mut packet, 12, 4)?, 16);
/// assert_eq!(packet[0] & 0x20, 0x20);
/// # Ok::<(), refract_rtp::RtpError>(())
/// ```
pub fn add_padding(packet: &mut [u8], len: usize, padding_len: u8) -> RtpResult<usize> {
    if padding_len == 0 {
        return Err(RtpError::ZeroPadding);
    }
    if len > packet.len() {
        return Err(RtpError::PacketTooShort { len });
    }
    RtpHeader::parse(&packet[..len])?;
    let padding = usize::from(padding_len);
    let Some(new_len) = len.checked_add(padding) else {
        return Err(RtpError::RewriteNoSpace {
            needed: padding,
            available: 0,
        });
    };
    if new_len > packet.len() {
        return Err(RtpError::RewriteNoSpace {
            needed: padding,
            available: packet.len() - len,
        });
    }
    packet[0] |= 0x20;
    packet[len..new_len].fill(0);
    packet[new_len - 1] = padding_len;
    Ok(new_len)
}

/// Returns the Stage 1 stability marker for this public module API.
///
/// # Examples
///
/// ```
/// # use refract_rtp::{pad_strip::stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> Stability {
    Stability::Stage1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_and_strips_padding() {
        let mut packet = [0_u8; 16];
        packet[..12].copy_from_slice(&[0x80, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]);
        let len = add_padding(&mut packet, 12, 4).expect("padding fits");
        assert_eq!(len, 16);
        assert_eq!(strip_padding(&packet[..len]).expect("valid padding"), 12);
    }
}
