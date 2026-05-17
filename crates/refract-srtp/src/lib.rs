//! `SRTP` and `SRTCP` AES-GCM protection for media packets.
//!
//! The crate implements the SRTP wrapping layer around aws-lc-rs AES-GCM:
//! RTP/RTCP parsing, nonce construction, AAD construction, rollover counter
//! tracking, replay protection, bulk protection, and fanout encryption.
//!
//! # Examples
//!
//! ```
//! # use refract_srtp::{SrtpContext, SrtpKeys, SrtpProfile};
//! let keys = SrtpKeys::new(SrtpProfile::AeadAes128Gcm, [1; 32], [2; 24])?;
//! let mut ctx = SrtpContext::new(keys, 64)?;
//! let mut packet = vec![0x80, 96, 0, 1, 0, 0, 0, 7, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4];
//! ctx.egress.protect_rtp(&mut packet)?;
//! let plaintext = ctx.ingress.unprotect_rtp(&mut packet)?;
//! assert_eq!(&plaintext[12..], &[1, 2, 3, 4]);
//! # Ok::<(), refract_srtp::SrtpError>(())
//! ```

#![cfg_attr(feature = "simd", feature(portable_simd))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{collections::BTreeMap, fmt};

use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use metrics::counter;
use thiserror::Error;

const RTP_FIXED_HEADER_LEN: usize = 12;
const RTCP_MIN_LEN: usize = 8;
const SRTCP_INDEX_LEN: usize = 4;
const GCM_TAG_LEN: usize = 16;
const GCM_SALT_LEN: usize = 12;
const AES_128_KEY_LEN: usize = 16;
const AES_256_KEY_LEN: usize = 32;
const MAX_REPLAY_WINDOW: u16 = 1024;
const DEFAULT_REPLAY_WINDOW: u16 = 64;
const SRTCP_ENCRYPTED_FLAG: u32 = 0x8000_0000;
const SRTCP_INDEX_MASK: u32 = 0x7fff_ffff;

/// Result alias for SRTP operations.
pub type SrtpResult<T> = Result<T, SrtpError>;

/// SRTP protection errors with stable dashboard codes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SrtpError {
    /// Packet is too short for the requested operation.
    #[error("packet too short: len={len} minimum={minimum}")]
    PacketTooShort {
        /// Observed packet length.
        len: usize,
        /// Minimum required packet length.
        minimum: usize,
    },
    /// RTP header shape is invalid.
    #[error("invalid rtp header: reason={reason}")]
    InvalidRtp {
        /// Stable reason label.
        reason: &'static str,
    },
    /// Configured key or salt length is invalid.
    #[error("invalid key material: field={field} len={len} expected={expected}")]
    InvalidKeyMaterial {
        /// Field name.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Expected length.
        expected: usize,
    },
    /// Replay window rejected a packet.
    #[error("srtp replay rejected")]
    Replay,
    /// Authentication failed and the peer context was torn down.
    #[error("srtp authentication failed; peer torn down")]
    AuthFailure,
    /// Context is already torn down.
    #[error("srtp context torn down")]
    PeerTornDown,
    /// Output packet would exceed the configured packet buffer capacity.
    #[error("packet buffer capacity exceeded: len={len} capacity={capacity}")]
    PacketCapacity {
        /// Attempted length.
        len: usize,
        /// Fixed capacity.
        capacity: usize,
    },
    /// AEAD provider failed.
    #[error("aead failure")]
    Aead,
}

impl SrtpError {
    /// Returns the stable operations-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::SrtpError;
    /// assert_eq!(SrtpError::Replay.error_code(), "HSF-SRTP-004");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::PacketTooShort { .. } => "HSF-SRTP-001",
            Self::InvalidRtp { .. } => "HSF-SRTP-002",
            Self::InvalidKeyMaterial { .. } => "HSF-SRTP-003",
            Self::Replay => "HSF-SRTP-004",
            Self::AuthFailure => "HSF-SRTP-005",
            Self::PeerTornDown => "HSF-SRTP-006",
            Self::PacketCapacity { .. } => "HSF-SRTP-007",
            Self::Aead => "HSF-SRTP-008",
        }
    }
}

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns a stable label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Supported RFC 7714 SRTP profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SrtpProfile {
    /// `SRTP_AEAD_AES_128_GCM`.
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM`.
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// Returns the master key length in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::SrtpProfile;
    /// assert_eq!(SrtpProfile::AeadAes128Gcm.key_len(), 16);
    /// ```
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm => AES_128_KEY_LEN,
            Self::AeadAes256Gcm => AES_256_KEY_LEN,
        }
    }

    /// Returns the master salt length in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::SrtpProfile;
    /// assert_eq!(SrtpProfile::AeadAes256Gcm.salt_len(), 12);
    /// ```
    #[must_use]
    pub const fn salt_len(self) -> usize {
        GCM_SALT_LEN
    }

    const fn algorithm(self) -> &'static aws_lc_rs::aead::Algorithm {
        match self {
            Self::AeadAes128Gcm => &AES_128_GCM,
            Self::AeadAes256Gcm => &AES_256_GCM,
        }
    }
}

/// Bidirectional SRTP key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SrtpKeys {
    profile: SrtpProfile,
    client_key: [u8; AES_256_KEY_LEN],
    server_key: [u8; AES_256_KEY_LEN],
    client_salt: [u8; GCM_SALT_LEN],
    server_salt: [u8; GCM_SALT_LEN],
}

impl SrtpKeys {
    /// Creates key material from DTLS-SRTP exporter output split by direction.
    ///
    /// The `keys` parameter is `client_key || server_key`; `salts` is
    /// `client_salt || server_salt`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::{SrtpKeys, SrtpProfile};
    /// let keys = SrtpKeys::new(SrtpProfile::AeadAes128Gcm, [0; 32], [1; 24])?;
    /// assert_eq!(keys.profile(), SrtpProfile::AeadAes128Gcm);
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when directional key material length does not match the profile.
    pub fn new<const K: usize, const S: usize>(
        profile: SrtpProfile,
        keys: [u8; K],
        salts: [u8; S],
    ) -> SrtpResult<Self> {
        let key_len = profile.key_len();
        let salt_len = profile.salt_len();
        if K != key_len * 2 {
            return Err(SrtpError::InvalidKeyMaterial {
                field: "keys",
                len: K,
                expected: key_len * 2,
            });
        }
        if S != salt_len * 2 {
            return Err(SrtpError::InvalidKeyMaterial {
                field: "salts",
                len: S,
                expected: salt_len * 2,
            });
        }

        let mut client_key = [0; AES_256_KEY_LEN];
        let mut server_key = [0; AES_256_KEY_LEN];
        let mut client_salt = [0; GCM_SALT_LEN];
        let mut server_salt = [0; GCM_SALT_LEN];
        client_key[..key_len].copy_from_slice(&keys[..key_len]);
        server_key[..key_len].copy_from_slice(&keys[key_len..]);
        client_salt.copy_from_slice(&salts[..salt_len]);
        server_salt.copy_from_slice(&salts[salt_len..]);
        Ok(Self {
            profile,
            client_key,
            server_key,
            client_salt,
            server_salt,
        })
    }

    /// Returns the SRTP profile.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::{SrtpKeys, SrtpProfile};
    /// let keys = SrtpKeys::new(SrtpProfile::AeadAes128Gcm, [0; 32], [1; 24])?;
    /// assert_eq!(keys.profile(), SrtpProfile::AeadAes128Gcm);
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    #[must_use]
    pub const fn profile(&self) -> SrtpProfile {
        self.profile
    }
}

/// Peer SRTP context with ingress and egress state.
#[derive(Debug)]
pub struct SrtpContext {
    /// Ingress state.
    pub ingress: Ingress,
    /// Egress state.
    pub egress: Egress,
}

impl SrtpContext {
    /// Creates a peer context with client-ingress and server-egress key direction.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::{SrtpContext, SrtpKeys, SrtpProfile};
    /// let keys = SrtpKeys::new(SrtpProfile::AeadAes128Gcm, [0; 32], [1; 24])?;
    /// let ctx = SrtpContext::new(keys, 64)?;
    /// assert!(!ctx.ingress.is_torn_down());
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if replay window or AEAD key setup is invalid.
    pub fn new(keys: SrtpKeys, replay_window: u16) -> SrtpResult<Self> {
        Ok(Self {
            ingress: Ingress::new(
                keys.profile,
                &keys.client_key[..keys.profile.key_len()],
                keys.client_salt,
                replay_window,
            )?,
            egress: Egress::new(
                keys.profile,
                &keys.server_key[..keys.profile.key_len()],
                keys.server_salt,
            )?,
        })
    }
}

/// Immutable packet buffer used by bulk protection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketBuf {
    bytes: Vec<u8>,
    capacity: usize,
}

impl PacketBuf {
    /// Creates a packet buffer from bytes with capacity for an authentication tag.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::PacketBuf;
    /// let packet = PacketBuf::from_slice(&[1, 2, 3], 32)?;
    /// assert_eq!(packet.as_slice(), &[1, 2, 3]);
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds capacity.
    pub fn from_slice(bytes: &[u8], capacity: usize) -> SrtpResult<Self> {
        if bytes.len() > capacity {
            return Err(SrtpError::PacketCapacity {
                len: bytes.len(),
                capacity,
            });
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| SrtpError::PacketCapacity {
                len: capacity,
                capacity: usize::MAX,
            })?;
        output.extend_from_slice(bytes);
        Ok(Self {
            bytes: output,
            capacity,
        })
    }

    /// Returns packet bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::PacketBuf;
    /// let packet = PacketBuf::from_slice(&[1], 16)?;
    /// assert_eq!(packet.as_slice(), &[1]);
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns mutable packet bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::PacketBuf;
    /// let mut packet = PacketBuf::from_slice(&[1], 16)?;
    /// packet.as_mut_vec()[0] = 2;
    /// assert_eq!(packet.as_slice(), &[2]);
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    #[must_use]
    pub const fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    fn ensure_extra(&self, extra: usize) -> SrtpResult<()> {
        let len = self
            .bytes
            .len()
            .checked_add(extra)
            .ok_or(SrtpError::PacketCapacity {
                len: usize::MAX,
                capacity: self.capacity,
            })?;
        if len > self.capacity {
            return Err(SrtpError::PacketCapacity {
                len,
                capacity: self.capacity,
            });
        }
        Ok(())
    }
}

/// Borrowed plaintext slot used by fanout protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArcSlot<'a> {
    payload: &'a [u8],
}

impl<'a> ArcSlot<'a> {
    /// Creates a fanout plaintext slot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::ArcSlot;
    /// let slot = ArcSlot::new(&[1, 2, 3]);
    /// assert_eq!(slot.as_slice(), &[1, 2, 3]);
    /// ```
    #[must_use]
    pub const fn new(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    /// Returns the plaintext bytes for one subscriber encryption pass.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::ArcSlot;
    /// let slot = ArcSlot::new(&[7]);
    /// assert_eq!(slot.as_slice(), &[7]);
    /// ```
    #[must_use]
    pub const fn as_slice(&self) -> &'a [u8] {
        self.payload
    }
}

/// Ingress SRTP/SRTCP state.
#[derive(Debug)]
pub struct Ingress {
    key: LessSafeKey,
    salt: [u8; GCM_SALT_LEN],
    streams: BTreeMap<u32, IngressStream>,
    replay_window: u16,
    torn_down: bool,
    replay_logs_left: u8,
}

impl Ingress {
    /// Creates ingress state.
    ///
    /// # Errors
    ///
    /// Returns an error if key length or replay window is invalid.
    pub fn new(
        profile: SrtpProfile,
        key: &[u8],
        salt: [u8; GCM_SALT_LEN],
        replay_window: u16,
    ) -> SrtpResult<Self> {
        if replay_window == 0 || replay_window > MAX_REPLAY_WINDOW {
            return Err(SrtpError::InvalidKeyMaterial {
                field: "replay_window",
                len: usize::from(replay_window),
                expected: usize::from(DEFAULT_REPLAY_WINDOW),
            });
        }
        Ok(Self {
            key: make_key(profile, key)?,
            salt,
            streams: BTreeMap::new(),
            replay_window,
            torn_down: false,
            replay_logs_left: 8,
        })
    }

    /// Unprotects an RTP packet in place and returns plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for parse failure, replay, authentication failure, or torn-down peer.
    pub fn unprotect_rtp<'a>(&mut self, packet: &'a mut Vec<u8>) -> SrtpResult<&'a [u8]> {
        self.ensure_live()?;
        let header_len = rtp_header_len(packet)?;
        if packet.len() < header_len + GCM_TAG_LEN {
            return Err(SrtpError::PacketTooShort {
                len: packet.len(),
                minimum: header_len + GCM_TAG_LEN,
            });
        }
        let ssrc = read_u32(packet, 8)?;
        let sequence = read_u16(packet, 2)?;
        let stream = self.streams.entry(ssrc).or_default();
        let index = stream.estimate_index(sequence);
        if stream.replay.contains(index, self.replay_window) {
            self.record_replay();
            return Err(SrtpError::Replay);
        }

        let roc = u32::try_from(index >> 16).map_err(|_| SrtpError::InvalidRtp {
            reason: "roc_overflow",
        })?;
        let nonce = rtp_nonce(self.salt, ssrc, roc, sequence);
        let aad = rtp_aad(packet, header_len)?;
        let payload = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut packet[header_len..],
            )
            .map_err(|_| {
                self.torn_down = true;
                SrtpError::AuthFailure
            })?;
        let new_len = header_len + payload.len();
        packet.truncate(new_len);
        stream.accept(index);
        Ok(packet.as_slice())
    }

    /// Unprotects an SRTCP packet in place and returns plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for parse failure, replay, authentication failure, or torn-down peer.
    pub fn unprotect_rtcp<'a>(&mut self, packet: &'a mut Vec<u8>) -> SrtpResult<&'a [u8]> {
        self.ensure_live()?;
        if packet.len() < RTCP_MIN_LEN + SRTCP_INDEX_LEN + GCM_TAG_LEN {
            return Err(SrtpError::PacketTooShort {
                len: packet.len(),
                minimum: RTCP_MIN_LEN + SRTCP_INDEX_LEN + GCM_TAG_LEN,
            });
        }
        let ssrc = read_u32(packet, 4)?;
        let index_offset = packet.len() - SRTCP_INDEX_LEN - GCM_TAG_LEN;
        let encrypted_index = read_u32(packet, index_offset)?;
        let index = encrypted_index & SRTCP_INDEX_MASK;
        let stream = self.streams.entry(ssrc).or_default();
        if stream.replay.contains(u64::from(index), self.replay_window) {
            self.record_replay();
            return Err(SrtpError::Replay);
        }
        let nonce = rtcp_nonce(self.salt, ssrc, index);
        let aad = rtcp_aad(packet, RTCP_MIN_LEN, encrypted_index)?;
        let tag_start = packet.len() - GCM_TAG_LEN;
        let tag = packet[tag_start..].to_vec();
        packet.truncate(index_offset);
        self.key
            .open_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &tag,
                &mut packet[RTCP_MIN_LEN..],
            )
            .map_err(|_| {
                self.torn_down = true;
                SrtpError::AuthFailure
            })?;
        stream.replay.accept(u64::from(index));
        Ok(packet.as_slice())
    }

    /// Returns whether authentication failure tore down this peer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_srtp::{Ingress, SrtpProfile};
    /// let ingress = Ingress::new(SrtpProfile::AeadAes128Gcm, &[0; 16], [0; 12], 64)?;
    /// assert!(!ingress.is_torn_down());
    /// # Ok::<(), refract_srtp::SrtpError>(())
    /// ```
    #[must_use]
    pub const fn is_torn_down(&self) -> bool {
        self.torn_down
    }

    const fn ensure_live(&self) -> SrtpResult<()> {
        if self.torn_down {
            return Err(SrtpError::PeerTornDown);
        }
        Ok(())
    }

    fn record_replay(&mut self) {
        if self.replay_logs_left > 0 {
            self.replay_logs_left -= 1;
            counter!("refract.srtp.replay_rejected").increment(1);
        }
    }
}

/// Egress SRTP/SRTCP state.
#[derive(Debug)]
pub struct Egress {
    key: LessSafeKey,
    salt: [u8; GCM_SALT_LEN],
    streams: BTreeMap<u32, EgressStream>,
    rtcp_index: u32,
}

impl Egress {
    /// Creates egress state.
    ///
    /// # Errors
    ///
    /// Returns an error if key length is invalid.
    pub fn new(profile: SrtpProfile, key: &[u8], salt: [u8; GCM_SALT_LEN]) -> SrtpResult<Self> {
        Ok(Self {
            key: make_key(profile, key)?,
            salt,
            streams: BTreeMap::new(),
            rtcp_index: 0,
        })
    }

    /// Protects an RTP packet in place.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed RTP or AEAD failure.
    pub fn protect_rtp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        let header_len = rtp_header_len(packet)?;
        let ssrc = read_u32(packet, 8)?;
        let sequence = read_u16(packet, 2)?;
        let stream = self.streams.entry(ssrc).or_default();
        let roc = stream.observe(sequence);
        let nonce = rtp_nonce(self.salt, ssrc, roc, sequence);
        let aad = rtp_aad(packet, header_len)?;
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut packet[header_len..],
            )
            .map_err(|_| SrtpError::Aead)?;
        packet.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Protects an RTCP packet in place.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed RTCP or AEAD failure.
    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        if packet.len() < RTCP_MIN_LEN {
            return Err(SrtpError::PacketTooShort {
                len: packet.len(),
                minimum: RTCP_MIN_LEN,
            });
        }
        let ssrc = read_u32(packet, 4)?;
        let index = self.rtcp_index & SRTCP_INDEX_MASK;
        self.rtcp_index = self.rtcp_index.wrapping_add(1) & SRTCP_INDEX_MASK;
        let nonce = rtcp_nonce(self.salt, ssrc, index);
        let encrypted_index = index | SRTCP_ENCRYPTED_FLAG;
        let aad = rtcp_aad(packet, RTCP_MIN_LEN, encrypted_index)?;
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut packet[RTCP_MIN_LEN..],
            )
            .map_err(|_| SrtpError::Aead)?;
        packet.extend_from_slice(&encrypted_index.to_be_bytes());
        packet.extend_from_slice(tag.as_ref());
        Ok(())
    }
}

/// Protects many RTP packets while reusing one egress context.
///
/// # Errors
///
/// Returns the first packet protection error.
pub fn protect_many(packets: &mut [PacketBuf], ctx: &mut Egress) -> SrtpResult<()> {
    for packet in packets {
        packet.ensure_extra(GCM_TAG_LEN)?;
        ctx.protect_rtp(packet.as_mut_vec())?;
    }
    Ok(())
}

/// Protects the same plaintext RTP packet for many subscribers.
///
/// Encryption runs once per subscriber because each subscriber has distinct
/// SRTP keys and rollover state.
///
/// # Errors
///
/// Returns the first subscriber protection error.
pub fn protect_fanout(payload: &[u8], subs: &mut [&mut Egress]) -> SrtpResult<Vec<Vec<u8>>> {
    let plaintext = ArcSlot::new(payload);
    let packet_capacity =
        plaintext
            .as_slice()
            .len()
            .checked_add(GCM_TAG_LEN)
            .ok_or(SrtpError::PacketCapacity {
                len: usize::MAX,
                capacity: usize::MAX,
            })?;
    let mut out = Vec::new();
    out.try_reserve_exact(subs.len())
        .map_err(|_| SrtpError::PacketCapacity {
            len: subs.len(),
            capacity: usize::MAX,
        })?;
    for sub in subs {
        let mut packet = Vec::new();
        packet
            .try_reserve_exact(packet_capacity)
            .map_err(|_| SrtpError::PacketCapacity {
                len: packet_capacity,
                capacity: usize::MAX,
            })?;
        packet.extend_from_slice(plaintext.as_slice());
        sub.protect_rtp(&mut packet)?;
        out.push(packet);
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct EgressStream {
    roc: u32,
    highest_seq: Option<u16>,
}

impl EgressStream {
    const fn observe(&mut self, sequence: u16) -> u32 {
        if let Some(highest) = self.highest_seq
            && highest > 0xf000
            && sequence < 0x1000
        {
            self.roc = self.roc.wrapping_add(1);
        }
        self.highest_seq = Some(sequence);
        self.roc
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct IngressStream {
    s_l: Option<u64>,
    replay: ReplayWindow,
}

impl IngressStream {
    fn estimate_index(&self, sequence: u16) -> u64 {
        let Some(s_l) = self.s_l else {
            return u64::from(sequence);
        };
        let local_roc = s_l >> 16;
        let local_seq = u16::try_from(s_l & 0xffff).unwrap_or_default();
        let roc = if local_seq < 0x1000 && sequence > 0xf000 && local_roc > 0 {
            local_roc - 1
        } else if local_seq > 0xf000 && sequence < 0x1000 {
            local_roc + 1
        } else {
            local_roc
        };
        (roc << 16) | u64::from(sequence)
    }

    fn accept(&mut self, index: u64) {
        self.s_l = Some(self.s_l.map_or(index, |old| old.max(index)));
        self.replay.accept(index);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReplayWindow {
    highest: Option<u64>,
    mask: u128,
}

impl ReplayWindow {
    fn contains(&self, index: u64, window: u16) -> bool {
        let Some(highest) = self.highest else {
            return false;
        };
        if index > highest {
            return false;
        }
        let delta = highest - index;
        delta >= u64::from(window) || (delta < 128 && ((self.mask >> delta) & 1) == 1)
    }

    const fn accept(&mut self, index: u64) {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.mask = 1;
            }
            Some(highest) if index > highest => {
                let shift = index - highest;
                self.mask = if shift >= 128 {
                    1
                } else {
                    (self.mask << shift) | 1
                };
                self.highest = Some(index);
            }
            Some(highest) => {
                let delta = highest - index;
                if delta < 128 {
                    self.mask |= 1_u128 << delta;
                }
            }
        }
    }
}

fn make_key(profile: SrtpProfile, key: &[u8]) -> SrtpResult<LessSafeKey> {
    if key.len() != profile.key_len() {
        return Err(SrtpError::InvalidKeyMaterial {
            field: "key",
            len: key.len(),
            expected: profile.key_len(),
        });
    }
    let unbound = UnboundKey::new(profile.algorithm(), key).map_err(|_| SrtpError::Aead)?;
    Ok(LessSafeKey::new(unbound))
}

fn rtp_header_len(packet: &[u8]) -> SrtpResult<usize> {
    if packet.len() < RTP_FIXED_HEADER_LEN {
        return Err(SrtpError::PacketTooShort {
            len: packet.len(),
            minimum: RTP_FIXED_HEADER_LEN,
        });
    }
    if packet[0] >> 6 != 2 {
        return Err(SrtpError::InvalidRtp {
            reason: "version_not_two",
        });
    }
    let csrc_count = usize::from(packet[0] & 0x0f);
    let mut header_len = RTP_FIXED_HEADER_LEN + (csrc_count * 4);
    if packet.len() < header_len {
        return Err(SrtpError::PacketTooShort {
            len: packet.len(),
            minimum: header_len,
        });
    }
    if (packet[0] & 0x10) != 0 {
        if packet.len() < header_len + 4 {
            return Err(SrtpError::PacketTooShort {
                len: packet.len(),
                minimum: header_len + 4,
            });
        }
        let extension_words = usize::from(read_u16(packet, header_len + 2)?);
        header_len += 4 + (extension_words * 4);
        if packet.len() < header_len {
            return Err(SrtpError::PacketTooShort {
                len: packet.len(),
                minimum: header_len,
            });
        }
    }
    Ok(header_len)
}

fn rtp_aad(packet: &[u8], header_len: usize) -> SrtpResult<Vec<u8>> {
    if packet.len() < header_len {
        return Err(SrtpError::PacketTooShort {
            len: packet.len(),
            minimum: header_len,
        });
    }
    Ok(aad_prefix(packet, header_len))
}

fn rtcp_aad(packet: &[u8], clear_len: usize, encrypted_index: u32) -> SrtpResult<Vec<u8>> {
    if packet.len() < clear_len {
        return Err(SrtpError::PacketTooShort {
            len: packet.len(),
            minimum: clear_len,
        });
    }
    let mut aad = packet[..clear_len].to_vec();
    aad.extend_from_slice(&encrypted_index.to_be_bytes());
    Ok(aad)
}

fn aad_prefix(packet: &[u8], header_len: usize) -> Vec<u8> {
    #[cfg(feature = "simd")]
    {
        simd_copy_prefix(packet, header_len)
    }
    #[cfg(not(feature = "simd"))]
    {
        scalar_copy_prefix(packet, header_len)
    }
}

#[cfg(not(feature = "simd"))]
fn scalar_copy_prefix(packet: &[u8], header_len: usize) -> Vec<u8> {
    packet[..header_len].to_vec()
}

#[cfg(feature = "simd")]
fn simd_copy_prefix(packet: &[u8], header_len: usize) -> Vec<u8> {
    use std::simd::u8x16;

    let mut out = vec![0; header_len];
    let mut chunks = packet[..header_len].chunks_exact(16);
    for (index, chunk) in chunks.by_ref().enumerate() {
        let vec = u8x16::from_slice(chunk);
        vec.copy_to_slice(&mut out[index * 16..index * 16 + 16]);
    }
    let remainder = chunks.remainder();
    let start = header_len - remainder.len();
    out[start..].copy_from_slice(remainder);
    out
}

fn rtp_nonce(salt: [u8; GCM_SALT_LEN], ssrc: u32, roc: u32, sequence: u16) -> [u8; GCM_SALT_LEN] {
    let mut base = [0_u8; GCM_SALT_LEN];
    base[2..6].copy_from_slice(&ssrc.to_be_bytes());
    base[6..10].copy_from_slice(&roc.to_be_bytes());
    base[10..12].copy_from_slice(&sequence.to_be_bytes());
    xor_nonce(salt, base)
}

fn rtcp_nonce(salt: [u8; GCM_SALT_LEN], ssrc: u32, index: u32) -> [u8; GCM_SALT_LEN] {
    let mut base = [0_u8; GCM_SALT_LEN];
    base[2..6].copy_from_slice(&ssrc.to_be_bytes());
    base[8..12].copy_from_slice(&index.to_be_bytes());
    xor_nonce(salt, base)
}

fn xor_nonce(salt: [u8; GCM_SALT_LEN], base: [u8; GCM_SALT_LEN]) -> [u8; GCM_SALT_LEN] {
    #[cfg(feature = "simd")]
    {
        simd_xor_nonce(salt, base)
    }
    #[cfg(not(feature = "simd"))]
    {
        scalar_xor_nonce(salt, base)
    }
}

#[cfg(not(feature = "simd"))]
fn scalar_xor_nonce(salt: [u8; GCM_SALT_LEN], base: [u8; GCM_SALT_LEN]) -> [u8; GCM_SALT_LEN] {
    let mut out = [0; GCM_SALT_LEN];
    for (dst, (salt_byte, base_byte)) in out.iter_mut().zip(salt.iter().zip(base.iter())) {
        *dst = salt_byte ^ base_byte;
    }
    out
}

#[cfg(feature = "simd")]
fn simd_xor_nonce(salt: [u8; GCM_SALT_LEN], base: [u8; GCM_SALT_LEN]) -> [u8; GCM_SALT_LEN] {
    use std::simd::u8x16;

    let mut left = [0_u8; 16];
    let mut right = [0_u8; 16];
    left[..GCM_SALT_LEN].copy_from_slice(&salt);
    right[..GCM_SALT_LEN].copy_from_slice(&base);
    let vec = u8x16::from_array(left) ^ u8x16::from_array(right);
    let array = vec.to_array();
    let mut out = [0; GCM_SALT_LEN];
    out.copy_from_slice(&array[..GCM_SALT_LEN]);
    out
}

fn read_u16(packet: &[u8], offset: usize) -> SrtpResult<u16> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(SrtpError::PacketTooShort {
            len: packet.len(),
            minimum: offset + 2,
        })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> SrtpResult<u32> {
    let bytes = packet
        .get(offset..offset + 4)
        .ok_or(SrtpError::PacketTooShort {
            len: packet.len(),
            minimum: offset + 4,
        })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

impl fmt::Display for SrtpProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            Self::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> SrtpKeys {
        SrtpKeys::new(SrtpProfile::AeadAes128Gcm, [7; 32], [9; 24])
            .expect("static test keys are valid")
    }

    fn rtp(seq: u16) -> Vec<u8> {
        let mut out = vec![0x80, 96];
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&7_u32.to_be_bytes());
        out.extend_from_slice(&0xaabb_ccdd_u32.to_be_bytes());
        out.extend_from_slice(&[1, 2, 3, 4]);
        out
    }

    #[test]
    fn rtp_protect_unprotect_round_trips() -> SrtpResult<()> {
        let mut ctx = SrtpContext::new(keys(), 64)?;
        let mut packet = rtp(1);
        ctx.egress.protect_rtp(&mut packet)?;
        assert_ne!(&packet[12..16], &[1, 2, 3, 4]);

        let plain = ctx.ingress.unprotect_rtp(&mut packet)?;

        assert_eq!(&plain[12..], &[1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn rtcp_protect_unprotect_round_trips() -> SrtpResult<()> {
        let mut ctx = SrtpContext::new(keys(), 64)?;
        let mut packet = vec![0x80, 200, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4];
        ctx.egress.protect_rtcp(&mut packet)?;

        let plain = ctx.ingress.unprotect_rtcp(&mut packet)?;

        assert_eq!(
            plain,
            &[0x80, 200, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4]
        );
        Ok(())
    }

    #[test]
    fn replay_rejects_duplicate_after_reorder() -> SrtpResult<()> {
        let mut sender = SrtpContext::new(keys(), 64)?;
        let mut receiver = SrtpContext::new(keys(), 64)?;
        let mut first = rtp(1);
        let mut second = rtp(2);
        sender.egress.protect_rtp(&mut first)?;
        sender.egress.protect_rtp(&mut second)?;
        let mut first_duplicate = first.clone();

        receiver.ingress.unprotect_rtp(&mut second)?;
        receiver.ingress.unprotect_rtp(&mut first)?;
        let error = receiver
            .ingress
            .unprotect_rtp(&mut first_duplicate)
            .expect_err("duplicate is rejected");

        assert_eq!(error.error_code(), "HSF-SRTP-004");
        Ok(())
    }

    #[test]
    fn rollover_is_accepted() -> SrtpResult<()> {
        let mut sender = SrtpContext::new(keys(), 64)?;
        let mut receiver = SrtpContext::new(keys(), 64)?;
        for seq in [0xfffe, 0xffff, 0, 1] {
            let mut packet = rtp(seq);
            sender.egress.protect_rtp(&mut packet)?;
            receiver.ingress.unprotect_rtp(&mut packet)?;
        }
        Ok(())
    }

    #[test]
    fn auth_failure_tears_down_peer() -> SrtpResult<()> {
        let mut ctx = SrtpContext::new(keys(), 64)?;
        let mut packet = rtp(1);
        ctx.egress.protect_rtp(&mut packet)?;
        let last = packet.len() - 1;
        packet[last] ^= 1;

        let error = ctx
            .ingress
            .unprotect_rtp(&mut packet)
            .expect_err("auth failure");

        assert_eq!(error.error_code(), "HSF-SRTP-005");
        assert!(ctx.ingress.is_torn_down());
        Ok(())
    }

    #[test]
    fn bulk_protects_packets() -> SrtpResult<()> {
        let mut ctx = SrtpContext::new(keys(), 64)?;
        let mut packets = [
            PacketBuf::from_slice(&rtp(1), 128)?,
            PacketBuf::from_slice(&rtp(2), 128)?,
        ];

        protect_many(&mut packets, &mut ctx.egress)?;

        assert_eq!(packets[0].as_slice().len(), 32);
        assert_eq!(packets[1].as_slice().len(), 32);
        Ok(())
    }

    #[test]
    fn fanout_encrypts_once_per_subscriber() -> SrtpResult<()> {
        let mut a = SrtpContext::new(keys(), 64)?;
        let mut b = SrtpContext::new(keys(), 64)?;
        let outputs = protect_fanout(&rtp(1), &mut [&mut a.egress, &mut b.egress])?;

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].len(), 32);
        assert_eq!(outputs[1].len(), 32);
        Ok(())
    }

    #[cfg(not(feature = "simd"))]
    #[test]
    fn scalar_nonce_is_deterministic() {
        let salt = [1; GCM_SALT_LEN];
        let nonce = scalar_xor_nonce(salt, [2; GCM_SALT_LEN]);

        assert_eq!(nonce, [3; GCM_SALT_LEN]);
    }

    #[cfg(feature = "simd")]
    fn scalar_xor_nonce_for_test(
        salt: [u8; GCM_SALT_LEN],
        base: [u8; GCM_SALT_LEN],
    ) -> [u8; GCM_SALT_LEN] {
        let mut out = [0; GCM_SALT_LEN];
        out.iter_mut().zip(salt.iter().zip(base.iter())).for_each(
            |(dst, (salt_byte, base_byte))| {
                *dst = salt_byte ^ base_byte;
            },
        );
        out
    }

    #[cfg(feature = "simd")]
    fn fill_bytes(state: &mut u64, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = state.to_be_bytes()[0];
        }
    }

    #[cfg(feature = "simd")]
    #[test]
    fn simd_matches_scalar_byte_for_byte_on_random_nonces() {
        let mut state = 0x1234_5678_9abc_def0;
        for _ in 0..1_000_000 {
            let mut salt = [0; GCM_SALT_LEN];
            let mut base = [0; GCM_SALT_LEN];
            fill_bytes(&mut state, &mut salt);
            fill_bytes(&mut state, &mut base);

            assert_eq!(
                simd_xor_nonce(salt, base),
                scalar_xor_nonce_for_test(salt, base)
            );
        }
    }

    #[cfg(feature = "simd")]
    #[test]
    fn simd_aad_prefix_matches_scalar_prefix() {
        let packet = (0..64).collect::<Vec<u8>>();

        assert_eq!(simd_copy_prefix(&packet, 47), packet[..47].to_vec());
    }

    #[test]
    fn rfc7714_aes_128_gcm_rtp_vector_matches() -> SrtpResult<()> {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let salt = [
            0x51, 0x75, 0x69, 0x64, 0x20, 0x70, 0x72, 0x6f, 0x20, 0x71, 0x75, 0x6f,
        ];
        let mut egress = Egress::new(SrtpProfile::AeadAes128Gcm, &key, salt)?;
        let mut packet = vec![
            0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0x47, 0x61,
            0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73,
            0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72,
            0x74, 0x65, 0x73, 0x20, 0x74, 0x72, 0x65, 0x73,
        ];
        let expected = [
            0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0xf2, 0x4d,
            0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c, 0x9d, 0x7e, 0x4b, 0xca,
            0xbe, 0x63, 0x3b, 0xd5, 0x0d, 0x29, 0x4e, 0x6f, 0x42, 0xa5, 0xf4, 0x7a, 0x51, 0xc7,
            0xd1, 0x9b, 0x36, 0xde, 0x3a, 0xdf, 0x88, 0x33, 0x89, 0x9d, 0x7f, 0x27, 0xbe, 0xb1,
            0x6a, 0x91, 0x52, 0xcf, 0x76, 0x5e, 0xe4, 0x39, 0x0c, 0xce,
        ];

        egress.protect_rtp(&mut packet)?;

        assert_eq!(packet, expected);
        Ok(())
    }
}
