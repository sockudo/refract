//! STUN parsing and serialization for RFC 5389 and RFC 8489.
//!
//! Messages are capped at 1500 bytes, attributes are represented as a typed
//! enum, and unknown comprehension-required attributes are rejected with a 420
//! response builder.
//!
//! # Examples
//!
//! ```
//! use refract_net::stun::{MessageClass, Method, StunMessage};
//!
//! let msg = StunMessage::new(Method::Binding, MessageClass::Request, [7; 12]);
//! assert_eq!(msg.class(), MessageClass::Request);
//! ```

#![allow(clippy::missing_const_for_fn)]

use core::fmt;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use thiserror::Error;

/// STUN magic cookie from RFC 5389.
pub const MAGIC_COOKIE: u32 = 0x2112_a442;

/// Maximum STUN message length accepted by this crate.
pub const MAX_STUN_MESSAGE_LEN: usize = 1_500;

const HEADER_LEN: usize = 20;
const ATTR_HEADER_LEN: usize = 4;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000a;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_PRIORITY: u16 = 0x0024;
const ATTR_USE_CANDIDATE: u16 = 0x0025;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_ICE_CONTROLLED: u16 = 0x8029;
const ATTR_ICE_CONTROLLING: u16 = 0x802a;
const ATTR_LIFETIME: u16 = 0x000d;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_DATA: u16 = 0x0013;
const ATTR_CHANNEL_NUMBER: u16 = 0x000c;

/// Result alias for network protocol operations.
pub type NetResult<T> = Result<T, NetError>;

/// Network protocol errors with stable codes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetError {
    /// STUN message is shorter than the fixed header.
    #[error("stun packet too short: len={len}")]
    StunTooShort {
        /// Observed length.
        len: usize,
    },
    /// STUN message exceeds the bounded MTU.
    #[error("stun packet too large: len={len}")]
    StunTooLarge {
        /// Observed length.
        len: usize,
    },
    /// STUN message length field is malformed.
    #[error("invalid stun length: declared={declared} remaining={remaining}")]
    InvalidStunLength {
        /// Declared body length.
        declared: usize,
        /// Remaining bytes after header.
        remaining: usize,
    },
    /// STUN magic cookie is invalid.
    #[error("invalid stun magic cookie: cookie={cookie:#x}")]
    InvalidMagicCookie {
        /// Observed cookie.
        cookie: u32,
    },
    /// STUN method is unsupported.
    #[error("unsupported stun method: method={method:#x}")]
    UnsupportedMethod {
        /// Raw method.
        method: u16,
    },
    /// STUN attribute exceeds the remaining message body.
    #[error("stun attribute length exceeds body: ty={ty:#x} len={len} remaining={remaining}")]
    AttributeLengthTooLarge {
        /// Attribute type.
        ty: u16,
        /// Declared attribute length.
        len: usize,
        /// Remaining bytes after attribute header.
        remaining: usize,
    },
    /// USERNAME exceeds the configured bound.
    #[error("stun username too long: len={len}")]
    UsernameTooLong {
        /// USERNAME length.
        len: usize,
    },
    /// Unknown comprehension-required attributes were present.
    #[error("unknown comprehension-required stun attributes")]
    UnknownRequiredAttributes,
    /// Attribute value is malformed.
    #[error("malformed stun attribute: ty={ty:#x}")]
    MalformedAttribute {
        /// Attribute type.
        ty: u16,
    },
    /// Output buffer is too small.
    #[error("output buffer too small: needed={needed} available={available}")]
    OutputTooSmall {
        /// Needed bytes.
        needed: usize,
        /// Available bytes.
        available: usize,
    },
    /// Amplification protection rejected a response.
    #[error("stun response would amplify: response={response} request={request}")]
    Amplification {
        /// Response length.
        response: usize,
        /// Request length.
        request: usize,
    },
    /// Transport I/O failed.
    #[error("transport io failed: {0}")]
    Io(#[from] io::Error),
}

impl NetError {
    /// Returns a stable operator-facing error code.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::StunTooShort { .. } => "NET_STUN_0001",
            Self::StunTooLarge { .. } => "NET_STUN_0002",
            Self::InvalidStunLength { .. } => "NET_STUN_0003",
            Self::InvalidMagicCookie { .. } => "NET_STUN_0004",
            Self::UnsupportedMethod { .. } => "NET_STUN_0005",
            Self::AttributeLengthTooLarge { .. } => "NET_STUN_0006",
            Self::UsernameTooLong { .. } => "NET_STUN_0007",
            Self::UnknownRequiredAttributes => "NET_STUN_0008",
            Self::MalformedAttribute { .. } => "NET_STUN_0009",
            Self::OutputTooSmall { .. } => "NET_STUN_0010",
            Self::Amplification { .. } => "NET_STUN_0011",
            Self::Io(_) => "NET_IO_0001",
        }
    }
}

/// STUN method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Binding method.
    Binding,
    /// TURN Allocate method.
    Allocate,
    /// TURN Refresh method.
    Refresh,
    /// TURN Send indication method.
    Send,
    /// TURN Data indication method.
    Data,
    /// TURN `CreatePermission` method.
    CreatePermission,
    /// TURN `ChannelBind` method.
    ChannelBind,
}

impl Method {
    /// Returns the wire method code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Binding => 0x001,
            Self::Allocate => 0x003,
            Self::Refresh => 0x004,
            Self::Send => 0x006,
            Self::Data => 0x007,
            Self::CreatePermission => 0x008,
            Self::ChannelBind => 0x009,
        }
    }

    const fn from_code(code: u16) -> NetResult<Self> {
        match code {
            0x001 => Ok(Self::Binding),
            0x003 => Ok(Self::Allocate),
            0x004 => Ok(Self::Refresh),
            0x006 => Ok(Self::Send),
            0x007 => Ok(Self::Data),
            0x008 => Ok(Self::CreatePermission),
            0x009 => Ok(Self::ChannelBind),
            method => Err(NetError::UnsupportedMethod { method }),
        }
    }
}

/// STUN message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageClass {
    /// Request class.
    Request,
    /// Indication class.
    Indication,
    /// Success response class.
    SuccessResponse,
    /// Error response class.
    ErrorResponse,
}

impl MessageClass {
    const fn bits(self) -> u16 {
        match self {
            Self::Request => 0b00,
            Self::Indication => 0b01,
            Self::SuccessResponse => 0b10,
            Self::ErrorResponse => 0b11,
        }
    }
}

/// STUN transaction ID.
pub type TransactionId = [u8; 12];

/// Parsed STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage<'a> {
    method: Method,
    class: MessageClass,
    transaction_id: TransactionId,
    attrs: Vec<Attribute<'a>>,
    unknown_required: Vec<u16>,
}

/// Typed STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attribute<'a> {
    /// USERNAME.
    Username(&'a str),
    /// REALM.
    Realm(&'a str),
    /// NONCE.
    Nonce(&'a [u8]),
    /// XOR-MAPPED-ADDRESS.
    XorMappedAddress(SocketAddr),
    /// PRIORITY.
    Priority(u32),
    /// USE-CANDIDATE.
    UseCandidate,
    /// ICE-CONTROLLED.
    IceControlled(u64),
    /// ICE-CONTROLLING.
    IceControlling(u64),
    /// ERROR-CODE.
    MessageIntegrity(&'a [u8]),
    /// ERROR-CODE.
    ErrorCode {
        /// Numeric code.
        code: u16,
        /// UTF-8 reason phrase when valid.
        reason: &'a str,
    },
    /// UNKNOWN-ATTRIBUTES.
    UnknownAttributes(Vec<u16>),
    /// SOFTWARE.
    Software(&'a str),
    /// FINGERPRINT.
    Fingerprint(u32),
    /// TURN LIFETIME.
    Lifetime(u32),
    /// REQUESTED-TRANSPORT.
    RequestedTransport(u8),
    /// XOR-PEER-ADDRESS.
    XorPeerAddress(SocketAddr),
    /// XOR-RELAYED-ADDRESS.
    XorRelayedAddress(SocketAddr),
    /// DATA.
    Data(&'a [u8]),
    /// CHANNEL-NUMBER.
    ChannelNumber(u16),
    /// Unknown comprehension-optional attribute.
    UnknownOptional {
        /// Attribute type.
        ty: u16,
        /// Raw value.
        value: &'a [u8],
    },
}

impl<'a> StunMessage<'a> {
    /// Creates an empty STUN message.
    #[must_use]
    pub const fn new(method: Method, class: MessageClass, transaction_id: TransactionId) -> Self {
        Self {
            method,
            class,
            transaction_id,
            attrs: Vec::new(),
            unknown_required: Vec::new(),
        }
    }

    /// Parses a STUN message.
    ///
    /// # Errors
    ///
    /// Returns an error when size, header, method, cookie, or attribute
    /// validation fails.
    pub fn parse(bytes: &'a [u8]) -> NetResult<Self> {
        if bytes.len() > MAX_STUN_MESSAGE_LEN {
            return Err(NetError::StunTooLarge { len: bytes.len() });
        }
        if bytes.len() < HEADER_LEN {
            return Err(NetError::StunTooShort { len: bytes.len() });
        }
        if bytes[0] & 0xc0 != 0 {
            return Err(NetError::MalformedAttribute { ty: 0 });
        }
        let typ = read_u16(&bytes[0..2]);
        let declared = usize::from(read_u16(&bytes[2..4]));
        let remaining = bytes.len() - HEADER_LEN;
        if declared > remaining || declared % 4 != 0 {
            return Err(NetError::InvalidStunLength {
                declared,
                remaining,
            });
        }
        let cookie = read_u32(&bytes[4..8]);
        if cookie != MAGIC_COOKIE {
            return Err(NetError::InvalidMagicCookie { cookie });
        }
        let method = Method::from_code(decode_method(typ))?;
        let class = decode_class(typ);
        let transaction_id = bytes[8..20]
            .try_into()
            .map_err(|_source| NetError::StunTooShort { len: bytes.len() })?;
        let mut attrs = Vec::new();
        let mut unknown_required = Vec::new();
        let mut offset = HEADER_LEN;
        let end = HEADER_LEN + declared;
        while offset < end {
            let attr_header =
                bytes
                    .get(offset..offset + ATTR_HEADER_LEN)
                    .ok_or(NetError::InvalidStunLength {
                        declared,
                        remaining: end - offset,
                    })?;
            let ty = read_u16(&attr_header[0..2]);
            let len = usize::from(read_u16(&attr_header[2..4]));
            offset += ATTR_HEADER_LEN;
            let remaining = end - offset;
            if len > remaining {
                return Err(NetError::AttributeLengthTooLarge { ty, len, remaining });
            }
            let value = &bytes[offset..offset + len];
            if let Some(attr) = parse_attr(ty, value, transaction_id)? {
                attrs.push(attr);
            } else if ty < 0x8000 {
                unknown_required.push(ty);
            } else {
                attrs.push(Attribute::UnknownOptional { ty, value });
            }
            offset += padded_len(len);
        }
        if !unknown_required.is_empty() {
            return Err(NetError::UnknownRequiredAttributes);
        }
        Ok(Self {
            method,
            class,
            transaction_id,
            attrs,
            unknown_required,
        })
    }

    /// Returns the STUN method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Returns the STUN class.
    #[must_use]
    pub const fn class(&self) -> MessageClass {
        self.class
    }

    /// Returns the transaction ID.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns parsed attributes.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute<'a>] {
        &self.attrs
    }

    /// Adds an attribute.
    pub fn push_attr(&mut self, attr: Attribute<'a>) {
        self.attrs.push(attr);
    }

    /// Serializes the message into `out`.
    ///
    /// # Errors
    ///
    /// Returns an error when the output buffer is too small or the message
    /// would exceed the bounded STUN size.
    pub fn encode(&self, out: &mut [u8]) -> NetResult<usize> {
        if out.len() < HEADER_LEN {
            return Err(NetError::OutputTooSmall {
                needed: HEADER_LEN,
                available: out.len(),
            });
        }
        let mut offset = HEADER_LEN;
        for attr in &self.attrs {
            let needed = attr_wire_len(attr);
            if offset + needed > out.len() {
                return Err(NetError::OutputTooSmall {
                    needed: offset + needed,
                    available: out.len(),
                });
            }
            offset += write_attr(attr, &mut out[offset..], self.transaction_id)?;
        }
        if offset > MAX_STUN_MESSAGE_LEN {
            return Err(NetError::StunTooLarge { len: offset });
        }
        let body_len = offset - HEADER_LEN;
        let body_len_u16 =
            u16::try_from(body_len).map_err(|_source| NetError::StunTooLarge { len: offset })?;
        write_u16(&mut out[0..2], encode_type(self.method, self.class));
        write_u16(&mut out[2..4], body_len_u16);
        write_u32(&mut out[4..8], MAGIC_COOKIE);
        out[8..20].copy_from_slice(&self.transaction_id);
        Ok(offset)
    }

    /// Builds a 420 Unknown Attribute error response.
    ///
    /// # Errors
    ///
    /// Returns an error if amplification protection would be violated.
    pub fn unknown_attribute_error(
        request: &'a [u8],
        method: Method,
        transaction_id: TransactionId,
        unknown: Vec<u16>,
        out: &mut [u8],
    ) -> NetResult<usize> {
        let mut response = StunMessage::new(method, MessageClass::ErrorResponse, transaction_id);
        response.push_attr(Attribute::ErrorCode {
            code: 420,
            reason: "Unknown Attribute",
        });
        response.push_attr(Attribute::UnknownAttributes(unknown));
        let len = response.encode(out)?;
        if len > request.len() {
            return Err(NetError::Amplification {
                response: len,
                request: request.len(),
            });
        }
        Ok(len)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Binding => "binding",
            Self::Allocate => "allocate",
            Self::Refresh => "refresh",
            Self::Send => "send",
            Self::Data => "data",
            Self::CreatePermission => "create_permission",
            Self::ChannelBind => "channel_bind",
        })
    }
}

fn parse_attr(
    ty: u16,
    value: &[u8],
    transaction_id: TransactionId,
) -> NetResult<Option<Attribute<'_>>> {
    Ok(Some(match ty {
        ATTR_USERNAME => {
            if value.len() > 256 {
                return Err(NetError::UsernameTooLong { len: value.len() });
            }
            Attribute::Username(
                core::str::from_utf8(value)
                    .map_err(|_source| NetError::MalformedAttribute { ty })?,
            )
        }
        ATTR_REALM => Attribute::Realm(
            core::str::from_utf8(value).map_err(|_source| NetError::MalformedAttribute { ty })?,
        ),
        ATTR_NONCE => Attribute::Nonce(value),
        ATTR_XOR_MAPPED_ADDRESS => {
            Attribute::XorMappedAddress(parse_xor_address(value, transaction_id)?)
        }
        ATTR_XOR_PEER_ADDRESS => {
            Attribute::XorPeerAddress(parse_xor_address(value, transaction_id)?)
        }
        ATTR_XOR_RELAYED_ADDRESS => {
            Attribute::XorRelayedAddress(parse_xor_address(value, transaction_id)?)
        }
        ATTR_PRIORITY => Attribute::Priority(read_exact_u32(ty, value)?),
        ATTR_MESSAGE_INTEGRITY => {
            if value.len() != 20 {
                return Err(NetError::MalformedAttribute { ty });
            }
            Attribute::MessageIntegrity(value)
        }
        ATTR_USE_CANDIDATE => {
            if !value.is_empty() {
                return Err(NetError::MalformedAttribute { ty });
            }
            Attribute::UseCandidate
        }
        ATTR_ICE_CONTROLLED => Attribute::IceControlled(read_exact_u64(ty, value)?),
        ATTR_ICE_CONTROLLING => Attribute::IceControlling(read_exact_u64(ty, value)?),
        ATTR_ERROR_CODE => {
            if value.len() < 4 {
                return Err(NetError::MalformedAttribute { ty });
            }
            let class = value[2] & 0x07;
            let number = value[3];
            let reason = core::str::from_utf8(&value[4..]).unwrap_or("");
            Attribute::ErrorCode {
                code: u16::from(class) * 100 + u16::from(number),
                reason,
            }
        }
        ATTR_UNKNOWN_ATTRIBUTES => {
            if !value.len().is_multiple_of(2) {
                return Err(NetError::MalformedAttribute { ty });
            }
            Attribute::UnknownAttributes(value.chunks_exact(2).map(read_u16).collect())
        }
        ATTR_SOFTWARE => Attribute::Software(
            core::str::from_utf8(value).map_err(|_source| NetError::MalformedAttribute { ty })?,
        ),
        ATTR_FINGERPRINT => Attribute::Fingerprint(read_exact_u32(ty, value)?),
        ATTR_LIFETIME => Attribute::Lifetime(read_exact_u32(ty, value)?),
        ATTR_REQUESTED_TRANSPORT => {
            if value.len() != 4 {
                return Err(NetError::MalformedAttribute { ty });
            }
            Attribute::RequestedTransport(value[0])
        }
        ATTR_DATA => Attribute::Data(value),
        ATTR_CHANNEL_NUMBER => {
            if value.len() != 4 {
                return Err(NetError::MalformedAttribute { ty });
            }
            Attribute::ChannelNumber(read_u16(&value[0..2]))
        }
        _ => return Ok(None),
    }))
}

fn parse_xor_address(value: &[u8], transaction_id: TransactionId) -> NetResult<SocketAddr> {
    if value.len() < 4 || value[0] != 0 {
        return Err(NetError::MalformedAttribute {
            ty: ATTR_XOR_MAPPED_ADDRESS,
        });
    }
    let family = value[1];
    let port = read_u16(&value[2..4]) ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 => {
            if value.len() != 8 {
                return Err(NetError::MalformedAttribute {
                    ty: ATTR_XOR_MAPPED_ADDRESS,
                });
            }
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let octets = [
                value[4] ^ cookie[0],
                value[5] ^ cookie[1],
                value[6] ^ cookie[2],
                value[7] ^ cookie[3],
            ];
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 => {
            if value.len() != 20 {
                return Err(NetError::MalformedAttribute {
                    ty: ATTR_XOR_MAPPED_ADDRESS,
                });
            }
            let mut mask = [0_u8; 16];
            mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);
            let mut octets = [0_u8; 16];
            for (out, (source, mask_byte)) in octets.iter_mut().zip(value[4..20].iter().zip(mask)) {
                *out = *source ^ mask_byte;
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(NetError::MalformedAttribute {
            ty: ATTR_XOR_MAPPED_ADDRESS,
        }),
    }
}

fn attr_wire_len(attr: &Attribute<'_>) -> usize {
    ATTR_HEADER_LEN + padded_len(attr_value_len(attr))
}

fn attr_value_len(attr: &Attribute<'_>) -> usize {
    match attr {
        Attribute::Username(value)
        | Attribute::Realm(value)
        | Attribute::Software(value)
        | Attribute::ErrorCode { reason: value, .. } => {
            if matches!(attr, Attribute::ErrorCode { .. }) {
                4 + value.len()
            } else {
                value.len()
            }
        }
        Attribute::Nonce(value)
        | Attribute::Data(value)
        | Attribute::MessageIntegrity(value)
        | Attribute::UnknownOptional { value, .. } => value.len(),
        Attribute::XorMappedAddress(SocketAddr::V4(_))
        | Attribute::XorPeerAddress(SocketAddr::V4(_))
        | Attribute::XorRelayedAddress(SocketAddr::V4(_))
        | Attribute::IceControlled(_)
        | Attribute::IceControlling(_) => 8,
        Attribute::XorMappedAddress(SocketAddr::V6(_))
        | Attribute::XorPeerAddress(SocketAddr::V6(_))
        | Attribute::XorRelayedAddress(SocketAddr::V6(_)) => 20,
        Attribute::Priority(_)
        | Attribute::Fingerprint(_)
        | Attribute::Lifetime(_)
        | Attribute::RequestedTransport(_)
        | Attribute::ChannelNumber(_) => 4,
        Attribute::UseCandidate => 0,
        Attribute::UnknownAttributes(values) => values.len() * 2,
    }
}

fn write_attr(
    attr: &Attribute<'_>,
    out: &mut [u8],
    transaction_id: TransactionId,
) -> NetResult<usize> {
    let (ty, len) = attr_type_len(attr);
    write_u16(&mut out[0..2], ty);
    write_u16(
        &mut out[2..4],
        u16::try_from(len).map_err(|_source| NetError::StunTooLarge { len })?,
    );
    let value = &mut out[4..4 + len];
    match attr {
        Attribute::Username(text) | Attribute::Realm(text) | Attribute::Software(text) => {
            value.copy_from_slice(text.as_bytes());
        }
        Attribute::Nonce(bytes)
        | Attribute::Data(bytes)
        | Attribute::MessageIntegrity(bytes)
        | Attribute::UnknownOptional { value: bytes, .. } => {
            value.copy_from_slice(bytes);
        }
        Attribute::Priority(v) | Attribute::Fingerprint(v) | Attribute::Lifetime(v) => {
            write_u32(value, *v);
        }
        Attribute::RequestedTransport(protocol) => {
            value[0] = *protocol;
            value[1..4].fill(0);
        }
        Attribute::UseCandidate => {}
        Attribute::IceControlled(v) | Attribute::IceControlling(v) => write_u64(value, *v),
        Attribute::ErrorCode { code, reason } => {
            value[0] = 0;
            value[1] = 0;
            value[2] =
                u8::try_from(code / 100).map_err(|_source| NetError::MalformedAttribute { ty })?;
            value[3] =
                u8::try_from(code % 100).map_err(|_source| NetError::MalformedAttribute { ty })?;
            value[4..].copy_from_slice(reason.as_bytes());
        }
        Attribute::UnknownAttributes(values) => {
            for (chunk, attr) in value.chunks_exact_mut(2).zip(values) {
                write_u16(chunk, *attr);
            }
        }
        Attribute::ChannelNumber(channel) => {
            write_u16(&mut value[0..2], *channel);
            value[2..4].fill(0);
        }
        Attribute::XorMappedAddress(addr)
        | Attribute::XorPeerAddress(addr)
        | Attribute::XorRelayedAddress(addr) => write_xor_address(value, *addr, transaction_id),
    }
    out[4 + len..4 + padded_len(len)].fill(0);
    Ok(ATTR_HEADER_LEN + padded_len(len))
}

fn attr_type_len(attr: &Attribute<'_>) -> (u16, usize) {
    let ty = match attr {
        Attribute::Username(_) => ATTR_USERNAME,
        Attribute::MessageIntegrity(_) => ATTR_MESSAGE_INTEGRITY,
        Attribute::Realm(_) => ATTR_REALM,
        Attribute::Nonce(_) => ATTR_NONCE,
        Attribute::XorMappedAddress(_) => ATTR_XOR_MAPPED_ADDRESS,
        Attribute::Priority(_) => ATTR_PRIORITY,
        Attribute::UseCandidate => ATTR_USE_CANDIDATE,
        Attribute::IceControlled(_) => ATTR_ICE_CONTROLLED,
        Attribute::IceControlling(_) => ATTR_ICE_CONTROLLING,
        Attribute::ErrorCode { .. } => ATTR_ERROR_CODE,
        Attribute::UnknownAttributes(_) => ATTR_UNKNOWN_ATTRIBUTES,
        Attribute::Software(_) => ATTR_SOFTWARE,
        Attribute::Fingerprint(_) => ATTR_FINGERPRINT,
        Attribute::Lifetime(_) => ATTR_LIFETIME,
        Attribute::RequestedTransport(_) => ATTR_REQUESTED_TRANSPORT,
        Attribute::XorPeerAddress(_) => ATTR_XOR_PEER_ADDRESS,
        Attribute::XorRelayedAddress(_) => ATTR_XOR_RELAYED_ADDRESS,
        Attribute::Data(_) => ATTR_DATA,
        Attribute::ChannelNumber(_) => ATTR_CHANNEL_NUMBER,
        Attribute::UnknownOptional { ty, .. } => *ty,
    };
    (ty, attr_value_len(attr))
}

fn write_xor_address(out: &mut [u8], addr: SocketAddr, transaction_id: TransactionId) {
    out[0] = 0;
    write_u16(&mut out[2..4], addr.port() ^ ((MAGIC_COOKIE >> 16) as u16));
    match addr.ip() {
        IpAddr::V4(ip) => {
            out[1] = 1;
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for (dst, (source, mask)) in out[4..8]
                .iter_mut()
                .zip(ip.octets().into_iter().zip(cookie))
            {
                *dst = source ^ mask;
            }
        }
        IpAddr::V6(ip) => {
            out[1] = 2;
            let mut mask = [0_u8; 16];
            mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);
            for (dst, (source, mask_byte)) in
                out[4..20].iter_mut().zip(ip.octets().into_iter().zip(mask))
            {
                *dst = source ^ mask_byte;
            }
        }
    }
}

const fn encode_type(method: Method, class: MessageClass) -> u16 {
    let m = method.code();
    let c = class.bits();
    (m & 0x000f) | ((m & 0x0070) << 1) | ((m & 0x0f80) << 2) | ((c & 0x01) << 4) | ((c & 0x02) << 7)
}

const fn decode_method(typ: u16) -> u16 {
    (typ & 0x000f) | ((typ & 0x00e0) >> 1) | ((typ & 0x3e00) >> 2)
}

const fn decode_class(typ: u16) -> MessageClass {
    match ((typ >> 4) & 0x01) | ((typ >> 7) & 0x02) {
        0 => MessageClass::Request,
        1 => MessageClass::Indication,
        2 => MessageClass::SuccessResponse,
        _ => MessageClass::ErrorResponse,
    }
}

const fn padded_len(len: usize) -> usize {
    (len + 3) & !3
}

fn read_exact_u32(ty: u16, value: &[u8]) -> NetResult<u32> {
    if value.len() == 4 {
        Ok(read_u32(value))
    } else {
        Err(NetError::MalformedAttribute { ty })
    }
}

fn read_exact_u64(ty: u16, value: &[u8]) -> NetResult<u64> {
    if value.len() == 8 {
        Ok(u64::from_be_bytes([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]))
    } else {
        Err(NetError::MalformedAttribute { ty })
    }
}

pub(crate) fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub(crate) fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(crate) fn write_u16(bytes: &mut [u8], value: u16) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u32(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

fn write_u64(bytes: &mut [u8], value: u64) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_5769_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e,
        0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20,
        0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
        0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5,
        0x7a, 0x3b, 0xcf,
    ];

    const RFC_5769_RESPONSE_V4: &[u8] = &[
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1,
        0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00,
        0x04, 0xc0, 0x7d, 0x4c, 0x96,
    ];

    const RFC_5769_RESPONSE_V6: &[u8] = &[
        0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01,
        0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9,
        0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41, 0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb,
        0x0b, 0x4c,
    ];

    const RFC_5769_LONG_TERM_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72,
        0xc0, 0x29, 0xda, 0x41, 0x2e, 0x00, 0x06, 0x00, 0x12, 0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88,
        0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9, 0x00, 0x00, 0x00,
        0x15, 0x00, 0x1c, 0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
        0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73,
        0x41, 0x00, 0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72,
        0x67, 0x00, 0x00, 0x08, 0x00, 0x14, 0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02,
        0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66,
    ];

    #[test]
    fn rfc_5769_vectors_parse_byte_for_byte() {
        let request = StunMessage::parse(RFC_5769_REQUEST).expect("rfc5769 request");
        assert_eq!(request.method(), Method::Binding);
        assert_eq!(request.class(), MessageClass::Request);
        assert_eq!(request.attributes().len(), 6);
        assert!(
            request
                .attributes()
                .contains(&Attribute::Software("STUN test client"))
        );
        assert!(
            request
                .attributes()
                .contains(&Attribute::Username("evtj:h6vY"))
        );

        let response_v4 = StunMessage::parse(RFC_5769_RESPONSE_V4).expect("rfc5769 response v4");
        assert_eq!(response_v4.class(), MessageClass::SuccessResponse);
        assert!(
            response_v4
                .attributes()
                .contains(&Attribute::XorMappedAddress(SocketAddr::from((
                    [192, 0, 2, 1],
                    32_853,
                ))))
        );

        let response_v6 = StunMessage::parse(RFC_5769_RESPONSE_V6).expect("rfc5769 response v6");
        assert_eq!(response_v6.class(), MessageClass::SuccessResponse);
        assert!(
            response_v6
                .attributes()
                .contains(&Attribute::XorMappedAddress(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0x0db8, 0x1234, 0x5678, 0x0011, 0x2233, 0x4455, 0x6677,
                    )),
                    32_853,
                )))
        );

        let long_term =
            StunMessage::parse(RFC_5769_LONG_TERM_REQUEST).expect("rfc5769 long-term request");
        assert_eq!(long_term.class(), MessageClass::Request);
        let long_term_username = core::str::from_utf8(&[
            0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82,
            0xaf, 0xe3, 0x82, 0xb9,
        ])
        .expect("rfc5769 username utf8");
        assert!(
            long_term
                .attributes()
                .contains(&Attribute::Username(long_term_username))
        );
        assert!(
            long_term
                .attributes()
                .contains(&Attribute::Realm("example.org"))
        );
    }

    #[test]
    fn roundtrip_binding_response() {
        let mut msg = StunMessage::new(Method::Binding, MessageClass::SuccessResponse, [3; 12]);
        msg.push_attr(Attribute::XorMappedAddress(SocketAddr::from((
            [192, 0, 2, 1],
            3478,
        ))));
        let mut out = [0_u8; 128];
        let len = msg.encode(&mut out).expect("encode");
        let parsed = StunMessage::parse(&out[..len]).expect("parse");
        assert_eq!(parsed.method(), Method::Binding);
        assert_eq!(parsed.attributes().len(), 1);
    }

    #[test]
    fn rejects_oversized_and_unknown_required() {
        let oversized = [0_u8; MAX_STUN_MESSAGE_LEN + 1];
        assert!(matches!(
            StunMessage::parse(&oversized),
            Err(NetError::StunTooLarge { .. })
        ));
        let mut request = [0_u8; 24];
        write_u16(
            &mut request[0..2],
            encode_type(Method::Binding, MessageClass::Request),
        );
        write_u16(&mut request[2..4], 4);
        write_u32(&mut request[4..8], MAGIC_COOKIE);
        request[20] = 0;
        request[21] = 1;
        assert!(matches!(
            StunMessage::parse(&request),
            Err(NetError::UnknownRequiredAttributes)
        ));
    }
}
