//! RFC 8285 RTP header extension parsing.
//!
//! The iterator validates each extension entry length before slicing. Malformed
//! entries are returned as errors and recorded as metrics; entries with known
//! invalid payload lengths do not stop later parseable entries.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::extensions::{ExtensionKind, ExtensionRegistry, RtpExtensions};
//! let payload = [0x10, 0xaa, 0, 0];
//! let registry = ExtensionRegistry::new().with(1, ExtensionKind::AudioLevel);
//! let mut iter = RtpExtensions::new(0xbede, &payload, registry)?;
//! let extension = iter.next().transpose()?;
//! assert_eq!(
//!     extension.map(|entry| entry.kind()),
//!     Some(Some(ExtensionKind::AudioLevel))
//! );
//! # Ok::<(), refract_rtp::RtpError>(())
//! ```

use crate::{
    RtpError, Stability,
    error::{ExtensionErrorReason, RtpResult},
    metrics::record_parse_error,
};

const ONE_BYTE_PROFILE: u16 = 0xbede;
const TWO_BYTE_PROFILE_MASK: u16 = 0xf000;
const TWO_BYTE_PROFILE_PREFIX: u16 = 0x1000;
const ONE_BYTE_RESERVED_ID: u8 = 15;
const MAX_MID_RID_LEN: usize = 16;
const TRANSPORT_CC_LEN: usize = 2;
const ABS_SEND_TIME_LEN: usize = 3;
const ONE_BYTE_KNOWN_LEN: usize = 1;
const EXTENSION_ID_COUNT: usize = 256;

/// Known RTP header extension kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionKind {
    /// Transport-wide congestion control sequence number.
    TransportCc,
    /// Absolute send time.
    AbsSendTime,
    /// Audio level.
    AudioLevel,
    /// Video orientation.
    VideoOrientation,
    /// Media identifier.
    Mid,
    /// RTP stream identifier.
    Rid,
    /// Repaired RTP stream identifier.
    RepairedRid,
    /// Dependency descriptor.
    DependencyDescriptor,
}

impl ExtensionKind {
    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{extensions::ExtensionKind, Stability};
    /// assert_eq!(ExtensionKind::TransportCc.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }

    /// Validates the payload length for known extensions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::ExtensionKind;
    /// assert!(ExtensionKind::AbsSendTime.accepts_len(3));
    /// ```
    #[must_use]
    pub const fn accepts_len(self, len: usize) -> bool {
        match self {
            Self::TransportCc => len == TRANSPORT_CC_LEN,
            Self::AbsSendTime => len == ABS_SEND_TIME_LEN,
            Self::AudioLevel | Self::VideoOrientation => len == ONE_BYTE_KNOWN_LEN,
            Self::Mid | Self::Rid | Self::RepairedRid => len <= MAX_MID_RID_LEN,
            Self::DependencyDescriptor => len > 0,
        }
    }

    /// Returns a stable metric label for the extension kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::ExtensionKind;
    /// assert_eq!(ExtensionKind::Rid.as_str(), "rid");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransportCc => "transport_cc",
            Self::AbsSendTime => "abs_send_time",
            Self::AudioLevel => "audio_level",
            Self::VideoOrientation => "video_orientation",
            Self::Mid => "mid",
            Self::Rid => "rid",
            Self::RepairedRid => "repaired_rid",
            Self::DependencyDescriptor => "dependency_descriptor",
        }
    }
}

/// Fixed-size extension ID registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionRegistry {
    kinds: [Option<ExtensionKind>; EXTENSION_ID_COUNT],
}

impl ExtensionRegistry {
    /// Creates an empty extension registry.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::ExtensionRegistry;
    /// assert!(ExtensionRegistry::new().kind(1).is_none());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            kinds: [None; EXTENSION_ID_COUNT],
        }
    }

    /// Returns a copy of the registry with `id` assigned to `kind`.
    ///
    /// IDs outside the valid one-byte/two-byte extension space are ignored so
    /// callers can feed bounded config without panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionKind, ExtensionRegistry};
    /// let registry = ExtensionRegistry::new().with(3, ExtensionKind::TransportCc);
    /// assert_eq!(registry.kind(3), Some(ExtensionKind::TransportCc));
    /// ```
    #[must_use]
    pub const fn with(mut self, id: u8, kind: ExtensionKind) -> Self {
        self.kinds[id as usize] = Some(kind);
        self
    }

    /// Returns the extension kind for an ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionKind, ExtensionRegistry};
    /// let registry = ExtensionRegistry::new().with(1, ExtensionKind::AudioLevel);
    /// assert_eq!(registry.kind(1), Some(ExtensionKind::AudioLevel));
    /// ```
    #[must_use]
    pub const fn kind(self, id: u8) -> Option<ExtensionKind> {
        self.kinds[id as usize]
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{extensions::ExtensionRegistry, Stability};
    /// assert_eq!(ExtensionRegistry::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 8285 extension block wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionFormat {
    /// RFC 8285 one-byte header format.
    OneByte,
    /// RFC 8285 two-byte header format.
    TwoByte,
}

impl ExtensionFormat {
    /// Returns the extension format for an RTP extension profile identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported extension profiles.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::ExtensionFormat;
    /// assert_eq!(
    ///     ExtensionFormat::from_profile(0xbede)?,
    ///     ExtensionFormat::OneByte
    /// );
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    pub const fn from_profile(profile: u16) -> RtpResult<Self> {
        if profile == ONE_BYTE_PROFILE {
            Ok(Self::OneByte)
        } else if profile & TWO_BYTE_PROFILE_MASK == TWO_BYTE_PROFILE_PREFIX {
            Ok(Self::TwoByte)
        } else {
            Err(RtpError::MalformedExtension {
                id: 0,
                reason: ExtensionErrorReason::InvalidKnownLength,
            })
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{extensions::ExtensionFormat, Stability};
    /// assert_eq!(ExtensionFormat::OneByte.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Borrowed parsed RTP extension entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpExtension<'a> {
    id: u8,
    kind: Option<ExtensionKind>,
    value: &'a [u8],
}

impl<'a> RtpExtension<'a> {
    /// Returns the extension ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionRegistry, RtpExtensions};
    /// let mut iter = RtpExtensions::new(0xbede, &[0x10, 0, 0, 0], ExtensionRegistry::new())?;
    /// assert_eq!(iter.next().transpose()?.map(|e| e.id()), Some(1));
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn id(self) -> u8 {
        self.id
    }

    /// Returns the registered extension kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionKind, ExtensionRegistry, RtpExtensions};
    /// let registry = ExtensionRegistry::new().with(1, ExtensionKind::AudioLevel);
    /// let mut iter = RtpExtensions::new(0xbede, &[0x10, 0, 0, 0], registry)?;
    /// assert_eq!(
    ///     iter.next().transpose()?.map(|e| e.kind()),
    ///     Some(Some(ExtensionKind::AudioLevel))
    /// );
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn kind(self) -> Option<ExtensionKind> {
        self.kind
    }

    /// Returns the borrowed extension value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionRegistry, RtpExtensions};
    /// let mut iter = RtpExtensions::new(0xbede, &[0x10, 0xaa, 0, 0], ExtensionRegistry::new())?;
    /// assert_eq!(
    ///     iter.next().transpose()?.map(|e| e.value()),
    ///     Some(&[0xaa][..])
    /// );
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{extensions::{ExtensionRegistry, RtpExtensions}, Stability};
    /// let mut iter = RtpExtensions::new(0xbede, &[0x10, 0, 0, 0], ExtensionRegistry::new())?;
    /// assert_eq!(
    ///     iter.next().transpose()?.map(|e| e.stability()),
    ///     Some(Stability::Stage1)
    /// );
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Iterator over RFC 8285 RTP header extensions.
#[derive(Debug, Clone)]
pub struct RtpExtensions<'a> {
    format: ExtensionFormat,
    remaining: &'a [u8],
    registry: ExtensionRegistry,
}

impl<'a> RtpExtensions<'a> {
    /// Creates an extension iterator for an RTP extension block.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension profile is unsupported.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionRegistry, RtpExtensions};
    /// assert!(RtpExtensions::new(0xbede, &[], ExtensionRegistry::new()).is_ok());
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    pub fn new(profile: u16, payload: &'a [u8], registry: ExtensionRegistry) -> RtpResult<Self> {
        Ok(Self {
            format: ExtensionFormat::from_profile(profile)?,
            remaining: payload,
            registry,
        })
    }

    /// Returns the detected RFC 8285 format.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::extensions::{ExtensionFormat, ExtensionRegistry, RtpExtensions};
    /// let iter = RtpExtensions::new(0xbede, &[], ExtensionRegistry::new())?;
    /// assert_eq!(iter.format(), ExtensionFormat::OneByte);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn format(&self) -> ExtensionFormat {
        self.format
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_rtp::{extensions::{ExtensionRegistry, RtpExtensions}, Stability};
    /// let iter = RtpExtensions::new(0xbede, &[], ExtensionRegistry::new())?;
    /// assert_eq!(iter.stability(), Stability::Stage1);
    /// # Ok::<(), refract_rtp::RtpError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn next_one_byte(&mut self) -> Option<RtpResult<RtpExtension<'a>>> {
        while let Some((&header, tail)) = self.remaining.split_first() {
            self.remaining = tail;
            if header == 0 {
                continue;
            }
            let id = header >> 4;
            if id == ONE_BYTE_RESERVED_ID {
                let error = RtpError::MalformedExtension {
                    id,
                    reason: ExtensionErrorReason::ReservedOneByteId,
                };
                record_parse_error(&error);
                return Some(Err(error));
            }
            let len = usize::from(header & 0x0f) + 1;
            if len > self.remaining.len() {
                let error = RtpError::MalformedExtension {
                    id,
                    reason: ExtensionErrorReason::EntryLengthExceedsBlock,
                };
                self.remaining = &[];
                record_parse_error(&error);
                return Some(Err(error));
            }
            let (value, tail) = self.remaining.split_at(len);
            self.remaining = tail;
            return Some(validate_entry(id, value, self.registry));
        }
        None
    }

    fn next_two_byte(&mut self) -> Option<RtpResult<RtpExtension<'a>>> {
        while let Some((&id, tail)) = self.remaining.split_first() {
            if id == 0 {
                self.remaining = tail;
                continue;
            }
            let Some((&len_byte, value_tail)) = tail.split_first() else {
                let error = RtpError::MalformedExtension {
                    id,
                    reason: ExtensionErrorReason::EntryLengthExceedsBlock,
                };
                self.remaining = &[];
                record_parse_error(&error);
                return Some(Err(error));
            };
            let len = usize::from(len_byte);
            self.remaining = value_tail;
            if len == 0 {
                let error = RtpError::MalformedExtension {
                    id,
                    reason: ExtensionErrorReason::EmptyTwoByteEntry,
                };
                record_parse_error(&error);
                return Some(Err(error));
            }
            if len > self.remaining.len() {
                let error = RtpError::MalformedExtension {
                    id,
                    reason: ExtensionErrorReason::EntryLengthExceedsBlock,
                };
                self.remaining = &[];
                record_parse_error(&error);
                return Some(Err(error));
            }
            let (value, tail) = self.remaining.split_at(len);
            self.remaining = tail;
            return Some(validate_entry(id, value, self.registry));
        }
        if self.remaining.is_empty() {
            None
        } else {
            let error = RtpError::MalformedExtension {
                id: 0,
                reason: ExtensionErrorReason::EntryLengthExceedsBlock,
            };
            self.remaining = &[];
            record_parse_error(&error);
            Some(Err(error))
        }
    }
}

impl<'a> Iterator for RtpExtensions<'a> {
    type Item = RtpResult<RtpExtension<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.format {
            ExtensionFormat::OneByte => self.next_one_byte(),
            ExtensionFormat::TwoByte => self.next_two_byte(),
        }
    }
}

fn validate_entry(
    id: u8,
    value: &[u8],
    registry: ExtensionRegistry,
) -> RtpResult<RtpExtension<'_>> {
    let kind = registry.kind(id);
    if kind.is_some_and(|extension_kind| !extension_kind.accepts_len(value.len())) {
        let error = RtpError::MalformedExtension {
            id,
            reason: ExtensionErrorReason::InvalidKnownLength,
        };
        record_parse_error(&error);
        Err(error)
    } else {
        Ok(RtpExtension { id, kind, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc_8285_one_byte_example_shape() {
        let payload = [0x10, 0xaa, 0x21, 0xbb, 0xcc, 0, 0, 0];
        let registry = ExtensionRegistry::new()
            .with(1, ExtensionKind::AudioLevel)
            .with(2, ExtensionKind::TransportCc);
        let parsed = RtpExtensions::new(ONE_BYTE_PROFILE, &payload, registry)
            .expect("one-byte profile")
            .collect::<RtpResult<Vec<_>>>()
            .expect("valid extensions");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id(), 1);
        assert_eq!(parsed[0].value(), &[0xaa]);
        assert_eq!(parsed[1].id(), 2);
        assert_eq!(parsed[1].value(), &[0xbb, 0xcc]);
    }

    #[test]
    fn malformed_known_extension_does_not_poison_following_entry() {
        let payload = [0x11, 0xaa, 0xbb, 0x20, 0x7f, 0, 0, 0];
        let registry = ExtensionRegistry::new()
            .with(1, ExtensionKind::AudioLevel)
            .with(2, ExtensionKind::AudioLevel);
        let mut iter =
            RtpExtensions::new(ONE_BYTE_PROFILE, &payload, registry).expect("one-byte profile");
        assert!(matches!(
            iter.next(),
            Some(Err(RtpError::MalformedExtension {
                id: 1,
                reason: ExtensionErrorReason::InvalidKnownLength
            }))
        ));
        let next = iter
            .next()
            .expect("second extension")
            .expect("second extension valid");
        assert_eq!(next.id(), 2);
        assert_eq!(next.value(), &[0x7f]);
    }

    #[test]
    fn parses_two_byte_extension() {
        let payload = [9, 3, 1, 2, 3, 0, 0, 0];
        let registry = ExtensionRegistry::new().with(9, ExtensionKind::AbsSendTime);
        let parsed = RtpExtensions::new(0x1000, &payload, registry)
            .expect("two-byte profile")
            .collect::<RtpResult<Vec<_>>>()
            .expect("valid extensions");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind(), Some(ExtensionKind::AbsSendTime));
        assert_eq!(parsed[0].value(), &[1, 2, 3]);
    }
}
