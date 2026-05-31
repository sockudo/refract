//! Tier 4 room state boundary for participants, tracks, subscriptions, and
//! active-speaker updates.
//!
//! `refract-roomstore` defines the Stage 1 trait that later storage backends
//! must implement unchanged. The interface is intentionally narrow: each method
//! is atomic at `(room, participant)` granularity, list operations are bounded
//! with cursors, and event delivery is represented as a stream without baking a
//! transaction model into the API.
//!
//! # Examples
//!
//! ```
//! # use refract_core::{NodeId, PeerId, RoomId};
//! # use refract_roomstore::{MockRoomStore, Participant, RoomStore};
//! # compio::runtime::Runtime::new()?.block_on(async {
//! let store = MockRoomStore::new();
//! let participant = Participant::new(PeerId::from_raw(7), NodeId::from_raw(1), 100)?;
//! let handle = store.join(RoomId::from_raw(10), participant).await?;
//! assert_eq!(handle.peer(), PeerId::from_raw(7));
//! # Ok::<(), refract_roomstore::RoomStoreError>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    pin::Pin,
    sync::{Mutex, MutexGuard, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use bincode::{Decode, Encode};
use futures_core::Stream;
use refract_core::{NodeId, PeerId, RoomId, TrackId};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result alias for room store operations.
pub type Result<T> = std::result::Result<T, RoomStoreError>;

/// Maximum participants returned by one paginated list call.
pub const MAX_PARTICIPANT_PAGE_LIMIT: usize = 4096;

/// Maximum participant application metadata bytes.
pub const MAX_PARTICIPANT_METADATA_BYTES: usize = 4096;

/// Maximum track label bytes.
pub const MAX_TRACK_LABEL_BYTES: usize = 128;

/// Redis and backend operation deadline expected by Stage 1 implementations.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_millis(50);

/// Redis key TTL expected by Stage 1 implementations.
pub const DEFAULT_ROOM_TTL: Duration = Duration::from_hours(24);

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns the stable marker label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Error taxonomy for room store operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RoomStoreError {
    /// A configuration field was invalid.
    #[error("invalid configuration: {field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// A list limit was zero or exceeded the bounded maximum.
    #[error("invalid page limit: {limit}")]
    InvalidLimit {
        /// Rejected limit.
        limit: usize,
    },
    /// A participant was not present in the room.
    #[error("participant not found")]
    ParticipantNotFound,
    /// A track was not present in the room.
    #[error("track not found")]
    TrackNotFound,
    /// A subscription was not present.
    #[error("subscription not found")]
    SubscriptionNotFound,
    /// A participant or track record exceeded its defensive bound.
    #[error("record too large: {field}")]
    RecordTooLarge {
        /// Oversized field.
        field: &'static str,
    },
    /// Serialization failed.
    #[error("serialization failed: {component}")]
    Serialization {
        /// Serialization component.
        component: &'static str,
    },
    /// Deserialization failed.
    #[error("deserialization failed: {component}")]
    Deserialization {
        /// Deserialization component.
        component: &'static str,
    },
    /// Backend operation exceeded its deterministic timeout.
    #[error("backend operation timed out after {timeout:?}")]
    Timeout {
        /// Timeout used for the operation.
        timeout: Duration,
    },
    /// Backend is degraded and refuses writes.
    #[error("backend degraded: {reason}")]
    Degraded {
        /// Degraded reason.
        reason: &'static str,
    },
    /// Backend memory pressure requires failing closed.
    #[error("backend memory pressure: used {used_percent}%")]
    MemoryPressure {
        /// Used memory percentage.
        used_percent: u8,
    },
    /// Backend command failed.
    #[error("backend failed: {message}")]
    Backend {
        /// Backend failure message.
        message: String,
    },
    /// Internal synchronization failed.
    #[error("internal synchronization failed")]
    InternalSync,
}

impl RoomStoreError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::RoomStoreError;
    /// assert_eq!(
    ///     RoomStoreError::ParticipantNotFound.error_code(),
    ///     "ROOMSTORE_STATE_0001",
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "ROOMSTORE_CONFIG_0001",
            Self::InvalidLimit { .. } => "ROOMSTORE_INPUT_0001",
            Self::ParticipantNotFound => "ROOMSTORE_STATE_0001",
            Self::TrackNotFound => "ROOMSTORE_STATE_0002",
            Self::SubscriptionNotFound => "ROOMSTORE_STATE_0003",
            Self::RecordTooLarge { .. } => "ROOMSTORE_INPUT_0002",
            Self::Serialization { .. } => "ROOMSTORE_CODEC_0001",
            Self::Deserialization { .. } => "ROOMSTORE_CODEC_0002",
            Self::Timeout { .. } => "ROOMSTORE_BACKEND_0001",
            Self::Degraded { .. } => "ROOMSTORE_BACKEND_0002",
            Self::MemoryPressure { .. } => "ROOMSTORE_BACKEND_0003",
            Self::Backend { .. } => "ROOMSTORE_BACKEND_0004",
            Self::InternalSync => "ROOMSTORE_INTERNAL_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{RoomStoreError, Stability};
    /// assert_eq!(
    ///     RoomStoreError::ParticipantNotFound.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for RoomStoreError {
    fn from(_source: PoisonError<MutexGuard<'_, T>>) -> Self {
        Self::InternalSync
    }
}

/// Paginated backend cursor.
#[derive(
    Archive,
    Clone,
    Copy,
    Debug,
    Decode,
    Deserialize,
    Encode,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    RkyvDeserialize,
    RkyvSerialize,
    Serialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Cursor(u64);

impl Cursor {
    /// Creates a cursor from its backend value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::Cursor;
    /// assert_eq!(Cursor::from_raw(42).raw(), 42);
    /// ```
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw backend cursor value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::Cursor;
    /// assert_eq!(Cursor::from_raw(7).raw(), 7);
    /// ```
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{Cursor, Stability};
    /// assert_eq!(Cursor::from_raw(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Durable participant record.
#[derive(
    Archive,
    Clone,
    Debug,
    Decode,
    Deserialize,
    Encode,
    Eq,
    PartialEq,
    RkyvDeserialize,
    RkyvSerialize,
    Serialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Participant {
    peer: u64,
    node: u64,
    joined_at_unix_ms: u64,
    metadata: Box<[u8]>,
}

impl Participant {
    /// Creates a participant record.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::RecordTooLarge`] when metadata exceeds
    /// [`MAX_PARTICIPANT_METADATA_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// let participant = Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 3)?;
    /// assert_eq!(participant.peer(), PeerId::from_raw(1));
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub fn new(peer: PeerId, node: NodeId, joined_at_unix_ms: u64) -> Result<Self> {
        Self::with_metadata(peer, node, joined_at_unix_ms, &[])
    }

    /// Creates a participant record with bounded metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::RecordTooLarge`] when metadata exceeds
    /// [`MAX_PARTICIPANT_METADATA_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// let participant = Participant::with_metadata(
    ///     PeerId::from_raw(1),
    ///     NodeId::from_raw(2),
    ///     3,
    ///     b"role=publisher",
    /// )?;
    /// assert_eq!(participant.metadata(), b"role=publisher");
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub fn with_metadata(
        peer: PeerId,
        node: NodeId,
        joined_at_unix_ms: u64,
        metadata: &[u8],
    ) -> Result<Self> {
        if metadata.len() > MAX_PARTICIPANT_METADATA_BYTES {
            return Err(RoomStoreError::RecordTooLarge { field: "metadata" });
        }
        Ok(Self {
            peer: peer.raw(),
            node: node.raw(),
            joined_at_unix_ms,
            metadata: metadata.into(),
        })
    }

    /// Returns the participant peer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// assert_eq!(
    ///     Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?.peer(),
    ///     PeerId::from_raw(1),
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        PeerId::from_raw(self.peer)
    }

    /// Returns the current owner node.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// assert_eq!(
    ///     Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?.node(),
    ///     NodeId::from_raw(2),
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn node(&self) -> NodeId {
        NodeId::from_raw(self.node)
    }

    /// Returns the join timestamp in Unix milliseconds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// assert_eq!(
    ///     Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 7)?.joined_at_unix_ms(),
    ///     7,
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn joined_at_unix_ms(&self) -> u64 {
        self.joined_at_unix_ms
    }

    /// Returns bounded participant metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// assert!(
    ///     Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?
    ///         .metadata()
    ///         .is_empty()
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Updates the current owner node for explicit participant migration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::Participant;
    /// let mut participant = Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?;
    /// participant.set_node(NodeId::from_raw(3));
    /// assert_eq!(participant.node(), NodeId::from_raw(3));
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub const fn set_node(&mut self, node: NodeId) {
        self.node = node.raw();
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId};
    /// # use refract_roomstore::{Participant, Stability};
    /// assert_eq!(
    ///     Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?.stability(),
    ///     Stability::Stage1,
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Track media kind stored with a published track.
#[derive(
    Archive,
    Clone,
    Copy,
    Debug,
    Decode,
    Deserialize,
    Encode,
    Eq,
    Hash,
    PartialEq,
    RkyvDeserialize,
    RkyvSerialize,
    Serialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum TrackKind {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Application data channel or non-media stream.
    Data,
}

impl TrackKind {
    /// Returns the bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::TrackKind;
    /// assert_eq!(TrackKind::Audio.as_str(), "audio");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Data => "data",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{Stability, TrackKind};
    /// assert_eq!(TrackKind::Video.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Durable track record.
#[derive(
    Archive,
    Clone,
    Debug,
    Decode,
    Deserialize,
    Encode,
    Eq,
    PartialEq,
    RkyvDeserialize,
    RkyvSerialize,
    Serialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TrackInfo {
    track: u64,
    publisher: u64,
    kind: TrackKind,
    label: Box<str>,
}

impl TrackInfo {
    /// Creates a bounded track record.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::RecordTooLarge`] when `label` exceeds
    /// [`MAX_TRACK_LABEL_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::{TrackInfo, TrackKind};
    /// let track = TrackInfo::new(
    ///     TrackId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     TrackKind::Audio,
    ///     "mic",
    /// )?;
    /// assert_eq!(track.track(), TrackId::from_raw(1));
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub fn new(
        track: TrackId,
        publisher: PeerId,
        kind: TrackKind,
        label: impl Into<Box<str>>,
    ) -> Result<Self> {
        let label = label.into();
        if label.len() > MAX_TRACK_LABEL_BYTES {
            return Err(RoomStoreError::RecordTooLarge { field: "label" });
        }
        Ok(Self {
            track: track.raw(),
            publisher: publisher.raw(),
            kind,
            label,
        })
    }

    /// Returns the track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::{TrackInfo, TrackKind};
    /// assert_eq!(
    ///     TrackInfo::new(
    ///         TrackId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         TrackKind::Audio,
    ///         "x"
    ///     )?
    ///     .track(),
    ///     TrackId::from_raw(1),
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn track(&self) -> TrackId {
        TrackId::from_raw(self.track)
    }

    /// Returns the publisher peer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::{TrackInfo, TrackKind};
    /// assert_eq!(
    ///     TrackInfo::new(
    ///         TrackId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         TrackKind::Audio,
    ///         "x"
    ///     )?
    ///     .publisher(),
    ///     PeerId::from_raw(2),
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn publisher(&self) -> PeerId {
        PeerId::from_raw(self.publisher)
    }

    /// Returns the track kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::{TrackInfo, TrackKind};
    /// assert_eq!(
    ///     TrackInfo::new(
    ///         TrackId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         TrackKind::Video,
    ///         "x"
    ///     )?
    ///     .kind(),
    ///     TrackKind::Video,
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn kind(&self) -> TrackKind {
        self.kind
    }

    /// Returns the bounded track label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::{TrackInfo, TrackKind};
    /// assert_eq!(
    ///     TrackInfo::new(
    ///         TrackId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         TrackKind::Audio,
    ///         "mic"
    ///     )?
    ///     .label(),
    ///     "mic",
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::{Stability, TrackInfo, TrackKind};
    /// assert_eq!(
    ///     TrackInfo::new(
    ///         TrackId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         TrackKind::Audio,
    ///         "x"
    ///     )?
    ///     .stability(),
    ///     Stability::Stage1,
    /// );
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Durable subscription identifier.
#[derive(
    Archive,
    Clone,
    Copy,
    Debug,
    Decode,
    Deserialize,
    Encode,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    RkyvDeserialize,
    RkyvSerialize,
    Serialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SubscriptionId(u128);

impl SubscriptionId {
    /// Creates a deterministic subscription identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::SubscriptionId;
    /// let id = SubscriptionId::new(PeerId::from_raw(1), TrackId::from_raw(2));
    /// assert_eq!(id.subscriber(), PeerId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn new(subscriber: PeerId, target: TrackId) -> Self {
        Self(((subscriber.raw() as u128) << 64) | (target.raw() as u128))
    }

    /// Creates an identifier from its raw value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::SubscriptionId;
    /// assert_eq!(SubscriptionId::from_raw(9).raw(), 9);
    /// ```
    #[must_use]
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    /// Returns the raw value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::SubscriptionId;
    /// assert_eq!(SubscriptionId::from_raw(10).raw(), 10);
    /// ```
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }

    /// Returns the subscriber peer encoded in this identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::SubscriptionId;
    /// assert_eq!(
    ///     SubscriptionId::new(PeerId::from_raw(3), TrackId::from_raw(4)).subscriber(),
    ///     PeerId::from_raw(3),
    /// );
    /// ```
    #[must_use]
    pub fn subscriber(self) -> PeerId {
        let raw = u64::try_from(self.0 >> 64).unwrap_or_default();
        PeerId::from_raw(raw)
    }

    /// Returns the target track encoded in this identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, TrackId};
    /// # use refract_roomstore::SubscriptionId;
    /// assert_eq!(
    ///     SubscriptionId::new(PeerId::from_raw(3), TrackId::from_raw(4)).target(),
    ///     TrackId::from_raw(4),
    /// );
    /// ```
    #[must_use]
    pub fn target(self) -> TrackId {
        let raw = u64::try_from(self.0 & u128::from(u64::MAX)).unwrap_or_default();
        TrackId::from_raw(raw)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{Stability, SubscriptionId};
    /// assert_eq!(SubscriptionId::from_raw(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sub_{:032x}", self.0)
    }
}

/// RTP audio level reported by the media path.
#[derive(
    Archive,
    Clone,
    Copy,
    Debug,
    Decode,
    Deserialize,
    Encode,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    RkyvDeserialize,
    RkyvSerialize,
    Serialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AudioLevel(u8);

impl AudioLevel {
    /// Creates an RTP audio-level value.
    ///
    /// Lower values are louder. Values greater than 127 are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::InvalidConfig`] when `value > 127`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::AudioLevel;
    /// assert_eq!(AudioLevel::new(7)?.as_u8(), 7);
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub const fn new(value: u8) -> Result<Self> {
        if value > 127 {
            return Err(RoomStoreError::InvalidConfig {
                field: "audio_level",
            });
        }
        Ok(Self(value))
    }

    /// Returns the raw audio-level value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::AudioLevel;
    /// assert_eq!(AudioLevel::new(7)?.as_u8(), 7);
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Returns a loudness score where higher is louder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::AudioLevel;
    /// assert!(AudioLevel::new(0)?.loudness() > AudioLevel::new(127)?.loudness());
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn loudness(self) -> u32 {
        (127 - self.0) as u32
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{AudioLevel, Stability};
    /// assert_eq!(AudioLevel::new(1)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Join operation handle returned after durable admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinHandle {
    room: RoomId,
    peer: PeerId,
    node: NodeId,
}

impl JoinHandle {
    /// Creates a join handle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId, RoomId};
    /// # use refract_roomstore::JoinHandle;
    /// let handle = JoinHandle::new(
    ///     RoomId::from_raw(1),
    ///     PeerId::from_raw(2),
    ///     NodeId::from_raw(3),
    /// );
    /// assert_eq!(handle.peer(), PeerId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn new(room: RoomId, peer: PeerId, node: NodeId) -> Self {
        Self { room, peer, node }
    }

    /// Returns the joined room.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId, RoomId};
    /// # use refract_roomstore::JoinHandle;
    /// assert_eq!(
    ///     JoinHandle::new(
    ///         RoomId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         NodeId::from_raw(3)
    ///     )
    ///     .room(),
    ///     RoomId::from_raw(1),
    /// );
    /// ```
    #[must_use]
    pub const fn room(self) -> RoomId {
        self.room
    }

    /// Returns the joined peer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId, RoomId};
    /// # use refract_roomstore::JoinHandle;
    /// assert_eq!(
    ///     JoinHandle::new(
    ///         RoomId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         NodeId::from_raw(3)
    ///     )
    ///     .peer(),
    ///     PeerId::from_raw(2),
    /// );
    /// ```
    #[must_use]
    pub const fn peer(self) -> PeerId {
        self.peer
    }

    /// Returns the owner node at join time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId, RoomId};
    /// # use refract_roomstore::JoinHandle;
    /// assert_eq!(
    ///     JoinHandle::new(
    ///         RoomId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         NodeId::from_raw(3)
    ///     )
    ///     .node(),
    ///     NodeId::from_raw(3),
    /// );
    /// ```
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, PeerId, RoomId};
    /// # use refract_roomstore::{JoinHandle, Stability};
    /// assert_eq!(
    ///     JoinHandle::new(
    ///         RoomId::from_raw(1),
    ///         PeerId::from_raw(2),
    ///         NodeId::from_raw(3)
    ///     )
    ///     .stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Room event emitted by backends after state changes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RoomEvent {
    /// A participant joined.
    ParticipantJoined {
        /// Joined room.
        room: RoomId,
        /// Participant record.
        participant: Participant,
    },
    /// A participant left.
    ParticipantLeft {
        /// Affected room.
        room: RoomId,
        /// Peer that left.
        peer: PeerId,
    },
    /// A track was published.
    TrackPublished {
        /// Affected room.
        room: RoomId,
        /// Published track.
        track: TrackInfo,
    },
    /// A subscription was created.
    Subscribed {
        /// Affected room.
        room: RoomId,
        /// Subscription identifier.
        subscription: SubscriptionId,
    },
    /// A subscription was removed.
    Unsubscribed {
        /// Subscription identifier.
        subscription: SubscriptionId,
    },
    /// Audio level was reported.
    AudioLevel {
        /// Affected room.
        room: RoomId,
        /// Reporting peer.
        peer: PeerId,
        /// Reported level.
        level: AudioLevel,
    },
    /// A participant migrated to another node.
    ParticipantMigrated {
        /// Affected room.
        room: RoomId,
        /// Migrated peer.
        peer: PeerId,
        /// Destination node.
        to: NodeId,
    },
}

impl RoomEvent {
    /// Returns the event label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_roomstore::RoomEvent;
    /// let event = RoomEvent::ParticipantLeft {
    ///     room: RoomId::from_raw(1),
    ///     peer: PeerId::from_raw(2),
    /// };
    /// assert_eq!(event.as_str(), "participant_left");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ParticipantJoined { .. } => "participant_joined",
            Self::ParticipantLeft { .. } => "participant_left",
            Self::TrackPublished { .. } => "track_published",
            Self::Subscribed { .. } => "subscribed",
            Self::Unsubscribed { .. } => "unsubscribed",
            Self::AudioLevel { .. } => "audio_level",
            Self::ParticipantMigrated { .. } => "participant_migrated",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{PeerId, RoomId};
    /// # use refract_roomstore::{RoomEvent, Stability};
    /// let event = RoomEvent::ParticipantLeft {
    ///     room: RoomId::from_raw(1),
    ///     peer: PeerId::from_raw(2),
    /// };
    /// assert_eq!(event.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Stream returned by [`RoomStore::watch_events`].
pub struct RoomEventStream {
    inner: Pin<Box<dyn Stream<Item = Result<RoomEvent>> + Send>>,
}

impl RoomEventStream {
    /// Creates a room event stream from any sendable stream.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::RoomEventStream;
    /// let stream = RoomEventStream::empty();
    /// assert_eq!(stream.stability(), refract_roomstore::Stability::Stage1);
    /// ```
    #[must_use]
    pub fn new(stream: impl Stream<Item = Result<RoomEvent>> + Send + 'static) -> Self {
        Self {
            inner: Box::pin(stream),
        }
    }

    /// Creates an empty event stream.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::RoomEventStream;
    /// let stream = RoomEventStream::empty();
    /// assert_eq!(stream.stability(), refract_roomstore::Stability::Stage1);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self::new(VecRoomEventStream::new(Vec::new()))
    }

    /// Creates a stream from already materialized events.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::RoomEventStream;
    /// let stream = RoomEventStream::from_events(Vec::new());
    /// assert_eq!(stream.stability(), refract_roomstore::Stability::Stage1);
    /// ```
    #[must_use]
    pub fn from_events(events: Vec<RoomEvent>) -> Self {
        Self::new(VecRoomEventStream::new(events))
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{RoomEventStream, Stability};
    /// assert_eq!(RoomEventStream::empty().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Debug for RoomEventStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoomEventStream")
            .finish_non_exhaustive()
    }
}

impl Stream for RoomEventStream {
    type Item = Result<RoomEvent>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

struct VecRoomEventStream {
    events: VecDeque<RoomEvent>,
}

impl VecRoomEventStream {
    fn new(events: Vec<RoomEvent>) -> Self {
        Self {
            events: events.into(),
        }
    }
}

impl Stream for VecRoomEventStream {
    type Item = Result<RoomEvent>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.events.pop_front().map(Ok))
    }
}

/// Encodes a serializable roomstore record using bincode.
///
/// # Errors
///
/// Returns [`RoomStoreError::Serialization`] when encoding fails.
///
/// # Examples
///
/// ```
/// # use refract_core::{NodeId, PeerId};
/// # use refract_roomstore::{encode_record, Participant};
/// let participant = Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?;
/// assert!(!encode_record(&participant)?.is_empty());
/// # Ok::<(), refract_roomstore::RoomStoreError>(())
/// ```
pub fn encode_record<T>(record: &T) -> Result<Vec<u8>>
where
    T: Encode,
{
    bincode::encode_to_vec(record, bincode::config::standard()).map_err(|_source| {
        RoomStoreError::Serialization {
            component: "bincode",
        }
    })
}

/// Decodes a bincode-serialized roomstore record.
///
/// # Errors
///
/// Returns [`RoomStoreError::Deserialization`] when decoding fails.
///
/// # Examples
///
/// ```
/// # use refract_core::{NodeId, PeerId};
/// # use refract_roomstore::{decode_record, encode_record, Participant};
/// let participant = Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?;
/// let bytes = encode_record(&participant)?;
/// assert_eq!(decode_record::<Participant>(&bytes)?, participant);
/// # Ok::<(), refract_roomstore::RoomStoreError>(())
/// ```
pub fn decode_record<T>(bytes: &[u8]) -> Result<T>
where
    T: Decode<()>,
{
    bincode::decode_from_slice(bytes, bincode::config::standard())
        .map(|(value, _bytes_read)| value)
        .map_err(|_source| RoomStoreError::Deserialization {
            component: "bincode",
        })
}

/// Stage 1 room store trait.
pub trait RoomStore: Send + Sync + 'static {
    /// Atomically joins a participant to one room.
    ///
    /// # Errors
    ///
    /// Returns backend, timeout, or validation errors.
    fn join(&self, room: RoomId, p: Participant)
    -> impl Future<Output = Result<JoinHandle>> + Send;

    /// Atomically removes a participant from one room.
    ///
    /// # Errors
    ///
    /// Returns backend, timeout, or validation errors.
    fn leave(&self, room: RoomId, peer: PeerId) -> impl Future<Output = Result<()>> + Send;

    /// Lists participants with a bounded page size and backend cursor.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::InvalidLimit`] when `limit` is zero or exceeds
    /// [`MAX_PARTICIPANT_PAGE_LIMIT`], plus backend or timeout errors.
    fn participants(
        &self,
        room: RoomId,
        limit: usize,
        cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<(Vec<Participant>, Option<Cursor>)>> + Send;

    /// Atomically publishes a track for one room participant.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::ParticipantNotFound`] if the publisher is not
    /// present, plus backend or timeout errors.
    fn publish_track(
        &self,
        room: RoomId,
        peer: PeerId,
        track: TrackInfo,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Subscribes one peer to a target track.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::ParticipantNotFound`] or
    /// [`RoomStoreError::TrackNotFound`] when prerequisites are missing.
    fn subscribe(
        &self,
        room: RoomId,
        sub: PeerId,
        target: TrackId,
    ) -> impl Future<Output = Result<SubscriptionId>> + Send;

    /// Removes one subscription.
    ///
    /// # Errors
    ///
    /// Returns backend or timeout errors.
    fn unsubscribe(&self, sub: SubscriptionId) -> impl Future<Output = Result<()>> + Send;

    /// Reports one peer audio level.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::ParticipantNotFound`] when the peer is not in
    /// the room, plus backend or timeout errors.
    fn report_audio_level(
        &self,
        room: RoomId,
        peer: PeerId,
        level: AudioLevel,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Watches room events from the backend's delivery mechanism.
    ///
    /// # Errors
    ///
    /// Returns backend or timeout errors when a watch cannot be established.
    fn watch_events(&self, room: RoomId) -> impl Future<Output = Result<RoomEventStream>> + Send;

    /// Explicitly migrates one participant to another node.
    ///
    /// # Errors
    ///
    /// Returns [`RoomStoreError::ParticipantNotFound`] if the peer is absent,
    /// plus backend or timeout errors.
    fn migrate_participant(
        &self,
        room: RoomId,
        peer: PeerId,
        to: NodeId,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// In-memory room store for upper-layer unit tests.
#[derive(Debug, Default)]
pub struct MockRoomStore {
    inner: Mutex<MockInner>,
}

impl MockRoomStore {
    /// Creates an empty mock room store.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::MockRoomStore;
    /// let store = MockRoomStore::new();
    /// assert_eq!(store.stability(), refract_roomstore::Stability::Stage1);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore::{MockRoomStore, Stability};
    /// assert_eq!(MockRoomStore::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn lock(&self) -> Result<MutexGuard<'_, MockInner>> {
        self.inner.lock().map_err(RoomStoreError::from)
    }
}

#[allow(clippy::significant_drop_tightening)]
impl RoomStore for MockRoomStore {
    async fn join(&self, room: RoomId, p: Participant) -> Result<JoinHandle> {
        let handle = JoinHandle::new(room, p.peer(), p.node());
        {
            let mut inner = self.lock()?;
            let state = inner.rooms.entry(room.raw()).or_default();
            state.events.push(RoomEvent::ParticipantJoined {
                room,
                participant: p.clone(),
            });
            state.participants.insert(p.peer().raw(), p);
        }
        Ok(handle)
    }

    async fn leave(&self, room: RoomId, peer: PeerId) -> Result<()> {
        {
            let mut inner = self.lock()?;
            if let Some(state) = inner.rooms.get_mut(&room.raw()) {
                state.participants.remove(&peer.raw());
                state
                    .tracks
                    .retain(|_track_id, track| track.publisher() != peer);
                state
                    .subscriptions
                    .retain(|subscription, _target| subscription.subscriber() != peer);
                state.events.push(RoomEvent::ParticipantLeft { room, peer });
            }
        }
        Ok(())
    }

    async fn participants(
        &self,
        room: RoomId,
        limit: usize,
        cursor: Option<Cursor>,
    ) -> Result<(Vec<Participant>, Option<Cursor>)> {
        validate_limit(limit)?;
        let start_after = cursor.map_or(0, Cursor::raw);
        let (page, next) = {
            let inner = self.lock()?;
            let Some(state) = inner.rooms.get(&room.raw()) else {
                return Ok((Vec::new(), None));
            };
            let mut page = Vec::new();
            page.try_reserve_exact(limit)
                .map_err(|_source| RoomStoreError::Backend {
                    message: "participant page allocation failed".to_owned(),
                })?;
            let mut next = None;
            for (peer, participant) in state
                .participants
                .range((start_after.saturating_add(1))..)
                .take(limit.saturating_add(1))
            {
                if page.len() == limit {
                    next = Some(Cursor::from_raw(peer.saturating_sub(1)));
                    break;
                }
                page.push(participant.clone());
            }
            (page, next)
        };
        Ok((page, next))
    }

    async fn publish_track(&self, room: RoomId, peer: PeerId, track: TrackInfo) -> Result<()> {
        {
            let mut inner = self.lock()?;
            let state = inner.rooms.entry(room.raw()).or_default();
            if !state.participants.contains_key(&peer.raw()) {
                return Err(RoomStoreError::ParticipantNotFound);
            }
            state.events.push(RoomEvent::TrackPublished {
                room,
                track: track.clone(),
            });
            state.tracks.insert(track.track().raw(), track);
        }
        Ok(())
    }

    async fn subscribe(
        &self,
        room: RoomId,
        sub: PeerId,
        target: TrackId,
    ) -> Result<SubscriptionId> {
        let subscription = SubscriptionId::new(sub, target);
        {
            let mut inner = self.lock()?;
            let state = inner.rooms.entry(room.raw()).or_default();
            if !state.participants.contains_key(&sub.raw()) {
                return Err(RoomStoreError::ParticipantNotFound);
            }
            if !state.tracks.contains_key(&target.raw()) {
                return Err(RoomStoreError::TrackNotFound);
            }
            state.subscriptions.insert(subscription, target);
            state
                .events
                .push(RoomEvent::Subscribed { room, subscription });
        }
        Ok(subscription)
    }

    async fn unsubscribe(&self, sub: SubscriptionId) -> Result<()> {
        {
            let mut inner = self.lock()?;
            for state in inner.rooms.values_mut() {
                if state.subscriptions.remove(&sub).is_some() {
                    state
                        .events
                        .push(RoomEvent::Unsubscribed { subscription: sub });
                    break;
                }
            }
        }
        Ok(())
    }

    async fn report_audio_level(
        &self,
        room: RoomId,
        peer: PeerId,
        level: AudioLevel,
    ) -> Result<()> {
        {
            let mut inner = self.lock()?;
            let state = inner.rooms.entry(room.raw()).or_default();
            if !state.participants.contains_key(&peer.raw()) {
                return Err(RoomStoreError::ParticipantNotFound);
            }
            state.speakers.insert(peer.raw(), level.loudness());
            state
                .events
                .push(RoomEvent::AudioLevel { room, peer, level });
        }
        Ok(())
    }

    async fn watch_events(&self, room: RoomId) -> Result<RoomEventStream> {
        let events = {
            let inner = self.lock()?;
            inner
                .rooms
                .get(&room.raw())
                .map_or_else(Vec::new, |state| state.events.clone())
        };
        Ok(RoomEventStream::from_events(events))
    }

    async fn migrate_participant(&self, room: RoomId, peer: PeerId, to: NodeId) -> Result<()> {
        {
            let mut inner = self.lock()?;
            let state = inner.rooms.entry(room.raw()).or_default();
            let participant = state
                .participants
                .get_mut(&peer.raw())
                .ok_or(RoomStoreError::ParticipantNotFound)?;
            participant.set_node(to);
            state
                .events
                .push(RoomEvent::ParticipantMigrated { room, peer, to });
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MockInner {
    rooms: BTreeMap<u64, MockRoomState>,
}

#[derive(Debug, Default)]
struct MockRoomState {
    participants: BTreeMap<u64, Participant>,
    tracks: BTreeMap<u64, TrackInfo>,
    subscriptions: BTreeMap<SubscriptionId, TrackId>,
    speakers: BTreeMap<u64, u32>,
    events: Vec<RoomEvent>,
}

/// Validates a participant page limit.
///
/// # Errors
///
/// Returns [`RoomStoreError::InvalidLimit`] when the limit is zero or exceeds
/// [`MAX_PARTICIPANT_PAGE_LIMIT`].
///
/// # Examples
///
/// ```
/// # use refract_roomstore::validate_limit;
/// validate_limit(100)?;
/// # Ok::<(), refract_roomstore::RoomStoreError>(())
/// ```
pub const fn validate_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > MAX_PARTICIPANT_PAGE_LIMIT {
        return Err(RoomStoreError::InvalidLimit { limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use compio::runtime::Runtime;
    use proptest::{prelude::*, test_runner::TestCaseError};
    use refract_core::{NodeId, PeerId, RoomId, TrackId};

    use super::{
        AudioLevel, Cursor, MockRoomStore, Participant, RoomStore, RoomStoreError, SubscriptionId,
        TrackInfo, TrackKind, decode_record, encode_record,
    };
    use crate::MAX_PARTICIPANT_PAGE_LIMIT;

    #[test]
    fn participant_and_track_records_round_trip_bincode() {
        let participant =
            Participant::with_metadata(PeerId::from_raw(1), NodeId::from_raw(2), 3, b"meta")
                .expect("bounded participant");
        let participant_bytes = encode_record(&participant).expect("participant encodes");
        assert_eq!(
            decode_record::<Participant>(&participant_bytes).expect("participant decodes"),
            participant
        );

        let track = TrackInfo::new(
            TrackId::from_raw(4),
            PeerId::from_raw(1),
            TrackKind::Audio,
            "mic",
        )
        .expect("bounded track");
        let track_bytes = encode_record(&track).expect("track encodes");
        assert_eq!(
            decode_record::<TrackInfo>(&track_bytes).expect("track decodes"),
            track
        );
    }

    #[test]
    fn mock_store_multi_client_room_flow() {
        Runtime::new().expect("runtime").block_on(async {
            let store = MockRoomStore::new();
            let room = RoomId::from_raw(10);
            let first = Participant::new(PeerId::from_raw(1), NodeId::from_raw(1), 100)
                .expect("first participant");
            let second = Participant::new(PeerId::from_raw(2), NodeId::from_raw(1), 101)
                .expect("second participant");
            store.join(room, first).await.expect("first joins");
            store.join(room, second).await.expect("second joins");

            let track = TrackInfo::new(
                TrackId::from_raw(99),
                PeerId::from_raw(1),
                TrackKind::Audio,
                "mic",
            )
            .expect("track");
            store
                .publish_track(room, PeerId::from_raw(1), track)
                .await
                .expect("publish");
            let subscription = store
                .subscribe(room, PeerId::from_raw(2), TrackId::from_raw(99))
                .await
                .expect("subscribe");
            assert_eq!(
                subscription,
                SubscriptionId::new(PeerId::from_raw(2), TrackId::from_raw(99))
            );

            let (participants, next) = store
                .participants(room, 100, None)
                .await
                .expect("participants");
            assert_eq!(participants.len(), 2);
            assert_eq!(next, None);
        });
    }

    #[test]
    fn mock_store_paginates_with_cursor() {
        Runtime::new().expect("runtime").block_on(async {
            let store = MockRoomStore::new();
            let room = RoomId::from_raw(77);
            for peer in 1..=3 {
                let participant =
                    Participant::new(PeerId::from_raw(peer), NodeId::from_raw(1), peer)
                        .expect("participant");
                store.join(room, participant).await.expect("join");
            }

            let (first, cursor) = store.participants(room, 2, None).await.expect("first page");
            assert_eq!(first.len(), 2);
            let (second, next) = store
                .participants(room, 2, cursor)
                .await
                .expect("second page");
            assert_eq!(second.len(), 1);
            assert_eq!(next, None);
        });
    }

    #[test]
    fn explicit_migration_updates_participant_without_leave_join() {
        Runtime::new().expect("runtime").block_on(async {
            let store = MockRoomStore::new();
            let room = RoomId::from_raw(5);
            let peer = PeerId::from_raw(9);
            store
                .join(
                    room,
                    Participant::new(peer, NodeId::from_raw(1), 1).expect("participant"),
                )
                .await
                .expect("join");
            store
                .migrate_participant(room, peer, NodeId::from_raw(2))
                .await
                .expect("migrate");
            let (participants, _cursor) = store
                .participants(room, 1, None)
                .await
                .expect("participants");

            assert_eq!(participants[0].node(), NodeId::from_raw(2));
        });
    }

    #[test]
    fn invalid_limits_fail_closed() {
        assert!(matches!(
            super::validate_limit(0),
            Err(RoomStoreError::InvalidLimit { limit: 0 })
        ));
        assert!(matches!(
            super::validate_limit(MAX_PARTICIPANT_PAGE_LIMIT + 1),
            Err(RoomStoreError::InvalidLimit { .. })
        ));
    }

    proptest! {
        #[test]
        fn property_join_leave_participant_listing_matches_model(ops in proptest::collection::vec((1_u64..32, any::<bool>()), 1..128)) {
            Runtime::new().expect("runtime").block_on(async {
                let store = MockRoomStore::new();
                let room = RoomId::from_raw(1);
                let mut model = std::collections::BTreeSet::new();

                for (peer_raw, should_join) in ops {
                    let peer = PeerId::from_raw(peer_raw);
                    if should_join {
                        let participant = Participant::new(peer, NodeId::from_raw(1), 0)
                            .expect("participant");
                        store.join(room, participant).await.expect("join");
                        model.insert(peer_raw);
                    } else {
                        store.leave(room, peer).await.expect("leave");
                        model.remove(&peer_raw);
                    }
                }

                let (participants, cursor) = store
                    .participants(room, MAX_PARTICIPANT_PAGE_LIMIT, None)
                    .await
                    .expect("participants");
                let observed = participants
                    .iter()
                    .map(|participant| participant.peer().raw())
                    .collect::<std::collections::BTreeSet<_>>();

                prop_assert_eq!(cursor, None);
                prop_assert_eq!(observed, model);
                Ok::<(), TestCaseError>(())
            })?;
        }

        #[test]
        fn property_audio_level_accepts_only_rtp_extension_range(value in any::<u8>()) {
            let result = AudioLevel::new(value);
            prop_assert_eq!(result.is_ok(), value <= 127);
        }

        #[test]
        fn property_cursor_preserves_raw_value(raw in any::<u64>()) {
            prop_assert_eq!(Cursor::from_raw(raw).raw(), raw);
        }
    }
}
