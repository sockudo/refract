//! Core shared types, errors, limits, clocks, media descriptors, and panic
//! discipline for the refract `SFU`.
//!
//! This crate is dependency-light by design. It contains semantic newtypes and
//! operational primitives used by later Stage 1 crates without introducing
//! media-plane allocation or runtime ownership.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

pub mod error;
pub mod ids;
pub mod limits;
pub mod media;
pub mod panic;
pub mod quality;
pub mod time;

pub use error::{Error, ErrorCategory, ErrorField, ErrorFields, FieldValue, Result};
pub use ids::{NodeId, PeerId, RoomId, SessionId, Ssrc, TrackId};
pub use media::{Codec, CodecKind, CodecPacket, Direction, MediaKind, PayloadType};
pub use quality::{Layer, LayerInfo, QualityScore};
pub use time::{Clock, Deadline, Duration, Instant, MockClock, SystemClock};
