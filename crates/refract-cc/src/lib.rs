//! Congestion control, transport-cc feedback, pacing, and probing primitives.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_cc::{Pacer, PacerConfig, PacedPacket, PacketPriority};
//! let mut pacer = Pacer::new(PacerConfig::default());
//! pacer.enqueue(PacedPacket::new(
//!     1,
//!     120,
//!     PacketPriority::Audio,
//!     Duration::ZERO,
//! ))?;
//! let mut out = [PacedPacket::default(); 1];
//! assert_eq!(pacer.drain(Duration::from_millis(10), &mut out), 1);
//! # Ok::<(), refract_cc::CcError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

pub mod gcc;
pub mod metrics;
pub mod pacer;
pub mod prober;
pub mod twcc;

mod error;
mod stability;

pub use error::{CcError, CcResult};
pub use gcc::{BandwidthUsage, BweEstimate, DelayBasedBwe, TrendlineEstimator, TrendlineSettings};
pub use pacer::{PacedPacket, Pacer, PacerConfig, PacketPriority};
pub use prober::{ProbeDecision, Prober, ProberConfig};
pub use stability::Stability;
pub use twcc::{
    MAX_TWCC_FEEDBACK_BYTES, MAX_TWCC_PACKETS, PacketStatus, TwccFeedback, TwccPacketRecord,
    TwccRecorder, TwccSequenceNumber,
};
