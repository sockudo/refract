//! Bounded jitter, RTP loss detection, and feedback coalescing.
//!
//! `refract-jitter` owns per-publisher recent RTP retention for RTX, ingress
//! sequence loss detection, per subscriber/publisher `NACK` dedupe and rate
//! limiting, and independent `PLI`/`FIR` coalescing.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_jitter::{
//! #     FeedbackCoalescer, JitterConfig, LossDetector, NackAggregator, PublisherBuffer,
//! #     RtpSequenceNumber,
//! # };
//! let mut buffer = PublisherBuffer::with_config(JitterConfig::default())?;
//! buffer.insert(RtpSequenceNumber::new(1), &[0x80, 0x60])?;
//!
//! let mut detector = LossDetector::new();
//! let mut nacks = NackAggregator::default();
//! detector.observe(RtpSequenceNumber::new(1), Duration::ZERO, &mut nacks);
//! let batch = detector.observe(RtpSequenceNumber::new(3), Duration::ZERO, &mut nacks);
//! assert_eq!(batch.sequences(), &[RtpSequenceNumber::new(2)]);
//!
//! let mut feedback = FeedbackCoalescer::default();
//! assert!(feedback.request_pli(Duration::ZERO));
//! # Ok::<(), refract_jitter::JitterError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

mod buffer;
mod config;
mod error;
mod feedback;
mod loss;
pub mod metrics;
mod nack;
mod sequence;
mod stability;

pub use buffer::{InsertOutcome, PublisherBuffer};
pub use config::{
    DEFAULT_AVERAGE_PACKET_BYTES, DEFAULT_MAX_BITRATE_BPS, DEFAULT_MAX_PACKET_BYTES,
    DEFAULT_MEMORY_CAP_BYTES, DEFAULT_RETRANSMIT_WINDOW, JitterConfig, MAX_BUFFER_PACKETS,
};
pub use error::{JitterError, JitterResult};
pub use feedback::{DEFAULT_FEEDBACK_COALESCE_WINDOW, FeedbackCoalescer, FeedbackKind};
pub use loss::LossDetector;
pub use nack::{
    DEFAULT_NACK_DEDUPE_WINDOW, DEFAULT_NACK_RATE_WINDOW, DEFAULT_NACKS_PER_WINDOW,
    MAX_NACK_HISTORY, NackAggregator, NackBatch, NackRateLimit,
};
pub use sequence::RtpSequenceNumber;
pub use stability::Stability;
