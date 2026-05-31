//! `RTP` and `RTCP` parsing, validation, and in-place rewrite primitives.
//!
//! The crate keeps the packet hot path allocation-free by parsing borrowed
//! packet views and rewriting fixed RTP header fields in caller-owned buffers.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::header::RtpHeader;
//! let packet = [0x80, 0x60, 0x12, 0x34, 0, 0, 0, 9, 0xaa, 0xbb, 0xcc, 0xdd];
//! let header = RtpHeader::parse(&packet)?;
//! assert_eq!(header.sequence(), 0x1234);
//! # Ok::<(), refract_rtp::RtpError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

pub mod error;
pub mod extensions;
pub mod header;
pub mod metrics;
pub mod pad_strip;
pub mod rewriter;
pub mod rtcp;
pub mod stability;

pub use error::{RtpError, RtpResult};
pub use stability::Stability;
