//! Linux `eBPF` and `XDP` rate-limiting integration boundary.
//!
//! The crate owns the user-space contract for the Stage 1 XDP hardening
//! program: bounded configuration, deterministic packet classification,
//! stable statistics names, and a Linux-only Aya loader.
//!
//! # Examples
//!
//! ```
//! use refract_xdp::{PacketClass, classify_udp_payload};
//!
//! let mut packet = [0_u8; 20];
//! packet[0] = 0x00;
//! packet[1] = 0x01;
//! packet[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
//! assert_eq!(classify_udp_payload(&packet), PacketClass::StunBinding);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

mod classifier;
mod config;
mod error;
#[cfg(target_os = "linux")]
mod loader;
mod stats;
mod wire;

pub use classifier::{PacketClass, classify_udp_payload};
pub use config::{AttachMode, InterfaceName, ListenPort, StunRateLimit, XdpConfig};
pub use error::{XdpError, XdpResult};
#[cfg(target_os = "linux")]
pub use loader::LoadedXdp;
pub use stats::{CounterId, XdpStats};
pub use wire::{
    DEFAULT_STUN_BURST, DEFAULT_STUN_RATE_PER_SECOND, STATS_COUNTERS, STUN_MAGIC_COOKIE,
};

/// Public API stability marker for the Stage 1 XDP boundary.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     refract_xdp::API_STABILITY,
///     refract_xdp::ApiStability::Stage1
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiStability {
    /// Stage 1 API. Compatible additions are allowed; breaking changes require
    /// revisiting the Stage 1 contract first.
    Stage1,
}

/// Stability marker for every public item in this crate.
pub const API_STABILITY: ApiStability = ApiStability::Stage1;
