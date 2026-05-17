//! `UDP`, `ICE`, and `STUN` networking boundary.
//!
//! The crate implements bounded STUN parsing/serialization, ICE-Lite state,
//! candidate SDP formatting, transport traits, per-IP STUN rate limiting, and
//! post-consent source validation.
//!
//! # Examples
//!
//! ```
//! use refract_net::stun::{MessageClass, Method, StunMessage};
//!
//! let msg = StunMessage::new(Method::Binding, MessageClass::Request, [1; 12]);
//! assert_eq!(msg.method(), Method::Binding);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

pub mod cand;
pub mod ice;
pub mod rate_limit;
pub mod stun;
pub mod transport;
pub mod validation;

pub use stun::{NetError, NetResult};
