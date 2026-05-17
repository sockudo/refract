//! Post-ICE source address validation.
//!
//! After consent succeeds for a candidate pair, packets are accepted only from
//! the validated five-tuple. A mismatch asks the ICE layer to run consent again.

#![allow(clippy::missing_const_for_fn)]

use std::net::SocketAddr;

/// Source validation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationDecision {
    /// Packet source matches the consented five-tuple.
    Accept,
    /// Packet source differs and should trigger a consent check.
    TriggerConsentCheck,
}

/// Validated source tuple state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceValidator {
    tuple: Option<SocketAddr>,
}

impl SourceValidator {
    /// Creates an empty source validator.
    #[must_use]
    pub const fn new() -> Self {
        Self { tuple: None }
    }

    /// Records the tuple that passed consent freshness.
    pub fn consented(&mut self, remote: SocketAddr) {
        self.tuple = Some(remote);
    }

    /// Validates an incoming packet source.
    #[must_use]
    pub const fn validate(self, remote: SocketAddr) -> ValidationDecision {
        match self.tuple {
            Some(tuple) if socket_addr_eq(tuple, remote) => ValidationDecision::Accept,
            Some(_) | None => ValidationDecision::TriggerConsentCheck,
        }
    }

    /// Returns the consented tuple.
    #[must_use]
    pub const fn tuple(self) -> Option<SocketAddr> {
        self.tuple
    }
}

const fn socket_addr_eq(left: SocketAddr, right: SocketAddr) -> bool {
    match (left, right) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => {
            a.ip().octets()[0] == b.ip().octets()[0]
                && a.ip().octets()[1] == b.ip().octets()[1]
                && a.ip().octets()[2] == b.ip().octets()[2]
                && a.ip().octets()[3] == b.ip().octets()[3]
                && a.port() == b.port()
        }
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            let left_segments = a.ip().segments();
            let right_segments = b.ip().segments();
            left_segments[0] == right_segments[0]
                && left_segments[1] == right_segments[1]
                && left_segments[2] == right_segments[2]
                && left_segments[3] == right_segments[3]
                && left_segments[4] == right_segments[4]
                && left_segments[5] == right_segments[5]
                && left_segments[6] == right_segments[6]
                && left_segments[7] == right_segments[7]
                && a.port() == b.port()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_rebinding_triggers_consent() {
        let original = SocketAddr::from(([192, 0, 2, 1], 5000));
        let rebound = SocketAddr::from(([192, 0, 2, 1], 5001));
        let mut validator = SourceValidator::new();
        validator.consented(original);
        assert_eq!(validator.validate(original), ValidationDecision::Accept);
        assert_eq!(
            validator.validate(rebound),
            ValidationDecision::TriggerConsentCheck
        );
    }
}
