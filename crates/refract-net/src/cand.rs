//! ICE candidate types and SDP serialization.
//!
//! # Examples
//!
//! ```
//! use std::net::SocketAddr;
//! use refract_net::cand::{Candidate, CandidateKind, TransportProtocol};
//!
//! let c = Candidate::new("1", 1, TransportProtocol::Udp, 100, "127.0.0.1:9".parse::<SocketAddr>()?, CandidateKind::Host);
//! assert!(c.to_sdp().starts_with("candidate:1 1 UDP"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::{fmt::Write, net::SocketAddr};

/// ICE candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// Host candidate.
    Host,
    /// Server-reflexive candidate.
    ServerReflexive,
    /// Peer-reflexive candidate.
    PeerReflexive,
    /// Relayed candidate.
    Relay,
}

impl CandidateKind {
    /// Returns SDP candidate type label.
    #[must_use]
    pub const fn as_sdp(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }
}

/// Candidate transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// UDP transport.
    Udp,
}

impl TransportProtocol {
    /// Returns SDP protocol label.
    #[must_use]
    pub const fn as_sdp(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
        }
    }
}

/// ICE candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    foundation: String,
    component: u16,
    protocol: TransportProtocol,
    priority: u32,
    address: SocketAddr,
    kind: CandidateKind,
    related_address: Option<SocketAddr>,
}

impl Candidate {
    /// Creates a candidate.
    #[must_use]
    pub fn new(
        foundation: impl Into<String>,
        component: u16,
        protocol: TransportProtocol,
        priority: u32,
        address: SocketAddr,
        kind: CandidateKind,
    ) -> Self {
        Self {
            foundation: foundation.into(),
            component,
            protocol,
            priority,
            address,
            kind,
            related_address: None,
        }
    }

    /// Adds a related address.
    #[must_use]
    pub const fn with_related_address(mut self, related_address: SocketAddr) -> Self {
        self.related_address = Some(related_address);
        self
    }

    /// Returns the priority.
    #[must_use]
    pub const fn priority(&self) -> u32 {
        self.priority
    }

    /// Returns the socket address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the candidate type.
    #[must_use]
    pub const fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// Serializes this candidate as an SDP `candidate` attribute value.
    #[must_use]
    pub fn to_sdp(&self) -> String {
        let ip = self.address.ip();
        let port = self.address.port();
        let mut sdp = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.protocol.as_sdp(),
            self.priority,
            ip,
            port,
            self.kind.as_sdp()
        );
        if let Some(related) = self.related_address {
            let _ = write!(sdp, " raddr {} rport {}", related.ip(), related.port());
        }
        sdp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_relay_candidate_with_related_address() {
        let candidate = Candidate::new(
            "relay",
            1,
            TransportProtocol::Udp,
            42,
            SocketAddr::from(([203, 0, 113, 1], 5000)),
            CandidateKind::Relay,
        )
        .with_related_address(SocketAddr::from(([10, 0, 0, 1], 4000)));
        assert_eq!(
            candidate.to_sdp(),
            "candidate:relay 1 UDP 42 203.0.113.1 5000 typ relay raddr 10.0.0.1 rport 4000"
        );
    }
}
