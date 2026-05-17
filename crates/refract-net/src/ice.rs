//! ICE-Lite state for RFC 8445, RFC 8838, RFC 8839, and RFC 7675.
//!
//! The SFU is always controlled in this implementation. Candidate-pair
//! selection is by highest remote priority, consent freshness is checked every
//! five seconds, and missing consent for thirty seconds disconnects the pair.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::{
    cand::Candidate,
    stun::{Attribute, MessageClass, Method, NetResult, StunMessage},
    validation::SourceValidator,
};

/// ICE consent freshness interval.
pub const CONSENT_INTERVAL: Duration = Duration::from_secs(5);

/// ICE consent disconnect timeout.
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// ICE role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// Controlled role; ICE-Lite SFU always uses this role.
    Controlled,
}

/// ICE connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// No nominated pair yet.
    New,
    /// Pair selected and consent currently fresh.
    Connected,
    /// Consent check is due or source tuple changed.
    Checking,
    /// Consent was missed for the disconnect timeout.
    Disconnected,
}

/// ICE candidate pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    local: Candidate,
    remote: Candidate,
}

impl CandidatePair {
    /// Creates a candidate pair.
    #[must_use]
    pub const fn new(local: Candidate, remote: Candidate) -> Self {
        Self { local, remote }
    }

    /// Returns local candidate.
    #[must_use]
    pub const fn local(&self) -> &Candidate {
        &self.local
    }

    /// Returns remote candidate.
    #[must_use]
    pub const fn remote(&self) -> &Candidate {
        &self.remote
    }

    /// Returns the remote priority used for pair selection.
    #[must_use]
    pub const fn remote_priority(&self) -> u32 {
        self.remote.priority()
    }
}

/// ICE-Lite agent state.
#[derive(Debug)]
pub struct IceLite {
    role: IceRole,
    state: IceState,
    pairs: Vec<CandidatePair>,
    selected: Option<usize>,
    last_consent: Option<Instant>,
    next_consent: Option<Instant>,
    validator: SourceValidator,
}

impl IceLite {
    /// Creates a controlled ICE-Lite agent.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            role: IceRole::Controlled,
            state: IceState::New,
            pairs: Vec::new(),
            selected: None,
            last_consent: None,
            next_consent: None,
            validator: SourceValidator::new(),
        }
    }

    /// Returns the ICE role.
    #[must_use]
    pub const fn role(&self) -> IceRole {
        self.role
    }

    /// Returns current ICE state.
    #[must_use]
    pub const fn state(&self) -> IceState {
        self.state
    }

    /// Adds a trickled remote candidate pair and reselects by remote priority.
    pub fn trickle_remote_candidate(&mut self, local: Candidate, remote: Candidate) {
        self.pairs.push(CandidatePair::new(local, remote));
        self.select_by_remote_priority();
    }

    /// Returns selected candidate pair.
    #[must_use]
    pub fn selected_pair(&self) -> Option<&CandidatePair> {
        self.selected.and_then(|index| self.pairs.get(index))
    }

    /// Handles an incoming connectivity check and builds a success response.
    ///
    /// # Errors
    ///
    /// Returns STUN serialization errors if the response cannot fit.
    pub fn connectivity_check_response<'a>(
        &mut self,
        request: &StunMessage<'a>,
        source: SocketAddr,
        now: Instant,
        out: &'a mut [u8],
    ) -> NetResult<usize> {
        self.handle_role_conflict(request);
        self.last_consent = Some(now);
        self.next_consent = Some(now + CONSENT_INTERVAL);
        self.state = IceState::Connected;
        self.validator.consented(source);
        let mut response = StunMessage::new(
            Method::Binding,
            MessageClass::SuccessResponse,
            request.transaction_id(),
        );
        response.push_attr(Attribute::XorMappedAddress(source));
        response.encode(out)
    }

    /// Returns whether a consent check should be sent at `now`.
    #[must_use]
    pub fn consent_due(&self, now: Instant) -> bool {
        self.next_consent.is_some_and(|deadline| now >= deadline)
    }

    /// Records consent success from a remote address.
    pub fn record_consent_success(&mut self, remote: SocketAddr, now: Instant) {
        self.last_consent = Some(now);
        self.next_consent = Some(now + CONSENT_INTERVAL);
        self.state = IceState::Connected;
        self.validator.consented(remote);
    }

    /// Advances consent freshness state.
    #[must_use]
    pub fn tick(&mut self, now: Instant) -> IceState {
        if let Some(last) = self.last_consent {
            if now.duration_since(last) >= CONSENT_TIMEOUT {
                self.state = IceState::Disconnected;
            } else if self.consent_due(now) {
                self.state = IceState::Checking;
            }
        }
        self.state
    }

    /// Handles a source tuple mismatch and requests consent.
    pub fn source_mismatch(&mut self) {
        if self.state == IceState::Connected {
            self.state = IceState::Checking;
        }
    }

    /// Returns the source validator.
    #[must_use]
    pub const fn source_validator(&self) -> SourceValidator {
        self.validator
    }

    fn select_by_remote_priority(&mut self) {
        self.selected = self
            .pairs
            .iter()
            .enumerate()
            .max_by_key(|(_index, pair)| pair.remote_priority())
            .map(|(index, _pair)| index);
    }

    fn handle_role_conflict(&mut self, request: &StunMessage<'_>) {
        let has_controlling = request
            .attributes()
            .iter()
            .any(|attr| matches!(attr, Attribute::IceControlling(_)));
        if has_controlling {
            self.role = IceRole::Controlled;
        }
    }
}

impl Default for IceLite {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cand::{CandidateKind, TransportProtocol};

    fn candidate(priority: u32, port: u16) -> Candidate {
        Candidate::new(
            "f",
            1,
            TransportProtocol::Udp,
            priority,
            SocketAddr::from(([127, 0, 0, 1], port)),
            CandidateKind::Host,
        )
    }

    #[test]
    fn selects_pair_by_remote_priority() {
        let mut ice = IceLite::new();
        ice.trickle_remote_candidate(candidate(1, 1), candidate(10, 2));
        ice.trickle_remote_candidate(candidate(1, 1), candidate(20, 3));
        assert_eq!(
            ice.selected_pair().map(CandidatePair::remote_priority),
            Some(20)
        );
    }

    #[test]
    fn consent_disconnects_after_timeout() {
        let start = Instant::now();
        let mut ice = IceLite::new();
        ice.record_consent_success(SocketAddr::from(([127, 0, 0, 1], 9)), start);
        assert!(ice.consent_due(start + CONSENT_INTERVAL));
        assert_eq!(ice.tick(start + CONSENT_TIMEOUT), IceState::Disconnected);
    }
}
