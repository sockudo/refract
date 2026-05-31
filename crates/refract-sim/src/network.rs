//! Deterministic virtual UDP network.
//!
//! The network enforces bounded node counts, bounded datagram length, seeded
//! loss, seeded latency jitter, seeded reorder delay, and explicit partitions.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    time::Duration,
};

use crate::{DeterministicRng, SimError, SimResult, Stability};

/// Maximum datagram payload accepted by the simulator.
pub const MAX_DATAGRAM_BYTES: usize = 2_048;

/// Maximum nodes accepted by one simulation.
pub const MAX_NODES: usize = 65_536;

/// Maximum datagrams that can be queued for future delivery.
pub const MAX_PENDING_DATAGRAMS: usize = 262_144;

/// Probability denominator for parts-per-million loss and reorder controls.
pub const PPM_DENOMINATOR: u32 = 1_000_000;

const MAX_LINK_DELAY: Duration = Duration::from_hours(1);

/// Node identifier inside a deterministic simulation topology.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SimNodeId(u32);

impl SimNodeId {
    /// Creates a simulation node identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::SimNodeId;
    /// assert_eq!(SimNodeId::new(3).as_u32(), 3);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw node identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::SimNodeId;
    /// assert_eq!(SimNodeId::new(3).as_u32(), 3);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{SimNodeId, Stability};
    /// assert_eq!(SimNodeId::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for SimNodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sim_node_{}", self.0)
    }
}

/// Probability represented in parts per million.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProbabilityPpm(u32);

impl ProbabilityPpm {
    /// Creates a bounded probability.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::ProbabilityOutOfRange`] when `value` is greater
    /// than [`PPM_DENOMINATOR`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::ProbabilityPpm;
    /// assert_eq!(ProbabilityPpm::new(500_000)?.as_u32(), 500_000);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub const fn new(value: u32) -> SimResult<Self> {
        if value > PPM_DENOMINATOR {
            return Err(SimError::ProbabilityOutOfRange { ppm: value });
        }
        Ok(Self(value))
    }

    /// Returns a probability that never hits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::ProbabilityPpm;
    /// assert_eq!(ProbabilityPpm::never().as_u32(), 0);
    /// ```
    #[must_use]
    pub const fn never() -> Self {
        Self(0)
    }

    /// Returns a probability that always hits.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{ProbabilityPpm, PPM_DENOMINATOR};
    /// assert_eq!(ProbabilityPpm::always().as_u32(), PPM_DENOMINATOR);
    /// ```
    #[must_use]
    pub const fn always() -> Self {
        Self(PPM_DENOMINATOR)
    }

    /// Returns the probability in parts per million.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::ProbabilityPpm;
    /// assert_eq!(ProbabilityPpm::never().as_u32(), 0);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{ProbabilityPpm, Stability};
    /// assert_eq!(ProbabilityPpm::never().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Link behavior for the virtual network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConditions {
    latency: Duration,
    jitter: Duration,
    loss: ProbabilityPpm,
    reorder: ProbabilityPpm,
    reorder_delay: Duration,
    partitioned: bool,
    max_datagram_bytes: usize,
}

impl NetworkConditions {
    /// Creates link conditions with fixed base latency.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::DurationTooLarge`] when `latency` exceeds the
    /// simulator's bounded link delay.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_sim::NetworkConditions;
    /// let conditions = NetworkConditions::new(Duration::from_millis(2))?;
    /// assert_eq!(conditions.latency(), Duration::from_millis(2));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn new(latency: Duration) -> SimResult<Self> {
        validate_delay(latency)?;
        Ok(Self {
            latency,
            ..Self::default()
        })
    }

    /// Returns zero-latency loopback conditions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// assert_eq!(
    ///     NetworkConditions::loopback().latency(),
    ///     std::time::Duration::ZERO
    /// );
    /// ```
    #[must_use]
    pub const fn loopback() -> Self {
        Self {
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
            loss: ProbabilityPpm::never(),
            reorder: ProbabilityPpm::never(),
            reorder_delay: Duration::ZERO,
            partitioned: false,
            max_datagram_bytes: MAX_DATAGRAM_BYTES,
        }
    }

    /// Sets latency jitter sampled uniformly from zero through `jitter`.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::DurationTooLarge`] when `jitter` exceeds the
    /// simulator's bounded link delay.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_sim::NetworkConditions;
    /// let conditions = NetworkConditions::loopback().with_jitter(Duration::from_millis(1))?;
    /// assert_eq!(conditions.jitter(), Duration::from_millis(1));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn with_jitter(mut self, jitter: Duration) -> SimResult<Self> {
        validate_delay(jitter)?;
        self.jitter = jitter;
        Ok(self)
    }

    /// Sets seeded loss probability.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{NetworkConditions, ProbabilityPpm};
    /// let conditions = NetworkConditions::loopback().with_loss(ProbabilityPpm::always());
    /// assert_eq!(conditions.loss(), ProbabilityPpm::always());
    /// ```
    #[must_use]
    pub const fn with_loss(mut self, loss: ProbabilityPpm) -> Self {
        self.loss = loss;
        self
    }

    /// Sets seeded reorder probability and extra delay.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::DurationTooLarge`] when `extra_delay` exceeds the
    /// simulator's bounded link delay.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_sim::{NetworkConditions, ProbabilityPpm};
    /// let conditions = NetworkConditions::loopback()
    ///     .with_reorder(ProbabilityPpm::new(100_000)?, Duration::from_millis(3))?;
    /// assert_eq!(conditions.reorder_delay(), Duration::from_millis(3));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn with_reorder(
        mut self,
        reorder: ProbabilityPpm,
        extra_delay: Duration,
    ) -> SimResult<Self> {
        validate_delay(extra_delay)?;
        self.reorder = reorder;
        self.reorder_delay = extra_delay;
        Ok(self)
    }

    /// Sets whether this link is partitioned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// assert!(
    ///     NetworkConditions::loopback()
    ///         .with_partition(true)
    ///         .is_partitioned()
    /// );
    /// ```
    #[must_use]
    pub const fn with_partition(mut self, partitioned: bool) -> Self {
        self.partitioned = partitioned;
        self
    }

    /// Sets the maximum accepted datagram bytes for this link.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::PayloadTooLarge`] when `max_datagram_bytes` is zero
    /// or exceeds [`MAX_DATAGRAM_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// let conditions = NetworkConditions::loopback().with_max_datagram_bytes(1_200)?;
    /// assert_eq!(conditions.max_datagram_bytes(), 1_200);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub const fn with_max_datagram_bytes(mut self, max_datagram_bytes: usize) -> SimResult<Self> {
        if max_datagram_bytes == 0 || max_datagram_bytes > MAX_DATAGRAM_BYTES {
            return Err(SimError::PayloadTooLarge {
                len: max_datagram_bytes,
                max: MAX_DATAGRAM_BYTES,
            });
        }
        self.max_datagram_bytes = max_datagram_bytes;
        Ok(self)
    }

    /// Returns fixed base latency.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// assert_eq!(
    ///     NetworkConditions::loopback().latency(),
    ///     std::time::Duration::ZERO
    /// );
    /// ```
    #[must_use]
    pub const fn latency(&self) -> Duration {
        self.latency
    }

    /// Returns maximum latency jitter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// assert_eq!(
    ///     NetworkConditions::loopback().jitter(),
    ///     std::time::Duration::ZERO
    /// );
    /// ```
    #[must_use]
    pub const fn jitter(&self) -> Duration {
        self.jitter
    }

    /// Returns seeded loss probability.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{NetworkConditions, ProbabilityPpm};
    /// assert_eq!(
    ///     NetworkConditions::loopback().loss(),
    ///     ProbabilityPpm::never()
    /// );
    /// ```
    #[must_use]
    pub const fn loss(&self) -> ProbabilityPpm {
        self.loss
    }

    /// Returns seeded reorder probability.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{NetworkConditions, ProbabilityPpm};
    /// assert_eq!(
    ///     NetworkConditions::loopback().reorder(),
    ///     ProbabilityPpm::never()
    /// );
    /// ```
    #[must_use]
    pub const fn reorder(&self) -> ProbabilityPpm {
        self.reorder
    }

    /// Returns extra delay applied to reordered packets.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// assert_eq!(
    ///     NetworkConditions::loopback().reorder_delay(),
    ///     std::time::Duration::ZERO
    /// );
    /// ```
    #[must_use]
    pub const fn reorder_delay(&self) -> Duration {
        self.reorder_delay
    }

    /// Returns whether this link is partitioned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::NetworkConditions;
    /// assert!(!NetworkConditions::loopback().is_partitioned());
    /// ```
    #[must_use]
    pub const fn is_partitioned(&self) -> bool {
        self.partitioned
    }

    /// Returns maximum datagram bytes accepted by this link.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{NetworkConditions, MAX_DATAGRAM_BYTES};
    /// assert_eq!(
    ///     NetworkConditions::loopback().max_datagram_bytes(),
    ///     MAX_DATAGRAM_BYTES
    /// );
    /// ```
    #[must_use]
    pub const fn max_datagram_bytes(&self) -> usize {
        self.max_datagram_bytes
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{NetworkConditions, Stability};
    /// assert_eq!(NetworkConditions::loopback().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    pub(crate) fn sample_delay(&self, rng: &mut DeterministicRng) -> SimResult<Duration> {
        let jitter = sample_duration(self.jitter, rng)?;
        let reorder = if rng.chance_ppm(self.reorder.as_u32()) {
            self.reorder_delay
        } else {
            Duration::ZERO
        };
        self.latency
            .checked_add(jitter)
            .and_then(|delay| delay.checked_add(reorder))
            .ok_or(SimError::TimeOverflow)
    }
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self::loopback()
    }
}

/// Datagram delivered by the virtual network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    delivered_at: Duration,
    source: SocketAddr,
    destination: SocketAddr,
    payload: Box<[u8]>,
}

impl Delivery {
    pub(crate) const fn new(
        delivered_at: Duration,
        source: SocketAddr,
        destination: SocketAddr,
        payload: Box<[u8]>,
    ) -> Self {
        Self {
            delivered_at,
            source,
            destination,
            payload,
        }
    }

    /// Returns the virtual delivery time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Seed, SimNodeId, Simulation};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), a)?;
    /// builder.add_node(SimNodeId::new(2), b)?;
    /// builder.add_event(ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::send(a, b, b"x")?,
    /// )?)?;
    /// assert_eq!(
    ///     builder.build()?.run()?.deliveries()[0].delivered_at(),
    ///     std::time::Duration::ZERO
    /// );
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn delivered_at(&self) -> Duration {
        self.delivered_at
    }

    /// Returns the source address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Seed, SimNodeId, Simulation};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), a)?;
    /// builder.add_node(SimNodeId::new(2), b)?;
    /// builder.add_event(ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::send(a, b, b"x")?,
    /// )?)?;
    /// assert_eq!(builder.build()?.run()?.deliveries()[0].source(), a);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Returns the destination address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Seed, SimNodeId, Simulation};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), a)?;
    /// builder.add_node(SimNodeId::new(2), b)?;
    /// builder.add_event(ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::send(a, b, b"x")?,
    /// )?)?;
    /// assert_eq!(builder.build()?.run()?.deliveries()[0].destination(), b);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns the delivered payload.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Seed, SimNodeId, Simulation};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), a)?;
    /// builder.add_node(SimNodeId::new(2), b)?;
    /// builder.add_event(ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::send(a, b, b"x")?,
    /// )?)?;
    /// assert_eq!(builder.build()?.run()?.deliveries()[0].payload(), b"x");
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation, Stability};
    /// assert_eq!(
    ///     Simulation::builder(Seed::new(1))
    ///         .build()?
    ///         .run()?
    ///         .stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingDatagram {
    deliver_at: Duration,
    order: u64,
    delivery: Delivery,
}

#[derive(Debug)]
pub(crate) struct VirtualNetwork {
    nodes: HashMap<SimNodeId, SocketAddr>,
    addresses: HashMap<SocketAddr, SimNodeId>,
    links: HashMap<(SocketAddr, SocketAddr), NetworkConditions>,
    default_conditions: NetworkConditions,
    pending: Vec<PendingDatagram>,
    inboxes: HashMap<SocketAddr, VecDeque<Delivery>>,
    next_order: u64,
    dropped: u64,
}

impl VirtualNetwork {
    pub(crate) fn new(default_conditions: NetworkConditions) -> Self {
        Self {
            nodes: HashMap::new(),
            addresses: HashMap::new(),
            links: HashMap::new(),
            default_conditions,
            pending: Vec::new(),
            inboxes: HashMap::new(),
            next_order: 0,
            dropped: 0,
        }
    }

    pub(crate) fn add_node(&mut self, node: SimNodeId, address: SocketAddr) -> SimResult<()> {
        if self.nodes.len() == MAX_NODES {
            return Err(SimError::TooManyNodes { max: MAX_NODES });
        }
        if self.nodes.contains_key(&node) {
            return Err(SimError::DuplicateNode {
                node: node.as_u32(),
            });
        }
        if self.addresses.contains_key(&address) {
            return Err(SimError::DuplicateAddress { address });
        }
        self.inboxes
            .try_reserve(1)
            .map_err(|_source| SimError::Allocation {
                component: "network_inboxes",
            })?;
        self.nodes
            .try_reserve(1)
            .map_err(|_source| SimError::Allocation {
                component: "network_nodes",
            })?;
        self.addresses
            .try_reserve(1)
            .map_err(|_source| SimError::Allocation {
                component: "network_addresses",
            })?;
        self.nodes.insert(node, address);
        self.addresses.insert(address, node);
        self.inboxes.insert(address, VecDeque::new());
        Ok(())
    }

    pub(crate) fn has_address(&self, address: SocketAddr) -> bool {
        self.addresses.contains_key(&address)
    }

    pub(crate) fn set_link(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        conditions: NetworkConditions,
    ) -> SimResult<()> {
        self.ensure_address(source)?;
        self.ensure_address(destination)?;
        self.links
            .try_reserve(1)
            .map_err(|_source| SimError::Allocation {
                component: "network_links",
            })?;
        self.links.insert((source, destination), conditions);
        Ok(())
    }

    pub(crate) fn set_partition(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        partitioned: bool,
    ) -> SimResult<()> {
        let mut conditions = self.conditions_for(source, destination)?;
        conditions = conditions.with_partition(partitioned);
        self.set_link(source, destination, conditions)
    }

    pub(crate) fn send(
        &mut self,
        now: Duration,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        rng: &mut DeterministicRng,
    ) -> SimResult<usize> {
        let conditions = self.conditions_for(source, destination)?;
        if payload.len() > conditions.max_datagram_bytes() {
            return Err(SimError::PayloadTooLarge {
                len: payload.len(),
                max: conditions.max_datagram_bytes(),
            });
        }
        if conditions.is_partitioned() || rng.chance_ppm(conditions.loss().as_u32()) {
            self.dropped = self.dropped.saturating_add(1);
            return Ok(payload.len());
        }
        if self.pending.len() == MAX_PENDING_DATAGRAMS {
            return Err(SimError::TooManyPendingDatagrams {
                max: MAX_PENDING_DATAGRAMS,
            });
        }
        let delay = conditions.sample_delay(rng)?;
        let deliver_at = now.checked_add(delay).ok_or(SimError::TimeOverflow)?;
        let copied = copy_payload(payload, conditions.max_datagram_bytes())?;
        self.pending
            .try_reserve_exact(1)
            .map_err(|_source| SimError::Allocation {
                component: "network_pending",
            })?;
        self.pending.push(PendingDatagram {
            deliver_at,
            order: self.next_order,
            delivery: Delivery::new(deliver_at, source, destination, copied),
        });
        self.next_order = self.next_order.wrapping_add(1);
        self.pending
            .sort_by_key(|pending| (pending.deliver_at, pending.order));
        Ok(payload.len())
    }

    pub(crate) fn deliver_due(
        &mut self,
        now: Duration,
        transcript: &mut Vec<Delivery>,
    ) -> SimResult<usize> {
        let due_count = self
            .pending
            .iter()
            .take_while(|pending| pending.deliver_at <= now)
            .count();
        if due_count == 0 {
            return Ok(0);
        }
        let mut due = Vec::new();
        due.try_reserve_exact(due_count)
            .map_err(|_source| SimError::Allocation {
                component: "network_due",
            })?;
        due.extend(self.pending.drain(..due_count));
        for pending in due {
            transcript
                .try_reserve_exact(1)
                .map_err(|_source| SimError::Allocation {
                    component: "simulation_transcript",
                })?;
            let delivery = pending.delivery;
            let inbox = self
                .inboxes
                .get_mut(&delivery.destination())
                .ok_or_else(|| SimError::UnknownAddress {
                    address: delivery.destination(),
                })?;
            transcript.push(delivery.clone());
            inbox.push_back(delivery);
        }
        Ok(due_count)
    }

    pub(crate) fn pop(&mut self, local: SocketAddr) -> SimResult<Option<Delivery>> {
        let inbox = self
            .inboxes
            .get_mut(&local)
            .ok_or(SimError::UnknownAddress { address: local })?;
        Ok(inbox.pop_front())
    }

    pub(crate) fn next_delivery_at(&self) -> Option<Duration> {
        self.pending.first().map(|pending| pending.deliver_at)
    }

    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }

    fn ensure_address(&self, address: SocketAddr) -> SimResult<()> {
        if self.addresses.contains_key(&address) {
            Ok(())
        } else {
            Err(SimError::UnknownAddress { address })
        }
    }

    fn conditions_for(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> SimResult<NetworkConditions> {
        self.ensure_address(source)?;
        self.ensure_address(destination)?;
        Ok(self
            .links
            .get(&(source, destination))
            .cloned()
            .unwrap_or_else(|| self.default_conditions.clone()))
    }
}

pub(crate) fn copy_payload(payload: &[u8], max: usize) -> SimResult<Box<[u8]>> {
    if payload.len() > max {
        return Err(SimError::PayloadTooLarge {
            len: payload.len(),
            max,
        });
    }
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(payload.len())
        .map_err(|_source| SimError::Allocation {
            component: "payload",
        })?;
    copied.extend_from_slice(payload);
    Ok(copied.into_boxed_slice())
}

fn validate_delay(duration: Duration) -> SimResult<()> {
    if duration > MAX_LINK_DELAY {
        Err(SimError::DurationTooLarge { duration })
    } else {
        Ok(())
    }
}

fn sample_duration(duration: Duration, rng: &mut DeterministicRng) -> SimResult<Duration> {
    if duration.is_zero() {
        return Ok(Duration::ZERO);
    }
    let nanos = u64::try_from(duration.as_nanos())
        .map_err(|_source| SimError::DurationTooLarge { duration })?;
    let sampled = rng.below(nanos.saturating_add(1))?;
    Ok(Duration::from_nanos(sampled))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::{NetworkConditions, ProbabilityPpm, SimNodeId, VirtualNetwork};
    use crate::{DeterministicRng, Seed};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn partition_drops_without_delivery() {
        let source = addr(1);
        let destination = addr(2);
        let mut network = VirtualNetwork::new(NetworkConditions::loopback());
        network.add_node(SimNodeId::new(1), source).expect("node");
        network
            .add_node(SimNodeId::new(2), destination)
            .expect("node");
        network
            .set_partition(source, destination, true)
            .expect("partition");
        let mut rng = DeterministicRng::new(Seed::new(1));
        let mut transcript = Vec::new();

        let sent = network
            .send(Duration::ZERO, source, destination, b"abc", &mut rng)
            .expect("send");
        let delivered = network
            .deliver_due(Duration::ZERO, &mut transcript)
            .expect("deliver");

        assert_eq!(sent, 3);
        assert_eq!(delivered, 0);
        assert_eq!(network.dropped(), 1);
    }

    #[test]
    fn latency_delivers_after_deadline() {
        let source = addr(3);
        let destination = addr(4);
        let mut network =
            VirtualNetwork::new(NetworkConditions::new(Duration::from_millis(5)).expect("delay"));
        network.add_node(SimNodeId::new(1), source).expect("node");
        network
            .add_node(SimNodeId::new(2), destination)
            .expect("node");
        let mut rng = DeterministicRng::new(Seed::new(2));
        let mut transcript = Vec::new();

        network
            .send(Duration::ZERO, source, destination, b"abc", &mut rng)
            .expect("send");
        assert_eq!(
            network
                .deliver_due(Duration::from_millis(4), &mut transcript)
                .expect("deliver"),
            0
        );
        assert_eq!(
            network
                .deliver_due(Duration::from_millis(5), &mut transcript)
                .expect("deliver"),
            1
        );
    }

    #[test]
    fn configured_loss_drops_packet() {
        let source = addr(5);
        let destination = addr(6);
        let mut network =
            VirtualNetwork::new(NetworkConditions::loopback().with_loss(ProbabilityPpm::always()));
        network.add_node(SimNodeId::new(1), source).expect("node");
        network
            .add_node(SimNodeId::new(2), destination)
            .expect("node");
        let mut rng = DeterministicRng::new(Seed::new(3));

        network
            .send(Duration::ZERO, source, destination, b"abc", &mut rng)
            .expect("send");

        assert_eq!(network.next_delivery_at(), None);
        assert_eq!(network.dropped(), 1);
    }
}
