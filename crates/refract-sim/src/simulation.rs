//! Scenario builder and deterministic simulation runner.
//!
//! A simulation owns topology, seeded random state, a virtual clock, scripted
//! events, and the transcript of delivered datagrams.

use std::{cell::RefCell, net::SocketAddr, rc::Rc, time::Duration};

use crate::{
    Delivery, DeterministicRng, NetworkConditions, Seed, SimError, SimNodeId, SimResult,
    SimTransport, Stability, VirtualClock,
    network::{MAX_DATAGRAM_BYTES, VirtualNetwork, copy_payload},
};

/// Maximum scripted events accepted by one simulation.
pub const MAX_SCRIPTED_EVENTS: usize = 262_144;

/// Maximum scheduler steps in one simulation run.
pub const DEFAULT_MAX_STEPS: usize = 1_000_000;

const MAX_BUG_LABEL_BYTES: usize = 64;

/// Opaque scripted action executed by a [`Simulation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedAction {
    kind: ScriptedActionKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScriptedActionKind {
    Send {
        source: SocketAddr,
        destination: SocketAddr,
        payload: Box<[u8]>,
    },
    SetLink {
        source: SocketAddr,
        destination: SocketAddr,
        conditions: NetworkConditions,
    },
    Partition {
        source: SocketAddr,
        destination: SocketAddr,
        partitioned: bool,
    },
    InjectBug {
        label: Box<str>,
    },
}

impl ScriptedAction {
    /// Creates a bounded datagram send action.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::PayloadTooLarge`] when `payload` exceeds
    /// [`MAX_DATAGRAM_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::ScriptedAction;
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let action = ScriptedAction::send(a, b, b"rtp")?;
    /// assert_eq!(action.stability().as_str(), "stage1");
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn send(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> SimResult<Self> {
        Ok(Self {
            kind: ScriptedActionKind::Send {
                source,
                destination,
                payload: copy_payload(payload, MAX_DATAGRAM_BYTES)?,
            },
        })
    }

    /// Creates an action that changes one directed link.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{NetworkConditions, ScriptedAction};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let action = ScriptedAction::set_link(a, b, NetworkConditions::loopback());
    /// assert_eq!(action.stability().as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn set_link(
        source: SocketAddr,
        destination: SocketAddr,
        conditions: NetworkConditions,
    ) -> Self {
        Self {
            kind: ScriptedActionKind::SetLink {
                source,
                destination,
                conditions,
            },
        }
    }

    /// Creates an action that toggles a directed network partition.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::ScriptedAction;
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let action = ScriptedAction::partition(a, b, true);
    /// assert_eq!(action.stability().as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn partition(source: SocketAddr, destination: SocketAddr, partitioned: bool) -> Self {
        Self {
            kind: ScriptedActionKind::Partition {
                source,
                destination,
                partitioned,
            },
        }
    }

    /// Creates a deterministic failure injection action.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::LabelTooLarge`] when `label` exceeds the bounded
    /// failure-label length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::ScriptedAction;
    /// let action = ScriptedAction::inject_bug("intentional")?;
    /// assert_eq!(action.stability().as_str(), "stage1");
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn inject_bug(label: &str) -> SimResult<Self> {
        Ok(Self {
            kind: ScriptedActionKind::InjectBug {
                label: copy_label(label)?,
            },
        })
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, Stability};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// assert_eq!(
    ///     ScriptedAction::partition(a, a, false).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Timed action in a deterministic simulation script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedEvent {
    at: Duration,
    action: ScriptedAction,
}

impl ScriptedEvent {
    /// Creates a timed scripted event.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::DurationTooLarge`] when `at` is outside the bounded
    /// simulator range.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let event = ScriptedEvent::at(
    ///     std::time::Duration::from_millis(1),
    ///     ScriptedAction::partition(addr, addr, false),
    /// )?;
    /// assert_eq!(event.time(), std::time::Duration::from_millis(1));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn at(at: Duration, action: ScriptedAction) -> SimResult<Self> {
        validate_script_time(at)?;
        Ok(Self { at, action })
    }

    /// Returns the event virtual time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let event = ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::partition(addr, addr, false),
    /// )?;
    /// assert_eq!(event.time(), std::time::Duration::ZERO);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn time(&self) -> Duration {
        self.at
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Stability};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let event = ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::partition(addr, addr, false),
    /// )?;
    /// assert_eq!(event.stability(), Stability::Stage1);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Bit-comparable result of a deterministic simulation run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transcript {
    seed: Seed,
    deliveries: Vec<Delivery>,
    dropped: u64,
}

impl Transcript {
    pub(crate) const fn new(seed: Seed, deliveries: Vec<Delivery>, dropped: u64) -> Self {
        Self {
            seed,
            deliveries,
            dropped,
        }
    }

    /// Returns the seed used for this transcript.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let transcript = Simulation::builder(Seed::new(9)).build()?.run()?;
    /// assert_eq!(transcript.seed(), Seed::new(9));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn seed(&self) -> Seed {
        self.seed
    }

    /// Returns delivered datagrams in deterministic delivery order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let transcript = Simulation::builder(Seed::new(9)).build()?.run()?;
    /// assert!(transcript.deliveries().is_empty());
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub fn deliveries(&self) -> &[Delivery] {
        &self.deliveries
    }

    /// Returns the number of datagrams dropped by loss or partitions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let transcript = Simulation::builder(Seed::new(9)).build()?.run()?;
    /// assert_eq!(transcript.dropped(), 0);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
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

/// Builder for deterministic simulation scenarios.
#[derive(Debug)]
pub struct SimulationBuilder {
    seed: Seed,
    default_conditions: NetworkConditions,
    nodes: Vec<(SimNodeId, SocketAddr)>,
    links: Vec<(SocketAddr, SocketAddr, NetworkConditions)>,
    events: Vec<ScriptedEvent>,
    max_steps: usize,
}

impl SimulationBuilder {
    /// Creates a builder from a reproducibility seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, SimulationBuilder};
    /// let builder = SimulationBuilder::new(Seed::new(1));
    /// assert_eq!(builder.seed(), Seed::new(1));
    /// ```
    #[must_use]
    pub const fn new(seed: Seed) -> Self {
        Self {
            seed,
            default_conditions: NetworkConditions::loopback(),
            nodes: Vec::new(),
            links: Vec::new(),
            events: Vec::new(),
            max_steps: DEFAULT_MAX_STEPS,
        }
    }

    /// Returns the configured seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, SimulationBuilder};
    /// assert_eq!(SimulationBuilder::new(Seed::new(3)).seed(), Seed::new(3));
    /// ```
    #[must_use]
    pub const fn seed(&self) -> Seed {
        self.seed
    }

    /// Adds a node and its simulated socket address.
    ///
    /// # Errors
    ///
    /// Returns duplicate or capacity errors when the topology is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{Seed, SimNodeId, Simulation};
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(
    ///     SimNodeId::new(1),
    ///     SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000),
    /// )?;
    /// assert_eq!(builder.node_count(), 1);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn add_node(&mut self, node: SimNodeId, address: SocketAddr) -> SimResult<&mut Self> {
        if self.nodes.len() == crate::MAX_NODES {
            return Err(SimError::TooManyNodes {
                max: crate::MAX_NODES,
            });
        }
        if self
            .nodes
            .iter()
            .any(|(existing, _address)| *existing == node)
        {
            return Err(SimError::DuplicateNode {
                node: node.as_u32(),
            });
        }
        if self
            .nodes
            .iter()
            .any(|(_node, existing_address)| *existing_address == address)
        {
            return Err(SimError::DuplicateAddress { address });
        }
        self.nodes
            .try_reserve_exact(1)
            .map_err(|_source| SimError::Allocation {
                component: "builder_nodes",
            })?;
        self.nodes.push((node, address));
        Ok(self)
    }

    /// Returns the number of configured nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// assert_eq!(Simulation::builder(Seed::new(1)).node_count(), 0);
    /// ```
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Sets default network conditions for links without overrides.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{NetworkConditions, Seed, Simulation};
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.set_default_conditions(NetworkConditions::loopback());
    /// ```
    pub const fn set_default_conditions(&mut self, conditions: NetworkConditions) -> &mut Self {
        self.default_conditions = conditions;
        self
    }

    /// Adds a directed link override.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::UnknownAddress`] if either endpoint is not present
    /// in the builder topology.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{NetworkConditions, Seed, SimNodeId, Simulation};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), a)?;
    /// builder.add_node(SimNodeId::new(2), b)?;
    /// builder.add_link(a, b, NetworkConditions::loopback())?;
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn add_link(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        conditions: NetworkConditions,
    ) -> SimResult<&mut Self> {
        self.ensure_builder_address(source)?;
        self.ensure_builder_address(destination)?;
        self.links
            .try_reserve_exact(1)
            .map_err(|_source| SimError::Allocation {
                component: "builder_links",
            })?;
        self.links.push((source, destination, conditions));
        Ok(self)
    }

    /// Adds a scripted event.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::TooManyEvents`] when the event bound has been
    /// reached.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Seed, Simulation};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_event(ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::partition(addr, addr, false),
    /// )?)?;
    /// assert_eq!(builder.event_count(), 1);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn add_event(&mut self, event: ScriptedEvent) -> SimResult<&mut Self> {
        if self.events.len() == MAX_SCRIPTED_EVENTS {
            return Err(SimError::TooManyEvents {
                max: MAX_SCRIPTED_EVENTS,
            });
        }
        self.events
            .try_reserve_exact(1)
            .map_err(|_source| SimError::Allocation {
                component: "builder_events",
            })?;
        self.events.push(event);
        Ok(self)
    }

    /// Returns the number of configured scripted events.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// assert_eq!(Simulation::builder(Seed::new(1)).event_count(), 0);
    /// ```
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Sets the maximum scheduler step count.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::StepLimit`] when `max_steps` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.set_max_steps(10)?;
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub const fn set_max_steps(&mut self, max_steps: usize) -> SimResult<&mut Self> {
        if max_steps == 0 {
            return Err(SimError::StepLimit { max: max_steps });
        }
        self.max_steps = max_steps;
        Ok(self)
    }

    /// Builds a simulation.
    ///
    /// # Errors
    ///
    /// Returns topology or allocation errors when configured nodes, links, or
    /// events are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let simulation = Simulation::builder(Seed::new(1)).build()?;
    /// assert_eq!(simulation.seed(), Seed::new(1));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn build(mut self) -> SimResult<Simulation> {
        let mut network = VirtualNetwork::new(self.default_conditions);
        for (node, address) in self.nodes {
            network.add_node(node, address)?;
        }
        for (source, destination, conditions) in self.links {
            network.set_link(source, destination, conditions)?;
        }
        self.events.sort_by_key(ScriptedEvent::time);
        Ok(Simulation::from_state(SimulationState {
            seed: self.seed,
            rng: DeterministicRng::new(self.seed),
            clock: VirtualClock::new(),
            network,
            events: self.events,
            transcript: Vec::new(),
            max_steps: self.max_steps,
        }))
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation, Stability};
    /// assert_eq!(
    ///     Simulation::builder(Seed::new(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn ensure_builder_address(&self, address: SocketAddr) -> SimResult<()> {
        if self
            .nodes
            .iter()
            .any(|(_node, existing_address)| *existing_address == address)
        {
            Ok(())
        } else {
            Err(SimError::UnknownAddress { address })
        }
    }
}

/// Deterministic simulation runtime.
#[derive(Debug)]
pub struct Simulation {
    seed: Seed,
    pub(crate) state: Rc<RefCell<SimulationState>>,
}

impl Simulation {
    /// Creates a simulation builder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// assert_eq!(Simulation::builder(Seed::new(1)).seed(), Seed::new(1));
    /// ```
    #[must_use]
    pub const fn builder(seed: Seed) -> SimulationBuilder {
        SimulationBuilder::new(seed)
    }

    pub(crate) fn from_state(state: SimulationState) -> Self {
        let seed = state.seed;
        Self {
            seed,
            state: Rc::new(RefCell::new(state)),
        }
    }

    /// Returns the simulation seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// assert_eq!(
    ///     Simulation::builder(Seed::new(1)).build()?.seed(),
    ///     Seed::new(1)
    /// );
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn seed(&self) -> Seed {
        self.seed
    }

    /// Returns a snapshot of the virtual clock.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::StateBusy`] when another operation holds a mutable
    /// borrow of the simulation state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let simulation = Simulation::builder(Seed::new(1)).build()?;
    /// assert_eq!(simulation.clock()?.elapsed(), std::time::Duration::ZERO);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn clock(&self) -> SimResult<VirtualClock> {
        Ok(self.borrow_state()?.clock.clone())
    }

    /// Creates a simulated transport bound to `local`.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::UnknownAddress`] when `local` is not a configured
    /// node address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{Seed, SimNodeId, Simulation};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), addr)?;
    /// let transport = builder.build()?.transport(addr)?;
    /// assert_eq!(transport.local_addr(), addr);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn transport(&self, local: SocketAddr) -> SimResult<SimTransport> {
        let state = self.borrow_state()?;
        if !state.network.has_address(local) {
            return Err(SimError::UnknownAddress { address: local });
        }
        drop(state);
        Ok(SimTransport::new(local, Rc::clone(&self.state)))
    }

    /// Adds a scripted event after build.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::TooManyEvents`] when the event bound has been
    /// reached or [`SimError::StateBusy`] when another operation is active.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{ScriptedAction, ScriptedEvent, Seed, Simulation};
    /// let simulation = Simulation::builder(Seed::new(1)).build()?;
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// simulation.add_event(ScriptedEvent::at(
    ///     std::time::Duration::ZERO,
    ///     ScriptedAction::partition(addr, addr, false),
    /// )?)?;
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn add_event(&self, event: ScriptedEvent) -> SimResult<()> {
        self.borrow_state_mut()?.add_event(event)
    }

    /// Advances the virtual clock and delivers due network datagrams.
    ///
    /// # Errors
    ///
    /// Returns time, allocation, or state-borrow errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_sim::{Seed, Simulation};
    /// let simulation = Simulation::builder(Seed::new(1)).build()?;
    /// simulation.advance_by(Duration::from_millis(1))?;
    /// assert_eq!(simulation.clock()?.elapsed(), Duration::from_millis(1));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn advance_by(&self, duration: Duration) -> SimResult<()> {
        let mut state = self.borrow_state_mut()?;
        state.clock.advance(duration)?;
        let _delivered = state.deliver_due()?;
        Ok(())
    }

    /// Runs the simulation until no scripted events or network deliveries remain.
    ///
    /// # Errors
    ///
    /// Returns deterministic topology, network, injected-bug, or step-limit
    /// errors. The seed in an [`SimError::InjectedBug`] is directly reusable.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let transcript = Simulation::builder(Seed::new(1)).build()?.run()?;
    /// assert_eq!(transcript.seed(), Seed::new(1));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn run(&self) -> SimResult<Transcript> {
        self.borrow_state_mut()?.run()
    }

    /// Returns a transcript snapshot without advancing simulation time.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::StateBusy`] when another operation is active.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation};
    /// let simulation = Simulation::builder(Seed::new(1)).build()?;
    /// assert!(simulation.transcript()?.deliveries().is_empty());
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn transcript(&self) -> SimResult<Transcript> {
        Ok(self.borrow_state()?.transcript())
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Simulation, Stability};
    /// assert_eq!(
    ///     Simulation::builder(Seed::new(1)).build()?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn borrow_state(&self) -> SimResult<std::cell::Ref<'_, SimulationState>> {
        self.state
            .try_borrow()
            .map_err(|_source| SimError::StateBusy)
    }

    fn borrow_state_mut(&self) -> SimResult<std::cell::RefMut<'_, SimulationState>> {
        self.state
            .try_borrow_mut()
            .map_err(|_source| SimError::StateBusy)
    }
}

#[derive(Debug)]
pub(crate) struct SimulationState {
    seed: Seed,
    rng: DeterministicRng,
    clock: VirtualClock,
    network: VirtualNetwork,
    events: Vec<ScriptedEvent>,
    transcript: Vec<Delivery>,
    max_steps: usize,
}

impl SimulationState {
    pub(crate) fn send(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> SimResult<usize> {
        self.network.send(
            self.clock.elapsed(),
            source,
            destination,
            payload,
            &mut self.rng,
        )
    }

    pub(crate) fn receive(&mut self, local: SocketAddr) -> SimResult<Option<Delivery>> {
        self.network.pop(local)
    }

    fn add_event(&mut self, event: ScriptedEvent) -> SimResult<()> {
        if self.events.len() == MAX_SCRIPTED_EVENTS {
            return Err(SimError::TooManyEvents {
                max: MAX_SCRIPTED_EVENTS,
            });
        }
        self.events
            .try_reserve_exact(1)
            .map_err(|_source| SimError::Allocation {
                component: "simulation_events",
            })?;
        self.events.push(event);
        self.events.sort_by_key(ScriptedEvent::time);
        Ok(())
    }

    fn run(&mut self) -> SimResult<Transcript> {
        let mut steps = 0_usize;
        loop {
            steps = steps.saturating_add(1);
            if steps > self.max_steps {
                return Err(SimError::StepLimit {
                    max: self.max_steps,
                });
            }

            let delivered = self.deliver_due()?;
            let processed = self.process_due_events()?;
            if delivered != 0 || processed != 0 {
                continue;
            }

            let Some(next_time) = self.next_time() else {
                break;
            };
            self.clock.advance_to(next_time)?;
        }
        Ok(self.transcript())
    }

    fn transcript(&self) -> Transcript {
        Transcript::new(self.seed, self.transcript.clone(), self.network.dropped())
    }

    fn deliver_due(&mut self) -> SimResult<usize> {
        self.network
            .deliver_due(self.clock.elapsed(), &mut self.transcript)
    }

    fn process_due_events(&mut self) -> SimResult<usize> {
        let due_count = self
            .events
            .iter()
            .take_while(|event| event.time() <= self.clock.elapsed())
            .count();
        if due_count == 0 {
            return Ok(0);
        }
        let mut due = Vec::new();
        due.try_reserve_exact(due_count)
            .map_err(|_source| SimError::Allocation {
                component: "simulation_due_events",
            })?;
        due.extend(self.events.drain(..due_count));
        for event in due {
            self.apply_action(event.action)?;
        }
        Ok(due_count)
    }

    fn apply_action(&mut self, action: ScriptedAction) -> SimResult<()> {
        match action.kind {
            ScriptedActionKind::Send {
                source,
                destination,
                payload,
            } => {
                let _sent = self.send(source, destination, &payload)?;
                Ok(())
            }
            ScriptedActionKind::SetLink {
                source,
                destination,
                conditions,
            } => self.network.set_link(source, destination, conditions),
            ScriptedActionKind::Partition {
                source,
                destination,
                partitioned,
            } => self.network.set_partition(source, destination, partitioned),
            ScriptedActionKind::InjectBug { label } => Err(SimError::InjectedBug {
                seed: self.seed,
                at: self.clock.elapsed(),
                label,
            }),
        }
    }

    fn next_time(&self) -> Option<Duration> {
        [
            self.events.first().map(ScriptedEvent::time),
            self.network.next_delivery_at(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

fn validate_script_time(at: Duration) -> SimResult<()> {
    let _nanos = u64::try_from(at.as_nanos())
        .map_err(|_source| SimError::DurationTooLarge { duration: at })?;
    Ok(())
}

fn copy_label(label: &str) -> SimResult<Box<str>> {
    if label.len() > MAX_BUG_LABEL_BYTES {
        return Err(SimError::LabelTooLarge {
            len: label.len(),
            max: MAX_BUG_LABEL_BYTES,
        });
    }
    let mut copied = String::new();
    copied
        .try_reserve_exact(label.len())
        .map_err(|_source| SimError::Allocation {
            component: "bug_label",
        })?;
    copied.push_str(label);
    Ok(copied.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::{ScriptedAction, ScriptedEvent, Simulation};
    use crate::{NetworkConditions, ProbabilityPpm, Seed, SimError, SimNodeId};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn hundred_peer_scenario_is_bit_identical_across_runs() {
        let left = hundred_peer_transcript(0xD15C_0DED).expect("left transcript");
        let right = hundred_peer_transcript(0xD15C_0DED).expect("right transcript");

        assert_eq!(left, right);
        assert_eq!(left.deliveries().len(), 100);
    }

    #[test]
    fn injected_bug_is_reproduced_from_seed() {
        let first = injected_bug(77).expect_err("first bug");
        let second = injected_bug(77).expect_err("second bug");

        assert_eq!(first.error_code(), "SIM_REPRO_0001");
        assert_eq!(first.to_string(), second.to_string());
    }

    #[test]
    fn partition_event_drops_later_packets() {
        let source = addr(10);
        let destination = addr(11);
        let mut builder = Simulation::builder(Seed::new(1));
        builder.add_node(SimNodeId::new(1), source).expect("node");
        builder
            .add_node(SimNodeId::new(2), destination)
            .expect("node");
        builder
            .add_event(
                ScriptedEvent::at(
                    Duration::ZERO,
                    ScriptedAction::partition(source, destination, true),
                )
                .expect("partition event"),
            )
            .expect("event");
        builder
            .add_event(
                ScriptedEvent::at(
                    Duration::from_millis(1),
                    ScriptedAction::send(source, destination, b"drop").expect("send action"),
                )
                .expect("send event"),
            )
            .expect("event");

        let transcript = builder.build().expect("build").run().expect("run");

        assert!(transcript.deliveries().is_empty());
        assert_eq!(transcript.dropped(), 1);
    }

    fn hundred_peer_transcript(seed: u64) -> Result<super::Transcript, SimError> {
        let hub = addr(9_000);
        let mut builder = Simulation::builder(Seed::new(seed));
        builder.add_node(SimNodeId::new(0), hub)?;
        builder.set_default_conditions(
            NetworkConditions::new(Duration::from_micros(100))?
                .with_jitter(Duration::from_micros(20))?
                .with_reorder(ProbabilityPpm::new(20_000)?, Duration::from_micros(50))?,
        );
        for index in 0_u16..100 {
            let peer = addr(10_000 + index);
            builder.add_node(SimNodeId::new(u32::from(index) + 1), peer)?;
            let payload = [index.to_be_bytes()[0], index.to_be_bytes()[1], 0xAA, 0x55];
            builder.add_event(ScriptedEvent::at(
                Duration::from_micros(u64::from(index)),
                ScriptedAction::send(peer, hub, &payload)?,
            )?)?;
        }
        builder.build()?.run()
    }

    fn injected_bug(seed: u64) -> Result<super::Transcript, SimError> {
        let mut builder = Simulation::builder(Seed::new(seed));
        builder.add_event(ScriptedEvent::at(
            Duration::from_millis(42),
            ScriptedAction::inject_bug("intentional-test-bug")?,
        )?)?;
        builder.build()?.run()
    }
}
