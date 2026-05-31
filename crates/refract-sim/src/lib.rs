//! Deterministic simulation framework for refract.
//!
//! `refract-sim` provides a seeded virtual clock, a bounded virtual UDP
//! network, scripted scenario events, and a simulated transport implementing
//! [`refract_net::transport::Transport`]. Production media code can stay
//! generic over the transport boundary while tests replace only the I/O layer.
//!
//! # Examples
//!
//! ```
//! # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! # use refract_sim::{
//! #     NetworkConditions, ScriptedAction, ScriptedEvent, Seed, SimNodeId, Simulation,
//! # };
//! let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_000);
//! let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_001);
//! let mut builder = Simulation::builder(Seed::new(7));
//! builder.add_node(SimNodeId::new(1), source)?;
//! builder.add_node(SimNodeId::new(2), destination)?;
//! builder.set_default_conditions(NetworkConditions::loopback());
//! builder.add_event(ScriptedEvent::at(
//!     std::time::Duration::ZERO,
//!     ScriptedAction::send(source, destination, b"rtp")?,
//! )?)?;
//! let simulation = builder.build()?;
//! let transcript = simulation.run()?;
//! assert_eq!(transcript.deliveries().len(), 1);
//! # Ok::<(), refract_sim::SimError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]

pub mod clock;
pub mod error;
pub mod network;
pub mod rng;
pub mod simulation;
pub mod stability;
pub mod transport;

pub use clock::VirtualClock;
pub use error::{SimError, SimResult};
pub use network::{
    Delivery, MAX_DATAGRAM_BYTES, MAX_NODES, MAX_PENDING_DATAGRAMS, NetworkConditions,
    PPM_DENOMINATOR, ProbabilityPpm, SimNodeId,
};
pub use rng::{DeterministicRng, Seed};
pub use simulation::{ScriptedAction, ScriptedEvent, Simulation, SimulationBuilder, Transcript};
pub use stability::Stability;
pub use transport::SimTransport;
