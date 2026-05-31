//! Simulated transport implementation for `refract-net`.
//!
//! The transport is intentionally single-threaded and shared-nothing. Clones
//! share simulation state through `Rc<RefCell<_>>`, not cross-core locks, and
//! every borrow failure is reported as a deterministic error instead of a panic.

use std::{cell::RefCell, fmt, io, net::SocketAddr, rc::Rc};

use refract_net::{NetError, NetResult, transport::Transport};

use crate::{SimError, SimResult, Stability, simulation::SimulationState};

/// Simulated UDP transport implementing [`Transport`].
#[derive(Clone)]
pub struct SimTransport {
    local: SocketAddr,
    state: Rc<RefCell<SimulationState>>,
}

impl SimTransport {
    pub(crate) const fn new(local: SocketAddr, state: Rc<RefCell<SimulationState>>) -> Self {
        Self { local, state }
    }

    /// Returns the local simulated socket address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{Seed, SimNodeId, Simulation};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), addr)?;
    /// assert_eq!(builder.build()?.transport(addr)?.local_addr(), addr);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Sends a datagram into the virtual network.
    ///
    /// # Errors
    ///
    /// Returns simulator topology, payload-bound, or state-borrow errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{Seed, SimNodeId, Simulation};
    /// let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), a)?;
    /// builder.add_node(SimNodeId::new(2), b)?;
    /// let simulation = builder.build()?;
    /// let transport = simulation.transport(a)?;
    /// assert_eq!(transport.send_datagram(b"rtp", b)?, 3);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn send_datagram(&self, payload: &[u8], destination: SocketAddr) -> SimResult<usize> {
        self.state
            .try_borrow_mut()
            .map_err(|_source| SimError::StateBusy)?
            .send(self.local, destination, payload)
    }

    /// Receives one available datagram from the virtual network.
    ///
    /// # Errors
    ///
    /// Returns simulator topology or state-borrow errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{Seed, SimNodeId, Simulation};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), addr)?;
    /// assert!(builder.build()?.transport(addr)?.recv_datagram()?.is_none());
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn recv_datagram(&self) -> SimResult<Option<crate::network::Delivery>> {
        self.state
            .try_borrow_mut()
            .map_err(|_source| SimError::StateBusy)?
            .receive(self.local)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use refract_sim::{Seed, SimNodeId, Simulation, Stability};
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    /// let mut builder = Simulation::builder(Seed::new(1));
    /// builder.add_node(SimNodeId::new(1), addr)?;
    /// assert_eq!(
    ///     builder.build()?.transport(addr)?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Debug for SimTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SimTransport")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Transport for SimTransport {
    async fn send_to<'a>(&'a self, payload: &'a [u8], destination: SocketAddr) -> NetResult<usize> {
        self.send_datagram(payload, destination)
            .map_err(|error| sim_to_net(&error))
    }

    async fn recv_from(&self, mut buffer: Vec<u8>) -> NetResult<(usize, SocketAddr, Vec<u8>)> {
        let Some(delivery) = self.recv_datagram().map_err(|error| sim_to_net(&error))? else {
            return Err(NetError::Io(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no simulated datagram is available",
            )));
        };
        let payload = delivery.payload();
        buffer.clear();
        let additional = payload.len().saturating_sub(buffer.capacity());
        if additional != 0 {
            buffer.try_reserve_exact(additional).map_err(|_source| {
                NetError::Io(io::Error::other("simulated recv allocation failed"))
            })?;
        }
        buffer.extend_from_slice(payload);
        Ok((payload.len(), delivery.source(), buffer))
    }
}

fn sim_to_net(error: &SimError) -> NetError {
    NetError::Io(io::Error::other(format!("{}: {error}", error.error_code())))
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use refract_net::transport::Transport;

    use crate::{Seed, SimNodeId, Simulation};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn simulated_transport_sends_and_receives_through_trait() {
        let source = addr(1);
        let destination = addr(2);
        let mut builder = Simulation::builder(Seed::new(1));
        builder.add_node(SimNodeId::new(1), source).expect("node");
        builder
            .add_node(SimNodeId::new(2), destination)
            .expect("node");
        let simulation = builder.build().expect("build");
        let tx = simulation.transport(source).expect("transport");
        let rx = simulation.transport(destination).expect("transport");

        let sent = ready(tx.send_to(b"abc", destination)).expect("send");
        simulation
            .advance_by(std::time::Duration::ZERO)
            .expect("advance");
        let (len, remote, buffer) = ready(rx.recv_from(Vec::new())).expect("recv");

        assert_eq!(sent, 3);
        assert_eq!(len, 3);
        assert_eq!(remote, source);
        assert_eq!(buffer, b"abc");
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("simulated transport futures must be ready"),
        }
    }
}
