//! UDP transport abstraction for plain `compio` and `refract-uring` backends.
//!
//! The SFU-facing code depends on [`Transport`] only.

#![allow(clippy::future_not_send)]

use std::{
    future::Future,
    net::{SocketAddr, UdpSocket},
};

use compio::net::UdpSocket as CompioUdpSocket;
use compio_buf::BufResult;
use refract_slab::SlabPool;
use refract_uring::{BatchSendmsg, MultishotRecvmsg, RecvPacket, SendMessage};

use crate::stun::{NetError, NetResult};

/// UDP transport abstraction.
pub trait Transport {
    /// Sends a datagram.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] when the underlying transport send fails.
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        destination: SocketAddr,
    ) -> impl Future<Output = NetResult<usize>> + 'a;

    /// Receives a datagram into an owned buffer.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] when the underlying transport receive fails.
    fn recv_from(
        &self,
        buffer: Vec<u8>,
    ) -> impl Future<Output = NetResult<(usize, SocketAddr, Vec<u8>)>> + '_;
}

/// Plain `compio` UDP transport.
#[derive(Debug)]
pub struct PlainCompioTransport {
    socket: CompioUdpSocket,
}

impl PlainCompioTransport {
    /// Creates a transport from a `compio` UDP socket.
    #[must_use]
    pub const fn new(socket: CompioUdpSocket) -> Self {
        Self { socket }
    }
}

impl Transport for PlainCompioTransport {
    async fn send_to<'a>(&'a self, payload: &'a [u8], destination: SocketAddr) -> NetResult<usize> {
        let BufResult(result, _buffer) = self.socket.send_to(payload.to_vec(), destination).await;
        result.map_err(NetError::Io)
    }

    async fn recv_from(&self, buffer: Vec<u8>) -> NetResult<(usize, SocketAddr, Vec<u8>)> {
        let BufResult(result, buffer) = self.socket.recv_from(buffer).await;
        let (len, source) = result.map_err(NetError::Io)?;
        Ok((len, source, buffer))
    }
}

/// `refract-uring` multishot receive plus batch-send transport.
#[derive(Debug)]
pub struct UringTransport {
    receiver: MultishotRecvmsg,
    sender: BatchSendmsg,
}

impl UringTransport {
    /// Creates an uring transport from one UDP socket.
    ///
    /// # Errors
    ///
    /// Returns transport setup errors from `refract-uring`.
    pub fn new(socket: UdpSocket, pool: SlabPool, core: u16) -> NetResult<Self> {
        let send_socket = socket.try_clone().map_err(NetError::Io)?;
        let receiver = MultishotRecvmsg::new(socket, pool, core).map_err(map_uring)?;
        let sender = BatchSendmsg::builder(send_socket, core)
            .build()
            .map_err(map_uring)?;
        Ok(Self { receiver, sender })
    }

    /// Receives the next uring packet.
    ///
    /// # Errors
    ///
    /// Returns transport receive errors.
    pub fn next_packet(&mut self) -> NetResult<RecvPacket> {
        self.receiver.next_packet().map_err(map_uring)
    }

    /// Sends a batch.
    ///
    /// # Errors
    ///
    /// Returns transport send errors.
    pub fn send_batch(&self, messages: &[SendMessage<'_>]) -> NetResult<usize> {
        self.sender.send(messages).map_err(map_uring)
    }
}

fn map_uring(error: refract_uring::UringError) -> NetError {
    match error {
        refract_uring::UringError::Io(source) => NetError::Io(source),
        other => NetError::Io(std::io::Error::other(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use compio_buf::IoBuf;

    fn assert_iobuf<T: IoBuf>(_buf: T) {}

    #[test]
    fn borrowed_slice_is_compio_buffer() {
        assert_iobuf(&b"abc"[..]);
    }
}
