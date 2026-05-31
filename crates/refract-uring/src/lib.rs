//! Linux `io_uring` and portable UDP I/O boundary for refract.
//!
//! The public surface is intentionally stable across platforms. Linux builds
//! expose capability detection and registration helpers for `io_uring`; every
//! platform also has a portable fallback receive stream and batched sender so
//! higher media-plane code can keep one interface.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

#[cfg(target_os = "linux")]
use core::mem::size_of_val;
use core::{
    fmt,
    mem::{MaybeUninit, size_of},
    time::Duration,
};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    io,
    net::{SocketAddr, SocketAddrV6, UdpSocket},
};

use compio_buf::{IoBufMut, SetLen};
#[cfg(target_os = "linux")]
use io_uring::{IoUring, Probe, opcode};
use refract_slab::{PacketBuf, SlabError, SlabPool};
#[cfg(target_os = "linux")]
use socket2::SockAddr;
use thiserror::Error;

/// Result alias for uring operations.
pub type Result<T> = core::result::Result<T, UringError>;

/// Maximum control message bytes captured by receive operations.
pub const MAX_CMSG_BYTES: usize = 256;

/// Default timeout used by blocking fallback receive tests and utilities.
pub const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_millis(500);

#[cfg(any(target_os = "macos", target_os = "ios"))]
type MsgControlLen = libc::socklen_t;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
type MsgControlLen = usize;

#[cfg(any(target_os = "macos", target_os = "ios"))]
type CmsgLen = libc::socklen_t;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
type CmsgLen = usize;

/// Runtime `io_uring` and UDP socket capabilities.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capabilities {
    /// Kernel supports multishot `recvmsg`.
    pub multishot_recvmsg: bool,
    /// Kernel supports zero-copy send.
    pub send_zc: bool,
    /// Kernel supports registered provided-buffer rings.
    pub register_pbuf_ring: bool,
    /// SQ polling can be requested for this process/kernel.
    pub sq_poll: bool,
    /// UDP segmentation offload is enabled for the tested socket.
    pub gso: bool,
}

impl Capabilities {
    /// Detects process and kernel capabilities without a socket-specific GSO probe.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] if Linux `io_uring` probing fails for a
    /// reason other than platform absence.
    pub fn detect() -> Result<Self> {
        Self::detect_for_socket(None)
    }

    /// Detects capabilities, including socket-specific UDP GSO when a socket is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] if Linux `io_uring` probing fails for a
    /// reason other than platform absence.
    pub fn detect_for_socket(socket: Option<&UdpSocket>) -> Result<Self> {
        let mut capabilities = platform_capabilities()?;
        capabilities.gso = socket.is_some_and(detect_gso);
        Ok(capabilities)
    }
}

/// Selected receive implementation tier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecvTier {
    /// `recvmsg` multishot with a registered provided-buffer ring.
    MultishotProvidedBuffers,
    /// `recv`/`recvmsg` multishot without provided-buffer ring registration.
    RecvMultishot,
    /// Batched single-shot fallback.
    #[default]
    BatchedSingleShot,
}

impl RecvTier {
    /// Selects the best available receive tier.
    #[must_use]
    pub const fn select(capabilities: Capabilities) -> Self {
        if capabilities.multishot_recvmsg && capabilities.register_pbuf_ring {
            Self::MultishotProvidedBuffers
        } else if capabilities.multishot_recvmsg {
            Self::RecvMultishot
        } else {
            Self::BatchedSingleShot
        }
    }
}

/// SQ polling configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqPoll {
    /// Whether SQ polling is requested.
    pub enabled: bool,
    /// Poll thread idle timeout in milliseconds.
    pub idle_ms: u32,
    /// Optional CPU to pin the SQ poll thread to.
    pub cpu: Option<u32>,
}

impl Default for SqPoll {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_ms: 2_000,
            cpu: None,
        }
    }
}

impl SqPoll {
    /// Creates a disabled SQ polling config.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            idle_ms: 2_000,
            cpu: None,
        }
    }

    /// Creates an enabled SQ polling config.
    #[must_use]
    pub const fn enabled(idle_ms: u32, cpu: Option<u32>) -> Self {
        Self {
            enabled: true,
            idle_ms,
            cpu,
        }
    }

    /// Builds a Linux `IoUring` with SQPOLL when supported and requested.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Unsupported`] on non-Linux platforms or when
    /// SQPOLL is requested but unavailable. Returns [`UringError::Io`] for
    /// `io_uring_setup` failures.
    #[cfg(target_os = "linux")]
    pub fn build_ring(self, entries: u32) -> Result<IoUring> {
        let capabilities = Capabilities::detect()?;
        let mut builder = IoUring::builder();
        if self.enabled {
            if !capabilities.sq_poll {
                return Err(UringError::Unsupported { feature: "sq_poll" });
            }
            builder.setup_sqpoll(self.idle_ms);
            if let Some(cpu) = self.cpu {
                builder.setup_sqpoll_cpu(cpu);
            }
        }
        builder.build(entries).map_err(UringError::Io)
    }

    /// Builds a ring on non-Linux platforms.
    ///
    /// # Errors
    ///
    /// Always returns [`UringError::Unsupported`] because `io_uring` is Linux-only.
    #[cfg(not(target_os = "linux"))]
    pub const fn build_ring(self, _entries: u32) -> Result<()> {
        Err(UringError::Unsupported {
            feature: "io_uring",
        })
    }
}

/// Parsed control message bytes from `recvmsg`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cmsg {
    /// Control message level.
    pub level: i32,
    /// Control message type.
    pub kind: i32,
    /// Raw control message payload.
    pub data: Vec<u8>,
}

/// One received packet from [`MultishotRecvmsg`].
#[derive(Debug)]
pub struct RecvPacket {
    /// Slab-owned packet buffer.
    pub packet: PacketBuf,
    /// Source socket address.
    pub source: SocketAddr,
    /// Number of bytes written into `packet`.
    pub len: usize,
    /// Optional first control message.
    pub cmsg: Option<Cmsg>,
    /// Whether the datagram exceeded the provided packet buffer.
    pub truncated: bool,
}

/// Receive stream backed by the best available runtime tier.
#[derive(Debug)]
pub struct MultishotRecvmsg {
    socket: UdpSocket,
    pool: SlabPool,
    tier: RecvTier,
    core: u16,
}

impl MultishotRecvmsg {
    /// Creates a receive stream and selects the runtime fallback tier.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] when socket configuration or capability
    /// detection fails.
    pub fn new(socket: UdpSocket, pool: SlabPool, core: u16) -> Result<Self> {
        socket
            .set_read_timeout(Some(DEFAULT_RECV_TIMEOUT))
            .map_err(UringError::Io)?;
        let capabilities = Capabilities::detect_for_socket(Some(&socket))?;
        Ok(Self {
            socket,
            pool,
            tier: RecvTier::select(capabilities),
            core,
        })
    }

    /// Creates a receive stream with a forced fallback tier for tests.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] when socket configuration fails.
    pub fn with_tier(socket: UdpSocket, pool: SlabPool, tier: RecvTier, core: u16) -> Result<Self> {
        socket
            .set_read_timeout(Some(DEFAULT_RECV_TIMEOUT))
            .map_err(UringError::Io)?;
        Ok(Self {
            socket,
            pool,
            tier,
            core,
        })
    }

    /// Returns the selected receive tier.
    #[must_use]
    pub const fn tier(&self) -> RecvTier {
        self.tier
    }

    /// Receives the next datagram.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] for socket errors and [`UringError::Slab`]
    /// when the slab cannot provide a packet buffer.
    pub fn next_packet(&mut self) -> Result<RecvPacket> {
        let mut packet = self.pool.acquire().map_err(UringError::Slab)?;
        let capacity = packet.capacity();
        let mut source = None;
        let mut cmsg = None;
        let (len, truncated) =
            recv_into_packet(&self.socket, &mut packet, capacity, &mut source, &mut cmsg)?;
        let source = source.ok_or(UringError::MissingAddress)?;

        record_recv_metrics(self.core, len, truncated);
        Ok(RecvPacket {
            packet,
            source,
            len,
            cmsg,
            truncated,
        })
    }
}

impl Iterator for MultishotRecvmsg {
    type Item = Result<RecvPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_packet())
    }
}

/// A borrowed packet for [`BatchSendmsg`].
#[derive(Clone, Copy, Debug)]
pub struct SendMessage<'a> {
    /// Payload bytes to transmit.
    pub payload: &'a [u8],
    /// Destination address.
    pub destination: SocketAddr,
}

/// Builder for [`BatchSendmsg`].
#[derive(Debug)]
pub struct BatchSendmsgBuilder {
    socket: UdpSocket,
    core: u16,
    requested_gso: bool,
}

impl BatchSendmsgBuilder {
    /// Enables or disables GSO use when the socket supports it.
    #[must_use]
    pub const fn gso(mut self, enabled: bool) -> Self {
        self.requested_gso = enabled;
        self
    }

    /// Builds a batch sender.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] if socket capability probing fails.
    pub fn build(self) -> Result<BatchSendmsg> {
        let gso = self.requested_gso && detect_gso(&self.socket);
        Ok(BatchSendmsg {
            socket: self.socket,
            core: self.core,
            gso,
        })
    }
}

/// Batched UDP sender using `sendmmsg` on Linux and portable sends elsewhere.
#[derive(Debug)]
pub struct BatchSendmsg {
    socket: UdpSocket,
    core: u16,
    gso: bool,
}

impl BatchSendmsg {
    /// Starts building a batch sender.
    #[must_use]
    pub const fn builder(socket: UdpSocket, core: u16) -> BatchSendmsgBuilder {
        BatchSendmsgBuilder {
            socket,
            core,
            requested_gso: false,
        }
    }

    /// Returns whether GSO is enabled for this sender.
    #[must_use]
    pub const fn gso_enabled(&self) -> bool {
        self.gso
    }

    /// Sends all messages, returning the packet count accepted by the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] when sending fails.
    pub fn send(&self, messages: &[SendMessage<'_>]) -> Result<usize> {
        if messages.is_empty() {
            return Ok(0);
        }

        match platform_send_batch(&self.socket, messages) {
            Ok(sent) => {
                record_send_metrics(self.core, sent, self.gso, None);
                Ok(sent)
            }
            Err(error) => {
                let errno = error.raw_errno();
                record_send_metrics(self.core, 0, self.gso, Some(&errno));
                Err(error)
            }
        }
    }
}

/// Fixed buffer registration owner.
#[derive(Debug)]
pub struct RegisteredBuffers {
    buffers: Vec<PacketBuf>,
    #[cfg(target_os = "linux")]
    iovecs: Vec<libc::iovec>,
}

impl RegisteredBuffers {
    /// Acquires `count` packet buffers and prepares `iovec` descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Slab`] when the slab cannot provide enough
    /// buffers.
    pub fn from_pool(pool: &mut SlabPool, count: usize) -> Result<Self> {
        let mut buffers = Vec::with_capacity(count);
        #[cfg(target_os = "linux")]
        let mut iovecs = Vec::with_capacity(count);
        for _index in 0..count {
            #[cfg(target_os = "linux")]
            let mut packet = pool.acquire().map_err(UringError::Slab)?;
            #[cfg(not(target_os = "linux"))]
            let packet = pool.acquire().map_err(UringError::Slab)?;
            #[cfg(target_os = "linux")]
            {
                let capacity = packet.capacity();
                let ptr = packet.as_uninit().as_mut_ptr().cast::<libc::c_void>();
                iovecs.push(libc::iovec {
                    iov_base: ptr,
                    iov_len: capacity,
                });
            }
            buffers.push(packet);
        }
        Ok(Self {
            buffers,
            #[cfg(target_os = "linux")]
            iovecs,
        })
    }

    /// Returns the registered buffer count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Returns whether no buffers are held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// Registers buffers with an existing Linux ring.
    ///
    /// # Errors
    ///
    /// Returns [`UringError::Io`] when `IORING_REGISTER_BUFFERS` fails.
    #[cfg(target_os = "linux")]
    pub fn register_with(&self, ring: &IoUring) -> Result<()> {
        // SAFETY: `iovecs` point into PacketBuf arena slots held by `self`.
        // `self` must outlive the kernel registration; callers unregister or
        // drop the ring before dropping this owner.
        unsafe { ring.submitter().register_buffers(&self.iovecs) }.map_err(UringError::Io)
    }

    /// Registers buffers on non-Linux platforms.
    ///
    /// # Errors
    ///
    /// Always returns [`UringError::Unsupported`] because fixed-buffer
    /// registration is an `io_uring` operation.
    #[cfg(not(target_os = "linux"))]
    pub const fn register_with(&self, _ring: &()) -> Result<()> {
        Err(UringError::Unsupported {
            feature: "registered_buffers",
        })
    }
}

/// Errors returned by this crate.
#[derive(Debug, Error)]
pub enum UringError {
    /// Operating system I/O failed.
    #[error("io operation failed: {0}")]
    Io(#[source] io::Error),
    /// Slab buffer acquisition failed.
    #[error("slab operation failed: {0}")]
    Slab(#[source] SlabError),
    /// The requested feature is unsupported on this platform or kernel.
    #[error("unsupported feature: {feature}")]
    Unsupported {
        /// Unsupported feature name.
        feature: &'static str,
    },
    /// The kernel returned an address family this crate does not understand.
    #[error("unsupported socket address")]
    UnsupportedAddress,
    /// A receive completion did not include a source address.
    #[error("receive operation did not return a source address")]
    MissingAddress,
}

impl UringError {
    /// Returns the stable operator-facing error code.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "HSF-URING-1001",
            Self::Slab(_) => "HSF-URING-1002",
            Self::Unsupported { .. } => "HSF-URING-1003",
            Self::UnsupportedAddress => "HSF-URING-1004",
            Self::MissingAddress => "HSF-URING-1005",
        }
    }

    fn raw_errno(&self) -> String {
        match self {
            Self::Io(error) => error
                .raw_os_error()
                .map_or_else(|| "unknown".to_owned(), |errno| errno.to_string()),
            Self::Slab(_) => "slab".to_owned(),
            Self::Unsupported { feature } => (*feature).to_owned(),
            Self::UnsupportedAddress => "unsupported_address".to_owned(),
            Self::MissingAddress => "missing_address".to_owned(),
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_capabilities() -> Result<Capabilities> {
    let kernel = KernelVersion::current();
    let ring = IoUring::new(2).map_err(UringError::Io)?;
    let mut probe = Probe::new();
    ring.submitter()
        .register_probe(&mut probe)
        .map_err(UringError::Io)?;

    let multishot_recvmsg =
        probe.is_supported(opcode::RecvMsgMulti::CODE) && kernel >= KernelVersion::new(6, 0);
    let send_zc = probe.is_supported(opcode::SendZc::CODE);
    let register_pbuf_ring = kernel >= KernelVersion::new(5, 19);
    let sq_poll = has_cap_sys_nice() || kernel >= KernelVersion::new(5, 13);

    Ok(Capabilities {
        multishot_recvmsg,
        send_zc,
        register_pbuf_ring,
        sq_poll,
        gso: false,
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn platform_capabilities() -> Result<Capabilities> {
    Ok(Capabilities::default())
}

#[cfg(target_os = "linux")]
fn detect_gso(socket: &UdpSocket) -> bool {
    const UDP_SEGMENT: libc::c_int = 103;
    let segment: libc::c_int = 1_200;
    let option_len = match libc::socklen_t::try_from(size_of_val(&segment)) {
        Ok(len) => len,
        Err(_error) => return false,
    };
    // SAFETY: the socket fd is valid for the duration of the call and the
    // option pointer/length describe an initialized integer.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_SEGMENT,
            (&raw const segment).cast(),
            option_len,
        )
    };
    if result != 0 {
        return false;
    }

    let disabled: libc::c_int = 0;
    // SAFETY: same as above; this restores normal non-GSO sends after probing.
    let _ignored = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_SEGMENT,
            (&raw const disabled).cast(),
            option_len,
        )
    };
    true
}

#[cfg(not(target_os = "linux"))]
const fn detect_gso(_socket: &UdpSocket) -> bool {
    false
}

#[cfg(unix)]
fn recv_into_packet(
    socket: &UdpSocket,
    packet: &mut PacketBuf,
    capacity: usize,
    source: &mut Option<SocketAddr>,
    cmsg: &mut Option<Cmsg>,
) -> Result<(usize, bool)> {
    let fd = socket.as_raw_fd();
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut control = [0_u8; MAX_CMSG_BYTES];
    let name_len = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .map_err(|_error| UringError::Io(io::Error::other("sockaddr length overflow")))?;
    let control_len = MsgControlLen::try_from(control.len())
        .map_err(|_error| UringError::Io(io::Error::other("control length overflow")))?;
    let mut iov = libc::iovec {
        iov_base: packet.as_uninit().as_mut_ptr().cast::<libc::c_void>(),
        iov_len: capacity,
    };
    let mut msg = libc::msghdr {
        msg_name: name.as_mut_ptr().cast::<libc::c_void>(),
        msg_namelen: name_len,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_len,
        msg_flags: 0,
    };

    // SAFETY: `msg` points to valid writable name/control storage and one iov
    // over the PacketBuf uninitialized payload capacity.
    let received = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_TRUNC) };
    if received < 0 {
        return Err(UringError::Io(io::Error::last_os_error()));
    }

    let received = usize::try_from(received)
        .map_err(|_error| UringError::Io(io::Error::other("negative recvmsg length")))?;
    let initialized = received.min(capacity);
    // SAFETY: recvmsg initialized exactly `initialized` bytes in the iovec.
    unsafe { packet.set_len(initialized) };

    // SAFETY: recvmsg wrote `msg_namelen` bytes to `name` on success.
    let name = unsafe { name.assume_init() };
    *source = socket_addr_from_storage(&name, msg.msg_namelen)?;
    *cmsg = parse_first_cmsg(&msg);

    let truncation_flag = (msg.msg_flags & libc::MSG_TRUNC) != 0;
    Ok((
        initialized,
        received > capacity || (truncation_flag && initialized == capacity),
    ))
}

#[cfg(not(unix))]
fn recv_into_packet(
    socket: &UdpSocket,
    packet: &mut PacketBuf,
    capacity: usize,
    source: &mut Option<SocketAddr>,
    cmsg: &mut Option<Cmsg>,
) -> Result<(usize, bool)> {
    let mut scratch = vec![0_u8; capacity];
    let (len, address) = socket.recv_from(&mut scratch).map_err(UringError::Io)?;
    packet
        .copy_from_slice(&scratch[..len])
        .map_err(UringError::Slab)?;
    *source = Some(address);
    *cmsg = None;
    Ok((len, false))
}

#[cfg(unix)]
fn socket_addr_from_storage(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Result<Option<SocketAddr>> {
    if len == 0 {
        return Ok(None);
    }
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: ss_family says this storage contains an IPv4 sockaddr.
            let address = unsafe { *(core::ptr::from_ref(storage).cast::<libc::sockaddr_in>()) };
            let octets = address.sin_addr.s_addr.to_ne_bytes();
            let port = u16::from_be(address.sin_port);
            Ok(Some(SocketAddr::from((octets, port))))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family says this storage contains an IPv6 sockaddr.
            let address = unsafe { *(core::ptr::from_ref(storage).cast::<libc::sockaddr_in6>()) };
            let octets = address.sin6_addr.s6_addr;
            let port = u16::from_be(address.sin6_port);
            Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                octets.into(),
                port,
                address.sin6_flowinfo,
                address.sin6_scope_id,
            ))))
        }
        _family => Err(UringError::UnsupportedAddress),
    }
}

#[cfg(unix)]
fn parse_first_cmsg(msg: &libc::msghdr) -> Option<Cmsg> {
    let controllen = control_len_to_usize(msg.msg_controllen);
    if controllen < size_of::<libc::cmsghdr>() {
        return None;
    }
    let header = msg.msg_control.cast::<libc::cmsghdr>();
    if header.is_null() {
        return None;
    }
    // SAFETY: msg_controllen was checked to include a cmsghdr.
    let header = unsafe { &*header };
    let header_len = size_of::<libc::cmsghdr>();
    let message_len = cmsg_len_to_usize(header.cmsg_len);
    if message_len < header_len {
        return None;
    }
    let data_len = message_len - header_len;
    if data_len > controllen.saturating_sub(header_len) {
        return None;
    }
    // SAFETY: cmsg data lies inside msg_control according to the bounds above.
    let data = unsafe {
        core::slice::from_raw_parts(msg.msg_control.cast::<u8>().add(header_len), data_len)
    };
    Some(Cmsg {
        level: header.cmsg_level,
        kind: header.cmsg_type,
        data: data.to_vec(),
    })
}

#[cfg(target_os = "linux")]
fn platform_send_batch(socket: &UdpSocket, messages: &[SendMessage<'_>]) -> Result<usize> {
    let mut addrs = Vec::with_capacity(messages.len());
    let mut iovecs = Vec::with_capacity(messages.len());
    let mut headers = Vec::with_capacity(messages.len());

    for message in messages {
        let address = SockAddr::from(message.destination);
        addrs.push(address);
        iovecs.push(libc::iovec {
            iov_base: message.payload.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: message.payload.len(),
        });
    }

    for index in 0..messages.len() {
        headers.push(libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: addrs[index].as_ptr().cast::<libc::c_void>().cast_mut(),
                msg_namelen: addrs[index].len(),
                msg_iov: &raw mut iovecs[index],
                msg_iovlen: 1,
                msg_control: core::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        });
    }

    let vlen = u32::try_from(headers.len()).map_err(|_error| {
        UringError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "send batch is too large",
        ))
    })?;

    // SAFETY: fd is valid, `headers` points to initialized mmsghdr values, and
    // each header references stable address/iovec storage owned by this stack.
    let sent = unsafe { libc::sendmmsg(socket.as_raw_fd(), headers.as_mut_ptr(), vlen, 0) };
    if sent < 0 {
        return Err(UringError::Io(io::Error::last_os_error()));
    }

    usize::try_from(sent)
        .map_err(|_error| UringError::Io(io::Error::other("negative sendmmsg result")))
}

#[cfg(not(target_os = "linux"))]
fn platform_send_batch(socket: &UdpSocket, messages: &[SendMessage<'_>]) -> Result<usize> {
    let mut sent = 0;
    for message in messages {
        socket
            .send_to(message.payload, message.destination)
            .map_err(UringError::Io)?;
        sent += 1;
    }
    Ok(sent)
}

fn record_recv_metrics(core: u16, bytes: usize, truncated: bool) {
    let core_label = core.to_string();
    metrics::counter!("refract.io.recv.packets", "core" => core_label.clone()).increment(1);
    metrics::counter!("refract.io.recv.bytes", "core" => core_label.clone())
        .increment(bytes as u64);
    if truncated {
        metrics::counter!("refract.io.recv.truncated", "core" => core_label).increment(1);
    }
}

fn record_send_metrics(core: u16, packets: usize, gso: bool, errno: Option<&str>) {
    let core_label = core.to_string();
    let gso_label = if gso { "gso" } else { "plain" };
    metrics::counter!(
        "refract.io.send.packets",
        "core" => core_label.clone(),
        "gso" => gso_label
    )
    .increment(packets as u64);
    if let Some(errno) = errno {
        metrics::counter!(
            "refract.io.send.errors",
            "core" => core_label,
            "errno" => errno.to_owned()
        )
        .increment(1);
    }
}

/// Records that an `io_uring` submission queue was full for a media core.
pub fn record_sq_full(core: u16) {
    metrics::counter!("refract.io.uring.sq_full", "core" => core.to_string()).increment(1);
}

const fn control_len_to_usize(value: MsgControlLen) -> usize {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        value as usize
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        value
    }
}

const fn cmsg_len_to_usize(value: CmsgLen) -> usize {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        value as usize
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        value
    }
}

#[cfg(target_os = "linux")]
fn has_cap_sys_nice() -> bool {
    const CAP_SYS_NICE: u64 = 23;
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: capget writes to the initialized header/data structures.
    let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    if result != 0 {
        return false;
    }
    let word = usize::try_from(CAP_SYS_NICE / 32).unwrap_or(0);
    let bit = u32::try_from(CAP_SYS_NICE % 32).unwrap_or(0);
    data.get(word)
        .is_some_and(|capabilities| (capabilities.effective & (1_u32 << bit)) != 0)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct KernelVersion {
    major: u16,
    minor: u16,
}

#[cfg(target_os = "linux")]
impl KernelVersion {
    const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    fn current() -> Self {
        let mut uts = MaybeUninit::<libc::utsname>::zeroed();
        // SAFETY: uname writes a complete utsname on success.
        let result = unsafe { libc::uname(uts.as_mut_ptr()) };
        if result != 0 {
            return Self::default();
        }
        // SAFETY: uname succeeded above.
        let uts = unsafe { uts.assume_init() };
        let release = uts
            .release
            .iter()
            .map_while(|byte| u8::try_from(*byte).ok())
            .take_while(|byte| *byte != 0)
            .collect::<Vec<_>>();
        let release = String::from_utf8_lossy(&release);
        Self::parse(&release)
    }

    fn parse(release: &str) -> Self {
        let mut parts = release.split(['.', '-']);
        let major = parts
            .next()
            .and_then(|part| part.parse::<u16>().ok())
            .unwrap_or_default();
        let minor = parts
            .next()
            .and_then(|part| part.parse::<u16>().ok())
            .unwrap_or_default();
        Self { major, minor }
    }
}

impl fmt::Display for RecvTier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultishotProvidedBuffers => formatter.write_str("multishot_provided_buffers"),
            Self::RecvMultishot => formatter.write_str("recv_multishot"),
            Self::BatchedSingleShot => formatter.write_str("batched_single_shot"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use compio_buf::IoBuf;
    use refract_slab::{ArenaKind, ExhaustionPolicy, SlabConfig};

    use super::*;

    const LOOPBACK_PACKETS: usize = 10_000;

    fn pool(slot_count: usize, packet_capacity: usize) -> SlabPool {
        let config = SlabConfig {
            slot_count,
            packet_capacity,
            arena: ArenaKind::Heap,
            exhaustion: ExhaustionPolicy::FailFast,
        };
        match SlabPool::with_config(config) {
            Ok(pool) => pool,
            Err(error) => panic!("slab pool setup failed: {error}"),
        }
    }

    fn bound_socket() -> UdpSocket {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        match UdpSocket::bind(address) {
            Ok(socket) => socket,
            Err(error) => panic!("bind failed: {error}"),
        }
    }

    #[test]
    fn capabilities_select_fallback_tiers() {
        assert_eq!(
            RecvTier::select(Capabilities::default()),
            RecvTier::BatchedSingleShot
        );
        assert_eq!(
            RecvTier::select(Capabilities {
                multishot_recvmsg: true,
                ..Capabilities::default()
            }),
            RecvTier::RecvMultishot
        );
        assert_eq!(
            RecvTier::select(Capabilities {
                multishot_recvmsg: true,
                register_pbuf_ring: true,
                ..Capabilities::default()
            }),
            RecvTier::MultishotProvidedBuffers
        );
    }

    #[test]
    fn loopback_packets_match_byte_for_byte() -> Result<()> {
        let receiver = bound_socket();
        let sender = bound_socket();
        let destination = receiver.local_addr().map_err(UringError::Io)?;
        let mut recv = MultishotRecvmsg::with_tier(
            receiver.try_clone().map_err(UringError::Io)?,
            pool(LOOPBACK_PACKETS + 8, 2_048),
            RecvTier::BatchedSingleShot,
            0,
        )?;

        for index in 0..LOOPBACK_PACKETS {
            let payload = index.to_le_bytes();
            sender
                .send_to(&payload, destination)
                .map_err(UringError::Io)?;
            let datagram = recv.next_packet()?;
            assert_eq!(
                datagram.source,
                sender.local_addr().map_err(UringError::Io)?
            );
            assert_eq!(datagram.packet.as_init(), payload);
            assert!(!datagram.truncated);
        }
        Ok(())
    }

    #[test]
    fn truncation_sets_flag() -> Result<()> {
        let receiver = bound_socket();
        let sender = bound_socket();
        let destination = receiver.local_addr().map_err(UringError::Io)?;
        let mut recv =
            MultishotRecvmsg::with_tier(receiver, pool(4, 64), RecvTier::BatchedSingleShot, 0)?;
        let payload = [7_u8; 512];

        sender
            .send_to(&payload, destination)
            .map_err(UringError::Io)?;
        let datagram = recv.next_packet()?;

        assert_eq!(datagram.len, 64);
        assert!(datagram.truncated);
        assert_eq!(datagram.packet.as_init(), &payload[..64]);
        Ok(())
    }

    #[test]
    fn forced_fallback_tiers_receive() -> Result<()> {
        for tier in [
            RecvTier::BatchedSingleShot,
            RecvTier::RecvMultishot,
            RecvTier::MultishotProvidedBuffers,
        ] {
            let receiver = bound_socket();
            let sender = bound_socket();
            let destination = receiver.local_addr().map_err(UringError::Io)?;
            let mut recv = MultishotRecvmsg::with_tier(receiver, pool(4, 2_048), tier, 0)?;
            sender
                .send_to(b"tier", destination)
                .map_err(UringError::Io)?;
            let datagram = recv.next_packet()?;
            assert_eq!(datagram.packet.as_init(), b"tier");
        }
        Ok(())
    }

    #[test]
    fn batch_sendmsg_sends_all_packets() -> Result<()> {
        let receiver = bound_socket();
        let sender = bound_socket();
        let destination = receiver.local_addr().map_err(UringError::Io)?;
        let batch = BatchSendmsg::builder(sender, 0).build()?;
        let messages = [
            SendMessage {
                payload: b"one",
                destination,
            },
            SendMessage {
                payload: b"two",
                destination,
            },
        ];

        assert_eq!(batch.send(&messages)?, 2);
        let mut buffer = [0_u8; 8];
        let (first_len, _) = receiver.recv_from(&mut buffer).map_err(UringError::Io)?;
        assert_eq!(&buffer[..first_len], b"one");
        let (second_len, _) = receiver.recv_from(&mut buffer).map_err(UringError::Io)?;
        assert_eq!(&buffer[..second_len], b"two");
        Ok(())
    }

    #[test]
    fn registered_buffers_hold_packet_slots() -> Result<()> {
        let mut pool = pool(4, 2_048);
        let buffers = RegisteredBuffers::from_pool(&mut pool, 3)?;
        assert_eq!(buffers.len(), 3);
        assert!(!buffers.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_version_parse_handles_suffixes() {
        assert_eq!(
            KernelVersion::parse("5.19.0-foo"),
            KernelVersion::new(5, 19)
        );
        assert_eq!(KernelVersion::parse("6.6.12"), KernelVersion::new(6, 6));
    }
}
