# refract-uring safety policy

`refract-uring` is one of the three crates allowed to contain unsafe code. The
unsafe surface exists to bridge Rust-owned slab buffers, socket address storage,
and Linux kernel I/O ABIs.

## Invariants

- `PacketBuf` ownership stays unique while receive operations write into its
  uninitialized payload area.
- `PacketBuf::set_len` is called only after the kernel reports a successful
  receive, and only for the initialized prefix bounded by packet capacity.
- `recvmsg` receives use valid writable `sockaddr_storage`, control storage,
  and a single `iovec` pointing at a live slab slot.
- Socket address parsing trusts `ss_family` only after `recvmsg` succeeds and
  copies the platform sockaddr value before constructing `SocketAddr`.
- `sendmmsg` headers borrow stable address and iovec arrays that live until the
  syscall returns.
- `RegisteredBuffers` owns all `PacketBuf` values referenced by its `iovec`
  table. Callers must unregister or drop the `IoUring` before dropping
  `RegisteredBuffers`.
- SQPOLL is config-gated and rejected unless capability detection says the
  kernel/process can request it.

## Unsafe block audit

Every unsafe block in `src/lib.rs` has an adjacent `SAFETY:` comment. Unsafe is
limited to:

- `recvmsg`, `sendmmsg`, `setsockopt`, `uname`, and Linux capability syscalls;
- interpreting initialized sockaddr storage returned by `recvmsg`;
- parsing the first control message header inside `msg_control`;
- setting `PacketBuf` initialized length after successful kernel receive;
- registering fixed buffers with an existing `IoUring`.

## Required verification

- `cargo test -p refract-uring`
- `cargo bench -p refract-uring`
- Linux compatibility checks on 5.10, 5.19, and 6.6 before enabling this crate
  in production media-plane builds.
