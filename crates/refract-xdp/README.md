# refract-xdp

Linux eBPF and XDP rate-limiting integration boundary for the refract media
socket. The Rust crate validates loader configuration, exposes deterministic
packet classification for tests, and owns the Linux-only Aya loader.

The XDP object is `crates/refract-xdp/ebpf/refract_xdp.bpf.c`. It is built by
`cargo xtask xdp-load` with clang and then loaded, configured, attached, read,
and detached through Aya.

Default policy:

- pass non-target traffic unchanged
- drop UDP packets to the configured media port unless they are STUN, DTLS, or
  SRTP/SRTCP per RFC 7983 demux ranges
- drop fragmented IPv4 UDP and IPv6 fragment traffic before socket delivery
- token-bucket STUN binding requests per source IP at 100 pps with a 100 packet
  burst by default

Example:

```sh
sudo REFRACT_XDP_INTERFACE=eth0 cargo xtask xdp-load --port 50000
```

Use `--generic` for SKB mode on development machines that do not support native
driver XDP.
