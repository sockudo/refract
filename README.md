# refract

`refract` is a Rust workspace for a production-grade, single-edge WebRTC SFU
and media control plane. The current codebase is Stage 1 focused: it defines
the stable crate boundaries, hot-path invariants, daemon wiring, media packet
primitives, signaling safety envelope, room/application interfaces, and the
verification gates required before multi-edge clustering and deeper protocol
surface area are expanded.

Repository: <https://github.com/sockudo/refract>

## What is in this workspace

- A thread-per-core SFU daemon in `crates/refract-bin`.
- RTP, RTCP, SRTP, jitter, pacing, congestion-control, slab, and UDP/XDP
  boundaries for the media plane.
- Stateless signaling, application policy, room store traits, admin actions,
  observability, resilience, and configuration crates for the control plane.
- Deterministic simulation and load generation support for release gates.
- Strict workspace automation through `cargo xtask ...` and optional `just`
  aliases.

## Current status

This is a Stage 1 workspace. Some crates are production-oriented
implementations, and some are explicit API or integration boundaries whose
backend implementations are intentionally deferred until later stages.

Implemented or substantially defined areas include:

- daemon startup, config loading, signal handling, watchdogs, systemd readiness,
  and worker ownership;
- RTP/RTCP parsing and rewrite helpers;
- AES-GCM SRTP/SRTCP protection and replay tracking;
- jitter buffer support, NACK/PLI/FIR coalescing, congestion control, and
  pacing primitives;
- signaling admission, bounded JSON parsing, auth/rate-limit/backpressure
  boundaries, and in-process load generation;
- admin operations for drain, stats, session inspection, kick, profiling
  requests, log-level update, and capabilities;
- Redis room store implementation behind the Stage 1 `RoomStore` trait;
- Linux XDP classifier/loader boundary, with deterministic classifier tests and
  Linux-only attach support.

Deferred or scaffolded areas are documented in the individual crate README
files, especially codec and future storage/application backends.

## Repository layout

```text
.
|-- Cargo.toml              # Rust workspace manifest
|-- Justfile                # short aliases for xtask commands
|-- example.toml            # local single-edge daemon config
|-- docs/                   # architecture, production gates, app protocols
|-- deploy/                 # systemd unit example
|-- crates/                 # workspace crates
`-- xtask/                  # project automation commands
```

Core crate groups:

| Area | Crates |
| --- | --- |
| Daemon and operations | `refract-bin`, `refract-admin`, `refract-config`, `refract-obs`, `refract-resilience` |
| Media hot path | `refract-sfu`, `refract-rtp`, `refract-srtp`, `refract-jitter`, `refract-cc`, `refract-slab`, `refract-uring`, `refract-xdp` |
| WebRTC and network | `refract-rtc`, `refract-net`, `refract-crypto`, `refract-signal` |
| Apps and room state | `refract-app`, `refract-app-room`, `refract-app-echo`, `refract-app-textroom`, `refract-app-audiomix`, `refract-app-recording`, `refract-app-sip`, `refract-app-streaming`, `refract-roomstore`, `refract-roomstore-redis`, `refract-roomstore-dual`, `refract-roomstore-scylla` |
| Codecs | `refract-codec-vp8`, `refract-codec-vp9`, `refract-codec-av1`, `refract-codec-h264`, `refract-codec-h265`, `refract-codec-opus` |
| Test and release support | `refract-sim`, `refract-loadgen`, `refract-chaos`, `xtask` |
| Extension boundary | `refract-wasm` |

## Requirements

- Rust toolchain from `rust-toolchain.toml`.
- Cargo with the workspace lockfile checked in.
- `just` is optional; every recipe maps to `cargo xtask ...`.

Useful optional tools:

```sh
cargo install cargo-audit --version 0.22.0 --locked
cargo install cargo-deny --version 0.19.6 --locked
cargo install cargo-llvm-cov --locked
cargo install cargo-fuzz
cargo install typos-cli
```

Linux XDP work additionally requires `clang` with BPF target support and a Linux
host where XDP attach is allowed.

## Quick start

Clone and enter the repository:

```sh
git clone git@github.com:sockudo/refract.git
cd refract
```

Build the workspace:

```sh
cargo build --workspace --all-targets --all-features
```

Run the daemon startup check against the sample config:

```sh
cargo run -p refract-bin -- --config example.toml --check
```

The `--check` mode loads configuration, starts the daemon components, triggers a
graceful drain, and exits. It is the fastest local smoke test for operator
wiring.

Run the daemon normally:

```sh
cargo run -p refract-bin -- --config example.toml
```

The sample config binds media to localhost and enables the echo app:

```toml
[runtime]
cores = 1

[net]
bind_addrs = ["127.0.0.1:50000"]
rtp_port = 50000
rtcp_port = 50001

[apps.echo]
enabled = true
max_sessions = 64
```

Stop the daemon with `SIGTERM` for graceful drain. `SIGUSR1` requests config
reload, and `SIGUSR2` requests a diagnostic stack dump.

## How to test

The canonical test path is `xtask`; the `Justfile` provides shorter aliases.

Run formatting checks:

```sh
cargo xtask fmt
# or
just fmt
```

Run lint checks:

```sh
cargo xtask lint
# or
just lint
```

This runs `cargo fmt --all --check` and workspace Clippy with all targets,
all features, and the workspace deny settings.

Run unit, integration, and doctests:

```sh
cargo xtask test
# or
just test
```

This expands to:

```sh
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features
```

Run one crate while iterating:

```sh
cargo test -p refract-rtp
cargo test -p refract-srtp --all-features
cargo test -p refract-bin --test refract_bin_starts
```

Run the daemon smoke check:

```sh
cargo run -p refract-bin -- --config example.toml --check
```

Run the Stage 1 signaling load gate:

```sh
cargo xtask signal-loadgen
```

Smaller local loadgen runs are useful during development:

```sh
cargo xtask signal-loadgen --connections 10000
cargo xtask signal-loadgen --connections 100000 --messages-per-connection 1
```

Run supply-chain checks:

```sh
cargo xtask audit
cargo xtask deny
```

Run coverage with the workspace threshold:

```sh
cargo xtask coverage
```

`coverage` requires `cargo-llvm-cov` and currently fails under 80 percent line
coverage, excluding `xtask`.

Run benchmarks:

```sh
cargo xtask bench
```

Run fuzzing:

```sh
cargo xtask fuzz --seconds 60
```

`xtask fuzz` looks for root-level targets under `fuzz/fuzz_targets`. Several
crates also carry crate-local fuzz packages. Run those directly, for example:

```sh
cd crates/refract-rtp/fuzz
cargo fuzz run rtp_parse -- -max_total_time=60
```

Other crate-local fuzz packages include `refract-net`, `refract-signal`,
`refract-srtp`, and the codec crates that have `fuzz/` directories.

Run Redis room-store tests:

```sh
cargo test -p refract-roomstore-redis
```

The ignored Redis integration path expects Sentinel configuration:

```sh
REFRACT_REDIS_SENTINELS=127.0.0.1:26379 \
REFRACT_REDIS_MASTER=mymaster \
cargo test -p refract-roomstore-redis --features redis-integration -- --ignored
```

Run Linux XDP load/attach validation:

```sh
sudo REFRACT_XDP_INTERFACE=eth0 cargo xtask xdp-load --port 50000
```

Use generic/SKB mode on development hosts without native driver XDP:

```sh
sudo REFRACT_XDP_INTERFACE=eth0 cargo xtask xdp-load --port 50000 --generic
```

Print the full release checklist:

```sh
cargo xtask preflight
```

Run the release gate:

```sh
cargo xtask release
```

For a native CPU-tuned release build:

```sh
cargo xtask release --native
```

## Development workflow

Recommended loop for most changes:

```sh
cargo xtask fmt
cargo xtask lint
cargo xtask test
```

Before opening or merging a production-facing change, also run:

```sh
cargo xtask audit
cargo xtask deny
cargo run -p refract-bin -- --config example.toml --check
```

Install the local pre-commit hook:

```sh
cargo xtask install-hooks
```

The hook runs format, lint, and tests.

## Configuration

Configuration is loaded by `refract-config` from:

1. built-in defaults,
2. TOML file values,
3. `REFRACT_` environment variables using `__` for nesting.

Example:

```sh
REFRACT_RUNTIME__CORES=2 \
REFRACT_NET__RTP_PORT=50000 \
cargo run -p refract-bin -- --config example.toml --check
```

Startup fields that cannot be changed safely at runtime are preserved during
reload and reported through reload warnings.

## Architecture model

`docs/architecture.md` describes the five-tier state model:

1. per-core hot-path state for routing, SRTP, jitter, pacing, and bandwidth
   estimation;
2. per-node process state for ICE, DTLS, WebRTC sessions, and app sessions;
3. Raft-owned placement, membership, configuration, and auth-key state;
4. sharded room state for participants, tracks, subscriptions, and active
   speakers;
5. off-hot-path recordings, audit logs, and long-term metrics.

Stage 1 keeps the sacred interfaces stable so later stages can swap storage,
mesh, and runtime details without touching hot-path contracts.

## Production invariants

The workspace follows these rules:

- `compio` is the async I/O runtime boundary; do not add competing runtimes.
- Hot-path code is thread-per-core and shared-nothing.
- `Arc<Mutex<_>>` is not allowed on media ingress-to-egress paths.
- Unsafe code is forbidden except in audited unsafe-boundary crates such as
  `refract-uring`, `refract-srtp`, and `refract-slab`.
- Every external parser needs bounded lengths, tests, fuzz targets, and seed
  corpus.
- New dependencies must be exact-pinned in `[workspace.dependencies]` and
  justified in the change record.

See `CONTRIBUTING.md`, `docs/production-gates.md`, and crate-local `SAFETY.md`
files for details.

## Documentation

- `docs/architecture.md` - state tiers and boundary model.
- `docs/production-gates.md` - current release and readiness gates.
- `docs/protocols/*.md` - versioned app protocol contracts.
- `crates/*/README.md` - crate-local status and verification notes.
- `deploy/refract.service` - example systemd service.

## License

Licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
