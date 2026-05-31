# refract-sim

Deterministic simulation framework for Stage 1.

`refract-sim` provides:

- a seeded SplitMix64 PRNG for reproducible scenarios
- a virtual monotonic clock compatible with `refract_core::Clock`
- a bounded virtual UDP network with latency, jitter, loss, reorder delay, and partitions
- a `Simulation` builder for nodes, directed link conditions, and scripted events
- a `SimTransport` implementation of `refract_net::transport::Transport`
- bit-comparable transcripts for seed repro

The crate is intentionally single-threaded. It uses no hot-path locks and no
unsafe code.
