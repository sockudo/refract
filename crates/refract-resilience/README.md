# refract-resilience

Panic isolation, watchdog, memory-pressure, resource-limit, and backpressure
support.

Stage 1 exposes safe primitives for:

- per-peer panic isolation with structured logging and panic metrics,
- OOM and cgroup `memory.high` pressure handling that requests graceful drain,
- core heartbeat watchdog checks that request fast drain on stalled progress,
- in-process resource admission checks for file descriptors, threads, and memory,
- global backpressure propagation toward signaling/load shedding.

The crate is `#![forbid(unsafe_code)]`. Allocator integration is therefore a
safe signal boundary (`OomHandler::allocation_failed`) that an audited allocator
wrapper can call from a crate allowed to implement allocator internals.
