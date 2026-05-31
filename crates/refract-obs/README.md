# refract-obs

Metrics, tracing, profiling, and diagnostics support for Stage 1.

`refract-obs` provides:

- a `metrics` recorder with per-core thread-local updates,
- Prometheus text rendering for pull scraping,
- an OTLP push boundary that delegates transport to the compio runtime owner,
- structured tracing subscriber construction with `RUST_LOG`,
- deterministic high-frequency sampling,
- slow-path event classification for operations over 50 ms,
- `/healthz`, `/readyz`, `/metrics`, and gated `/debug/pprof/{cpu,heap,allocs}` endpoint semantics.

The crate does not open sockets or spawn tasks. Runtime and admin crates mount
the handlers on compio so the workspace keeps a single async runtime.
