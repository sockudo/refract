# refract-app

Application trait boundary for room policy and subscription decisions.

Stage 1 defines:

- `Application` and `Session` traits using RPITIT, with no `async-trait`.
- `AppRegistry` keyed by bounded app names.
- Type-erased `SessionRunner` over `Box<dyn ErasedSession>` for slow-path dispatch.
- `SessionHandle` with bounded `rtrb` client and `SFU` core command rings.
- Slow-path latency measurement with a 5 ms p99 target and 50 ms warning threshold.
