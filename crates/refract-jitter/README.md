# refract-jitter

Bounded jitter, RTP loss detection, and feedback coalescing for the refract media plane.

This crate provides:

- A preallocated per-publisher RTP ring used for RTX lookup.
- Wrap-aware ingress sequence loss detection.
- Per subscriber/publisher `NACK` dedupe with a 20 ms default window.
- Bounded `NACK` history of 256 entries and rate-limited upstream batches.
- Independent `PLI` and `FIR` coalescing with a 200 ms default window.

All state is `unsafe`-free and uses caller-provided monotonic timestamps so rate
limits remain deterministic under test and production replay.
