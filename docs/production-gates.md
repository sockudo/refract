# Production gates

Current scaffold contributions:

- Workspace compiles with `#![forbid(unsafe_code)]` at crate roots.
- Future unsafe crates have explicit `SAFETY.md` review contracts.
- Stage 1 sacred interfaces are defined before implementation crates depend on
  backend choices.
- Public core APIs carry stable error codes, typed IDs, and rustdoc examples.
- The workspace has no runtime dependencies yet, keeping the first boundary
  review focused on API shape.

Gates still open:

- compio runtime integration.
- protocol parsers and fuzz targets.
- hot-path allocation tracker.
- criterion benchmarks.
- Raft, Redis, signaling, and SFU engine implementations.

