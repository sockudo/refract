# Contributing

`refract` is built under strict production invariants from the first commit.

## Invariants

- `compio` is the runtime for async I/O; do not add `tokio`, `async-std`, `smol`, `glommio`, or `monoio`.
- Hot-path code is thread-per-core and shared-nothing; no `Arc<Mutex<_>>` on media ingress-to-egress paths.
- Unsafe code is forbidden except in `refract-uring`, `refract-srtp`, and `refract-slab`, where every unsafe block needs an inline `SAFETY:` comment and crate `SAFETY.md` coverage.
- Every external input parser needs bounded lengths, unit tests, fuzz targets, and seed corpus.
- Every new dependency must be exact-pinned in `[workspace.dependencies]` and justified in the pull request.

## Bump Policy

Dependency bumps are intentional changes. Use exact versions (`=x.y.z`), run `cargo xtask audit`, run `cargo xtask deny`, and record why the bump is needed in the commit body.

## Pull Request Checklist

- [ ] `cargo xtask fmt`
- [ ] `cargo xtask lint`
- [ ] `cargo xtask test`
- [ ] `cargo xtask audit`
- [ ] `cargo xtask deny`
- [ ] Production gate impact is documented.

## Commit Format

Commits follow the Lore protocol: the first line states why the change was made, followed by context and git-native trailers such as `Constraint:`, `Rejected:`, `Confidence:`, `Scope-risk:`, `Directive:`, `Tested:`, and `Not-tested:`.

