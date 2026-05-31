# Safety policy

`refract-srtp` intentionally keeps `#![forbid(unsafe_code)]` enabled.

The crate is allowed by the workspace invariant to opt out only if a future
optimization truly requires it. This implementation does not opt out: AES-GCM
is delegated to aws-lc-rs, nonce/AAD/replay logic is safe Rust, and the optional
`simd` feature currently routes through the scalar implementation until stable
portable SIMD is available on the pinned toolchain.

Current unsafe boundary:

- Direct unsafe in `refract-srtp`: none.
- Cryptographic primitive unsafe is inside audited upstream `aws-lc-rs`.
- Buffer aliasing unsafe is not used here; packet mutation is via safe slices.

Before introducing unsafe code:

- keep scalar safe fallbacks for every optimized path;
- gate SIMD behind the `simd` feature and runtime CPU detection;
- add an inline `SAFETY:` comment to every unsafe block;
- prove constant-time behavior where key material is involved;
- update this file with the new invariant and review evidence.
