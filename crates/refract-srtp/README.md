# refract-srtp

SRTP/SRTCP AES-GCM protection for refract media packets.

## Stage 1 guarantees

- `#![forbid(unsafe_code)]`.
- AES-GCM is provided by aws-lc-rs.
- RTP protection keeps RTP headers authenticated but clear and encrypts payload.
- RTCP protection keeps the common header and SSRC authenticated but clear,
  appends the encrypted SRTCP index, and encrypts the RTCP body.
- Rollover counters and replay windows are tracked per SSRC.
- Authentication failure tears down the ingress peer context.
- Replay rejection increments a bounded metric counter.
- Fanout protection keeps plaintext behind `ArcSlot` and encrypts once per
  subscriber context.
- `simd` feature is reserved for stable portable-SIMD AAD/nonce helper paths;
  it currently uses the scalar implementation so `--all-features` remains
  compatible with the pinned stable toolchain.

## Performance gates

The benchmark targets from the Stage 1 prompt are represented in
`benches/srtp.rs`, but this change does not claim the throughput gates without
running on a pinned AVX2/PMULL host with perf counters enabled.
