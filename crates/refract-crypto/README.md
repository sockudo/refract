# refract-crypto

DTLS policy, certificate identity, and DTLS-SRTP exporter boundary for the
refract SFU.

## Stage 1 guarantees

- `#![forbid(unsafe_code)]`.
- rustls configured with the aws-lc-rs provider.
- TLS 1.3 primitives only; TLS/DTLS 1.2 inputs are rejected with
  `HSF-CRY-001`.
- Session resumption and 0-RTT disabled.
- X25519 is the only configured ECDHE group.
- Self-signed ECDSA P-256 identity is generated at startup and persisted.
- SDP SHA-256 fingerprint is stable across restarts.
- DTLS-SRTP profiles are restricted to `SRTP_AEAD_AES_128_GCM` and
  `SRTP_AEAD_AES_256_GCM`.

## Interop transcripts

Manual browser interop is tracked here until automated browser harnesses land.

| Browser family | Version | SHA-256 transcript | Status |
| --- | --- | --- | --- |
| Chrome stable | pending | pending | not run in this change |
| Firefox stable | pending | pending | not run in this change |
| Safari latest | pending | pending | not run in this change |

The ignored `pion_dtls_client_interop` test documents the command contract for
running an external Pion DTLS client in environments that provide one.
