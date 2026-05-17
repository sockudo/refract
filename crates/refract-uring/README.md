# refract-uring

`refract-uring` owns the unsafe Linux `io_uring` boundary and the portable UDP
fallback surface used by the media plane. It detects kernel capabilities at
runtime, selects the best receive tier, provides slab-backed packet receive
buffers, batches UDP sends, and exposes fixed-buffer registration helpers for
Linux rings.

## Kernel compatibility

| Kernel | Expected receive tier | Notes |
|---|---|---|
| `< 5.19` | `BatchedSingleShot` | Portable receive path; no provided-buffer ring. |
| `5.19.x` | `RecvMultishot` when opcode probe allows it | Provided-buffer ring can be detected separately. |
| `6.0+` | `MultishotProvidedBuffers` when probe and pbuf support are both present | Intended full Linux hot path. |
| non-Linux | `BatchedSingleShot` | Uses the portable socket layer with identical API shape. |
