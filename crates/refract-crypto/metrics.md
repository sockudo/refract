# refract-crypto metrics

## `refract.crypto.errors`

- Type: counter
- Unit: errors
- Labels:
  - `error_code`: bounded by `CryptoError::error_code()`
- Cardinality bound: 13 series at current Stage 1 error taxonomy
