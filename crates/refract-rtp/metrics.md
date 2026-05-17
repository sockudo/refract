# refract-rtp metrics

## `refract.rtp.parse.errors`

- Type: counter
- Unit: errors
- Labels:
  - `error_code`: bounded by `RtpError::error_code()`
  - `kind`: one of `rtp_parse`, `rtp_extension`, `rtp_rewrite`, `rtcp_parse`
- Cardinality bound: 18 series at current Stage 1 error taxonomy

## `refract.rtp.parse.packets`

- Type: counter
- Unit: packets
- Labels: none
- Cardinality bound: 1 series

## `refract.rtp.parse.bytes`

- Type: counter
- Unit: bytes
- Labels: none
- Cardinality bound: 1 series

## `refract.rtp.rewrite.packets`

- Type: counter
- Unit: packets
- Labels: none
- Cardinality bound: 1 series
