# refract-jitter metrics

## `refract.jitter.publisher_buffer.inserts`

- Type: counter
- Unit: packets
- Labels:
  - `outcome`: one of `stored`, `refreshed_duplicate`, `evicted`
- Cardinality bound: 3 series

## `refract.jitter.nack.batches`

- Type: counter
- Unit: batches
- Labels: none
- Cardinality bound: 1 series

## `refract.jitter.nack.packets`

- Type: counter
- Unit: packets
- Labels: none
- Cardinality bound: 1 series

## `refract.jitter.nack.suppressed`

- Type: counter
- Unit: packets
- Labels:
  - `reason`: one of `dedupe_window`, `rate_limited`, `batch_full`
- Cardinality bound: 3 series

## `refract.jitter.feedback.requests`

- Type: counter
- Unit: requests
- Labels:
  - `kind`: one of `pli`, `fir`
  - `outcome`: one of `forwarded`, `coalesced`
- Cardinality bound: 4 series
