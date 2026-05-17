# refract-srtp metrics

## `refract.srtp.replay_rejected`

- Type: counter
- Unit: packets
- Labels: none
- Cardinality bound: 1 series
- Notes: incremented with bounded per-peer logging budget to avoid replay-log
  amplification under adversarial reorder/duplicate traffic.
