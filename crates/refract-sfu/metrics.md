# refract-sfu metrics

`refract-sfu` keeps per-core hot-path counters in lock-free atomics so an
aggregator core can snapshot them without taking locks. These counters are the
source values for the process metrics exporter.

| Name | Type | Unit | Cardinality bound |
| --- | --- | --- | --- |
| `refract_sfu_ingress_packets_total` | counter | packets | one time series per core |
| `refract_sfu_forwarded_packets_total` | counter | packets | one time series per core |
| `refract_sfu_stun_packets_total` | counter | packets | one time series per core |
| `refract_sfu_dtls_packets_total` | counter | packets | one time series per core |
| `refract_sfu_dropped_packets_total` | counter | packets | one time series per core |
| `refract_sfu_isolated_peer_panics_total` | counter | panics | one time series per core |

No peer IDs, socket addresses, SSRCs, room IDs, or subscription IDs are metric
labels. Hot-path code updates these counters only; it never logs.
