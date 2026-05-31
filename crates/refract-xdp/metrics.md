# refract-xdp metrics

All counters are read from the `REFRACT_XDP_STATS` per-CPU array and summed in
user space. Cardinality is fixed: one series per attached interface and counter.

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_xdp_packets_passed_total` | counter | packets | interfaces * 1 | Packets explicitly accepted by the XDP policy. |
| `refract_xdp_udp_unsupported_dropped_total` | counter | packets | interfaces * 1 | Target-port UDP packets dropped because payload was not STUN, DTLS, or SRTP/SRTCP. |
| `refract_xdp_fragments_dropped_total` | counter | packets | interfaces * 1 | Fragmented UDP packets dropped before socket delivery. |
| `refract_xdp_stun_rate_limited_total` | counter | packets | interfaces * 1 | STUN binding requests dropped by the per-source token bucket. |
| `refract_xdp_stun_binding_accepted_total` | counter | packets | interfaces * 1 | STUN binding requests accepted by the token bucket. |
| `refract_xdp_stun_other_accepted_total` | counter | packets | interfaces * 1 | Non-binding STUN packets accepted. |
| `refract_xdp_dtls_accepted_total` | counter | packets | interfaces * 1 | DTLS packets accepted. |
| `refract_xdp_srtp_accepted_total` | counter | packets | interfaces * 1 | SRTP/SRTCP packets accepted. |
