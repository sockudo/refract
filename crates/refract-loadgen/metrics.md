# refract-loadgen metrics

The load generator emits summary reports today. These metric names are reserved
for wiring the same counters into the production metrics sink.

| Name | Type | Unit | Cardinality bound |
| --- | --- | --- | --- |
| `refract_loadgen_signal_target_connections` | Gauge | Connections | `scenario="signal_open_signal_close"` |
| `refract_loadgen_signal_opened_connections` | Counter | Connections | `scenario="signal_open_signal_close"` |
| `refract_loadgen_signal_closed_connections` | Counter | Connections | `scenario="signal_open_signal_close"` |
| `refract_loadgen_signal_rejected_connections` | Counter | Connections | `scenario="signal_open_signal_close"` |
| `refract_loadgen_signal_messages_total` | Counter | Messages | `scenario="signal_open_signal_close"` |
| `refract_loadgen_signal_elapsed_seconds` | Gauge | Seconds | `scenario="signal_open_signal_close"` |

Connection ids, room ids, peer ids, JWT claims, endpoint addresses, and error
messages must not be metric labels.
