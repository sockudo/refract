# refract-signal metrics

All hot-path media forwarding remains outside this crate. These metrics are signaling slow-path metrics and must be emitted by the listener adapter that owns the concrete sockets.

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_signal_connections_active` | gauge | connections | `listener` <= configured listeners, `transport` in `{http3_h3_quinn,http11_websocket}` | Active accepted signaling connections. |
| `refract_signal_connections_rejected_total` | counter | connections | `reason` in `{ceiling,auth,rate,protocol,slow_loris,idle,backpressure}` | Connections rejected or closed by a safety gate. |
| `refract_signal_handshake_duration_seconds` | histogram | seconds | `transport` in `{http3_h3_quinn,http11_websocket}` | Completed handshake duration. |
| `refract_signal_messages_in_total` | counter | messages | `app` <= registered applications, `type` in `{join,leave,app,ping}` | Accepted inbound signaling messages after auth and rate limiting. |
| `refract_signal_parse_errors_total` | counter | messages | `error_code` bounded by `SignalError::error_code()` | Defensive parser failures. |
| `refract_signal_send_queue_bytes` | gauge | bytes | `listener` <= configured listeners | Per-connection queued outbound bytes sampled by owner worker. |
| `refract_signal_backpressure_disconnects_total` | counter | connections | `error_code` fixed to `HSF-BP-001` | Disconnects caused by send queue overflow. |
