# refract-app metrics

`refract-app` emits metrics outside the media hot path only.

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract.app.slow_path.latency.seconds` | histogram | seconds | `operation` in `{handle_message,negotiation,publish,subscribe,unsubscribe,disconnect}` | Wall-clock latency for one application session operation. |

Operations slower than 50 ms also emit one structured warning with message
`slow-path`, `operation`, `elapsed_micros`, and `warn_threshold_micros`.
