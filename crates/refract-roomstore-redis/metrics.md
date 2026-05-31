# refract-roomstore-redis metrics

Redis implementation metrics must follow the shared `refract-roomstore`
cardinality contract.

| Name | Type | Unit | Cardinality bound |
| --- | --- | --- | --- |
| `roomstore_operation_duration_seconds` | Histogram | Seconds | `operation` has 9 fixed values, `backend="redis"` |
| `roomstore_operation_errors_total` | Counter | Errors | `operation` has 9 fixed values, `error_code` is bounded by roomstore error variants |
| `roomstore_participants_page_size` | Histogram | Participants | `backend="redis"` |
| `roomstore_redis_health` | Gauge | State enum (`0=degraded`, `1=healthy`, `2=refusing_writes`) | `backend="redis"` |
| `roomstore_redis_memory_used_percent` | Gauge | Percent | `backend="redis"` |
| `roomstore_redis_keepalive_failures_total` | Counter | Failures | `backend="redis"` |
| `roomstore_redis_sentinel_reconnects_total` | Counter | Reconnects | `backend="redis"` |
| `roomstore_redis_lua_errors_total` | Counter | Errors | `script` has 6 fixed values, `error_code` is bounded by roomstore error variants |
| `roomstore_event_stream_open_total` | Counter | Streams | `backend="redis"` |
| `roomstore_event_stream_errors_total` | Counter | Errors | `backend="redis"`, `error_code` is bounded by roomstore error variants |

Room identifiers, peer identifiers, track identifiers, subscription identifiers,
Redis endpoint addresses, and Redis error messages must not be metric labels.
