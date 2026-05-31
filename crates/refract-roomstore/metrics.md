# refract-roomstore metrics

The trait crate does not emit runtime metrics directly. Implementations must use
the metric contract below so dashboards remain backend-swappable.

| Name | Type | Unit | Cardinality bound |
| --- | --- | --- | --- |
| `roomstore_operation_duration_seconds` | Histogram | Seconds | `operation` has 9 fixed values, `backend` is fixed per implementation |
| `roomstore_operation_errors_total` | Counter | Errors | `operation` has 9 fixed values, `error_code` is bounded by `RoomStoreError` variants |
| `roomstore_participants_page_size` | Histogram | Participants | `backend` is fixed per implementation |
| `roomstore_event_stream_open_total` | Counter | Streams | `backend` is fixed per implementation |
| `roomstore_event_stream_errors_total` | Counter | Errors | `backend` is fixed per implementation, `error_code` is bounded by `RoomStoreError` variants |

Room identifiers, peer identifiers, track identifiers, subscription identifiers,
JWT claims, IP addresses, and user-provided metadata must not be metric labels.
