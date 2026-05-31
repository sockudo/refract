# refract-app-streaming metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_app_streaming_command_total` | counter | commands | `type` <= 5, `result` <= 2 | Streaming commands accepted or rejected by the app slow path. |
| `refract_app_streaming_active_streams` | gauge | streams | per-process | Streams currently published through the streaming app. |
| `refract_app_streaming_permission_denied_total` | counter | denials | `permission` <= 3 | Permission denials for broadcaster/viewer/admin actions. |
