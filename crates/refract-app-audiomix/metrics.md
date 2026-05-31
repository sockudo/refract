# refract-app-audiomix metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_app_audiomix_command_total` | counter | commands | `type` <= 7, `result` <= 2 | Audiomix commands accepted or rejected by the app slow path. |
| `refract_app_audiomix_active_mixes` | gauge | mixes | per-process | Mixes currently tracked by the audiomix app. |
| `refract_app_audiomix_permission_denied_total` | counter | denials | `permission` <= 3 | Permission denials for participant/mixer/admin actions. |
