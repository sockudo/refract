# refract-app-sip metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_app_sip_command_total` | counter | commands | `type` <= 4, `result` <= 2 | SIP commands accepted or rejected by the app slow path. |
| `refract_app_sip_active_calls` | gauge | calls | per-process | Calls tracked by the SIP bridge app. |
| `refract_app_sip_permission_denied_total` | counter | denials | `permission` <= 2 | Permission denials for bridge/admin actions. |
