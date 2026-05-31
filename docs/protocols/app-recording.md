# refract-app-recording protocol

Cargo feature: `app-recording`.

Every command includes `protocol_version: 1`.

Commands:

```json
{ "protocol_version": 1, "type": "start" }
{ "protocol_version": 1, "type": "stop" }
{ "protocol_version": 1, "type": "status" }
{ "protocol_version": 1, "type": "list" }
```

Permissions:

- `operator`: may start, stop, status, and list.
- `viewer`: may status and list.

Future protocol versions are rejected with `APP_RECORDING_PROTOCOL_0001`.
