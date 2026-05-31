# refract-app-room protocol

Every client command is a JSON object with a required `protocol_version` field.
The current version is `2`; version `1` remains accepted for backwards
compatibility.

Common response shape:

```json
{
  "protocol_version": 2,
  "kind": "response",
  "status": "ok",
  "message": "created"
}
```

Error response shape:

```json
{
  "protocol_version": 2,
  "kind": "response",
  "status": "error",
  "code": "APP_ROOM_PERMISSION_ADMIN"
}
```

Commands:

```json
{ "protocol_version": 2, "type": "create" }
{ "protocol_version": 2, "type": "destroy" }
{ "protocol_version": 2, "type": "list" }
{ "protocol_version": 2, "type": "kick", "session_id": 42 }
{ "protocol_version": 2, "type": "ban", "peer_id": 42 }
{ "protocol_version": 2, "type": "mute", "session_id": 42 }
{ "protocol_version": 2, "type": "unmute", "session_id": 42 }
{ "protocol_version": 2, "type": "publish", "track_id": 7, "ssrc": 1234, "max_layer": 2 }
{ "protocol_version": 2, "type": "subscribe", "track_id": 7 }
{ "protocol_version": 2, "type": "unsubscribe", "track_id": 7 }
{ "protocol_version": 2, "type": "audio_level", "track_id": 7, "level": 12 }
{ "protocol_version": 2, "type": "start_recording" }
```

Version 1 compatibility:

- Uses the same `type` discriminator.
- `publish.max_layer` is optional and defaults to the configured room cap.
- Future protocol versions are rejected with `APP_ROOM_PROTOCOL_0001`.

Permission mapping:

- `publisher`: may publish and report audio level for its own tracks.
- `subscriber`: may subscribe and receive auto-subscribe routes.
- `admin`: may create, destroy, list, kick, ban, mute others, unmute others,
  publish, subscribe, and trigger recording.
