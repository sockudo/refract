# Streaming Application Protocol

The streaming app uses bounded JSON control messages with a mandatory
`protocol_version` field. The current version is `1`; unsupported versions are
rejected with `APP_STREAMING_PROTOCOL_0001`.

## Roles

JWT claims are mapped to `broadcaster`, `viewer`, and `admin` permissions.

| Command | Required role |
| --- | --- |
| `publish` | `broadcaster` or `admin` |
| `watch` | `viewer` or `admin` |
| `unwatch` | existing route owner |
| `end` | `broadcaster` or `admin` |
| `list` | `viewer` or `admin` |

## Commands

```json
{"protocol_version":1,"type":"publish","stream_id":"main","track_id":77,"ssrc":1234,"max_layer":2}
{"protocol_version":1,"type":"watch","stream_id":"main"}
{"protocol_version":1,"type":"unwatch","stream_id":"main"}
{"protocol_version":1,"type":"end","stream_id":"main"}
{"protocol_version":1,"type":"list"}
```

`stream_id` is bounded by `MAX_STREAM_ID_BYTES`, and `max_layer` is capped at
`MAX_STREAMING_LAYER` before route creation.

## Responses

Every response includes `protocol_version`, `status`, and `code`.

```json
{"protocol_version":1,"status":"published","code":"ok"}
{"protocol_version":1,"status":"error","code":"APP_STREAMING_PERMISSION_VIEW"}
```

Backwards compatibility is covered by protocol-version rejection tests.
