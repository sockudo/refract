# SIP Application Protocol

The SIP app uses bounded JSON control messages with a mandatory
`protocol_version` field. The current version is `1`; unsupported versions are
rejected with `APP_SIP_PROTOCOL_0001`.

## Roles

JWT claims are mapped to `bridge` and `admin` permissions.

| Command | Required role |
| --- | --- |
| `invite` | `bridge` or `admin` |
| `bye` | `bridge` or `admin` |
| `dtmf` | `bridge` or `admin` |
| `list` | `admin` |

## Commands

```json
{"protocol_version":1,"type":"invite","uri":"sip:room@example.test"}
{"protocol_version":1,"type":"bye","call_id":0}
{"protocol_version":1,"type":"dtmf","call_id":0,"digits":"123#"}
{"protocol_version":1,"type":"list"}
```

Inputs are bounded by `MAX_SIP_COMMAND_BYTES`, `MAX_SIP_URI_BYTES`, and
`MAX_DTMF_DIGITS`.

## Responses

Every response includes `protocol_version`, `status`, and `code`.

```json
{"protocol_version":1,"status":"invited","code":"ok","call_id":0}
{"protocol_version":1,"status":"error","code":"APP_SIP_PERMISSION_BRIDGE"}
```

Backwards compatibility is covered by protocol-version rejection tests.
