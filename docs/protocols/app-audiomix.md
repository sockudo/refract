# Audiomix Application Protocol

The audiomix app uses bounded JSON control messages with a mandatory
`protocol_version` field. The current version is `1`; unsupported versions are
rejected with `APP_AUDIOMIX_PROTOCOL_0001`.

## Roles

JWT claims are mapped to `participant`, `mixer`, and `admin` permissions.

| Command | Required role |
| --- | --- |
| `join_mix` | `participant` or `admin` |
| `leave_mix` | joined session |
| `set_gain` | `mixer` or `admin` |
| `mute` | `mixer` or `admin` |
| `unmute` | `mixer` or `admin` |
| `audio_level` | self participant, or `mixer`/`admin` for another session |
| `status` | any connected session |

## Commands

```json
{"protocol_version":1,"type":"join_mix","mix_id":"main"}
{"protocol_version":1,"type":"leave_mix","mix_id":"main"}
{"protocol_version":1,"type":"set_gain","mix_id":"main","session_id":7,"gain_mb":-300}
{"protocol_version":1,"type":"mute","mix_id":"main","session_id":7}
{"protocol_version":1,"type":"unmute","mix_id":"main","session_id":7}
{"protocol_version":1,"type":"audio_level","mix_id":"main","session_id":7,"level":20}
{"protocol_version":1,"type":"status","mix_id":"main"}
```

`mix_id` is bounded by `MAX_MIX_ID_BYTES`, and `gain_mb` must be in
`MIN_GAIN_MB..=MAX_GAIN_MB`.

## Responses

Every response includes `protocol_version`, `status`, and `code`.

```json
{"protocol_version":1,"status":"active_speaker","code":"ok","active_speaker":7}
{"protocol_version":1,"status":"error","code":"APP_AUDIOMIX_PERMISSION_MIXER"}
```

Backwards compatibility is covered by protocol-version rejection tests.
