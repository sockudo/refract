# refract-app-echo protocol

Cargo feature: `app-echo`.

```json
{ "protocol_version": 1, "type": "echo", "payload": "hello" }
```

Permission: sessions require echo-enabled claims. Future protocol versions are
rejected with `APP_ECHO_PROTOCOL_0001`.
