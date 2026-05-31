# refract-app-textroom protocol

Cargo feature: `app-textroom`.

Commands:

```json
{ "protocol_version": 1, "type": "send", "text": "hello" }
{ "protocol_version": 1, "type": "history" }
{ "protocol_version": 1, "type": "delete", "message_id": 1 }
```

Permissions:

- `sender`: may send and read history.
- `moderator`: may send, read history, and delete.

Future protocol versions are rejected with `APP_TEXTROOM_PROTOCOL_0001`.
