# refract-app-streaming

Broadcast and streaming application boundary for versioned slow-path stream
control.

The crate is gated by the `app-streaming` Cargo feature and implements bounded
JSON commands for publishing, watching, unwatching, ending, and listing streams.
It enforces broadcaster/viewer/admin claims before posting route changes.
