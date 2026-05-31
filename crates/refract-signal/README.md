# refract-signal

Stateless signaling safety boundary for HTTP/3 WebSocket-over-HTTP/3 and fallback HTTP/1.1 WebSocket listeners.

This crate owns connection-local production gates only: bounded handshakes, idle deadlines, versioned JSON parsing, JWT authentication, governor-backed rate limiting, connection ceilings, and send-queue backpressure. Application and room state remains outside this crate in the Stage 1 `Application`, future `RoomStore`, and Raft boundaries.
