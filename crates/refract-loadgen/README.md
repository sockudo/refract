# refract-loadgen

Production load generation harness for release gates.

## Stage 1 signaling gate

`refract-loadgen` implements the Stage 1 signaling open/signal/close gate used
by Prompt 5.1:

```sh
cargo xtask signal-loadgen
```

The default scenario targets 100,000 concurrent signaling WebSocket lifecycles.
It admits all connections through `ConnectionLedger`, runs each connection
through handshake tracking, JSON signaling parse, rate limiting, send-queue
accounting, idle tracking, and closes every permit.

This is an in-process safety-envelope load gate. It validates the current
`refract-signal` lifecycle primitives and connection ceiling. Transport-level
HTTP/3 and HTTP/1.1 WebSocket socket load should be added when the concrete
listener adapter lands.

Useful overrides:

```sh
cargo xtask signal-loadgen --connections 10000
cargo xtask signal-loadgen --connections 100000 --messages-per-connection 1
```
