# refract-resilience metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract.resilience.peer.panics` | counter | count | `operation`, bounded by static caller labels; `error_code` fixed to `HSF-PANIC-PEER` | Peer-local panics isolated by `PanicGuard`. |
| `refract.resilience.drain.triggered` | counter | count | `mode` max 2, `reason` max 3, `error_code` bounded by resilience triggers | Drain requests raised by OOM, watchdog, or backpressure. |
| `refract.resilience.oom.graceful_drains` | counter | count | `error_code` fixed to `HSF-OOM-001` | Cgroup memory pressure or allocation failure triggered graceful drain. |
| `refract.resilience.watchdog.stalls` | counter | count | `error_code` fixed to `HSF-WD-001` | Core heartbeat watchdog detected stalled progress. |
| `refract.resilience.resource.rejected` | counter | count | `resource` max 3, `error_code` fixed to `HSF-RESOURCE-001` | In-process resource limit rejected an operation. |
| `refract.resilience.backpressure.raised` | counter | count | `component` bounded by static component names, `error_code` fixed to `HSF-BP-001` | Saturated component raised load shedding signal. |
