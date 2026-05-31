# refract-obs metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract.obs.health.requests` | counter | count | `endpoint` label, max 3 values (`healthz`, `readyz`, `metrics`) | Health, readiness, and metrics endpoint requests handled by `refract-obs`. |
| `refract.obs.profiling.requests` | counter | count | no labels | Authorized profiling endpoint requests. |
| `refract.obs.slow_path.duration` | histogram | milliseconds | no labels in this crate | Slow-path operation durations used by the slow-query log gate. |

The recorder accepts at most `RecorderConfig::max_metrics` series and at most
`RecorderConfig::max_labels_per_metric` labels per series. Registration over
those bounds returns a no-op metrics handle rather than expanding attacker-driven
cardinality.
