# refract-bin metrics

This crate installs the workspace `refract-obs` recorder and delegates emitted
runtime metrics to composed crates.

| Name | Type | Unit | Cardinality bound | Owner |
| --- | --- | --- | --- | --- |
| `refract.resilience.drain.triggered` | counter | events | `mode <= 2`, `reason <= 8`, `error_code <= 8` | `refract-resilience` |
| `refract.resilience.watchdog.stalls` | counter | events | `error_code <= 1` | `refract-resilience` |
| `refract.obs.health.requests` | counter | events | no labels | `refract-obs` |

`refract-bin` does not emit hot-path metrics directly. Worker hot-loop metrics
remain owned by the media crates so cardinality and allocation gates can be
verified at the hot-path boundary.
