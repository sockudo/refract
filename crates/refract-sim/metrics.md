# refract-sim metrics

`refract-sim` emits no runtime metrics in Stage 1.

Simulation outcomes are returned as `Transcript` values instead of metric
events. When this crate starts emitting metrics, each metric must be documented
here with name, type, unit, and cardinality bound before release.
