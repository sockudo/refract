# refract-app-room metrics

`refract-app-room` currently records behavior through `refract-app` slow-path
operation metrics. Room-specific counters are intentionally deferred until the
metrics exporter can preserve bounded room cardinality without exposing dynamic
room identifiers.
