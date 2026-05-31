# refract-wasm metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_wasm_hook_calls_total` | Counter | calls | `hook` has 3 fixed values, `decision` has 2 fixed values | Hook calls by policy result. |
| `refract_wasm_fail_closed_total` | Counter | calls | `hook` has 3 fixed values, `error_code` has bounded `HSF-WASM-*` values | Hook calls denied because sandboxing, loading, or execution failed. |
| `refract_wasm_reload_total` | Counter | reloads | `result` has 2 fixed values | Hot-reload attempts by result. |
| `refract_wasm_hook_duration_seconds` | Histogram | seconds | `hook` has 3 fixed values | Hook execution latency, excluding component compilation. |
