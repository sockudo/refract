# refract-config metrics

No metrics are emitted directly by `refract-config` in Stage 1.

Reload callers are expected to increment the owning admin/runtime crate metrics
from `ConfigStore::reload` and `ConfigWatcher` results. This keeps
configuration parsing independent from the metrics recorder lifecycle.
