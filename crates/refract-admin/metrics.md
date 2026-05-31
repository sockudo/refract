# refract-admin metrics

No metrics are emitted directly by `refract-admin` in Stage 1.

The runtime/admin socket owner should record request counters, auth failures,
drain duration, and profile start counters through `refract-obs` once the API is
mounted. Keeping this crate metric-free avoids coupling request routing to a
global recorder during startup and tests.
