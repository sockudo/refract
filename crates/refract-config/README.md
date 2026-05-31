# refract-config

Strongly typed Stage 1 configuration and online reload support.

Configuration is loaded with `figment` using:

1. defaults,
2. TOML file values,
3. `REFRACT_` environment overrides using `__` for nesting.

`ConfigStore` keeps the active config in `ArcSwap`, so in-flight work keeps its
old snapshot while new work observes a validated hot-swap. Immutable startup
fields are preserved during reload and reported through `ReloadWarning`.
