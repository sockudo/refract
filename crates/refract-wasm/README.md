# refract-wasm

`refract-wasm` hosts Stage 1 extension hooks as Wasmtime component-model
components. Extension authors target `wit/refract-extension.wit` and export:

- `on-auth(peer-id, token-hash) -> bool`
- `on-room-create(peer-id, room-id) -> bool`
- `on-subscribe(peer-id, room-id, track-id, spatial-layer, temporal-layer) -> bool`

The runtime is fail-closed. Any compile, instantiate, hook type, timeout, fuel,
or memory failure returns a deny outcome.

## Sandbox

Each hook call uses a fresh Wasmtime store with:

- fuel enabled and reset per call
- 16 MiB linear-memory ceiling by default
- no filesystem, network, environment, clock, or random imports
- an epoch watchdog that interrupts calls after 50 ms by default

The linker intentionally exposes no WASI imports. Components that require
ambient capabilities fail to instantiate.

## Hot Reload

The active compiled component is held behind `ArcSwap`. Reload compiles a new
component and atomically swaps it in as the next generation. In-flight calls hold
an `Arc` to their original generation, so reload does not invalidate active
stores or functions.

## Sample Guest Shape

Guest extensions should use `wit-bindgen` against `wit/refract-extension.wit`:

```rust
wit_bindgen::generate!({
    world: "refract-extension",
    path: "wit",
});
```

The crate tests include a WAT component equivalent to that exported shape so CI
does not depend on a locally installed `wasm32-wasip2` target.
