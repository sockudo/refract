# xtask

The `xtask` package owns repository automation for formatting, linting, testing,
auditing, coverage, fuzzing, release builds, load-generation gates, and local
hook installation. It is intentionally small and shells out to the same tools
used by CI so local and remote gates stay aligned.

## Signaling Loadgen

Run the Stage 1 signaling open/signal/close gate:

```sh
cargo xtask signal-loadgen
```

The default target is 100,000 signaling lifecycles. Use
`--connections <n>` and `--messages-per-connection <n>` for smaller local
checks or deeper stress runs.
