# refract-bin

Executable package for the refract SFU process.

`refract-bin` composes Stage 1 crates into the single daemon binary:

- `clap` CLI with `--config` and `--check`.
- `refract-config` loading and hot reload on `SIGUSR1`.
- `refract-obs` tracing and metrics initialization.
- `refract-resilience` panic hook, OOM handler, watchdog, and drain signal.
- Thread-per-core `SfuCore` workers plus separate signaling and admin threads.
- `SIGTERM` graceful drain and `SIGUSR2` stack dump.
- systemd `Type=notify` readiness when `NOTIFY_SOCKET` is present.
