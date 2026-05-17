# refract-net metrics

`refract-net` currently exposes protocol decisions through typed return values.
The concrete transport backends emit their own I/O counters in `refract-uring`.
When STUN/ICE runtime handlers are wired into the SFU receive loop, this crate
will add bounded counters for STUN parse errors, rate-limit drops, consent
checks, and source-validation mismatches.
