# refract-app-audiomix

Audio mixing application boundary kept outside the forwarding hot path.

The crate is gated by the `app-audiomix` Cargo feature and implements bounded
JSON commands for mix membership, gain control, mute/unmute, audio-level
updates, and status. It enforces participant/mixer/admin claims before mutating
mix state.
