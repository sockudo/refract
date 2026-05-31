# str0m Fork Decision

`refract-rtc` does not carry a str0m fork at this stage.

The crate uses upstream `str0m = 0.19.0` with `default-features = false` and
`features = ["aws-lc-rs"]`. The dependency is pinned by exact version in
`crates/refract-rtc/Cargo.toml` and by crates.io checksum
`431befc786d98bfa860118d96890df038e4db51635494203bbe600b05582f920` in
`Cargo.lock`.

The SRTP override is implemented by enabling str0m RTP mode and routing refract
media packets through `refract-srtp`. str0m remains responsible for the sans-IO
WebRTC control state machine: `Input::Receive`, output draining, ICE state
changes, RTCP feedback, and transmit scheduling.

Fork trigger: if upstream str0m no longer exposes the RTP-mode boundary required
to keep SRTP in `refract-srtp`, introduce a patched fork pinned by exact git
revision and update this file with the upstream base revision, fork revision,
patch summary, and review owner.
