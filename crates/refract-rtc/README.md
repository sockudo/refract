# refract-rtc

`refract-rtc` adapts str0m's sans-IO WebRTC state machine to the refract
media plane.

## str0m SRTP Boundary

This crate pins upstream `str0m = 0.19.0` exactly in `Cargo.toml`; the lockfile
checksum for that crate is
`431befc786d98bfa860118d96890df038e4db51635494203bbe600b05582f920`.

No patched fork is currently used. The adapter enables str0m RTP mode so str0m
drives ICE, DTLS, SDP-adjacent state, RTCP feedback, and transmit scheduling
without owning the media SRTP boundary. Media packets entering the refract path
are unprotected and protected by `refract-srtp` through `RtcSession::install_srtp`
and `RtcSession::handle_refract_rtp`.

If a later str0m upgrade removes the exposed RTP boundary needed here, the
replacement must be a patched fork pinned by an exact git revision and this file
must record the upstream base revision, patch revision, and reason for the fork.
