# refract-rtp

RTP and RTCP parsing, validation, and header rewrite boundary.

This crate provides:

- borrowed defensive RTP header views
- RFC 8285 one-byte and two-byte extension iteration
- allocation-free fixed-header rewrite helpers
- rolling sequence and timestamp remappers
- bounded RTCP compound parsing and generation
- RTP padding strip/add helpers for the pacer

The crate root forbids unsafe code. Hot-path parsing and rewriting operate on
borrowed slices and caller-owned mutable slices.
