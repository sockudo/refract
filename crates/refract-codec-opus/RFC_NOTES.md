# refract-codec-opus RFC notes

Implemented:
- RFC 7587 RTP payload TOC byte parsing.
- RFC 7587 frame packing codes 0, 1, 2, and 3 length sanity checks.
- RFC 6464 one-byte audio-level extension parsing.
- FMTP keys: `maxplaybackrate`, `stereo`, `useinbandfec`, `usedtx`, `cbr`.
- Keyframe classification: always true for accepted Opus payloads.

Known deviations / TODO:
- Code 3 self-delimiting frame byte accounting is conservative and does not expose per-frame slices yet.
- DTX detection is a bounded heuristic based on compact config-0 payloads.
