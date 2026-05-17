# refract-codec-h264 RFC notes

Implemented:
- RFC 6184 single NAL unit type classification.
- STAP-A, STAP-B, MTAP16, MTAP24 length validation.
- FU-A and FU-B start-fragment classification.
- IDR, SPS, and PPS detection.
- FMTP keys: `profile-level-id`, `packetization-mode`, `sprop-parameter-sets`.
- Per-publisher SPS/PPS presence cache.

Known deviations / TODO:
- Parameter-set cache records presence only; byte retention and injection buffers belong in the packetizer stage.
