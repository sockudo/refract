# refract-codec-h265 RFC notes

Implemented:
- RFC 7798 two-byte NAL header parsing.
- IDR NAL types 19, 20, and 21.
- VPS/SPS/PPS NAL types 32, 33, and 34.
- AP length validation.
- FU start-fragment classification.
- FMTP keys: `profile-id`, `tier-flag`, `level-id`, `sprop-vps`, `sprop-sps`, `sprop-pps`.

Known deviations / TODO:
- Parameter-set byte injection is deferred to packetization/subscriber bootstrap code.
