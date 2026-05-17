# refract-codec-vp8 RFC notes

Implemented:
- RFC 7741 payload descriptor base byte.
- Extended control bits: `I`, `L`, `T`, `K`.
- PictureID parsing for 7-bit and 15-bit encodings.
- `TL0PICIDX`, `TID`, layer-sync, and `KEYIDX` parsing.
- Keyframe classification: `P == 0` and start of partition 0.
- Temporal-layer extraction and `Vp8Rewriter` PictureID continuity helper.

Known deviations / TODO:
- Rewriter currently provides continuity state; byte-level descriptor rewrite is not yet exposed.
