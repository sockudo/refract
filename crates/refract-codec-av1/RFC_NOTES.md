# refract-codec-av1 RFC notes

Implemented:
- RFC 9420 aggregation header bits `Z`, `Y`, `W`, `N`.
- OBU header parsing and LEB128 size validation.
- Sequence-header keyframe candidate detection.
- Compact Dependency Descriptor template ID, spatial ID, temporal ID, start flag, and active decode-target mask parsing.
- Per-publisher template store primitive.
- `DdWriter` regeneration for forwarded layer subsets.

Known deviations / TODO:
- Dependency Descriptor parsing uses a compact internal representation pending full bit-exact DD grammar expansion.
- Frame dependency chains are represented by the active decode-target mask only in this pass.
