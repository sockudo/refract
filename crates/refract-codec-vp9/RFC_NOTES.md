# refract-codec-vp9 RFC notes

Implemented:
- VP9 descriptor bits: `I`, `P`, `L`, `F`, `B`, `E`, `V`.
- PictureID parsing, `TL0PICIDX`, `TID`, `U`, `SID`, and `D`.
- Flexible-mode reference byte walking.
- Scalability-structure length validation for resolution and group records.
- Keyframe classification: `P == 0` and beginning of frame.
- Spatial/temporal layer extraction and transparent layer-drop helper.

Known deviations / TODO:
- K-SVC mode switching is represented through parsed layer metadata; full stream-state policy is not in this crate yet.
