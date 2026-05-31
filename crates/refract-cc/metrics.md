# refract-cc metrics

## `refract.cc.gcc.usage`

- Type: counter
- Unit: samples
- Labels:
  - `usage`: one of `underusing`, `normal`, `overusing`
- Cardinality bound: 3 series

## `refract.cc.pacer.packets`

- Type: counter
- Unit: packets
- Labels:
  - `priority`: one of `audio`, `rtx`, `video_keyframe`, `video_delta`, `padding`
- Cardinality bound: 5 series

## `refract.cc.prober.padding_bytes`

- Type: counter
- Unit: bytes
- Labels: none
- Cardinality bound: 1 series

## `refract.cc.prober.skipped`

- Type: counter
- Unit: decisions
- Labels: none
- Cardinality bound: 1 series
