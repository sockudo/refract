# refract-cc

Congestion control, bandwidth estimation, and pacing primitives.

This crate provides:

- RFC 8888 transport-wide congestion-control feedback generation and parsing.
- A GCC trendline delay estimator ported against libwebrtc revision
  `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`.
- A per-subscriber leaky-bucket pacer with strict audio, RTX, video, and
  padding priority order.
- A padding prober for bandwidth probing when target send rate exceeds current
  media send rate.
