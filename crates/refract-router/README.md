# refract-router

Per-core, per-room subscription routing with lock-free hot-path reads.

This crate provides:

- `Route` descriptors for `(publisher_track, subscriber_session) + Layer`.
- `RoutingTable` slow-path subscription, BWE, and active-speaker updates.
- `ArcSwap<RoutingSnapshot>` publication for lock-free route reads.
- Greedy layer allocation seeded by active-speaker EWMA scores.
- Bounded metrics for snapshot publication.
