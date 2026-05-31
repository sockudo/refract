# refract-roomstore

Stage 1 Tier 4 room state boundary for rooms, participants, tracks,
subscriptions, audio-level reports, event streams, and explicit participant
migration.

This crate owns the sacred `RoomStore` trait used by later storage backends. It
does not expose transactions; every mutation is scoped to one room participant
or one subscription. List APIs are bounded with `(limit, cursor)` and every
fallible operation returns `RoomStoreError` with an operations error code.

The crate also provides `MockRoomStore` for upper-layer unit tests. The mock is
not a hot-path implementation; it exists so signaling and placement code can
exercise the Stage 1 boundary without Redis or Raft.

## Verification

Run:

```sh
cargo test -p refract-roomstore
```

This covers unit tests, property tests for join/leave invariants, bincode
round-trips, pagination, explicit migration, and doctests for public APIs.
