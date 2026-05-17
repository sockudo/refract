# refract architecture

This workspace follows the five-tier state model from the implementation
contract:

1. Tier 1 hot-path routing, SRTP, jitter, pacer, and BWE state is per-core
   memory and is regenerated after restart.
2. Tier 2 ICE, DTLS, str0m, and application session state is per-node process
   memory and is not replicated.
3. Tier 3 placement, membership, configuration, and auth keys belong in Raft.
4. Tier 4 participants, tracks, subscriptions, and active speakers belong in a
   sharded room store.
5. Tier 5 recordings, audit logs, and long-term metrics belong outside the SFU
   hot path.

The sacred Stage 1 interfaces are defined in `crates/refract-core` and are
re-exported by domain crates where appropriate.

