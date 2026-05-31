# refract-roomstore-redis

Redis Sentinel-backed Stage 1 implementation of `refract-roomstore`.

The supported topology is a single Redis primary with replicas discovered
through Sentinel. Redis Cluster is intentionally out of scope for Stage 1. The
driver connects to the Sentinel-reported primary, applies a deterministic 50 ms
socket deadline to every operation, and refuses writes when health is degraded
or Redis memory pressure reaches the fail-closed threshold.

## Schema

Room-local keys:

- `room:{id}:participants`: hash, field per peer, bincode participant payload
- `room:{id}:tracks`: hash, field per track, bincode track payload
- `room:{id}:speakers`: sorted set, score is audio-level loudness
- `room:{id}:subscriptions`: hash, field per subscription id
- `room:{id}:events`: pub/sub channel

Global support key:

- `roomstore:subscriptions`: subscription id to room index mapping, used so
  `unsubscribe(SubscriptionId)` works without changing the Stage 1 trait

Every state key receives a 24 hour TTL refresh on activity. Room mutations that
touch more than one key are implemented with Lua scripts to keep room-local
updates atomic.

Redis must run with `maxmemory-policy noeviction` and `appendfsync everysec`.

## Verification

Run:

```sh
cargo test -p refract-roomstore-redis
cargo test -p refract-roomstore-redis --features redis-integration
```

The `redis-integration` test is ignored by default and expects
`REFRACT_REDIS_SENTINELS` plus `REFRACT_REDIS_MASTER` when run explicitly.
