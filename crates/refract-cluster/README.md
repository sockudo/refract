# refract-cluster

Control-plane placement, membership, and future mesh boundary.

Stage 1 defines the sacred `PlacementOracle` trait and a single-edge
implementation plus the sacred `MeshTransport` trait and local-only stub.
OpenRaft owns the consensus configuration boundary, redb stores the local state
machine, and Quinn/rustls configuration is represented as the inter-node QUIC
transport policy.

## Mesh transport swap path

`MeshTransportLocalOnly` is the Stage 1 implementation. Every cross-node method
returns `HSF-MESH-LOCAL` because one edge never needs mesh forwarding. Stage 3's
`QuicMeshTransport` must implement the same `MeshTransport` trait and preserve
the `ForwardedPacket` wire rule: original RTP header plus decrypted RTP payload
only. The receiving node re-encrypts with its own SRTP context; nodes never
share SRTP keys.

## Disaster recovery restore procedure

1. Stop admission at the edge and preserve the latest exported
   `ClusterSnapshot` bytes from the backup store.
2. Start a fresh 3- or 5-node control-plane membership with empty redb files.
3. Call `ClusterSnapshot::from_bytes` on the exported bytes and restore every
   node with `RedbStateMachine::restore`.
4. Elect a leader, verify the restored room placement count, then reopen
   admission.
5. Keep the old redb files until the restored cluster has produced and exported
   a newer snapshot.

The `cluster-tests` feature validates the recovery shape by killing the
deterministic in-process cluster and restoring placements from a snapshot.
