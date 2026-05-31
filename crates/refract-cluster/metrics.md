# refract-cluster metrics

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_cluster_raft_leader_changes_total` | Counter | changes | `node` is bounded by configured control-plane nodes, max 5 | Leader election changes. |
| `refract_cluster_raft_write_rejections_total` | Counter | writes | `error_code` is bounded by `ClusterError` variants | Writes rejected by minority partitions or missing leaders. |
| `refract_cluster_mesh_local_only_rejections_total` | Counter | operations | `operation` has 4 fixed values, `error_code="HSF-MESH-LOCAL"` | Stage 1 local-only mesh operations rejected defensively. |
| `refract_cluster_snapshot_restore_total` | Counter | restores | no labels | Completed local state-machine restores. |
| `refract_cluster_edge_health_cpu_millis` | Gauge | CPU millis, 0-1000 | `node` is bounded by edge nodes in membership | Latest 1s CPU health sample. |
| `refract_cluster_edge_health_memory_percent` | Gauge | percent, 0-100 | `node` is bounded by edge nodes in membership | Latest 1s memory health sample. |
| `refract_cluster_edge_health_pps` | Gauge | packets/second | `node` is bounded by edge nodes in membership | Latest 1s packet-rate health sample. |
| `refract_cluster_edge_health_peers` | Gauge | peers | `node` is bounded by edge nodes in membership | Latest 1s peer-count health sample. |
