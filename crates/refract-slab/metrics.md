# refract-slab metrics

Runtime counters are exposed through `SlabPool::stats`; this crate does not
emit process-global metrics directly.

| Name | Type | Unit | Cardinality | Description |
|---|---|---|---|---|
| `slab.live` | gauge | slots | one per pool | Slots currently checked out. |
| `slab.peak` | gauge | slots | one per pool | Maximum live slot count observed. |
| `slab.miss` | counter | acquisitions | one per pool | Failed acquisitions due to exhaustion. |
| `slab.cross_thread_release` | counter | releases | one per pool | Slot releases observed on non-owner threads. |
