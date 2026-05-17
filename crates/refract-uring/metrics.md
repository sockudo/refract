# refract-uring metrics

All labels are bounded by core count and a small static outcome set.

| Name | Type | Unit | Labels | Cardinality |
|---|---|---|---|---|
| `refract.io.recv.packets` | counter | packets | `core` | one per media core |
| `refract.io.recv.bytes` | counter | bytes | `core` | one per media core |
| `refract.io.recv.truncated` | counter | packets | `core` | one per media core |
| `refract.io.send.packets` | counter | packets | `core`, `gso` | media cores x `{plain,gso}` |
| `refract.io.send.errors` | counter | errors | `core`, `errno` | media cores x OS errno set |
| `refract.io.uring.sq_full` | counter | events | `core` | one per media core |
