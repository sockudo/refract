# refract-slab

`refract-slab` provides the audited fixed-size packet buffer arena used by the
media hot path. It gives each thread a local `SlabPool`, returns cross-thread
drops through a lock-free queue, exposes buffers as `compio::buf::IoBuf` /
`IoBufMut`, and supports refcounted immutable `ArcSlot` views for fan-out.
