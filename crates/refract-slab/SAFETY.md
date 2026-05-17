# refract-slab safety policy

`refract-slab` is one of the three crates allowed to contain unsafe code. The
unsafe surface exists to expose raw slab arena memory as `compio::buf::IoBuf`
and `IoBufMut` without allocating on packet hot paths.

## Invariants

- Pool lifetime: `PacketBuf` stores a raw pointer to the owning `PoolInner` to
  avoid a per-packet atomic `Arc` clone/drop on the hot path. `SlabPool::drop`
  drains cross-thread releases and leaks one `Arc<PoolInner>` guard if any slot
  is still live, so the arena cannot be freed while erased-lifetime packet
  buffers still exist. `ArcSlot` holds a normal `Arc<PoolInner>` because fan-out
  is not the unique mutable packet hot path.
- Slot aliasing: a slot is either on a free-list, uniquely owned by one
  `PacketBuf`, or immutably shared by one or more `ArcSlot` values. The public
  API never exposes mutable access after `PacketBuf::into_arc_slot`.
- One mutable borrow per slot: `SlabPool::acquire` removes an index from the
  owner-thread free-list before creating `PacketBuf`. The index returns only
  when the unique buffer is dropped or the final `ArcSlot` reference is dropped.
- Header layout: each slot starts with `SlotHeader`; the `u16` refcount is at
  offset zero. The payload begins at the next 16-byte boundary and never
  overlaps the refcount or returned flag.
- Refcounting: `ArcSlot` uses atomic refcount updates when more than one view
  may exist. Same-owner transitions from refcount 1 use a non-atomic
  `UnsafeCell`/Cell-style path because no other clone can exist.
- Arena alignment: mmap and boxed-slice fallback arenas are 16-byte aligned;
  slot stride is also 16-byte aligned, so every slot header and payload starts
  on the required boundary.
- Cross-thread release: `SlabPool` is not `Send`. Drops on non-owner threads
  enqueue slot indices in `crossbeam_queue::SegQueue`; only the owner thread
  drains that queue into the same-thread `Vec` free-list.
- No double-free: every slot has a returned flag. Release sets it to returned
  exactly once before the slot is pushed back to a free-list. The flag is
  non-atomic because only a unique `PacketBuf` or the final `ArcSlot` release
  can reach it.
- `SetLen`: callers of `compio::buf::SetLen::set_len` must initialize all bytes
  in the new initialized range and must not set length beyond `PacketBuf`
  capacity.

## Unsafe block audit

Every unsafe block in `src/lib.rs` has an adjacent `SAFETY:` comment naming the
active invariant. Unsafe is limited to:

- converting arena pointers into slices for `IoBuf` / `IoBufMut`;
- writing slot headers into freshly allocated arena memory;
- accessing owner-thread local free-list state through `UnsafeCell`;
- casting the refcount storage to `AtomicU16` for shared refcount operations;
- dereferencing `PacketBuf`'s raw `PoolInner` pointer and reconstructing an
  `Arc<PoolInner>` only when freezing a packet into `ArcSlot`;
- calling platform `mmap`, `madvise`, and `munmap`;
- forwarding through the allocation-tracking global allocator.

## Required verification

- `cargo test -p refract-slab`
- `cargo +nightly miri test -p refract-slab`
- `RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p refract-slab`
- `cargo bench -p refract-slab`
