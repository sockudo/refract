//! Fixed-size packet buffer slab for media-plane hot paths.
//!
//! The slab owns an aligned arena split into fixed-size slots. [`SlabPool`]
//! acquires unique mutable [`PacketBuf`] values from a same-thread free-list and
//! accepts cross-thread drops through a lock-free queue. [`ArcSlot`] freezes one
//! slot into a refcounted immutable view for fan-out.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use core::{
    cell::{Cell, UnsafeCell},
    fmt,
    marker::PhantomData,
    mem::{self, MaybeUninit, size_of},
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{rc::Rc, sync::Arc, thread, thread::ThreadId};

use compio_buf::{IoBuf, IoBufMut, SetLen};
use crossbeam_queue::SegQueue;

/// Default packet payload capacity, including jumbo RTP headroom.
pub const DEFAULT_PACKET_CAPACITY: usize = 2_048;

/// Default number of packet slots in a pool.
pub const DEFAULT_SLOT_COUNT: usize = 4_096;

/// Maximum packet payload capacity accepted by [`SlabConfig`].
pub const MAX_PACKET_CAPACITY: usize = 16 * 1_024;

/// Maximum slot count accepted by [`SlabConfig`].
pub const MAX_SLOT_COUNT: usize = 1_048_576;

/// Alignment required for every slot and arena base pointer.
pub const SLOT_ALIGNMENT: usize = 16;

/// Linux huge page size requested by the explicit hugepage arena path.
pub const HUGE_PAGE_SIZE: usize = 2 * 1_024 * 1_024;

const BLOCK_SHORT_SPINS: usize = 64;
const REFCOUNT_ZERO: u16 = 0;
const REFCOUNT_ONE: u16 = 1;
const REFCOUNT_MAX: u16 = u16::MAX;

/// Exhaustion behavior when no slot is immediately available.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExhaustionPolicy {
    /// Briefly yield and retry before returning exhaustion.
    BlockShort,
    /// Prefer the oldest safely available slot and fail if none exists.
    DropOldest,
    /// Return exhaustion immediately.
    #[default]
    FailFast,
}

/// Arena allocation preference.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ArenaKind {
    /// Try explicit Linux huge pages, then transparent huge pages, then heap.
    #[default]
    Auto,
    /// Require explicit Linux huge pages.
    HugePages,
    /// Use anonymous mapping with transparent hugepage advice where supported.
    TransparentHugePages,
    /// Use an aligned boxed-slice heap arena.
    Heap,
}

/// Slab pool configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlabConfig {
    /// Number of fixed-size slots.
    pub slot_count: usize,
    /// Payload bytes per slot.
    pub packet_capacity: usize,
    /// Arena allocation preference.
    pub arena: ArenaKind,
    /// Exhaustion behavior.
    pub exhaustion: ExhaustionPolicy,
}

impl Default for SlabConfig {
    fn default() -> Self {
        Self {
            slot_count: DEFAULT_SLOT_COUNT,
            packet_capacity: DEFAULT_PACKET_CAPACITY,
            arena: ArenaKind::Auto,
            exhaustion: ExhaustionPolicy::FailFast,
        }
    }
}

impl SlabConfig {
    /// Creates a config with a custom slot count and default packet size.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_slab::{DEFAULT_PACKET_CAPACITY, SlabConfig};
    ///
    /// let config = SlabConfig::with_slot_count(128);
    /// assert_eq!(config.packet_capacity, DEFAULT_PACKET_CAPACITY);
    /// ```
    #[must_use]
    pub const fn with_slot_count(slot_count: usize) -> Self {
        Self {
            slot_count,
            packet_capacity: DEFAULT_PACKET_CAPACITY,
            arena: ArenaKind::Auto,
            exhaustion: ExhaustionPolicy::FailFast,
        }
    }

    /// Validates bounded allocation inputs.
    ///
    /// # Errors
    ///
    /// Returns [`SlabError::InvalidConfig`] when a bound is zero, exceeds a
    /// documented maximum, or overflows the arena size calculation.
    pub fn validate(self) -> Result<Self, SlabError> {
        if self.slot_count == 0 || self.slot_count > MAX_SLOT_COUNT {
            return Err(SlabError::InvalidConfig {
                field: "slot_count",
            });
        }

        if self.packet_capacity == 0 || self.packet_capacity > MAX_PACKET_CAPACITY {
            return Err(SlabError::InvalidConfig {
                field: "packet_capacity",
            });
        }

        let stride = slot_stride(self.packet_capacity)?;
        let _arena_len = stride
            .checked_mul(self.slot_count)
            .ok_or(SlabError::InvalidConfig {
                field: "slot_count",
            })?;

        Ok(self)
    }
}

/// Runtime slab counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SlabStats {
    /// Slots currently checked out.
    pub live: usize,
    /// Peak live slot count observed by the pool.
    pub peak: usize,
    /// Number of failed acquisitions.
    pub miss: usize,
    /// Number of slots returned from non-owner threads.
    pub cross_thread_release: usize,
}

/// Errors returned by slab operations.
#[derive(Debug)]
pub enum SlabError {
    /// Pool configuration was outside documented bounds.
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// Arena allocation failed.
    Arena {
        /// Source allocation error.
        source: std::io::Error,
    },
    /// No slot was available.
    Exhausted {
        /// Active exhaustion policy.
        policy: ExhaustionPolicy,
    },
    /// Packet input exceeded the fixed slot capacity.
    PacketTooLarge {
        /// Attempted packet length.
        len: usize,
        /// Slot capacity.
        capacity: usize,
    },
    /// Arc fan-out refcount reached the `u16` maximum.
    RefcountOverflow,
}

impl fmt::Display for SlabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(formatter, "invalid slab configuration field {field}")
            }
            Self::Arena { source } => write!(formatter, "arena allocation failed: {source}"),
            Self::Exhausted { policy } => {
                write!(formatter, "slab exhausted under {policy:?} policy")
            }
            Self::PacketTooLarge { len, capacity } => {
                write!(formatter, "packet length {len} exceeds capacity {capacity}")
            }
            Self::RefcountOverflow => formatter.write_str("arc slot refcount overflow"),
        }
    }
}

impl std::error::Error for SlabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Arena { source } => Some(source),
            Self::InvalidConfig { .. }
            | Self::Exhausted { .. }
            | Self::PacketTooLarge { .. }
            | Self::RefcountOverflow => None,
        }
    }
}

/// Thread-local slab pool.
///
/// `SlabPool` is deliberately not [`Send`]. Move [`PacketBuf`] or [`ArcSlot`]
/// values across threads instead; their drops return slots through the
/// cross-thread queue.
#[derive(Debug)]
pub struct SlabPool {
    inner: Arc<PoolInner>,
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for SlabPool {
    fn drop(&mut self) {
        self.drain_cross_thread();
        // SAFETY: `SlabPool` is !Send, so drop runs on the owner thread. If
        // raw PacketBuf handles are still live, leak one Arc guard so their
        // erased lifetime cannot outlive the arena allocation.
        let local = unsafe { &*self.inner.local.get() };
        if local.live != 0 {
            let leaked_guard = Arc::clone(&self.inner);
            mem::forget(leaked_guard);
        }
    }
}

impl SlabPool {
    /// Creates a pool with [`SlabConfig::default`].
    ///
    /// # Errors
    ///
    /// Returns [`SlabError`] when config validation or arena allocation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_slab::SlabPool;
    ///
    /// let mut pool = SlabPool::new()?;
    /// let buf = pool.acquire()?;
    /// assert_eq!(buf.capacity(), refract_slab::DEFAULT_PACKET_CAPACITY);
    /// # Ok::<(), refract_slab::SlabError>(())
    /// ```
    pub fn new() -> Result<Self, SlabError> {
        Self::with_config(SlabConfig::default())
    }

    /// Creates a pool with a custom slot count.
    ///
    /// # Errors
    ///
    /// Returns [`SlabError`] when config validation or arena allocation fails.
    pub fn with_slot_count(slot_count: usize) -> Result<Self, SlabError> {
        Self::with_config(SlabConfig::with_slot_count(slot_count))
    }

    /// Creates a pool with an explicit config.
    ///
    /// # Errors
    ///
    /// Returns [`SlabError`] when config validation or arena allocation fails.
    pub fn with_config(config: SlabConfig) -> Result<Self, SlabError> {
        let config = config.validate()?;
        let inner = PoolInner::new(config)?;

        Ok(Self {
            inner: Arc::new(inner),
            _not_send: PhantomData,
        })
    }

    /// Acquires a mutable packet buffer from the pool.
    ///
    /// # Errors
    ///
    /// Returns [`SlabError::Exhausted`] when no slot is available under the
    /// configured exhaustion policy.
    pub fn acquire(&mut self) -> Result<PacketBuf, SlabError> {
        if let Some(index) = self.local_state().free_list.pop() {
            self.local_state().record_acquire();
            return Ok(self.inner.packet_buf(index));
        }

        self.drain_cross_thread();
        if let Some(index) = self.local_state().free_list.pop() {
            self.local_state().record_acquire();
            return Ok(self.inner.packet_buf(index));
        }

        self.acquire_exhausted()
    }

    /// Returns a snapshot of runtime counters.
    #[must_use]
    pub fn stats(&self) -> SlabStats {
        debug_assert!(self.inner.is_owner_thread());
        // SAFETY: `SlabPool` is !Send, so stats snapshots are taken on the
        // owner thread and cannot race with owner-local counter updates.
        let local = unsafe { &*self.inner.local.get() };
        self.inner.stats.snapshot(local)
    }

    /// Returns the configured packet capacity.
    #[must_use]
    pub fn packet_capacity(&self) -> usize {
        self.inner.config.packet_capacity
    }

    /// Returns the configured slot count.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.inner.config.slot_count
    }

    /// Returns the arena source actually used by the pool.
    #[must_use]
    pub fn arena_source(&self) -> ArenaSource {
        self.inner.arena.source()
    }

    fn acquire_exhausted(&mut self) -> Result<PacketBuf, SlabError> {
        match self.inner.config.exhaustion {
            ExhaustionPolicy::FailFast | ExhaustionPolicy::DropOldest => {
                self.local_state().record_miss();
                Err(SlabError::Exhausted {
                    policy: self.inner.config.exhaustion,
                })
            }
            ExhaustionPolicy::BlockShort => {
                for _spin in 0..BLOCK_SHORT_SPINS {
                    thread::yield_now();
                    self.drain_cross_thread();
                    if let Some(index) = self.local_state().free_list.pop() {
                        self.local_state().record_acquire();
                        return Ok(self.inner.packet_buf(index));
                    }
                }
                self.local_state().record_miss();
                Err(SlabError::Exhausted {
                    policy: ExhaustionPolicy::BlockShort,
                })
            }
        }
    }

    fn drain_cross_thread(&mut self) {
        while let Some(index) = self.inner.cross_thread.pop() {
            let local = self.local_state();
            local.record_release();
            local.free_list.push(index);
        }
    }

    fn local_state(&mut self) -> &mut LocalState {
        debug_assert!(self.inner.is_owner_thread());
        // SAFETY: `SlabPool` is !Send, so only the owner thread can call pool
        // methods. Same-thread PacketBuf drops also access this `UnsafeCell`,
        // but Rust executes them synchronously on the same thread and there is
        // no concurrent access.
        unsafe { &mut *self.inner.local.get() }
    }
}

/// Arena source selected for a pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArenaSource {
    /// Linux explicit hugepage mapping.
    HugePages,
    /// Anonymous mapping with transparent hugepage advice.
    TransparentHugePages,
    /// Aligned heap boxed-slice fallback.
    Heap,
}

/// Unique mutable packet buffer.
#[derive(Debug)]
pub struct PacketBuf {
    inner: NonNull<PoolInner>,
    index: usize,
    len: usize,
    released: bool,
}

impl PacketBuf {
    /// Returns the slot index inside the owning pool.
    #[must_use]
    pub const fn slot_index(&self) -> usize {
        self.index
    }

    /// Returns the fixed payload capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.inner().config.packet_capacity
    }

    /// Returns the initialized byte length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether this buffer contains no initialized bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns initialized packet bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.as_init()
    }

    /// Returns mutable initialized packet bytes.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        let ptr = self.payload_ptr();
        // SAFETY: PacketBuf has unique ownership of its slot. `len` is always
        // bounded by capacity through `set_len` and `copy_from_slice`.
        unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), len) }
    }

    /// Copies bytes into the packet buffer and sets its initialized length.
    ///
    /// # Errors
    ///
    /// Returns [`SlabError::PacketTooLarge`] when `source` exceeds the fixed
    /// packet capacity.
    pub fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), SlabError> {
        if source.len() > self.capacity() {
            return Err(SlabError::PacketTooLarge {
                len: source.len(),
                capacity: self.capacity(),
            });
        }

        // SAFETY: source length was checked against slot capacity and the
        // source slice cannot overlap this unique slot borrow.
        unsafe {
            core::ptr::copy_nonoverlapping(
                source.as_ptr(),
                self.payload_ptr().as_ptr(),
                source.len(),
            );
        }
        self.len = source.len();
        Ok(())
    }

    /// Clears the initialized length without zeroing memory.
    pub const fn clear(&mut self) {
        self.len = 0;
    }

    /// Freezes this mutable packet into a refcounted immutable view.
    #[must_use]
    pub fn into_arc_slot(mut self) -> ArcSlot {
        let slot = ArcSlot {
            inner: self.inner_arc(),
            index: self.index,
            len: self.len,
            _not_sync: PhantomData,
        };
        self.released = true;
        slot
    }

    fn payload_ptr(&self) -> NonNull<u8> {
        self.inner().payload_ptr(self.index)
    }

    const fn inner(&self) -> &PoolInner {
        // SAFETY: PacketBuf is created only from a live SlabPool. If the pool
        // is dropped before the PacketBuf, SlabPool::drop leaks an Arc guard so
        // this pointer remains valid until process teardown.
        unsafe { self.inner.as_ref() }
    }

    fn inner_arc(&self) -> Arc<PoolInner> {
        let ptr = self.inner.as_ptr();
        // SAFETY: `inner` points at an Arc allocation owned by SlabPool or by a
        // previously leaked drop guard. Incrementing then reconstructing an Arc
        // creates a normal owning guard for ArcSlot fan-out.
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }
}

// SAFETY: PacketBuf has unique ownership of its slot, and dropping it from a
// non-owner thread uses the cross-thread queue instead of touching local state.
unsafe impl Send for PacketBuf {}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        if !self.released {
            self.inner().release_slot(self.index);
            self.released = true;
        }
    }
}

impl IoBuf for PacketBuf {
    fn as_init(&self) -> &[u8] {
        // SAFETY: PacketBuf owns the slot and `len` is bounded by capacity.
        unsafe { core::slice::from_raw_parts(self.payload_ptr().as_ptr(), self.len) }
    }
}

impl IoBufMut for PacketBuf {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let capacity = self.capacity();
        // SAFETY: PacketBuf has unique ownership of its slot. The returned
        // slice is bounded by the fixed payload capacity.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.payload_ptr().as_ptr().cast::<MaybeUninit<u8>>(),
                capacity,
            )
        }
    }
}

impl SetLen for PacketBuf {
    unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.capacity());
        self.len = len;
    }
}

/// Refcounted immutable packet view for fan-out.
#[derive(Debug)]
pub struct ArcSlot {
    inner: Arc<PoolInner>,
    index: usize,
    len: usize,
    _not_sync: PhantomData<Cell<()>>,
}

impl ArcSlot {
    /// Returns the slot index inside the owning pool.
    #[must_use]
    pub const fn slot_index(&self) -> usize {
        self.index
    }

    /// Returns the initialized byte length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether this slot contains no initialized bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns initialized packet bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.as_init()
    }

    /// Clones the view, returning an error if the `u16` refcount is exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`SlabError::RefcountOverflow`] if too many fan-out views point
    /// at the same slot.
    pub fn try_clone(&self) -> Result<Self, SlabError> {
        self.inner.increment_ref(self.index)?;
        Ok(Self {
            inner: Arc::clone(&self.inner),
            index: self.index,
            len: self.len,
            _not_sync: PhantomData,
        })
    }

    fn payload_ptr(&self) -> NonNull<u8> {
        self.inner.payload_ptr(self.index)
    }
}

// SAFETY: ArcSlot is immutable. Clones may move across threads, and their
// drops use atomic refcount operations unless the dropping clone is provably
// the only remaining reference.
unsafe impl Send for ArcSlot {}

impl Clone for ArcSlot {
    fn clone(&self) -> Self {
        match self.try_clone() {
            Ok(slot) => slot,
            Err(SlabError::RefcountOverflow) => panic!("arc slot refcount overflow"),
            Err(error) => panic!("unexpected arc slot clone error: {error}"),
        }
    }
}

impl Drop for ArcSlot {
    fn drop(&mut self) {
        self.inner.decrement_ref(self.index);
    }
}

impl IoBuf for ArcSlot {
    fn as_init(&self) -> &[u8] {
        // SAFETY: ArcSlot is immutable and payload length was captured when the
        // PacketBuf was frozen.
        unsafe { core::slice::from_raw_parts(self.payload_ptr().as_ptr(), self.len) }
    }
}

#[derive(Debug)]
struct PoolInner {
    config: SlabConfig,
    owner: ThreadId,
    arena: Arena,
    stride: usize,
    payload_offset: usize,
    local: UnsafeCell<LocalState>,
    cross_thread: SegQueue<usize>,
    stats: StatsInner,
}

// SAFETY: cross-thread mutation uses atomics and `SegQueue`. The `local`
// `UnsafeCell` is accessed only on the owner thread, enforced by SlabPool being
// !Send and by the same-thread release check.
unsafe impl Send for PoolInner {}

// SAFETY: shared access to PoolInner does not expose mutable local state except
// on the owner thread; cross-thread operations use atomics and `SegQueue`.
unsafe impl Sync for PoolInner {}

impl PoolInner {
    fn new(config: SlabConfig) -> Result<Self, SlabError> {
        let stride = slot_stride(config.packet_capacity)?;
        let arena_len = stride
            .checked_mul(config.slot_count)
            .ok_or(SlabError::InvalidConfig {
                field: "slot_count",
            })?;
        let arena = Arena::allocate(arena_len, config.arena)?;
        let payload_offset = align_up(size_of::<SlotHeader>(), SLOT_ALIGNMENT)?;

        let inner = Self {
            config,
            owner: thread::current().id(),
            arena,
            stride,
            payload_offset,
            local: UnsafeCell::new(LocalState::new(config.slot_count)),
            cross_thread: SegQueue::new(),
            stats: StatsInner::default(),
        };
        inner.initialize_headers();
        Ok(inner)
    }

    fn packet_buf(self: &Arc<Self>, index: usize) -> PacketBuf {
        self.prepare_slot_for_acquire(index);
        let inner = Arc::as_ptr(self).cast_mut();
        PacketBuf {
            // SAFETY: Arc::as_ptr never returns null while `self` is live.
            inner: unsafe { NonNull::new_unchecked(inner) },
            index,
            len: 0,
            released: false,
        }
    }

    fn release_slot(&self, index: usize) {
        let header = self.header(index);
        if header.mark_returned() {
            debug_assert!(!header.mark_returned());
            return;
        }
        header.set_ref_count_local(REFCOUNT_ZERO);

        if self.is_owner_thread() {
            // SAFETY: same-thread releases execute on the owner thread, and
            // local state is not accessed concurrently.
            let local = unsafe { &mut *self.local.get() };
            local.record_release();
            local.free_list.push(index);
        } else {
            self.stats.record_cross_thread_release();
            self.cross_thread.push(index);
        }
    }

    fn increment_ref(&self, index: usize) -> Result<(), SlabError> {
        let header = self.header(index);
        if self.is_owner_thread()
            && header.ref_count_atomic().load(Ordering::Acquire) == REFCOUNT_ONE
        {
            header.set_ref_count_local(REFCOUNT_ONE + REFCOUNT_ONE);
            return Ok(());
        }

        let previous = header
            .ref_count_atomic()
            .fetch_add(REFCOUNT_ONE, Ordering::AcqRel);
        if previous == REFCOUNT_MAX {
            let _restored = header
                .ref_count_atomic()
                .fetch_sub(REFCOUNT_ONE, Ordering::AcqRel);
            return Err(SlabError::RefcountOverflow);
        }

        Ok(())
    }

    fn decrement_ref(&self, index: usize) {
        let header = self.header(index);
        if self.is_owner_thread()
            && header.ref_count_atomic().load(Ordering::Acquire) == REFCOUNT_ONE
        {
            self.release_slot(index);
            return;
        }

        let previous = header
            .ref_count_atomic()
            .fetch_sub(REFCOUNT_ONE, Ordering::AcqRel);
        debug_assert!(previous > REFCOUNT_ZERO);
        if previous == REFCOUNT_ONE {
            self.release_slot(index);
        }
    }

    fn prepare_slot_for_acquire(&self, index: usize) {
        let header = self.header(index);
        header.set_ref_count_local(REFCOUNT_ONE);
        header.set_returned(false);
    }

    fn initialize_headers(&self) {
        for index in 0..self.config.slot_count {
            let header_ptr = self.header_ptr(index);
            // SAFETY: each computed header pointer is within the arena because
            // arena_len = stride * slot_count. Slot starts are aligned to
            // SLOT_ALIGNMENT, which satisfies SlotHeader alignment.
            unsafe { header_ptr.as_ptr().write(SlotHeader::new()) };
        }
    }

    fn is_owner_thread(&self) -> bool {
        thread::current().id() == self.owner
    }

    fn slot_ptr(&self, index: usize) -> NonNull<u8> {
        debug_assert!(index < self.config.slot_count);
        let offset = index.saturating_mul(self.stride);
        // SAFETY: index is sourced from pool-managed free-lists and bounded by
        // slot_count. Offset therefore stays inside the arena.
        unsafe { NonNull::new_unchecked(self.arena.base_ptr().as_ptr().add(offset)) }
    }

    fn header_ptr(&self, index: usize) -> NonNull<SlotHeader> {
        self.slot_ptr(index).cast()
    }

    fn header(&self, index: usize) -> &SlotHeader {
        // SAFETY: headers are initialized once during PoolInner construction
        // before any PacketBuf is created and live for the arena lifetime.
        unsafe { self.header_ptr(index).as_ref() }
    }

    fn payload_ptr(&self, index: usize) -> NonNull<u8> {
        // SAFETY: payload_offset is within stride by construction.
        unsafe { NonNull::new_unchecked(self.slot_ptr(index).as_ptr().add(self.payload_offset)) }
    }
}

#[derive(Debug)]
struct LocalState {
    free_list: Vec<usize>,
    live: usize,
    peak: usize,
    miss: usize,
}

impl LocalState {
    fn new(slot_count: usize) -> Self {
        let mut free_list = Vec::with_capacity(slot_count);
        free_list.extend((0..slot_count).rev());
        Self {
            free_list,
            live: 0,
            peak: 0,
            miss: 0,
        }
    }

    fn record_acquire(&mut self) {
        self.live += 1;
        self.peak = self.peak.max(self.live);
    }

    fn record_release(&mut self) {
        debug_assert!(self.live > 0);
        self.live = self.live.saturating_sub(1);
    }

    const fn record_miss(&mut self) {
        self.miss += 1;
    }
}

#[repr(C, align(16))]
#[derive(Debug)]
struct SlotHeader {
    ref_count: UnsafeCell<u16>,
    returned: UnsafeCell<bool>,
}

// SAFETY: SlotHeader refcount is accessed atomically except in proven-unique
// same-owner cases. `returned` is mutated only by the unique/final release path.
unsafe impl Sync for SlotHeader {}

impl SlotHeader {
    const fn new() -> Self {
        Self {
            ref_count: UnsafeCell::new(REFCOUNT_ZERO),
            returned: UnsafeCell::new(true),
        }
    }

    fn set_ref_count_local(&self, value: u16) {
        // SAFETY: callers use this on newly acquired slots, final-release
        // slots, or same-owner refcount-one transitions with no concurrent
        // refcount access.
        unsafe { *self.ref_count.get() = value };
    }

    fn ref_count_atomic(&self) -> &core::sync::atomic::AtomicU16 {
        let ptr = self.ref_count.get().cast::<core::sync::atomic::AtomicU16>();
        // SAFETY: ref_count is aligned for u16 atomics by SlotHeader alignment
        // and remains valid for the header lifetime.
        unsafe { &*ptr }
    }

    fn set_returned(&self, returned: bool) {
        // SAFETY: callers reset this flag only while acquiring a free slot,
        // when no PacketBuf or ArcSlot can reference it.
        unsafe { *self.returned.get() = returned };
    }

    fn mark_returned(&self) -> bool {
        // SAFETY: release happens once per unique PacketBuf or final ArcSlot.
        // Concurrent non-final ArcSlot drops do not call this method.
        let was_returned = unsafe { *self.returned.get() };
        // SAFETY: same invariant as above; this is the unique release marker.
        unsafe { *self.returned.get() = true };
        was_returned
    }
}

#[derive(Debug, Default)]
struct StatsInner {
    cross_thread_release: AtomicUsize,
}

impl StatsInner {
    fn snapshot(&self, local: &LocalState) -> SlabStats {
        SlabStats {
            live: local.live,
            peak: local.peak,
            miss: local.miss,
            cross_thread_release: self.cross_thread_release.load(Ordering::Acquire),
        }
    }

    fn record_cross_thread_release(&self) {
        let _previous = self.cross_thread_release.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
enum Arena {
    #[cfg(target_os = "linux")]
    Mmap {
        ptr: NonNull<u8>,
        len: usize,
        source: ArenaSource,
    },
    Heap {
        storage: Box<UnsafeCell<[AlignedChunk]>>,
    },
}

impl Arena {
    fn allocate(len: usize, kind: ArenaKind) -> Result<Self, SlabError> {
        match kind {
            ArenaKind::Auto => Self::allocate_auto(len),
            ArenaKind::HugePages => allocate_huge_pages(len),
            ArenaKind::TransparentHugePages => allocate_transparent_huge_pages(len),
            ArenaKind::Heap => allocate_heap(len),
        }
    }

    fn allocate_auto(len: usize) -> Result<Self, SlabError> {
        allocate_huge_pages(len)
            .or_else(|_huge_error| allocate_transparent_huge_pages(len))
            .or_else(|_mmap_error| allocate_heap(len))
    }

    fn base_ptr(&self) -> NonNull<u8> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Mmap { ptr, .. } => *ptr,
            Self::Heap { storage, .. } => {
                let ptr = storage.get().cast::<AlignedChunk>().cast::<u8>();
                // SAFETY: heap arenas are validated to have at least one
                // chunk, and Box never stores a null data pointer.
                unsafe { NonNull::new_unchecked(ptr) }
            }
        }
    }

    const fn source(&self) -> ArenaSource {
        match self {
            #[cfg(target_os = "linux")]
            Self::Mmap { source, .. } => *source,
            Self::Heap { .. } => ArenaSource::Heap,
        }
    }
}

// SAFETY: Arena owns raw memory and releases it in Drop. Access synchronization
// is handled by PoolInner slot ownership.
unsafe impl Send for Arena {}

// SAFETY: shared Arena references expose only stable base pointers; mutation is
// mediated by PacketBuf unique ownership and ArcSlot immutable views.
unsafe impl Sync for Arena {}

impl Drop for Arena {
    fn drop(&mut self) {
        match self {
            #[cfg(target_os = "linux")]
            Self::Mmap { ptr, len, .. } => {
                unmap(*ptr, *len);
            }
            Self::Heap { .. } => {}
        }
    }
}

#[repr(align(16))]
#[derive(Clone, Copy, Debug)]
struct AlignedChunk {
    _bytes: [u8; SLOT_ALIGNMENT],
}

fn allocate_heap(len: usize) -> Result<Arena, SlabError> {
    let len = align_up(len, SLOT_ALIGNMENT)?;
    let chunks = len
        .checked_div(SLOT_ALIGNMENT)
        .ok_or(SlabError::InvalidConfig { field: "arena" })?;
    let storage = vec![
        AlignedChunk {
            _bytes: [0; SLOT_ALIGNMENT],
        };
        chunks
    ]
    .into_boxed_slice();
    let raw_slice = Box::into_raw(storage);
    let raw_cell = raw_slice as *mut UnsafeCell<[AlignedChunk]>;
    // SAFETY: UnsafeCell<T> has the same in-memory representation as T. The
    // boxed slice allocation is immediately re-owned as a boxed UnsafeCell of
    // the same unsized slice.
    let storage = unsafe { Box::from_raw(raw_cell) };
    Ok(Arena::Heap { storage })
}

#[cfg(target_os = "linux")]
fn allocate_huge_pages(len: usize) -> Result<Arena, SlabError> {
    let len = align_up(len, HUGE_PAGE_SIZE)?;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB | libc::MAP_HUGE_2MB;
    map_anonymous(len, flags, ArenaSource::HugePages)
}

#[cfg(not(target_os = "linux"))]
fn allocate_huge_pages(_len: usize) -> Result<Arena, SlabError> {
    Err(SlabError::Arena {
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "explicit huge pages are linux-only",
        ),
    })
}

#[cfg(target_os = "linux")]
fn allocate_transparent_huge_pages(len: usize) -> Result<Arena, SlabError> {
    let len = align_up(len, SLOT_ALIGNMENT)?;
    let arena = map_anonymous(
        len,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        ArenaSource::TransparentHugePages,
    )?;
    let ptr = arena.base_ptr();
    // SAFETY: ptr and len describe the mapping returned by mmap. MADV_HUGEPAGE
    // is advisory; failure leaves the mapping usable, so the result is ignored.
    let _result = unsafe { libc::madvise(ptr.as_ptr().cast(), len, libc::MADV_HUGEPAGE) };
    Ok(arena)
}

#[cfg(not(target_os = "linux"))]
fn allocate_transparent_huge_pages(_len: usize) -> Result<Arena, SlabError> {
    Err(SlabError::Arena {
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "transparent hugepage advice is linux-only",
        ),
    })
}

#[cfg(target_os = "linux")]
fn map_anonymous(len: usize, flags: libc::c_int, source: ArenaSource) -> Result<Arena, SlabError> {
    // SAFETY: mmap is called with no file descriptor and an aligned length. On
    // success, the pointer is owned by Arena and unmapped in Drop.
    let ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(SlabError::Arena {
            source: std::io::Error::last_os_error(),
        });
    }

    let ptr = NonNull::new(ptr.cast::<u8>()).ok_or_else(|| SlabError::Arena {
        source: std::io::Error::other("mmap returned null"),
    })?;
    Ok(Arena::Mmap { ptr, len, source })
}

#[cfg(target_os = "linux")]
fn unmap(ptr: NonNull<u8>, len: usize) {
    // SAFETY: ptr and len are exactly the mapping owned by Arena.
    let _result = unsafe { libc::munmap(ptr.as_ptr().cast(), len) };
}

fn slot_stride(packet_capacity: usize) -> Result<usize, SlabError> {
    let header = align_up(size_of::<SlotHeader>(), SLOT_ALIGNMENT)?;
    let raw = header
        .checked_add(packet_capacity)
        .ok_or(SlabError::InvalidConfig {
            field: "packet_capacity",
        })?;
    align_up(raw, SLOT_ALIGNMENT)
}

fn align_up(value: usize, alignment: usize) -> Result<usize, SlabError> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(SlabError::InvalidConfig { field: "arena" })
}

#[cfg(feature = "alloc-track")]
pub mod alloc_tracking {
    //! Allocation tracker used by hot-path tests.

    use core::alloc::{GlobalAlloc, Layout};
    use std::{
        alloc::System,
        backtrace::Backtrace,
        cell::{Cell, RefCell},
    };

    /// One allocation record captured by the tracking allocator.
    #[derive(Clone, Debug)]
    pub struct AllocationRecord {
        /// Requested layout size.
        pub size: usize,
        /// Requested layout alignment.
        pub align: usize,
        /// Captured allocation backtrace.
        pub backtrace: String,
    }

    struct TrackingAllocator;

    #[global_allocator]
    static GLOBAL: TrackingAllocator = TrackingAllocator;

    thread_local! {
        static ENABLED: Cell<bool> = const { Cell::new(false) };
        static RECORDING: Cell<bool> = const { Cell::new(false) };
        static RECORDS: RefCell<Vec<AllocationRecord>> = const { RefCell::new(Vec::new()) };
    }

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwarding to the system allocator with the caller's
            // layout preserves GlobalAlloc's contract.
            let ptr = unsafe { System.alloc(layout) };
            record_allocation(layout);
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: forwarding to the system allocator with the caller's
            // pointer and layout preserves GlobalAlloc's contract.
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    /// Runs `work` and panics if any allocation occurs on the current thread.
    ///
    /// # Panics
    ///
    /// Panics with allocation backtraces when `work` allocates.
    pub fn assert_no_alloc<R>(work: impl FnOnce() -> R) -> R {
        RECORDS.with(|records| records.borrow_mut().clear());
        ENABLED.with(|enabled| enabled.set(true));
        let result = work();
        ENABLED.with(|enabled| enabled.set(false));
        let records = take_records();
        assert!(
            records.is_empty(),
            "unexpected allocations on hot path:\n{}",
            format_records(&records)
        );
        result
    }

    fn record_allocation(layout: Layout) {
        let enabled = ENABLED.with(Cell::get);
        let recording = RECORDING.with(Cell::get);
        if !enabled || recording {
            return;
        }

        RECORDING.with(|guard| guard.set(true));
        RECORDS.with(|records| {
            records.borrow_mut().push(AllocationRecord {
                size: layout.size(),
                align: layout.align(),
                backtrace: Backtrace::force_capture().to_string(),
            });
        });
        RECORDING.with(|guard| guard.set(false));
    }

    fn take_records() -> Vec<AllocationRecord> {
        RECORDS.with(|records| core::mem::take(&mut *records.borrow_mut()))
    }

    fn format_records(records: &[AllocationRecord]) -> String {
        let mut output = String::new();
        for record in records {
            use core::fmt::Write;
            let _ignored = writeln!(
                output,
                "allocation size={} align={}\n{}",
                record.size, record.align, record.backtrace
            );
        }
        output
    }
}

#[cfg(not(feature = "alloc-track"))]
#[doc(hidden)]
pub mod alloc_tracking {
    //! No-op allocation tracker when `alloc-track` is disabled.

    /// Runs `work` without allocation tracking.
    pub fn assert_no_alloc<R>(work: impl FnOnce() -> R) -> R {
        work()
    }
}

/// Asserts that a closure performs no allocations when `alloc-track` is
/// enabled.
#[macro_export]
macro_rules! assert_no_alloc {
    ($work:expr $(,)?) => {{ $crate::alloc_tracking::assert_no_alloc($work) }};
}

impl fmt::Display for ArenaSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HugePages => formatter.write_str("huge_pages"),
            Self::TransparentHugePages => formatter.write_str("transparent_huge_pages"),
            Self::Heap => formatter.write_str("heap"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use compio_buf::{IoBuf, IoBufMut, SetLen};

    use super::{
        ArcSlot, ArenaKind, DEFAULT_PACKET_CAPACITY, ExhaustionPolicy, PacketBuf, SlabConfig,
        SlabError, SlabPool,
    };

    const SMALL_POOL: usize = 8;
    const STRESS_OPS: usize = 10_000_000;
    const FANOUT_CLONES: usize = 32;

    fn heap_config(slot_count: usize) -> SlabConfig {
        SlabConfig {
            slot_count,
            packet_capacity: DEFAULT_PACKET_CAPACITY,
            arena: ArenaKind::Heap,
            exhaustion: ExhaustionPolicy::FailFast,
        }
    }

    #[test]
    fn lifecycle_single_thread_reuses_slot() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let mut first = pool.acquire()?;
        first.copy_from_slice(b"rtp")?;
        let first_index = first.slot_index();

        assert_eq!(first.as_init(), b"rtp");
        drop(first);

        let second = pool.acquire()?;
        assert_eq!(second.slot_index(), first_index);
        assert_eq!(pool.stats().live, 1);
        drop(second);
        assert_eq!(pool.stats().live, 0);
        Ok(())
    }

    #[test]
    fn lifecycle_cross_thread_release_returns_slot() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let first = pool.acquire()?;
        let first_index = first.slot_index();

        thread::spawn(move || drop(first))
            .join()
            .map_err(|_panic| SlabError::InvalidConfig { field: "thread" })?;

        let mut acquired = Vec::with_capacity(SMALL_POOL);
        let mut returned_slot_seen = false;
        for _attempt in 0..SMALL_POOL {
            let packet = pool.acquire()?;
            if packet.slot_index() == first_index {
                returned_slot_seen = true;
                break;
            }
            acquired.push(packet);
        }

        assert!(returned_slot_seen);
        assert!(acquired.len() < SMALL_POOL);
        assert_eq!(pool.stats().cross_thread_release, 1);
        Ok(())
    }

    #[test]
    fn exhaustion_fail_fast_records_miss() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(1))?;
        let _held = pool.acquire()?;

        assert!(matches!(
            pool.acquire(),
            Err(SlabError::Exhausted {
                policy: ExhaustionPolicy::FailFast
            })
        ));
        assert_eq!(pool.stats().miss, 1);
        Ok(())
    }

    #[test]
    fn refcount_parallel_clones_drop_correctly() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let mut packet = pool.acquire()?;
        packet.copy_from_slice(b"fanout")?;
        let index = packet.slot_index();
        let shared = packet.into_arc_slot();

        let mut handles = Vec::with_capacity(FANOUT_CLONES);
        for _clone_index in 0..FANOUT_CLONES {
            let clone = shared.clone();
            handles.push(thread::spawn(move || {
                assert_eq!(clone.as_init(), b"fanout");
            }));
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_panic| SlabError::InvalidConfig { field: "thread" })?;
        }
        drop(shared);

        let reused = pool.acquire()?;
        assert_eq!(reused.slot_index(), index);
        Ok(())
    }

    #[test]
    fn packet_buf_implements_compio_mut_buffer() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let mut packet = pool.acquire()?;
        let uninit = packet.as_uninit();
        uninit[0].write(b'x');
        // SAFETY: byte 0 was initialized immediately above.
        unsafe { packet.set_len(1) };

        assert_eq!(packet.as_init(), b"x");
        Ok(())
    }

    #[test]
    fn assert_no_alloc_macro_wraps_hot_path() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let warm = pool.acquire()?;
        drop(warm);

        crate::assert_no_alloc!(|| {
            let packet = match pool.acquire() {
                Ok(packet) => packet,
                Err(error) => panic!("hot path acquire failed: {error}"),
            };
            drop(packet);
        });
        Ok(())
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn stress_many_operations_without_leaks() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;

        for _operation in 0..STRESS_OPS {
            let packet = pool.acquire()?;
            drop(packet);
        }

        assert_eq!(pool.stats().live, 0);
        Ok(())
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn arc_slot_try_clone_reports_refcount_overflow() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let packet = pool.acquire()?;
        let shared = packet.into_arc_slot();

        let mut clones: Vec<ArcSlot> = Vec::new();
        let mut overflow = None;
        for _clone in 0..usize::from(u16::MAX) {
            match shared.try_clone() {
                Ok(clone) => clones.push(clone),
                Err(error) => {
                    overflow = Some(error);
                    break;
                }
            }
        }

        assert!(matches!(overflow, Some(SlabError::RefcountOverflow)));
        drop(clones);
        drop(shared);
        Ok(())
    }

    #[test]
    fn packet_too_large_is_rejected() -> Result<(), SlabError> {
        let mut pool = SlabPool::with_config(heap_config(SMALL_POOL))?;
        let mut packet = pool.acquire()?;
        let oversized = [0; DEFAULT_PACKET_CAPACITY + 1];

        assert!(matches!(
            packet.copy_from_slice(&oversized),
            Err(SlabError::PacketTooLarge { .. })
        ));
        Ok(())
    }

    fn _send_bounds(packet: PacketBuf, slot: ArcSlot) {
        let _packet = packet;
        let _slot = slot;
    }
}
