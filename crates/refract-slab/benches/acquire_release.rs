//! Acquire/release throughput benchmarks for the packet slab.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use refract_slab::{
    ArenaKind, DEFAULT_PACKET_CAPACITY, ExhaustionPolicy, SlabConfig, SlabError, SlabPool,
};

const BENCH_SLOT_COUNT: usize = 25_000;

fn heap_pool() -> Result<SlabPool, SlabError> {
    SlabPool::with_config(SlabConfig {
        slot_count: BENCH_SLOT_COUNT,
        packet_capacity: DEFAULT_PACKET_CAPACITY,
        arena: ArenaKind::Heap,
        exhaustion: ExhaustionPolicy::FailFast,
    })
}

fn acquire_release(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("acquire_release");

    group.bench_function("slab", |bencher| {
        let mut pool = match heap_pool() {
            Ok(pool) => pool,
            Err(error) => panic!("slab pool setup failed: {error}"),
        };
        let mut packets = Vec::with_capacity(BENCH_SLOT_COUNT);
        bencher.iter(|| {
            for _slot in 0..BENCH_SLOT_COUNT {
                let packet = match pool.acquire() {
                    Ok(packet) => packet,
                    Err(error) => panic!("slab acquire failed: {error}"),
                };
                black_box(packet.capacity());
                packets.push(packet);
            }
            while let Some(packet) = packets.pop() {
                drop(packet);
            }
        });
    });

    group.bench_function("box_2048", |bencher| {
        let mut heap_buffers = Vec::with_capacity(BENCH_SLOT_COUNT);
        bencher.iter(|| {
            for _slot in 0..BENCH_SLOT_COUNT {
                let heap_buffer = Box::new(black_box([0_u8; DEFAULT_PACKET_CAPACITY]));
                black_box(heap_buffer.as_ptr());
                heap_buffers.push(heap_buffer);
            }
            while let Some(heap_buffer) = heap_buffers.pop() {
                drop(heap_buffer);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, acquire_release);
criterion_main!(benches);
