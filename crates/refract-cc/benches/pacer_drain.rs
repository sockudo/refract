//! Criterion benchmark for pacer drain throughput.

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use refract_cc::{PacedPacket, Pacer, PacerConfig, PacketPriority};

fn pacer_drain_bench(c: &mut Criterion) {
    c.bench_function("pacer_drain_packet", |b| {
        b.iter_batched(
            || {
                let mut pacer = Pacer::new(PacerConfig {
                    rate_bps: 100_000_000,
                    burst_bytes: 1_000_000,
                    max_queue_packets: 256,
                });
                for id in 0..128 {
                    pacer
                        .enqueue(PacedPacket::new(
                            id,
                            1_200,
                            PacketPriority::VideoDelta,
                            Duration::ZERO,
                        ))
                        .unwrap_or_else(|error| panic!("bench setup failed: {error}"));
                }
                pacer
            },
            |mut pacer| {
                let mut out = [PacedPacket::default(); 128];
                let drained = pacer.drain(Duration::from_millis(20), &mut out);
                std::hint::black_box(drained);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, pacer_drain_bench);
criterion_main!(benches);
