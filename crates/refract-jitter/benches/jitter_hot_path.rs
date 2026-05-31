//! Criterion benchmarks for jitter hot-path state updates.

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use refract_jitter::{
    JitterConfig, LossDetector, NackAggregator, PublisherBuffer, RtpSequenceNumber,
};

fn packet() -> [u8; 1_200] {
    let mut packet = [0_u8; 1_200];
    packet[..12].copy_from_slice(&[0x80, 96, 0, 1, 0, 0, 0, 9, 0xaa, 0xbb, 0xcc, 0xdd]);
    packet
}

fn jitter_benches(c: &mut Criterion) {
    let packet = packet();
    c.bench_function("publisher_buffer_insert_1200", |b| {
        let mut buffer = PublisherBuffer::with_config(JitterConfig::default())
            .unwrap_or_else(|error| panic!("bench setup failed: {error}"));
        let mut sequence = RtpSequenceNumber::new(0);
        b.iter(|| {
            let result = buffer.insert(
                std::hint::black_box(sequence),
                std::hint::black_box(&packet),
            );
            sequence = sequence.next();
            result
        });
    });

    c.bench_function("loss_detector_in_order", |b| {
        let mut detector = LossDetector::new();
        let mut nacks = NackAggregator::default();
        let mut sequence = RtpSequenceNumber::new(0);
        b.iter(|| {
            let batch = detector.observe(
                std::hint::black_box(sequence),
                std::hint::black_box(Duration::ZERO),
                std::hint::black_box(&mut nacks),
            );
            sequence = sequence.next();
            batch
        });
    });
}

criterion_group!(benches, jitter_benches);
criterion_main!(benches);
