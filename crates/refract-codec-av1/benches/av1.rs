//! AV1 parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_codec_av1::parse;

fn benches(c: &mut Criterion) {
    let payload = [0x18, 0x0a, 0x00];
    c.bench_function("av1_parse", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)));
    });
    c.bench_function("av1_keyframe_detect", |b| {
        b.iter(|| {
            parse(std::hint::black_box(&payload)).map(refract_codec_av1::Av1Packet::is_keyframe)
        });
    });
    c.bench_function("av1_layer_extract", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)).map(|_packet| Option::<u8>::None));
    });
}

criterion_group!(codec_benches, benches);
criterion_main!(codec_benches);
