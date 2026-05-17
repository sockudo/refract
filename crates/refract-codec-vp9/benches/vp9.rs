//! VP9 parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_codec_vp9::parse;

fn benches(c: &mut Criterion) {
    let payload = [0x28, 0b0101_0010, 7, 0];
    c.bench_function("vp9_parse", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)));
    });
    c.bench_function("vp9_keyframe_detect", |b| {
        b.iter(|| {
            parse(std::hint::black_box(&payload)).map(refract_codec_vp9::Vp9Packet::is_keyframe)
        });
    });
    c.bench_function("vp9_layer_extract", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)).map(refract_codec_vp9::Vp9Packet::layer));
    });
}

criterion_group!(codec_benches, benches);
criterion_main!(codec_benches);
