//! VP8 parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_codec_vp8::parse;

fn benches(c: &mut Criterion) {
    let payload = [0x90, 0x20, 0x80, 0x00];
    c.bench_function("vp8_parse", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)));
    });
    c.bench_function("vp8_keyframe_detect", |b| {
        b.iter(|| {
            parse(std::hint::black_box(&payload)).map(refract_codec_vp8::Vp8Packet::is_keyframe)
        });
    });
    c.bench_function("vp8_layer_extract", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)).map(refract_codec_vp8::Vp8Packet::layer));
    });
}

criterion_group!(codec_benches, benches);
criterion_main!(codec_benches);
