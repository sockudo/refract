//! Opus parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_codec_opus::parse;

fn benches(c: &mut Criterion) {
    let payload = [0x78, 0xaa, 0xbb, 0xcc];
    c.bench_function("opus_parse", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)));
    });
    c.bench_function("opus_keyframe_detect", |b| {
        b.iter(|| {
            parse(std::hint::black_box(&payload)).map(refract_codec_opus::OpusPacket::is_keyframe)
        });
    });
    c.bench_function("opus_layer_extract", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)).map(|_packet| Option::<u8>::None));
    });
}

criterion_group!(codec_benches, benches);
criterion_main!(codec_benches);
