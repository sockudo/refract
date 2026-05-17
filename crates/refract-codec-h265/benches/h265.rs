//! H.265 parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_codec_h265::parse;

fn benches(c: &mut Criterion) {
    let payload = [19 << 1, 1, 0xaa];
    c.bench_function("h265_parse", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)));
    });
    c.bench_function("h265_keyframe_detect", |b| {
        b.iter(|| {
            parse(std::hint::black_box(&payload)).map(refract_codec_h265::H265Packet::is_keyframe)
        });
    });
    c.bench_function("h265_layer_extract", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)).map(|_packet| Option::<u8>::None));
    });
}

criterion_group!(codec_benches, benches);
criterion_main!(codec_benches);
