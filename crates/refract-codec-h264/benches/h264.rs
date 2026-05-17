//! H.264 parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_codec_h264::parse;

fn benches(c: &mut Criterion) {
    let payload = [0x65, 0xaa, 0xbb];
    c.bench_function("h264_parse", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)));
    });
    c.bench_function("h264_keyframe_detect", |b| {
        b.iter(|| {
            parse(std::hint::black_box(&payload)).map(refract_codec_h264::H264Packet::is_keyframe)
        });
    });
    c.bench_function("h264_layer_extract", |b| {
        b.iter(|| parse(std::hint::black_box(&payload)).map(|_packet| Option::<u8>::None));
    });
}

criterion_group!(codec_benches, benches);
criterion_main!(codec_benches);
