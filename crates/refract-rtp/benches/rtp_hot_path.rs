//! Criterion benchmarks for RTP parse and fixed header rewrite hot paths.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_rtp::{
    header::RtpHeader,
    rewriter::{RtpRewrite, RtpRewriter},
};

fn sample_packet() -> [u8; 1_500] {
    let mut packet = [0_u8; 1_500];
    packet[..12].copy_from_slice(&[0x80, 96, 0x12, 0x34, 0, 0, 0, 9, 0xaa, 0xbb, 0xcc, 0xdd]);
    packet
}

fn rtp_benches(c: &mut Criterion) {
    let packet = sample_packet();
    c.bench_function("rtp_parse_1500", |b| {
        b.iter(|| RtpHeader::parse(std::hint::black_box(&packet)));
    });

    c.bench_function("rtp_rewrite_fixed_header", |b| {
        let mut packet = sample_packet();
        b.iter(|| {
            RtpRewriter::new().rewrite(
                std::hint::black_box(&mut packet),
                RtpRewrite::new()
                    .with_ssrc(7)
                    .with_sequence(9)
                    .with_timestamp(11),
            )
        });
    });
}

criterion_group!(benches, rtp_benches);
criterion_main!(benches);
