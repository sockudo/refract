//! Criterion benchmarks for SRTP AES-GCM protection paths.

#![forbid(unsafe_code)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use refract_srtp::{Egress, SrtpProfile, protect_fanout};

fn rtp(seq: u16) -> Vec<u8> {
    let mut out = vec![0x80, 96];
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&7_u32.to_be_bytes());
    out.extend_from_slice(&0xaabb_ccdd_u32.to_be_bytes());
    out.extend_from_slice(&[0x55; 1200]);
    out
}

fn egress() -> Egress {
    Egress::new(SrtpProfile::AeadAes128Gcm, &[7; 16], [9; 12]).expect("bench egress is valid")
}

fn single_stream_encrypt(c: &mut Criterion) {
    let packet = rtp(1);
    let mut ctx = egress();
    let mut group = c.benchmark_group("srtp_single_stream_encrypt");
    group.throughput(Throughput::Bytes(packet.len() as u64));
    group.bench_function("aes_128_gcm_rtp", |b| {
        b.iter(|| {
            let mut working = packet.clone();
            ctx.protect_rtp(&mut working).expect("protect succeeds");
        });
    });
    group.finish();
}

fn fanout_encrypt(c: &mut Criterion) {
    let packet = rtp(1);
    let mut subs = (0..1000).map(|_| egress()).collect::<Vec<_>>();
    c.bench_function("srtp_fanout_1000", |b| {
        b.iter(|| {
            let mut refs = subs.iter_mut().collect::<Vec<_>>();
            protect_fanout(&packet, &mut refs).expect("fanout succeeds");
        });
    });
}

criterion_group!(benches, single_stream_encrypt, fanout_encrypt);
criterion_main!(benches);
