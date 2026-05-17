//! Network parser benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use refract_net::stun::StunMessage;

const fn binding_request() -> [u8; 20] {
    [
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ]
}

fn benches(c: &mut Criterion) {
    let request = binding_request();
    c.bench_function("stun_parse_binding", |b| {
        b.iter(|| StunMessage::parse(std::hint::black_box(&request)));
    });
}

criterion_group!(net_benches, benches);
criterion_main!(net_benches);
