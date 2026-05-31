//! Criterion benchmarks for the per-core `SFU` hot loop.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use criterion::{Criterion, criterion_group, criterion_main};
use refract_core::PeerId;
use refract_router::{
    BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore, SubscriberSessionId,
    Subscription,
};
use refract_sfu::{CoreId, FiveTuple, IngressPacket, IpProtocol, SfuConfig, SfuCore};

const fn tuple(port: u16) -> FiveTuple {
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    FiveTuple::new(local, remote, IpProtocol::Udp)
}

fn rtp(ssrc: u32, sequence: u16) -> [u8; 16] {
    let mut packet = [0_u8; 16];
    packet[..12].copy_from_slice(&[0x80, 96, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0]);
    packet[2..4].copy_from_slice(&sequence.to_be_bytes());
    packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
    packet[12..].copy_from_slice(&[1, 2, 3, 4]);
    packet
}

fn subscribed_core(peers: u16) -> SfuCore {
    let mut core = SfuCore::new(
        SfuConfig::new(CoreId::new(0), usize::from(peers))
            .and_then(|config| config.with_outbox_depth(16))
            .unwrap_or_else(|error| panic!("bench config failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("bench core failed: {error}"));
    for index in 0..peers {
        core.register_plain_peer(
            PeerId::from_raw(u64::from(index) + 1),
            tuple(10_000 + index),
            SubscriberSessionId::new(u64::from(index) + 1),
        )
        .unwrap_or_else(|error| panic!("bench peer failed: {error}"));
    }
    let subscription = Subscription::new(
        PublisherTrackId::new(1),
        SubscriberSessionId::new(2),
        IngressSsrc::new(42),
        vec![
            Layer::new(
                LayerId::new(0),
                BandwidthBps::new(100_000),
                QualityScore::new(1),
            )
            .unwrap_or_else(|error| panic!("bench layer failed: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("bench subscription failed: {error}"));
    core.add_subscription(subscription)
        .unwrap_or_else(|error| panic!("bench route failed: {error}"));
    core
}

fn sfu_hot_loop(c: &mut Criterion) {
    let mut core = subscribed_core(1_000);
    let packet = rtp(42, 1);
    let batch = [IngressPacket::new(tuple(10_000), &packet)];
    c.bench_function("sfu_hot_loop_one_route", |bencher| {
        bencher.iter(|| {
            core.process_synthetic_batch(std::hint::black_box(&batch), Duration::from_millis(1))
        });
    });
}

criterion_group!(benches, sfu_hot_loop);
criterion_main!(benches);
