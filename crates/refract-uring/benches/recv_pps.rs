//! Receive throughput benchmark for `refract-uring` fallback surfaces.

use std::{
    hint::black_box,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    thread,
};

use criterion::{Criterion, criterion_group, criterion_main};
use refract_slab::{ArenaKind, ExhaustionPolicy, SlabConfig, SlabPool};
use refract_uring::{MultishotRecvmsg, RecvTier, UringError};

const PACKETS: usize = 10_000;
const PAYLOAD: &[u8] = b"0123456789abcdef0123456789abcdef";

fn make_pool() -> SlabPool {
    let config = SlabConfig {
        slot_count: PACKETS + 16,
        packet_capacity: 2_048,
        arena: ArenaKind::Heap,
        exhaustion: ExhaustionPolicy::FailFast,
    };
    match SlabPool::with_config(config) {
        Ok(pool) => pool,
        Err(error) => panic!("pool setup failed: {error}"),
    }
}

fn bound_socket() -> UdpSocket {
    match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)) {
        Ok(socket) => socket,
        Err(error) => panic!("bind failed: {error}"),
    }
}

fn recv_pps(criterion: &mut Criterion) {
    criterion.bench_function("recv_pps_fallback", |bencher| {
        bencher.iter(|| {
            let receiver = bound_socket();
            let sender = bound_socket();
            let destination = match receiver.local_addr() {
                Ok(address) => address,
                Err(error) => panic!("local_addr failed: {error}"),
            };

            let send_thread = thread::spawn(move || -> Result<(), UringError> {
                for _packet in 0..PACKETS {
                    sender
                        .send_to(PAYLOAD, destination)
                        .map_err(UringError::Io)?;
                }
                Ok(())
            });

            let mut recv = match MultishotRecvmsg::with_tier(
                receiver,
                make_pool(),
                RecvTier::BatchedSingleShot,
                0,
            ) {
                Ok(recv) => recv,
                Err(error) => panic!("recv setup failed: {error}"),
            };

            for _packet in 0..PACKETS {
                let packet = match recv.next_packet() {
                    Ok(packet) => packet,
                    Err(error) => panic!("receive failed: {error}"),
                };
                black_box(packet.len);
            }

            let send_result = match send_thread.join() {
                Ok(result) => result,
                Err(panic_payload) => {
                    drop(panic_payload);
                    panic!("sender panicked");
                }
            };
            if let Err(error) = send_result {
                panic!("sender failed: {error}");
            }
        });
    });
}

criterion_group!(benches, recv_pps);
criterion_main!(benches);
