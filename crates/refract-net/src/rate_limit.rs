//! Per-source-IP token-bucket rate limiting for STUN Binding requests.
//!
//! The limiter shards state by source IP so callers can keep one limiter per
//! runtime thread or per receive lane.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

/// Default STUN Binding rate in packets per second.
pub const DEFAULT_STUN_PPS: u32 = 100;

const DEFAULT_CAPACITY: u32 = 100;
const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Token bucket rate limiter sharded by source IP.
#[derive(Debug)]
pub struct StunRateLimiter {
    shards: Vec<Shard>,
    rate_per_second: u32,
    capacity: u32,
    max_entries_per_shard: usize,
}

#[derive(Debug, Default)]
struct Shard {
    buckets: HashMap<IpAddr, Bucket>,
    lru: VecDeque<IpAddr>,
}

#[derive(Debug)]
struct Bucket {
    tokens: AtomicU32,
    last_refill: Instant,
}

impl StunRateLimiter {
    /// Creates a limiter with default 100 pps behavior.
    #[must_use]
    pub fn new() -> Self {
        let shard_count = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .max(1);
        Self::with_shards(
            shard_count,
            DEFAULT_STUN_PPS,
            DEFAULT_CAPACITY,
            DEFAULT_MAX_ENTRIES,
        )
    }

    /// Creates a limiter with explicit shard and bucket configuration.
    #[must_use]
    pub fn with_shards(
        shard_count: usize,
        rate_per_second: u32,
        capacity: u32,
        max_entries_per_shard: usize,
    ) -> Self {
        let shards = (0..shard_count.max(1))
            .map(|_index| Shard::default())
            .collect();
        Self {
            shards,
            rate_per_second,
            capacity,
            max_entries_per_shard,
        }
    }

    /// Returns true when a packet from `ip` is allowed at `now`.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let shard_index = shard_index(ip, self.shards.len());
        let shard = &mut self.shards[shard_index];
        let bucket = shard.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: AtomicU32::new(self.capacity),
            last_refill: now,
        });
        refill(bucket, now, self.rate_per_second, self.capacity);
        let tokens = bucket.tokens.load(Ordering::Relaxed);
        let allowed = if tokens > 0 {
            bucket.tokens.store(tokens - 1, Ordering::Relaxed);
            true
        } else {
            false
        };
        shard.lru.push_back(ip);
        while shard.buckets.len() > self.max_entries_per_shard {
            if let Some(evict) = shard.lru.pop_front() {
                if evict != ip {
                    shard.buckets.remove(&evict);
                }
            } else {
                break;
            }
        }
        allowed
    }
}

impl Default for StunRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

fn refill(bucket: &mut Bucket, now: Instant, rate_per_second: u32, capacity: u32) {
    let elapsed = now.saturating_duration_since(bucket.last_refill);
    let add = elapsed
        .as_nanos()
        .saturating_mul(u128::from(rate_per_second))
        / 1_000_000_000;
    if add > 0 {
        let add_tokens = u32::try_from(add).unwrap_or(u32::MAX);
        let tokens = bucket.tokens.load(Ordering::Relaxed);
        bucket.tokens.store(
            tokens.saturating_add(add_tokens).min(capacity),
            Ordering::Relaxed,
        );
        let nanos = u64::try_from(add.saturating_mul(1_000_000_000) / u128::from(rate_per_second))
            .unwrap_or(u64::MAX);
        bucket.last_refill += Duration::from_nanos(nanos);
    }
}

fn shard_index(ip: IpAddr, shards: usize) -> usize {
    let hash = match ip {
        IpAddr::V4(v4) => u64::from(u32::from(v4)),
        IpAddr::V6(v6) => v6.segments().iter().fold(0_u64, |acc, segment| {
            acc.wrapping_mul(16_777_619) ^ u64::from(*segment)
        }),
    };
    usize::try_from(hash % shards as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn limits_burst_and_refills() {
        let start = Instant::now();
        let mut limiter = StunRateLimiter::with_shards(1, 100, 100, 16);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!((0..100).all(|_i| limiter.allow(ip, start)));
        assert!(!limiter.allow(ip, start));
        assert!(limiter.allow(ip, start + Duration::from_millis(10)));
    }

    #[test]
    fn evicts_lru_entries() {
        let start = Instant::now();
        let mut limiter = StunRateLimiter::with_shards(1, 1, 1, 1);
        assert!(limiter.allow(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), start));
        assert!(limiter.allow(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), start));
        assert_eq!(limiter.shards[0].buckets.len(), 1);
    }
}
