//! Leaky-bucket per-subscriber pacer.
//!
//! Packet priority order is audio, RTX, video keyframe, video delta, then
//! padding. Audio packets are released once they reach the 10 ms ceiling even
//! if that creates temporary bucket debt.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_cc::{PacedPacket, Pacer, PacerConfig, PacketPriority};
//! let mut pacer = Pacer::new(PacerConfig::default());
//! pacer.enqueue(PacedPacket::new(
//!     1,
//!     100,
//!     PacketPriority::Audio,
//!     Duration::ZERO,
//! ))?;
//! let mut out = [PacedPacket::default(); 1];
//! assert_eq!(pacer.drain(Duration::from_millis(10), &mut out), 1);
//! # Ok::<(), refract_cc::CcError>(())
//! ```

use std::{collections::VecDeque, time::Duration};

use crate::{CcError, CcResult};

/// Maximum time audio may wait in the pacer.
pub const AUDIO_MAX_DELAY: Duration = Duration::from_millis(10);
/// Default maximum packets retained per subscriber pacer.
pub const DEFAULT_MAX_QUEUE_PACKETS: usize = 4_096;
/// Default pacing rate.
pub const DEFAULT_PACING_RATE_BPS: u64 = 2_000_000;
/// Default burst budget.
pub const DEFAULT_BURST_BYTES: usize = 16_000;

/// Pacer priority class.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketPriority {
    /// Audio RTP.
    #[default]
    Audio,
    /// Retransmission RTP.
    Rtx,
    /// Video keyframe RTP.
    VideoKeyframe,
    /// Video delta-frame RTP.
    VideoDelta,
    /// Padding or probing packet.
    Padding,
}

impl PacketPriority {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::PacketPriority;
    /// assert_eq!(PacketPriority::Rtx.as_str(), "rtx");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Rtx => "rtx",
            Self::VideoKeyframe => "video_keyframe",
            Self::VideoDelta => "video_delta",
            Self::Padding => "padding",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{PacketPriority, Stability};
    /// assert_eq!(PacketPriority::Audio.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Packet metadata retained by the pacer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PacedPacket {
    /// Caller-owned packet identifier.
    pub id: u64,
    /// Packet bytes charged to the leaky bucket.
    pub bytes: usize,
    /// Pacing priority.
    pub priority: PacketPriority,
    /// Queue insertion timestamp.
    pub enqueued_at: Duration,
}

impl PacedPacket {
    /// Creates a paced packet descriptor.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{PacedPacket, PacketPriority};
    /// assert_eq!(
    ///     PacedPacket::new(7, 120, PacketPriority::Audio, Duration::ZERO).id,
    ///     7
    /// );
    /// ```
    #[must_use]
    pub const fn new(
        id: u64,
        bytes: usize,
        priority: PacketPriority,
        enqueued_at: Duration,
    ) -> Self {
        Self {
            id,
            bytes,
            priority,
            enqueued_at,
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{PacedPacket, PacketPriority, Stability};
    /// assert_eq!(
    ///     PacedPacket::new(1, 1, PacketPriority::Padding, Duration::ZERO).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Pacer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacerConfig {
    /// Pacing rate in bits per second.
    pub rate_bps: u64,
    /// Maximum burst budget in bytes.
    pub burst_bytes: usize,
    /// Maximum packets queued across all priorities.
    pub max_queue_packets: usize,
}

impl Default for PacerConfig {
    fn default() -> Self {
        Self {
            rate_bps: DEFAULT_PACING_RATE_BPS,
            burst_bytes: DEFAULT_BURST_BYTES,
            max_queue_packets: DEFAULT_MAX_QUEUE_PACKETS,
        }
    }
}

impl PacerConfig {
    /// Validates pacer configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CcError::InvalidConfig`] when rate, burst, or queue bounds are
    /// zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::PacerConfig;
    /// assert!(PacerConfig::default().validate().is_ok());
    /// ```
    pub const fn validate(self) -> CcResult<Self> {
        if self.rate_bps == 0 {
            return Err(CcError::InvalidConfig { field: "rate_bps" });
        }
        if self.burst_bytes == 0 {
            return Err(CcError::InvalidConfig {
                field: "burst_bytes",
            });
        }
        if self.max_queue_packets == 0 {
            return Err(CcError::InvalidConfig {
                field: "max_queue_packets",
            });
        }
        Ok(self)
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{PacerConfig, Stability};
    /// assert_eq!(PacerConfig::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Leaky-bucket pacer for one subscriber.
#[derive(Debug, Clone)]
pub struct Pacer {
    config: PacerConfig,
    audio: VecDeque<PacedPacket>,
    rtx: VecDeque<PacedPacket>,
    video_keyframe: VecDeque<PacedPacket>,
    video_delta: VecDeque<PacedPacket>,
    padding: VecDeque<PacedPacket>,
    queued: usize,
    budget_bytes: i64,
    last_update: Duration,
}

impl Pacer {
    /// Creates a pacer with bounded queues.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Pacer, PacerConfig};
    /// assert_eq!(Pacer::new(PacerConfig::default()).len(), 0);
    /// ```
    #[must_use]
    pub fn new(config: PacerConfig) -> Self {
        let config = config.validate().unwrap_or_default();
        Self {
            config,
            audio: VecDeque::new(),
            rtx: VecDeque::new(),
            video_keyframe: VecDeque::new(),
            video_delta: VecDeque::new(),
            padding: VecDeque::new(),
            queued: 0,
            budget_bytes: i64::try_from(config.burst_bytes).unwrap_or(i64::MAX),
            last_update: Duration::ZERO,
        }
    }

    /// Enqueues a packet for pacing.
    ///
    /// # Errors
    ///
    /// Returns [`CcError::QueueFull`] when `max_queue_packets` is reached.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{PacedPacket, Pacer, PacerConfig, PacketPriority};
    /// let mut pacer = Pacer::new(PacerConfig::default());
    /// pacer.enqueue(PacedPacket::new(
    ///     1,
    ///     100,
    ///     PacketPriority::Padding,
    ///     Duration::ZERO,
    /// ))?;
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    pub fn enqueue(&mut self, packet: PacedPacket) -> CcResult<()> {
        if self.queued == self.config.max_queue_packets {
            return Err(CcError::QueueFull { component: "pacer" });
        }
        match packet.priority {
            PacketPriority::Audio => self.audio.push_back(packet),
            PacketPriority::Rtx => self.rtx.push_back(packet),
            PacketPriority::VideoKeyframe => self.video_keyframe.push_back(packet),
            PacketPriority::VideoDelta => self.video_delta.push_back(packet),
            PacketPriority::Padding => self.padding.push_back(packet),
        }
        self.queued += 1;
        Ok(())
    }

    /// Drains ready packets into `out` and returns the number written.
    ///
    /// Audio packets are emitted at or before their 10 ms ceiling even if the
    /// bucket must go negative to enforce that ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{PacedPacket, Pacer, PacerConfig, PacketPriority};
    /// let mut pacer = Pacer::new(PacerConfig::default());
    /// pacer.enqueue(PacedPacket::new(
    ///     1,
    ///     100,
    ///     PacketPriority::Audio,
    ///     Duration::ZERO,
    /// ))?;
    /// let mut out = [PacedPacket::default(); 1];
    /// assert_eq!(pacer.drain(Duration::from_millis(10), &mut out), 1);
    /// # Ok::<(), refract_cc::CcError>(())
    /// ```
    pub fn drain(&mut self, now: Duration, out: &mut [PacedPacket]) -> usize {
        self.refill(now);
        let mut written = 0;

        while written < out.len() {
            let Some(packet) = self.peek_next(now) else {
                break;
            };
            let packet_bytes = i64::try_from(packet.bytes).unwrap_or(i64::MAX);
            let audio_ceiling = packet.priority == PacketPriority::Audio
                && now.saturating_sub(packet.enqueued_at) >= AUDIO_MAX_DELAY;
            if self.budget_bytes < packet_bytes && !audio_ceiling {
                break;
            }

            let packet = self.pop_next(now);
            out[written] = packet;
            written += 1;
            self.queued = self.queued.saturating_sub(1);
            self.budget_bytes = self.budget_bytes.saturating_sub(packet_bytes);
        }

        written
    }

    /// Returns queued packet count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Pacer, PacerConfig};
    /// assert_eq!(Pacer::new(PacerConfig::default()).len(), 0);
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.queued
    }

    /// Returns whether no packets are queued.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Pacer, PacerConfig};
    /// assert!(Pacer::new(PacerConfig::default()).is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.queued == 0
    }

    /// Returns current byte budget.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Pacer, PacerConfig};
    /// assert!(Pacer::new(PacerConfig::default()).budget_bytes() > 0);
    /// ```
    #[must_use]
    pub const fn budget_bytes(&self) -> i64 {
        self.budget_bytes
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Pacer, PacerConfig, Stability};
    /// assert_eq!(
    ///     Pacer::new(PacerConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }

    fn refill(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.last_update);
        self.last_update = now;
        let added = (elapsed.as_micros() * u128::from(self.config.rate_bps)) / 8_000_000;
        let added_i64 = i64::try_from(added).unwrap_or(i64::MAX);
        let max_budget = i64::try_from(self.config.burst_bytes).unwrap_or(i64::MAX);
        self.budget_bytes = self.budget_bytes.saturating_add(added_i64).min(max_budget);
    }

    fn peek_next(&self, now: Duration) -> Option<PacedPacket> {
        self.audio.front().copied().or_else(|| {
            if self.audio_overdue(now) {
                None
            } else {
                self.rtx
                    .front()
                    .or_else(|| self.video_keyframe.front())
                    .or_else(|| self.video_delta.front())
                    .or_else(|| self.padding.front())
                    .copied()
            }
        })
    }

    fn pop_next(&mut self, now: Duration) -> PacedPacket {
        if let Some(packet) = self.audio.pop_front() {
            return packet;
        }
        if self.audio_overdue(now) {
            return PacedPacket::default();
        }
        self.rtx
            .pop_front()
            .or_else(|| self.video_keyframe.pop_front())
            .or_else(|| self.video_delta.pop_front())
            .or_else(|| self.padding.pop_front())
            .unwrap_or_default()
    }

    fn audio_overdue(&self, now: Duration) -> bool {
        self.audio
            .front()
            .is_some_and(|packet| now.saturating_sub(packet.enqueued_at) >= AUDIO_MAX_DELAY)
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new(PacerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc-track")]
    use refract_slab::assert_no_alloc;

    use super::*;

    #[cfg(feature = "alloc-track")]
    const HOT_PATH_SOAK_PACKETS: u64 = 16_384;

    #[test]
    fn drains_by_priority_before_lower_classes() {
        let mut pacer = Pacer::new(PacerConfig::default());
        pacer
            .enqueue(PacedPacket::new(
                5,
                100,
                PacketPriority::Padding,
                Duration::ZERO,
            ))
            .unwrap();
        pacer
            .enqueue(PacedPacket::new(
                1,
                100,
                PacketPriority::Audio,
                Duration::ZERO,
            ))
            .unwrap();
        pacer
            .enqueue(PacedPacket::new(
                2,
                100,
                PacketPriority::Rtx,
                Duration::ZERO,
            ))
            .unwrap();

        let mut out = [PacedPacket::default(); 3];
        assert_eq!(pacer.drain(Duration::ZERO, &mut out), 3);
        assert_eq!(out.map(|packet| packet.id), [1, 2, 5]);
    }

    #[test]
    fn enforces_audio_ten_millisecond_ceiling() {
        let config = PacerConfig {
            rate_bps: 8,
            burst_bytes: 1,
            max_queue_packets: 8,
        };
        let mut pacer = Pacer::new(config);
        pacer
            .enqueue(PacedPacket::new(
                1,
                1_200,
                PacketPriority::Audio,
                Duration::ZERO,
            ))
            .unwrap();
        let mut out = [PacedPacket::default(); 1];

        assert_eq!(pacer.drain(Duration::from_millis(9), &mut out), 0);
        assert_eq!(pacer.drain(Duration::from_millis(10), &mut out), 1);
        assert_eq!(out[0].id, 1);
    }

    #[test]
    fn allows_lower_priority_after_audio_queue_clears() {
        let mut pacer = Pacer::new(PacerConfig::default());
        for id in 0..4 {
            pacer
                .enqueue(PacedPacket::new(
                    id,
                    100,
                    PacketPriority::VideoDelta,
                    Duration::ZERO,
                ))
                .unwrap();
        }
        let mut out = [PacedPacket::default(); 4];

        assert_eq!(pacer.drain(Duration::ZERO, &mut out), 4);
        assert_eq!(out.map(|packet| packet.id), [0, 1, 2, 3]);
    }

    #[cfg(feature = "alloc-track")]
    #[test]
    fn drain_hot_path_does_not_allocate() {
        let mut pacer = Pacer::new(PacerConfig::default());
        pacer
            .enqueue(PacedPacket::new(
                1,
                100,
                PacketPriority::Audio,
                Duration::ZERO,
            ))
            .expect("enqueue is warmup");
        let mut out = [PacedPacket::default(); 1];

        assert_no_alloc!(|| pacer.drain(Duration::ZERO, &mut out));
    }

    #[cfg(feature = "alloc-track")]
    #[test]
    fn enqueue_and_drain_hot_path_soak_does_not_allocate() {
        let mut pacer = Pacer::new(PacerConfig::default());
        pacer
            .enqueue(PacedPacket::new(
                0,
                100,
                PacketPriority::Audio,
                Duration::ZERO,
            ))
            .expect("warmup enqueue succeeds");
        let mut out = [PacedPacket::default(); 1];
        assert_eq!(pacer.drain(Duration::ZERO, &mut out), 1);

        assert_no_alloc!(|| {
            (1..=HOT_PATH_SOAK_PACKETS).for_each(|id| {
                let now = Duration::from_millis(id);
                pacer
                    .enqueue(PacedPacket::new(
                        id,
                        100,
                        PacketPriority::Audio,
                        Duration::ZERO,
                    ))
                    .expect("enqueue succeeds");
                assert_eq!(pacer.drain(now, &mut out), 1);
            });
        });
    }
}
