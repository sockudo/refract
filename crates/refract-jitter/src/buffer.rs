//! Bounded per-publisher RTP retention for RTX lookup.
//!
//! The buffer preallocates each packet slot during construction. Inserts copy
//! caller-owned RTP bytes into fixed-capacity slots and never allocate after
//! warmup when packets respect [`crate::JitterConfig::max_packet_bytes`].
//!
//! # Examples
//!
//! ```
//! # use refract_jitter::{JitterConfig, PublisherBuffer, RtpSequenceNumber};
//! let mut buffer = PublisherBuffer::with_config(JitterConfig::default())?;
//! buffer.insert(RtpSequenceNumber::new(7), &[0x80, 0x60])?;
//! assert_eq!(
//!     buffer.get(RtpSequenceNumber::new(7)),
//!     Some(&[0x80, 0x60][..])
//! );
//! # Ok::<(), refract_jitter::JitterError>(())
//! ```

use crate::{JitterConfig, JitterError, JitterResult, RtpSequenceNumber};

/// Result of inserting an RTP packet into a publisher buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// A previously empty slot was filled.
    Stored,
    /// A packet with the same sequence number refreshed its slot.
    RefreshedDuplicate,
    /// A different sequence number was evicted from the slot.
    Evicted {
        /// Evicted RTP sequence number.
        sequence: RtpSequenceNumber,
    },
}

impl InsertOutcome {
    /// Returns a bounded label for metrics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::InsertOutcome;
    /// assert_eq!(InsertOutcome::Stored.as_str(), "stored");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::RefreshedDuplicate => "refreshed_duplicate",
            Self::Evicted { .. } => "evicted",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{InsertOutcome, Stability};
    /// assert_eq!(InsertOutcome::Stored.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Preallocated per-publisher RTP ring for RTX.
#[derive(Debug)]
pub struct PublisherBuffer {
    slots: Vec<PacketSlot>,
    max_packet_bytes: usize,
    occupied: usize,
}

impl PublisherBuffer {
    /// Builds a publisher buffer from validated [`JitterConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`JitterError`] when configuration is invalid or preallocation
    /// fails during warmup.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert!(buffer.capacity() > 0);
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    pub fn with_config(config: JitterConfig) -> JitterResult<Self> {
        let config = config.validate()?;
        let capacity = config.capacity_packets()?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|source| JitterError::Allocation {
                component: "publisher_slots",
                source,
            })?;

        for _slot_index in 0..capacity {
            slots.push(PacketSlot::with_capacity(config.max_packet_bytes)?);
        }

        Ok(Self {
            slots,
            max_packet_bytes: config.max_packet_bytes,
            occupied: 0,
        })
    }

    /// Inserts a retained RTP packet by sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`JitterError::PacketTooLarge`] when `packet` exceeds the
    /// configured per-packet byte bound.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{InsertOutcome, JitterConfig, PublisherBuffer, RtpSequenceNumber};
    /// let mut buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// let outcome = buffer.insert(RtpSequenceNumber::new(12), &[1, 2, 3])?;
    /// assert_eq!(outcome, InsertOutcome::Stored);
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    pub fn insert(
        &mut self,
        sequence: RtpSequenceNumber,
        packet: &[u8],
    ) -> JitterResult<InsertOutcome> {
        if packet.len() > self.max_packet_bytes {
            return Err(JitterError::PacketTooLarge {
                len: packet.len(),
                max: self.max_packet_bytes,
            });
        }

        let index = self.slot_index(sequence);
        let slot = &mut self.slots[index];
        let outcome = match slot.sequence {
            None => {
                self.occupied += 1;
                InsertOutcome::Stored
            }
            Some(existing) if existing == sequence => InsertOutcome::RefreshedDuplicate,
            Some(existing) => InsertOutcome::Evicted { sequence: existing },
        };

        slot.sequence = Some(sequence);
        slot.bytes.clear();
        slot.bytes.extend_from_slice(packet);
        Ok(outcome)
    }

    /// Returns the retained packet bytes for `sequence` when still present.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer, RtpSequenceNumber};
    /// let mut buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// buffer.insert(RtpSequenceNumber::new(3), &[9])?;
    /// assert_eq!(buffer.get(RtpSequenceNumber::new(3)), Some(&[9][..]));
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub fn get(&self, sequence: RtpSequenceNumber) -> Option<&[u8]> {
        let slot = &self.slots[self.slot_index(sequence)];
        (slot.sequence == Some(sequence)).then_some(slot.bytes.as_slice())
    }

    /// Returns configured packet slots.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert_eq!(
    ///     buffer.capacity(),
    ///     JitterConfig::default().capacity_packets()?
    /// );
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Returns occupied packet slots.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert_eq!(buffer.occupied_len(), 0);
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub const fn occupied_len(&self) -> usize {
        self.occupied
    }

    /// Returns whether the buffer has no retained packets.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert!(buffer.is_empty());
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.occupied == 0
    }

    /// Returns the configured packet byte capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert_eq!(
    ///     buffer.packet_capacity(),
    ///     JitterConfig::default().max_packet_bytes
    /// );
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub const fn packet_capacity(&self) -> usize {
        self.max_packet_bytes
    }

    /// Returns the preallocated byte budget for packet payload storage.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert_eq!(
    ///     buffer.memory_budget_bytes(),
    ///     buffer.capacity() * buffer.packet_capacity()
    /// );
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub const fn memory_budget_bytes(&self) -> usize {
        self.capacity() * self.max_packet_bytes
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, PublisherBuffer, Stability};
    /// let buffer = PublisherBuffer::with_config(JitterConfig::default())?;
    /// assert_eq!(buffer.stability(), Stability::Stage1);
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }

    fn slot_index(&self, sequence: RtpSequenceNumber) -> usize {
        usize::from(sequence.as_u16()) % self.slots.len()
    }
}

#[derive(Debug)]
struct PacketSlot {
    sequence: Option<RtpSequenceNumber>,
    bytes: Vec<u8>,
}

impl PacketSlot {
    fn with_capacity(capacity: usize) -> JitterResult<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|source| JitterError::Allocation {
                component: "packet_slot",
                source,
            })?;

        Ok(Self {
            sequence: None,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_config() -> JitterConfig {
        JitterConfig {
            max_bitrate_bps: 100_000_000,
            memory_cap_bytes: 4 * 16,
            max_packet_bytes: 16,
            ..JitterConfig::default()
        }
    }

    #[test]
    fn retains_and_replaces_packets_by_sequence_slot() {
        let mut buffer = PublisherBuffer::with_config(small_config()).unwrap();

        assert_eq!(
            buffer.insert(RtpSequenceNumber::new(1), &[1, 2]).unwrap(),
            InsertOutcome::Stored
        );
        assert_eq!(buffer.get(RtpSequenceNumber::new(1)), Some(&[1, 2][..]));
        assert_eq!(
            buffer.insert(RtpSequenceNumber::new(1), &[3]).unwrap(),
            InsertOutcome::RefreshedDuplicate
        );
        assert_eq!(buffer.occupied_len(), 1);
        assert_eq!(buffer.get(RtpSequenceNumber::new(1)), Some(&[3][..]));

        assert_eq!(
            buffer.insert(RtpSequenceNumber::new(5), &[5]).unwrap(),
            InsertOutcome::Evicted {
                sequence: RtpSequenceNumber::new(1)
            }
        );
        assert_eq!(buffer.get(RtpSequenceNumber::new(1)), None);
        assert_eq!(buffer.get(RtpSequenceNumber::new(5)), Some(&[5][..]));
    }

    #[test]
    fn enforces_memory_and_packet_caps() {
        let config = small_config();
        let mut buffer = PublisherBuffer::with_config(config).unwrap();

        assert_eq!(buffer.capacity(), 4);
        assert_eq!(buffer.memory_budget_bytes(), config.memory_cap_bytes);
        assert!(matches!(
            buffer.insert(RtpSequenceNumber::new(1), &[0; 17]),
            Err(JitterError::PacketTooLarge { len: 17, max: 16 })
        ));
    }

    #[test]
    fn insert_hot_path_does_not_allocate_after_warmup() {
        let mut buffer = PublisherBuffer::with_config(small_config()).unwrap();
        let packet = [7_u8; 16];

        refract_slab::assert_no_alloc!(|| {
            for sequence in 0..32 {
                let outcome = buffer
                    .insert(RtpSequenceNumber::new(sequence), &packet)
                    .unwrap();
                assert!(matches!(
                    outcome,
                    InsertOutcome::Stored
                        | InsertOutcome::RefreshedDuplicate
                        | InsertOutcome::Evicted { .. }
                ));
            }
        });
    }

    #[test]
    fn retains_rollover_sequences_when_slots_are_available() {
        let mut buffer = PublisherBuffer::with_config(small_config()).unwrap();

        for sequence in [u16::MAX - 1, u16::MAX, 0, 1] {
            let byte = u8::try_from(sequence & 0xff).unwrap();
            buffer
                .insert(RtpSequenceNumber::new(sequence), &[byte])
                .unwrap();
        }

        assert_eq!(
            buffer.get(RtpSequenceNumber::new(u16::MAX - 1)),
            Some(&[254][..])
        );
        assert_eq!(
            buffer.get(RtpSequenceNumber::new(u16::MAX)),
            Some(&[255][..])
        );
        assert_eq!(buffer.get(RtpSequenceNumber::new(0)), Some(&[0][..]));
        assert_eq!(buffer.get(RtpSequenceNumber::new(1)), Some(&[1][..]));
    }
}
