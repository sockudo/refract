//! Active-speaker scoring from RTP audio-level extensions.
//!
//! # Examples
//!
//! ```
//! # use refract_router::{ActiveSpeakerTracker, AudioLevel, PublisherTrackId};
//! let mut tracker = ActiveSpeakerTracker::default();
//! assert!(tracker.observe(PublisherTrackId::new(1), AudioLevel::new(10)?));
//! assert_eq!(tracker.top_speakers(), &[PublisherTrackId::new(1)]);
//! # Ok::<(), refract_router::RouterError>(())
//! ```

use std::collections::HashMap;

use crate::{PublisherTrackId, QualityScore, RouterError, RouterResult, Stability};

/// Default number of active speakers that receive allocator seed bonuses.
pub const DEFAULT_TOP_SPEAKERS: usize = 3;

/// Fixed-point EWMA old-sample weight out of 1000.
pub const DEFAULT_EWMA_OLD_WEIGHT: u16 = 800;

/// Quality score bonus assigned per active-speaker rank.
pub const ACTIVE_SPEAKER_BONUS: QualityScore = QualityScore::new(1_000);

const EWMA_SCALE: u32 = 1_000;
const MAX_AUDIO_LEVEL: u8 = 127;

/// RTP audio-level extension value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AudioLevel(u8);

impl AudioLevel {
    /// Creates a bounded audio-level value.
    ///
    /// Lower values are louder, matching the RTP audio-level extension.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::AudioLevel;
    /// assert_eq!(AudioLevel::new(7)?.as_u8(), 7);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::InvalidConfig`] when the value exceeds 127.
    pub const fn new(value: u8) -> RouterResult<Self> {
        if value > MAX_AUDIO_LEVEL {
            return Err(RouterError::InvalidConfig {
                field: "audio_level",
            });
        }
        Ok(Self(value))
    }

    /// Returns the raw audio-level value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::AudioLevel;
    /// assert_eq!(AudioLevel::new(7)?.as_u8(), 7);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Returns a loudness score where higher is louder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::AudioLevel;
    /// assert!(AudioLevel::new(0)?.loudness() > AudioLevel::new(127)?.loudness());
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub fn loudness(self) -> u32 {
        u32::from(MAX_AUDIO_LEVEL - self.0)
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{AudioLevel, Stability};
    /// assert_eq!(AudioLevel::new(1)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Active-speaker tracker using fixed-point EWMA and a top-K rule.
#[derive(Debug, Clone)]
pub struct ActiveSpeakerTracker {
    top_k: usize,
    ewma_old_weight: u16,
    scores: HashMap<PublisherTrackId, u32>,
    top: Vec<PublisherTrackId>,
}

impl Default for ActiveSpeakerTracker {
    fn default() -> Self {
        Self {
            top_k: DEFAULT_TOP_SPEAKERS,
            ewma_old_weight: DEFAULT_EWMA_OLD_WEIGHT,
            scores: HashMap::new(),
            top: Vec::new(),
        }
    }
}

impl ActiveSpeakerTracker {
    /// Creates a tracker with explicit top-K and EWMA settings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::ActiveSpeakerTracker;
    /// let tracker = ActiveSpeakerTracker::new(2, 800)?;
    /// assert_eq!(tracker.top_k(), 2);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::InvalidConfig`] when `top_k` is zero or the EWMA
    /// old weight is greater than 1000.
    pub fn new(top_k: usize, ewma_old_weight: u16) -> RouterResult<Self> {
        if top_k == 0 {
            return Err(RouterError::InvalidConfig { field: "top_k" });
        }
        if u32::from(ewma_old_weight) > EWMA_SCALE {
            return Err(RouterError::InvalidConfig {
                field: "ewma_old_weight",
            });
        }
        Ok(Self {
            top_k,
            ewma_old_weight,
            scores: HashMap::new(),
            top: Vec::new(),
        })
    }

    /// Updates EWMA for one publisher track and returns whether top-K changed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{ActiveSpeakerTracker, AudioLevel, PublisherTrackId};
    /// let mut tracker = ActiveSpeakerTracker::default();
    /// assert!(tracker.observe(PublisherTrackId::new(1), AudioLevel::new(0)?));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    pub fn observe(&mut self, publisher_track: PublisherTrackId, level: AudioLevel) -> bool {
        let old_weight = u32::from(self.ewma_old_weight);
        let new_weight = EWMA_SCALE.saturating_sub(old_weight);
        let loudness = level.loudness().saturating_mul(EWMA_SCALE);
        self.scores
            .entry(publisher_track)
            .and_modify(|score| {
                *score = ((*score).saturating_mul(old_weight)
                    + loudness.saturating_mul(new_weight))
                    / EWMA_SCALE;
            })
            .or_insert(loudness);
        self.rebuild_top()
    }

    /// Returns the configured top-K speaker count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::ActiveSpeakerTracker;
    /// assert_eq!(ActiveSpeakerTracker::default().top_k(), 3);
    /// ```
    #[must_use]
    pub const fn top_k(&self) -> usize {
        self.top_k
    }

    /// Returns current active speakers in descending EWMA order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{ActiveSpeakerTracker, AudioLevel, PublisherTrackId};
    /// let mut tracker = ActiveSpeakerTracker::default();
    /// tracker.observe(PublisherTrackId::new(1), AudioLevel::new(1)?);
    /// assert_eq!(tracker.top_speakers(), &[PublisherTrackId::new(1)]);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub fn top_speakers(&self) -> &[PublisherTrackId] {
        &self.top
    }

    /// Returns allocator seed scores for the current top-K active speakers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{ActiveSpeakerTracker, AudioLevel, PublisherTrackId};
    /// let mut tracker = ActiveSpeakerTracker::default();
    /// tracker.observe(PublisherTrackId::new(1), AudioLevel::new(1)?);
    /// assert!(
    ///     tracker
    ///         .speaker_scores()
    ///         .contains_key(&PublisherTrackId::new(1))
    /// );
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub fn speaker_scores(&self) -> HashMap<PublisherTrackId, QualityScore> {
        self.top
            .iter()
            .enumerate()
            .map(|(index, track)| {
                let rank_bonus = u32::try_from(self.top_k.saturating_sub(index))
                    .map_or(u32::MAX, |rank| {
                        rank.saturating_mul(ACTIVE_SPEAKER_BONUS.as_u32())
                    });
                (*track, QualityScore::new(rank_bonus))
            })
            .collect()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{ActiveSpeakerTracker, Stability};
    /// assert_eq!(
    ///     ActiveSpeakerTracker::default().stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn rebuild_top(&mut self) -> bool {
        let previous = self.top.clone();
        let mut ranked: Vec<_> = self
            .scores
            .iter()
            .map(|(track, score)| (*track, *score))
            .collect();
        ranked.sort_unstable_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.0.as_u64().cmp(&right.0.as_u64()))
        });
        self.top.clear();
        self.top.extend(
            ranked
                .into_iter()
                .take(self.top_k)
                .map(|(track, _score)| track),
        );
        self.top != previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_audio_level_wins_top_speaker() {
        let mut tracker = ActiveSpeakerTracker::new(1, DEFAULT_EWMA_OLD_WEIGHT).unwrap();

        assert!(tracker.observe(PublisherTrackId::new(1), AudioLevel::new(80).unwrap()));
        assert!(tracker.observe(PublisherTrackId::new(2), AudioLevel::new(5).unwrap()));

        assert_eq!(tracker.top_speakers(), &[PublisherTrackId::new(2)]);
    }

    #[test]
    fn speaker_scores_are_ranked() {
        let mut tracker = ActiveSpeakerTracker::new(2, DEFAULT_EWMA_OLD_WEIGHT).unwrap();
        tracker.observe(PublisherTrackId::new(1), AudioLevel::new(0).unwrap());
        tracker.observe(PublisherTrackId::new(2), AudioLevel::new(10).unwrap());

        let scores = tracker.speaker_scores();
        assert!(
            scores[&PublisherTrackId::new(1)].as_u32() > scores[&PublisherTrackId::new(2)].as_u32()
        );
    }
}
