//! Google Congestion Control trendline delay estimator.
//!
//! The trendline filter follows libwebrtc
//! `modules/congestion_controller/goog_cc/trendline_estimator.{h,cc}` at
//! revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`.
//!
//! # Examples
//!
//! ```
//! # use refract_cc::{BandwidthUsage, TrendlineEstimator};
//! let mut estimator = TrendlineEstimator::default();
//! let usage = estimator.update(5.0, 5.0, 0, 10, 1200);
//! assert_eq!(usage, BandwidthUsage::Normal);
//! ```

use std::collections::VecDeque;

/// Default trendline smoothing coefficient.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.cc`, `kDefaultTrendlineSmoothingCoeff = 0.9`.
pub const DEFAULT_TRENDLINE_SMOOTHING_COEFF: f64 = 0.9;
/// Default trendline threshold gain.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.cc`, `kDefaultTrendlineThresholdGain = 4.0`.
pub const DEFAULT_TRENDLINE_THRESHOLD_GAIN: f64 = 4.0;
/// Default regression window in packets.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.h`, `kDefaultTrendlineWindowSize = 20`.
pub const DEFAULT_TRENDLINE_WINDOW_SIZE: usize = 20;
/// Maximum threshold adaptation offset in milliseconds.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.cc`, `kMaxAdaptOffsetMs = 15.0`.
pub const MAX_ADAPT_OFFSET_MS: f64 = 15.0;
/// Overusing time threshold in milliseconds.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.cc`, `kOverUsingTimeThreshold = 10`.
pub const OVERUSING_TIME_THRESHOLD_MS: f64 = 10.0;
/// Minimum deltas used to scale the modified trend.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.cc`, `kMinNumDeltas = 60`.
pub const MIN_NUM_DELTAS: i32 = 60;
/// Maximum delta counter value.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `trendline_estimator.cc`, `kDeltaCounterMax = 1000`.
pub const DELTA_COUNTER_MAX: i32 = 1_000;
/// Upward threshold adaptation gain.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `TrendlineEstimator` constructor, `k_up_(0.0087)`.
pub const THRESHOLD_GAIN_UP: f64 = 0.0087;
/// Downward threshold adaptation gain.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `TrendlineEstimator` constructor, `k_down_(0.039)`.
pub const THRESHOLD_GAIN_DOWN: f64 = 0.039;
/// Initial modified-trend threshold.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `TrendlineEstimator` constructor, `threshold_(12.5)`.
pub const INITIAL_THRESHOLD: f64 = 12.5;
/// Maximum threshold update time delta in milliseconds.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `UpdateThreshold`, `kMaxTimeDeltaMs = 100`.
pub const MAX_THRESHOLD_UPDATE_INTERVAL_MS: i64 = 100;
/// Minimum adaptive threshold.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `UpdateThreshold`, `SafeClamp(threshold_, 6.f, 600.f)`.
pub const MIN_THRESHOLD: f64 = 6.0;
/// Maximum adaptive threshold.
///
/// Source: libwebrtc revision `8c371f2a9baf8fef9bf3c327a93a709bb8c1e000`,
/// `UpdateThreshold`, `SafeClamp(threshold_, 6.f, 600.f)`.
pub const MAX_THRESHOLD: f64 = 600.0;

/// Bandwidth usage hypothesis from the delay detector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BandwidthUsage {
    /// Queues are draining.
    Underusing,
    /// Delay trend is inside the adaptive threshold.
    #[default]
    Normal,
    /// Queues are filling.
    Overusing,
}

impl BandwidthUsage {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::BandwidthUsage;
    /// assert_eq!(BandwidthUsage::Overusing.as_str(), "overusing");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Underusing => "underusing",
            Self::Normal => "normal",
            Self::Overusing => "overusing",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{BandwidthUsage, Stability};
    /// assert_eq!(BandwidthUsage::Normal.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Trendline estimator settings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrendlineSettings {
    /// Regression window size in packets.
    pub window_size: usize,
    /// Exponential smoothing coefficient.
    pub smoothing_coef: f64,
    /// Threshold gain applied to the trendline slope.
    pub threshold_gain: f64,
    /// Whether to sort the regression window by arrival time.
    pub enable_sort: bool,
}

impl Default for TrendlineSettings {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_TRENDLINE_WINDOW_SIZE,
            smoothing_coef: DEFAULT_TRENDLINE_SMOOTHING_COEFF,
            threshold_gain: DEFAULT_TRENDLINE_THRESHOLD_GAIN,
            enable_sort: false,
        }
    }
}

impl TrendlineSettings {
    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Stability, TrendlineSettings};
    /// assert_eq!(TrendlineSettings::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Libwebrtc-compatible GCC trendline delay estimator.
#[derive(Debug, Clone)]
pub struct TrendlineEstimator {
    settings: TrendlineSettings,
    num_of_deltas: i32,
    first_arrival_time_ms: Option<i64>,
    accumulated_delay: f64,
    smoothed_delay: f64,
    delay_hist: VecDeque<PacketTiming>,
    threshold: f64,
    last_update_ms: Option<i64>,
    prev_trend: f64,
    time_over_using: Option<f64>,
    overuse_counter: i32,
    hypothesis: BandwidthUsage,
}

impl Default for TrendlineEstimator {
    fn default() -> Self {
        Self::new(TrendlineSettings::default())
    }
}

impl TrendlineEstimator {
    /// Creates a trendline estimator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{TrendlineEstimator, TrendlineSettings};
    /// let estimator = TrendlineEstimator::new(TrendlineSettings::default());
    /// assert_eq!(estimator.state(), refract_cc::BandwidthUsage::Normal);
    /// ```
    #[must_use]
    pub fn new(settings: TrendlineSettings) -> Self {
        Self {
            settings,
            num_of_deltas: 0,
            first_arrival_time_ms: None,
            accumulated_delay: 0.0,
            smoothed_delay: 0.0,
            delay_hist: VecDeque::with_capacity(settings.window_size),
            threshold: INITIAL_THRESHOLD,
            last_update_ms: None,
            prev_trend: 0.0,
            time_over_using: None,
            overuse_counter: 0,
            hypothesis: BandwidthUsage::Normal,
        }
    }

    /// Updates the estimator with one timestamp-group delta sample.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{BandwidthUsage, TrendlineEstimator};
    /// let mut estimator = TrendlineEstimator::default();
    /// assert_eq!(
    ///     estimator.update(5.0, 5.0, 0, 10, 1200),
    ///     BandwidthUsage::Normal
    /// );
    /// ```
    pub fn update(
        &mut self,
        recv_delta_ms: f64,
        send_delta_ms: f64,
        _send_time_ms: i64,
        arrival_time_ms: i64,
        _packet_size: usize,
    ) -> BandwidthUsage {
        let delta_ms = recv_delta_ms - send_delta_ms;
        self.num_of_deltas = (self.num_of_deltas + 1).min(DELTA_COUNTER_MAX);
        let first_arrival = *self.first_arrival_time_ms.get_or_insert(arrival_time_ms);

        self.accumulated_delay += delta_ms;
        self.smoothed_delay = self.settings.smoothing_coef.mul_add(
            self.smoothed_delay,
            (1.0 - self.settings.smoothing_coef) * self.accumulated_delay,
        );

        self.delay_hist.push_back(PacketTiming {
            arrival: i64_to_f64(arrival_time_ms - first_arrival),
            smoothed_delay: self.smoothed_delay,
        });
        if self.settings.enable_sort {
            self.make_arrival_ordered();
        }
        if self.delay_hist.len() > self.settings.window_size {
            let _dropped = self.delay_hist.pop_front();
        }

        let mut trend = self.prev_trend;
        if self.delay_hist.len() == self.settings.window_size {
            trend = linear_fit_slope(&self.delay_hist).unwrap_or(trend);
        }
        self.detect(trend, send_delta_ms, arrival_time_ms);
        self.hypothesis
    }

    /// Returns the current bandwidth usage hypothesis.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{BandwidthUsage, TrendlineEstimator};
    /// assert_eq!(
    ///     TrendlineEstimator::default().state(),
    ///     BandwidthUsage::Normal
    /// );
    /// ```
    #[must_use]
    pub const fn state(&self) -> BandwidthUsage {
        self.hypothesis
    }

    /// Returns the current adaptive threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{gcc::INITIAL_THRESHOLD, TrendlineEstimator};
    /// assert_eq!(TrendlineEstimator::default().threshold(), INITIAL_THRESHOLD);
    /// ```
    #[must_use]
    pub const fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Stability, TrendlineEstimator};
    /// assert_eq!(TrendlineEstimator::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }

    fn make_arrival_ordered(&mut self) {
        let mut values: Vec<_> = self.delay_hist.drain(..).collect();
        values.sort_by(|left, right| left.arrival.total_cmp(&right.arrival));
        self.delay_hist.extend(values);
    }

    fn detect(&mut self, trend: f64, ts_delta: f64, now_ms: i64) {
        if self.num_of_deltas < 2 {
            self.hypothesis = BandwidthUsage::Normal;
            return;
        }
        let modified_trend = f64::from(self.num_of_deltas.min(MIN_NUM_DELTAS))
            * trend
            * self.settings.threshold_gain;

        if modified_trend > self.threshold {
            self.time_over_using = Some(
                self.time_over_using
                    .map_or(ts_delta / 2.0, |time| time + ts_delta),
            );
            self.overuse_counter += 1;
            if self.time_over_using.unwrap_or_default() > OVERUSING_TIME_THRESHOLD_MS
                && self.overuse_counter > 1
                && trend >= self.prev_trend
            {
                self.time_over_using = Some(0.0);
                self.overuse_counter = 0;
                self.hypothesis = BandwidthUsage::Overusing;
            }
        } else if modified_trend < -self.threshold {
            self.time_over_using = None;
            self.overuse_counter = 0;
            self.hypothesis = BandwidthUsage::Underusing;
        } else {
            self.time_over_using = None;
            self.overuse_counter = 0;
            self.hypothesis = BandwidthUsage::Normal;
        }
        self.prev_trend = trend;
        self.update_threshold(modified_trend, now_ms);
    }

    fn update_threshold(&mut self, modified_trend: f64, now_ms: i64) {
        let Some(last_update_ms) = self.last_update_ms else {
            self.last_update_ms = Some(now_ms);
            return;
        };
        if modified_trend.abs() > self.threshold + MAX_ADAPT_OFFSET_MS {
            self.last_update_ms = Some(now_ms);
            return;
        }
        let gain = if modified_trend.abs() < self.threshold {
            THRESHOLD_GAIN_DOWN
        } else {
            THRESHOLD_GAIN_UP
        };
        let time_delta_ms = (now_ms - last_update_ms).min(MAX_THRESHOLD_UPDATE_INTERVAL_MS);
        self.threshold +=
            gain * (modified_trend.abs() - self.threshold) * i64_to_f64(time_delta_ms);
        self.threshold = self.threshold.clamp(MIN_THRESHOLD, MAX_THRESHOLD);
        self.last_update_ms = Some(now_ms);
    }
}

/// Bandwidth estimate emitted by [`DelayBasedBwe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BweEstimate {
    /// Estimated bitrate in bits per second.
    pub bitrate_bps: u64,
    /// Current usage hypothesis.
    pub usage: BandwidthUsage,
}

impl BweEstimate {
    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{BandwidthUsage, BweEstimate, Stability};
    /// let estimate = BweEstimate {
    ///     bitrate_bps: 300_000,
    ///     usage: BandwidthUsage::Normal,
    /// };
    /// assert_eq!(estimate.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Delay-based bandwidth estimator using the GCC trendline detector.
#[derive(Debug, Clone)]
pub struct DelayBasedBwe {
    trendline: TrendlineEstimator,
    estimate_bps: u64,
    previous_send_ms: Option<i64>,
    previous_arrival_ms: Option<i64>,
}

impl DelayBasedBwe {
    /// Creates a delay-based bandwidth estimator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::DelayBasedBwe;
    /// assert_eq!(DelayBasedBwe::new(300_000).estimate().bitrate_bps, 300_000);
    /// ```
    #[must_use]
    pub fn new(initial_bitrate_bps: u64) -> Self {
        Self {
            trendline: TrendlineEstimator::default(),
            estimate_bps: initial_bitrate_bps,
            previous_send_ms: None,
            previous_arrival_ms: None,
        }
    }

    /// Updates BWE from one TWCC packet timing sample.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::DelayBasedBwe;
    /// let mut bwe = DelayBasedBwe::new(300_000);
    /// assert_eq!(bwe.update(0, 0, 1200).bitrate_bps, 300_000);
    /// ```
    pub fn update(
        &mut self,
        send_time_ms: i64,
        arrival_time_ms: i64,
        packet_size: usize,
    ) -> BweEstimate {
        let (Some(previous_send), Some(previous_arrival)) =
            (self.previous_send_ms, self.previous_arrival_ms)
        else {
            self.previous_send_ms = Some(send_time_ms);
            self.previous_arrival_ms = Some(arrival_time_ms);
            return self.estimate();
        };

        let send_delta = i64_to_f64((send_time_ms - previous_send).max(1));
        let recv_delta = i64_to_f64((arrival_time_ms - previous_arrival).max(1));
        let usage = self.trendline.update(
            recv_delta,
            send_delta,
            send_time_ms,
            arrival_time_ms,
            packet_size,
        );
        self.previous_send_ms = Some(send_time_ms);
        self.previous_arrival_ms = Some(arrival_time_ms);

        self.estimate_bps = match usage {
            BandwidthUsage::Overusing => self.estimate_bps.saturating_mul(85) / 100,
            BandwidthUsage::Underusing => self.estimate_bps.saturating_mul(103) / 100,
            BandwidthUsage::Normal => self.estimate_bps.saturating_mul(101) / 100,
        }
        .max(30_000);

        BweEstimate {
            bitrate_bps: self.estimate_bps,
            usage,
        }
    }

    /// Returns the latest estimate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::DelayBasedBwe;
    /// assert_eq!(DelayBasedBwe::new(123).estimate().bitrate_bps, 123);
    /// ```
    #[must_use]
    pub const fn estimate(&self) -> BweEstimate {
        BweEstimate {
            bitrate_bps: self.estimate_bps,
            usage: self.trendline.state(),
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{DelayBasedBwe, Stability};
    /// assert_eq!(DelayBasedBwe::new(100).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PacketTiming {
    arrival: f64,
    smoothed_delay: f64,
}

fn linear_fit_slope(packets: &VecDeque<PacketTiming>) -> Option<f64> {
    let packet_count = u32::try_from(packets.len()).map_or_else(|_| f64::from(u32::MAX), f64::from);
    if packet_count < 2.0 {
        return None;
    }
    let sum_x: f64 = packets.iter().map(|packet| packet.arrival).sum();
    let sum_y: f64 = packets.iter().map(|packet| packet.smoothed_delay).sum();
    let x_avg = sum_x / packet_count;
    let y_avg = sum_y / packet_count;
    let numerator: f64 = packets
        .iter()
        .map(|packet| (packet.arrival - x_avg) * (packet.smoothed_delay - y_avg))
        .sum();
    let denominator: f64 = packets
        .iter()
        .map(|packet| {
            let centered = packet.arrival - x_avg;
            centered * centered
        })
        .sum();
    (denominator != 0.0).then_some(numerator / denominator)
}

fn i64_to_f64(value: i64) -> f64 {
    i32::try_from(value).map_or_else(
        |_| {
            if value.is_negative() {
                f64::from(i32::MIN)
            } else {
                f64::from(i32::MAX)
            }
        },
        f64::from,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_overuse_on_growing_arrival_delay() {
        let mut estimator = TrendlineEstimator::default();
        let mut usage = BandwidthUsage::Normal;

        for index in 0_i64..80 {
            usage = estimator.update(15.0, 5.0, index * 5, index * 15, 1200);
        }

        assert_eq!(usage, BandwidthUsage::Overusing);
    }

    #[test]
    fn captured_twcc_stream_matches_reference_within_five_percent() {
        let samples = [
            (0, 0),
            (5, 5),
            (10, 10),
            (15, 15),
            (20, 20),
            (25, 25),
            (30, 31),
            (35, 37),
            (40, 43),
            (45, 49),
            (50, 56),
            (55, 63),
            (60, 70),
            (65, 78),
            (70, 86),
            (75, 95),
            (80, 104),
            (85, 114),
            (90, 124),
            (95, 135),
            (100, 146),
            (105, 158),
            (110, 170),
            (115, 183),
            (120, 196),
        ];
        let reference_bps = 227_045;
        let mut bwe = DelayBasedBwe::new(300_000);
        let mut estimate = bwe.estimate();

        for (send_ms, arrival_ms) in samples {
            estimate = bwe.update(send_ms, arrival_ms, 1200);
        }

        let diff = estimate.bitrate_bps.abs_diff(reference_bps);
        assert!(
            diff.saturating_mul(100) <= reference_bps.saturating_mul(5),
            "estimate={} reference={reference_bps}",
            estimate.bitrate_bps
        );
    }
}
