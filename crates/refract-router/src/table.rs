//! Per-core, per-room routing table with lock-free readers.
//!
//! Slow-path methods mutate local state and publish a new immutable snapshot
//! whenever subscriptions, layers, active speakers, or material BWE changes
//! require reallocation.
//!
//! # Examples
//!
//! ```
//! # use refract_router::{RoutingTable, IngressSsrc};
//! let table = RoutingTable::new();
//! assert!(table.routes_for(IngressSsrc::new(1)).is_empty());
//! ```

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;

use crate::{
    ActiveSpeakerTracker, AudioLevel, BandwidthBps, IngressSsrc, LayerAllocator, PublisherTrackId,
    RouteSet, RouterError, RouterResult, RoutingSnapshot, Stability, SubscriberSessionId,
    Subscription,
};

/// Default maximum number of subscriptions per per-core routing table.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 4_096;

/// Default subscriber bandwidth used until the first BWE update arrives.
pub const DEFAULT_SUBSCRIBER_BWE: BandwidthBps = BandwidthBps::new(500_000);

const BWE_REALLOCATION_PERCENT: u64 = 10;

/// Routing table configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingTableConfig {
    max_subscriptions: usize,
    active_speaker_top_k: usize,
}

impl Default for RoutingTableConfig {
    fn default() -> Self {
        Self {
            max_subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
            active_speaker_top_k: crate::DEFAULT_TOP_SPEAKERS,
        }
    }
}

impl RoutingTableConfig {
    /// Creates a routing table configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTableConfig;
    /// assert_eq!(RoutingTableConfig::new(16, 2)?.max_subscriptions(), 16);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::InvalidConfig`] when either bound is zero.
    pub const fn new(max_subscriptions: usize, active_speaker_top_k: usize) -> RouterResult<Self> {
        if max_subscriptions == 0 {
            return Err(RouterError::InvalidConfig {
                field: "max_subscriptions",
            });
        }
        if active_speaker_top_k == 0 {
            return Err(RouterError::InvalidConfig {
                field: "active_speaker_top_k",
            });
        }
        Ok(Self {
            max_subscriptions,
            active_speaker_top_k,
        })
    }

    /// Returns the subscription cap.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTableConfig;
    /// assert_eq!(RoutingTableConfig::new(16, 2)?.max_subscriptions(), 16);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn max_subscriptions(self) -> usize {
        self.max_subscriptions
    }

    /// Returns the active-speaker top-K setting.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTableConfig;
    /// assert_eq!(RoutingTableConfig::new(16, 2)?.active_speaker_top_k(), 2);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn active_speaker_top_k(self) -> usize {
        self.active_speaker_top_k
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{RoutingTableConfig, Stability};
    /// assert_eq!(RoutingTableConfig::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Per-core, per-room routing table.
pub struct RoutingTable {
    config: RoutingTableConfig,
    snapshot: ArcSwap<RoutingSnapshot>,
    subscriptions: Vec<Subscription>,
    bandwidth_by_subscriber: HashMap<SubscriberSessionId, BandwidthBps>,
    active_speakers: ActiveSpeakerTracker,
}

impl std::fmt::Debug for RoutingTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoutingTable")
            .field("config", &self.config)
            .field("subscriptions", &self.subscriptions.len())
            .field(
                "bandwidth_by_subscriber",
                &self.bandwidth_by_subscriber.len(),
            )
            .field("active_speakers", &self.active_speakers.top_speakers())
            .finish_non_exhaustive()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    /// Creates a routing table with default bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTable;
    /// assert_eq!(RoutingTable::new().subscription_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RoutingTableConfig::default(),
            snapshot: ArcSwap::from_pointee(RoutingSnapshot::empty()),
            subscriptions: Vec::new(),
            bandwidth_by_subscriber: HashMap::new(),
            active_speakers: ActiveSpeakerTracker::default(),
        }
    }

    /// Creates a routing table with explicit bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{RoutingTable, RoutingTableConfig};
    /// let table = RoutingTable::with_config(RoutingTableConfig::new(16, 2)?)?;
    /// assert_eq!(table.config().max_subscriptions(), 16);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::InvalidConfig`] if active-speaker configuration is invalid.
    pub fn with_config(config: RoutingTableConfig) -> RouterResult<Self> {
        Ok(Self {
            config,
            snapshot: ArcSwap::from_pointee(RoutingSnapshot::empty()),
            subscriptions: Vec::new(),
            bandwidth_by_subscriber: HashMap::new(),
            active_speakers: ActiveSpeakerTracker::new(
                config.active_speaker_top_k(),
                crate::DEFAULT_EWMA_OLD_WEIGHT,
            )?,
        })
    }

    /// Returns the routing table configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTable;
    /// assert!(RoutingTable::new().config().max_subscriptions() > 0);
    /// ```
    #[must_use]
    pub const fn config(&self) -> RoutingTableConfig {
        self.config
    }

    /// Returns the hot-path routes for an ingress SSRC.
    ///
    /// The returned [`RouteSet`] keeps the snapshot alive and dereferences to
    /// `[Route]`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{IngressSsrc, RoutingTable};
    /// assert!(
    ///     RoutingTable::new()
    ///         .routes_for(IngressSsrc::new(1))
    ///         .is_empty()
    /// );
    /// ```
    #[must_use]
    pub fn routes_for(&self, ssrc: IngressSsrc) -> RouteSet {
        RouteSet::new(self.snapshot.load(), ssrc)
    }

    /// Returns a full snapshot clone for diagnostics and tests.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTable;
    /// assert_eq!(RoutingTable::new().snapshot().route_count(), 0);
    /// ```
    #[must_use]
    pub fn snapshot(&self) -> Arc<RoutingSnapshot> {
        self.snapshot.load_full()
    }

    /// Adds or replaces a subscription and publishes a new snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     RoutingTable, SubscriberSessionId, Subscription,
    /// # };
    /// let mut table = RoutingTable::new();
    /// let subscription = Subscription::new(
    ///     PublisherTrackId::new(1),
    ///     SubscriberSessionId::new(2),
    ///     IngressSsrc::new(3),
    ///     vec![Layer::new(
    ///         LayerId::new(0),
    ///         BandwidthBps::new(10),
    ///         QualityScore::new(1),
    ///     )?],
    /// )?;
    /// assert!(table.add_subscription(subscription)?);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::Capacity`] when the configured subscription cap is reached.
    pub fn add_subscription(&mut self, subscription: Subscription) -> RouterResult<bool> {
        if let Some(existing) = self.subscriptions.iter_mut().find(|existing| {
            existing.publisher_track() == subscription.publisher_track()
                && existing.subscriber_session() == subscription.subscriber_session()
        }) {
            *existing = subscription;
            self.publish_snapshot();
            return Ok(true);
        }
        if self.subscriptions.len() == self.config.max_subscriptions() {
            return Err(RouterError::Capacity {
                component: "subscriptions",
                len: self.subscriptions.len(),
                max: self.config.max_subscriptions(),
            });
        }
        self.bandwidth_by_subscriber
            .entry(subscription.subscriber_session())
            .or_insert(DEFAULT_SUBSCRIBER_BWE);
        self.subscriptions.push(subscription);
        self.publish_snapshot();
        Ok(true)
    }

    /// Removes a subscription and publishes a new snapshot if it existed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{PublisherTrackId, RoutingTable, SubscriberSessionId};
    /// let mut table = RoutingTable::new();
    /// assert!(!table.remove(PublisherTrackId::new(1), SubscriberSessionId::new(2)));
    /// ```
    #[must_use]
    pub fn remove(
        &mut self,
        publisher_track: PublisherTrackId,
        subscriber_session: SubscriberSessionId,
    ) -> bool {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|subscription| {
            subscription.publisher_track() != publisher_track
                || subscription.subscriber_session() != subscriber_session
        });
        let changed = self.subscriptions.len() != before;
        if changed {
            self.publish_snapshot();
        }
        changed
    }

    /// Updates subscriber BWE and reallocates when the delta exceeds 10%.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, RoutingTable, SubscriberSessionId};
    /// let mut table = RoutingTable::new();
    /// assert!(table.update_bwe(SubscriberSessionId::new(1), BandwidthBps::new(100_000)));
    /// assert!(!table.update_bwe(SubscriberSessionId::new(1), BandwidthBps::new(105_000)));
    /// ```
    #[must_use]
    pub fn update_bwe(&mut self, subscriber: SubscriberSessionId, bandwidth: BandwidthBps) -> bool {
        let should_publish = self
            .bandwidth_by_subscriber
            .get(&subscriber)
            .is_none_or(|old| should_reallocate_bwe(*old, bandwidth));
        if should_publish {
            self.bandwidth_by_subscriber.insert(subscriber, bandwidth);
            self.publish_snapshot();
        }
        should_publish
    }

    /// Updates active-speaker EWMA and reallocates when top-K changes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{AudioLevel, PublisherTrackId, RoutingTable};
    /// let mut table = RoutingTable::new();
    /// assert!(table.observe_audio_level(PublisherTrackId::new(1), AudioLevel::new(0)?));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub fn observe_audio_level(
        &mut self,
        publisher_track: PublisherTrackId,
        level: AudioLevel,
    ) -> bool {
        let changed = self.active_speakers.observe(publisher_track, level);
        if changed {
            self.publish_snapshot();
        }
        changed
    }

    /// Returns the number of slow-path subscriptions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingTable;
    /// assert_eq!(RoutingTable::new().subscription_count(), 0);
    /// ```
    #[must_use]
    pub const fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{RoutingTable, Stability};
    /// assert_eq!(RoutingTable::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn publish_snapshot(&self) {
        let speaker_scores = self.active_speakers.speaker_scores();
        let allocations = LayerAllocator.allocate(
            &self.subscriptions,
            &self.bandwidth_by_subscriber,
            &speaker_scores,
        );
        let routes = allocations
            .into_iter()
            .map(|allocation| (allocation.ingress_ssrc(), allocation.into_route()))
            .collect();
        let snapshot = RoutingSnapshot::from_routes(routes);
        crate::metrics::record_snapshot(snapshot.route_count());
        self.snapshot.store(Arc::new(snapshot));
    }
}

const fn should_reallocate_bwe(old: BandwidthBps, new: BandwidthBps) -> bool {
    let old_value = old.as_u64();
    let new_value = new.as_u64();
    if old_value == 0 {
        return new_value > 0;
    }
    old_value.abs_diff(new_value).saturating_mul(100)
        > old_value.saturating_mul(BWE_REALLOCATION_PERCENT)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc-track")]
    use refract_slab::assert_no_alloc;

    use super::*;
    use crate::{Layer, LayerId, QualityScore};

    #[cfg(feature = "alloc-track")]
    const HOT_PATH_SOAK_READS: usize = 16_384;

    fn layer(id: u8, bandwidth: u64, quality: u32) -> Layer {
        Layer::new(
            LayerId::new(id),
            BandwidthBps::new(bandwidth),
            QualityScore::new(quality),
        )
        .unwrap()
    }

    fn subscription(track: u64, subscriber: u64, ssrc: u32) -> Subscription {
        Subscription::new(
            PublisherTrackId::new(track),
            SubscriberSessionId::new(subscriber),
            IngressSsrc::new(ssrc),
            vec![layer(0, 100, 10)],
        )
        .unwrap()
    }

    #[test]
    fn routes_for_reads_published_snapshot() {
        let mut table = RoutingTable::new();
        table.add_subscription(subscription(1, 2, 3)).unwrap();

        let routes = table.routes_for(IngressSsrc::new(3));

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].subscriber_session(), SubscriberSessionId::new(2));
    }

    #[test]
    fn update_bwe_threshold_controls_reallocation() {
        let mut table = RoutingTable::new();

        assert!(table.update_bwe(SubscriberSessionId::new(1), BandwidthBps::new(100)));
        assert!(!table.update_bwe(SubscriberSessionId::new(1), BandwidthBps::new(110)));
        assert!(table.update_bwe(SubscriberSessionId::new(1), BandwidthBps::new(112)));
    }

    #[test]
    fn reader_survives_writer_update() {
        let mut table = RoutingTable::new();
        table.add_subscription(subscription(1, 2, 3)).unwrap();
        let old_routes = table.routes_for(IngressSsrc::new(3));

        table.add_subscription(subscription(4, 5, 3)).unwrap();

        assert_eq!(old_routes.len(), 1);
        assert_eq!(table.routes_for(IngressSsrc::new(3)).len(), 2);
    }

    #[cfg(feature = "alloc-track")]
    #[test]
    fn read_path_does_not_allocate() {
        let mut table = RoutingTable::new();
        table.add_subscription(subscription(1, 2, 3)).unwrap();
        let warm = table.routes_for(IngressSsrc::new(3));
        assert_eq!(warm.len(), 1);

        let routes = assert_no_alloc!(|| table.routes_for(IngressSsrc::new(3)));

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].subscriber_session(), SubscriberSessionId::new(2));
    }

    #[cfg(feature = "alloc-track")]
    #[test]
    fn read_path_soak_does_not_allocate() {
        let mut table = RoutingTable::new();
        table.add_subscription(subscription(1, 2, 3)).unwrap();
        table.add_subscription(subscription(4, 5, 3)).unwrap();
        let warm = table.routes_for(IngressSsrc::new(3));
        assert_eq!(warm.len(), 2);

        assert_no_alloc!(|| {
            (0..HOT_PATH_SOAK_READS).for_each(|_| {
                let routes = table.routes_for(IngressSsrc::new(3));
                assert_eq!(routes.len(), 2);
            });
        });
    }
}
