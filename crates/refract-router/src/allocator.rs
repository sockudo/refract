//! Layer allocation under subscriber bandwidth limits.
//!
//! The allocator greedily chooses incremental layer upgrades with active-speaker
//! seed bonuses, maximizing utility without exceeding each subscriber's BWE.
//!
//! # Examples
//!
//! ```
//! # use std::collections::HashMap;
//! # use refract_router::{
//! #     BandwidthBps, IngressSsrc, Layer, LayerAllocator, LayerId, PublisherTrackId,
//! #     QualityScore, SubscriberSessionId, Subscription,
//! # };
//! let subscription = Subscription::new(
//!     PublisherTrackId::new(1),
//!     SubscriberSessionId::new(2),
//!     IngressSsrc::new(3),
//!     vec![Layer::new(
//!         LayerId::new(0),
//!         BandwidthBps::new(100),
//!         QualityScore::new(10),
//!     )?],
//! )?;
//! let mut bwe = HashMap::new();
//! bwe.insert(SubscriberSessionId::new(2), BandwidthBps::new(100));
//! assert_eq!(
//!     LayerAllocator::default()
//!         .allocate(&[subscription], &bwe, &HashMap::new())
//!         .len(),
//!     1
//! );
//! # Ok::<(), refract_router::RouterError>(())
//! ```

use std::collections::HashMap;

use crate::{
    BandwidthBps, IngressSsrc, Layer, PublisherTrackId, QualityScore, Route, Stability,
    SubscriberSessionId, Subscription,
};

/// Selected allocation for one ingress SSRC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    ingress_ssrc: IngressSsrc,
    route: Route,
}

impl Allocation {
    /// Creates an allocation result.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     Allocation, BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId,
    /// #     QualityScore, Route, SubscriberSessionId,
    /// # };
    /// let route = Route::new(
    ///     PublisherTrackId::new(1),
    ///     SubscriberSessionId::new(2),
    ///     Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?,
    /// );
    /// assert_eq!(
    ///     Allocation::new(IngressSsrc::new(3), route).ingress_ssrc(),
    ///     IngressSsrc::new(3)
    /// );
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn new(ingress_ssrc: IngressSsrc, route: Route) -> Self {
        Self {
            ingress_ssrc,
            route,
        }
    }

    /// Returns the ingress SSRC for this route.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     Allocation, BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId,
    /// #     QualityScore, Route, SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// # let allocation = Allocation::new(IngressSsrc::new(3), route);
    /// assert_eq!(allocation.ingress_ssrc(), IngressSsrc::new(3));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn ingress_ssrc(&self) -> IngressSsrc {
        self.ingress_ssrc
    }

    /// Returns the selected route.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     Allocation, BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId,
    /// #     QualityScore, Route, SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// # let allocation = Allocation::new(IngressSsrc::new(3), route);
    /// assert_eq!(allocation.route().subscriber_session(), SubscriberSessionId::new(2));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn route(&self) -> &Route {
        &self.route
    }

    /// Consumes the allocation and returns the selected route.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     Allocation, BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId,
    /// #     QualityScore, Route, SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// # let allocation = Allocation::new(IngressSsrc::new(3), route);
    /// assert_eq!(allocation.into_route().publisher_track(), PublisherTrackId::new(1));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn into_route(self) -> Route {
        self.route
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     Allocation, BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId,
    /// #     QualityScore, Route, Stability, SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// # let allocation = Allocation::new(IngressSsrc::new(3), route);
    /// assert_eq!(allocation.stability(), Stability::Stage1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Greedy layer allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct LayerAllocator;

impl LayerAllocator {
    /// Allocates routes subject to each subscriber's bandwidth estimate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::HashMap;
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerAllocator, LayerId, PublisherTrackId,
    /// #     QualityScore, SubscriberSessionId, Subscription,
    /// # };
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
    /// let mut bwe = HashMap::new();
    /// bwe.insert(SubscriberSessionId::new(2), BandwidthBps::new(10));
    /// assert_eq!(
    ///     LayerAllocator
    ///         .allocate(&[subscription], &bwe, &HashMap::new())
    ///         .len(),
    ///     1
    /// );
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub fn allocate(
        self,
        subscriptions: &[Subscription],
        bandwidth_by_subscriber: &HashMap<SubscriberSessionId, BandwidthBps>,
        speaker_scores: &HashMap<PublisherTrackId, QualityScore>,
    ) -> Vec<Allocation> {
        let mut subscribers: Vec<_> = bandwidth_by_subscriber.keys().copied().collect();
        subscribers.sort_unstable();
        subscribers
            .into_iter()
            .flat_map(|subscriber| {
                let budget = bandwidth_by_subscriber[&subscriber];
                let entries: Vec<_> = subscriptions
                    .iter()
                    .filter(|subscription| subscription.subscriber_session() == subscriber)
                    .collect();
                allocate_for_subscriber(entries.as_slice(), budget, speaker_scores)
            })
            .collect()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{LayerAllocator, Stability};
    /// assert_eq!(LayerAllocator.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Upgrade {
    subscription_index: usize,
    layer_index: usize,
    delta_bandwidth: u64,
    delta_score: u32,
    active_score: u32,
}

fn allocate_for_subscriber(
    subscriptions: &[&Subscription],
    budget: BandwidthBps,
    speaker_scores: &HashMap<PublisherTrackId, QualityScore>,
) -> Vec<Allocation> {
    let mut selected = vec![None; subscriptions.len()];
    let mut remaining = budget.as_u64();

    while let Some(upgrade) = best_upgrade(subscriptions, &selected, remaining, speaker_scores) {
        selected[upgrade.subscription_index] = Some(upgrade.layer_index);
        remaining = remaining.saturating_sub(upgrade.delta_bandwidth);
    }

    subscriptions
        .iter()
        .zip(selected)
        .filter_map(|(subscription, maybe_index)| {
            maybe_index.map(|index| {
                Allocation::new(
                    subscription.ingress_ssrc(),
                    Route::new(
                        subscription.publisher_track(),
                        subscription.subscriber_session(),
                        subscription.layers()[index],
                    ),
                )
            })
        })
        .collect()
}

fn best_upgrade(
    subscriptions: &[&Subscription],
    selected: &[Option<usize>],
    remaining: u64,
    speaker_scores: &HashMap<PublisherTrackId, QualityScore>,
) -> Option<Upgrade> {
    subscriptions
        .iter()
        .enumerate()
        .filter_map(|(index, subscription)| {
            let next_index = selected[index].map_or(0, |current| current.saturating_add(1));
            let next = *subscription.layers().get(next_index)?;
            let previous = selected[index].map(|current| subscription.layers()[current]);
            let previous_bandwidth = previous.map_or(0, |layer| layer.bandwidth().as_u64());
            let delta_bandwidth = next.bandwidth().as_u64().saturating_sub(previous_bandwidth);
            if delta_bandwidth == 0 || delta_bandwidth > remaining {
                return None;
            }
            let previous_quality = previous.map_or(QualityScore::new(0), Layer::quality);
            let seed = previous.map_or_else(
                || {
                    speaker_scores
                        .get(&subscription.publisher_track())
                        .copied()
                        .unwrap_or(QualityScore::new(0))
                },
                |_layer| QualityScore::new(0),
            );
            let delta_score = next
                .quality()
                .saturating_sub(previous_quality)
                .saturating_add(seed)
                .as_u32();
            Some(Upgrade {
                subscription_index: index,
                layer_index: next_index,
                delta_bandwidth,
                delta_score,
                active_score: seed.as_u32(),
            })
        })
        .max_by(compare_upgrade)
}

fn compare_upgrade(left: &Upgrade, right: &Upgrade) -> std::cmp::Ordering {
    let left_weighted = u128::from(left.delta_score) * u128::from(right.delta_bandwidth);
    let right_weighted = u128::from(right.delta_score) * u128::from(left.delta_bandwidth);
    left_weighted
        .cmp(&right_weighted)
        .then_with(|| left.active_score.cmp(&right.active_score))
        .then_with(|| right.delta_bandwidth.cmp(&left.delta_bandwidth))
        .then_with(|| right.subscription_index.cmp(&left.subscription_index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LayerId, RouterResult};

    fn layer(id: u8, bandwidth: u64, quality: u32) -> RouterResult<Layer> {
        Layer::new(
            LayerId::new(id),
            BandwidthBps::new(bandwidth),
            QualityScore::new(quality),
        )
    }

    fn subscription(
        track: u64,
        subscriber: u64,
        ssrc: u32,
        layers: Vec<Layer>,
    ) -> RouterResult<Subscription> {
        Subscription::new(
            PublisherTrackId::new(track),
            SubscriberSessionId::new(subscriber),
            IngressSsrc::new(ssrc),
            layers,
        )
    }

    #[test]
    fn allocator_prefers_active_speaker_seed() -> RouterResult<()> {
        let subscriptions = vec![
            subscription(1, 9, 11, vec![layer(0, 100, 10)?])?,
            subscription(2, 9, 22, vec![layer(0, 100, 10)?])?,
        ];
        let mut bwe = HashMap::new();
        bwe.insert(SubscriberSessionId::new(9), BandwidthBps::new(100));
        let mut speakers = HashMap::new();
        speakers.insert(PublisherTrackId::new(2), QualityScore::new(1_000));

        let allocation = LayerAllocator.allocate(&subscriptions, &bwe, &speakers);

        assert_eq!(allocation.len(), 1);
        assert_eq!(
            allocation[0].route().publisher_track(),
            PublisherTrackId::new(2)
        );
        Ok(())
    }

    #[test]
    fn allocator_upgrades_quality_with_remaining_budget() -> RouterResult<()> {
        let subscriptions = vec![subscription(
            1,
            9,
            11,
            vec![layer(0, 100, 10)?, layer(1, 200, 30)?],
        )?];
        let mut bwe = HashMap::new();
        bwe.insert(SubscriberSessionId::new(9), BandwidthBps::new(200));

        let allocation = LayerAllocator.allocate(&subscriptions, &bwe, &HashMap::new());

        assert_eq!(allocation.len(), 1);
        assert_eq!(allocation[0].route().layer().id(), LayerId::new(1));
        Ok(())
    }

    #[test]
    fn allocator_keeps_within_bandwidth() -> RouterResult<()> {
        let subscriptions = vec![
            subscription(1, 9, 11, vec![layer(0, 100, 50)?])?,
            subscription(2, 9, 22, vec![layer(0, 100, 40)?])?,
        ];
        let mut bwe = HashMap::new();
        bwe.insert(SubscriberSessionId::new(9), BandwidthBps::new(100));

        let allocation = LayerAllocator.allocate(&subscriptions, &bwe, &HashMap::new());

        assert_eq!(allocation.len(), 1);
        assert_eq!(
            allocation[0].route().publisher_track(),
            PublisherTrackId::new(1)
        );
        Ok(())
    }
}
