//! Strongly typed identifiers and route descriptors.
//!
//! # Examples
//!
//! ```
//! # use refract_router::{BandwidthBps, Layer, LayerId, QualityScore};
//! let layer = Layer::new(
//!     LayerId::new(1),
//!     BandwidthBps::new(250_000),
//!     QualityScore::new(50),
//! )?;
//! assert_eq!(layer.id(), LayerId::new(1));
//! # Ok::<(), refract_router::RouterError>(())
//! ```

use crate::{RouterError, RouterResult, Stability};

/// Maximum number of layers accepted for one subscription.
pub const MAX_LAYERS_PER_SUBSCRIPTION: usize = 8;

/// RTP SSRC observed on ingress for one publisher track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IngressSsrc(u32);

impl IngressSsrc {
    /// Creates an ingress SSRC identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::IngressSsrc;
    /// assert_eq!(IngressSsrc::new(123).as_u32(), 123);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::IngressSsrc;
    /// assert_eq!(IngressSsrc::new(99).as_u32(), 99);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{IngressSsrc, Stability};
    /// assert_eq!(IngressSsrc::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Publisher track identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublisherTrackId(u64);

impl PublisherTrackId {
    /// Creates a publisher track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::PublisherTrackId;
    /// assert_eq!(PublisherTrackId::new(7).as_u64(), 7);
    /// ```
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::PublisherTrackId;
    /// assert_eq!(PublisherTrackId::new(9).as_u64(), 9);
    /// ```
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{PublisherTrackId, Stability};
    /// assert_eq!(PublisherTrackId::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Subscriber session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriberSessionId(u64);

impl SubscriberSessionId {
    /// Creates a subscriber session identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::SubscriberSessionId;
    /// assert_eq!(SubscriberSessionId::new(11).as_u64(), 11);
    /// ```
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::SubscriberSessionId;
    /// assert_eq!(SubscriberSessionId::new(11).as_u64(), 11);
    /// ```
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{Stability, SubscriberSessionId};
    /// assert_eq!(SubscriberSessionId::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Semantic layer identifier inside one publisher track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayerId(u8);

impl LayerId {
    /// Creates a layer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::LayerId;
    /// assert_eq!(LayerId::new(2).as_u8(), 2);
    /// ```
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::LayerId;
    /// assert_eq!(LayerId::new(2).as_u8(), 2);
    /// ```
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{LayerId, Stability};
    /// assert_eq!(LayerId::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Bandwidth in bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BandwidthBps(u64);

impl BandwidthBps {
    /// Creates a bandwidth value in bits per second.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::BandwidthBps;
    /// assert_eq!(BandwidthBps::new(1000).as_u64(), 1000);
    /// ```
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw bits-per-second value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::BandwidthBps;
    /// assert_eq!(BandwidthBps::new(1000).as_u64(), 1000);
    /// ```
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, Stability};
    /// assert_eq!(BandwidthBps::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Utility score for an allocated layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualityScore(u32);

impl QualityScore {
    /// Creates a quality score.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::QualityScore;
    /// assert_eq!(QualityScore::new(42).as_u32(), 42);
    /// ```
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw score.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::QualityScore;
    /// assert_eq!(QualityScore::new(42).as_u32(), 42);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Saturating score addition.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::QualityScore;
    /// assert_eq!(
    ///     QualityScore::new(40)
    ///         .saturating_add(QualityScore::new(2))
    ///         .as_u32(),
    ///     42
    /// );
    /// ```
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating score subtraction.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::QualityScore;
    /// assert_eq!(
    ///     QualityScore::new(40)
    ///         .saturating_sub(QualityScore::new(50))
    ///         .as_u32(),
    ///     0
    /// );
    /// ```
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{QualityScore, Stability};
    /// assert_eq!(QualityScore::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// A routable media layer and its allocator cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Layer {
    id: LayerId,
    bandwidth: BandwidthBps,
    quality: QualityScore,
}

impl Layer {
    /// Creates a routable layer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, Layer, LayerId, QualityScore};
    /// let layer = Layer::new(
    ///     LayerId::new(0),
    ///     BandwidthBps::new(80_000),
    ///     QualityScore::new(5),
    /// )?;
    /// assert_eq!(layer.bandwidth(), BandwidthBps::new(80_000));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::InvalidConfig`] when bandwidth is zero.
    pub const fn new(
        id: LayerId,
        bandwidth: BandwidthBps,
        quality: QualityScore,
    ) -> RouterResult<Self> {
        if bandwidth.as_u64() == 0 {
            return Err(RouterError::InvalidConfig {
                field: "layer_bandwidth",
            });
        }
        Ok(Self {
            id,
            bandwidth,
            quality,
        })
    }

    /// Returns the layer identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, Layer, LayerId, QualityScore};
    /// # let layer = Layer::new(LayerId::new(2), BandwidthBps::new(1), QualityScore::new(1))?;
    /// assert_eq!(layer.id(), LayerId::new(2));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn id(self) -> LayerId {
        self.id
    }

    /// Returns the bandwidth cost.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, Layer, LayerId, QualityScore};
    /// # let layer = Layer::new(LayerId::new(2), BandwidthBps::new(10), QualityScore::new(1))?;
    /// assert_eq!(layer.bandwidth(), BandwidthBps::new(10));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn bandwidth(self) -> BandwidthBps {
        self.bandwidth
    }

    /// Returns the allocator quality score.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, Layer, LayerId, QualityScore};
    /// # let layer = Layer::new(LayerId::new(2), BandwidthBps::new(10), QualityScore::new(9))?;
    /// assert_eq!(layer.quality(), QualityScore::new(9));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn quality(self) -> QualityScore {
        self.quality
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{BandwidthBps, Layer, LayerId, QualityScore, Stability};
    /// # let layer = Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?;
    /// assert_eq!(layer.stability(), Stability::Stage1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// A forwarding route from one publisher track to one subscriber at one layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    publisher_track: PublisherTrackId,
    subscriber_session: SubscriberSessionId,
    layer: Layer,
}

impl Route {
    /// Creates a route descriptor.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, Route,
    /// #     SubscriberSessionId,
    /// # };
    /// let route = Route::new(
    ///     PublisherTrackId::new(1),
    ///     SubscriberSessionId::new(2),
    ///     Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?,
    /// );
    /// assert_eq!(route.publisher_track(), PublisherTrackId::new(1));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn new(
        publisher_track: PublisherTrackId,
        subscriber_session: SubscriberSessionId,
        layer: Layer,
    ) -> Self {
        Self {
            publisher_track,
            subscriber_session,
            layer,
        }
    }

    /// Returns the publisher track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, Route,
    /// #     SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// assert_eq!(route.publisher_track(), PublisherTrackId::new(1));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn publisher_track(&self) -> PublisherTrackId {
        self.publisher_track
    }

    /// Returns the subscriber session identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, Route,
    /// #     SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// assert_eq!(route.subscriber_session(), SubscriberSessionId::new(2));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn subscriber_session(&self) -> SubscriberSessionId {
        self.subscriber_session
    }

    /// Returns the selected layer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, Route,
    /// #     SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(7), BandwidthBps::new(1), QualityScore::new(1))?);
    /// assert_eq!(route.layer().id(), LayerId::new(7));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn layer(&self) -> Layer {
        self.layer
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, Route, Stability,
    /// #     SubscriberSessionId,
    /// # };
    /// # let route = Route::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), Layer::new(LayerId::new(0), BandwidthBps::new(1), QualityScore::new(1))?);
    /// assert_eq!(route.stability(), Stability::Stage1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Slow-path subscription descriptor used by the allocator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    publisher_track: PublisherTrackId,
    subscriber_session: SubscriberSessionId,
    ingress_ssrc: IngressSsrc,
    layers: Box<[Layer]>,
}

impl Subscription {
    /// Creates a bounded subscription and sorts layers by bandwidth.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId, Subscription,
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
    /// assert_eq!(subscription.layers().len(), 1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RouterError::EmptyLayers`] for empty layer sets,
    /// [`RouterError::TooManyLayers`] when the layer bound is exceeded, and
    /// [`RouterError::InvalidConfig`] for duplicate layer bandwidths.
    pub fn new(
        publisher_track: PublisherTrackId,
        subscriber_session: SubscriberSessionId,
        ingress_ssrc: IngressSsrc,
        mut layers: Vec<Layer>,
    ) -> RouterResult<Self> {
        validate_layers(&mut layers)?;
        Ok(Self {
            publisher_track,
            subscriber_session,
            ingress_ssrc,
            layers: layers.into_boxed_slice(),
        })
    }

    /// Returns the publisher track identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId, Subscription,
    /// # };
    /// # let subscription = Subscription::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), IngressSsrc::new(3), vec![Layer::new(LayerId::new(0), BandwidthBps::new(10), QualityScore::new(1))?])?;
    /// assert_eq!(subscription.publisher_track(), PublisherTrackId::new(1));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn publisher_track(&self) -> PublisherTrackId {
        self.publisher_track
    }

    /// Returns the subscriber session identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId, Subscription,
    /// # };
    /// # let subscription = Subscription::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), IngressSsrc::new(3), vec![Layer::new(LayerId::new(0), BandwidthBps::new(10), QualityScore::new(1))?])?;
    /// assert_eq!(subscription.subscriber_session(), SubscriberSessionId::new(2));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn subscriber_session(&self) -> SubscriberSessionId {
        self.subscriber_session
    }

    /// Returns the ingress SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId, Subscription,
    /// # };
    /// # let subscription = Subscription::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), IngressSsrc::new(3), vec![Layer::new(LayerId::new(0), BandwidthBps::new(10), QualityScore::new(1))?])?;
    /// assert_eq!(subscription.ingress_ssrc(), IngressSsrc::new(3));
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn ingress_ssrc(&self) -> IngressSsrc {
        self.ingress_ssrc
    }

    /// Returns routable layers sorted by bandwidth.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
    /// #     SubscriberSessionId, Subscription,
    /// # };
    /// # let subscription = Subscription::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), IngressSsrc::new(3), vec![Layer::new(LayerId::new(0), BandwidthBps::new(10), QualityScore::new(1))?])?;
    /// assert_eq!(subscription.layers().len(), 1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{
    /// #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore, Stability,
    /// #     SubscriberSessionId, Subscription,
    /// # };
    /// # let subscription = Subscription::new(PublisherTrackId::new(1), SubscriberSessionId::new(2), IngressSsrc::new(3), vec![Layer::new(LayerId::new(0), BandwidthBps::new(10), QualityScore::new(1))?])?;
    /// assert_eq!(subscription.stability(), Stability::Stage1);
    /// # Ok::<(), refract_router::RouterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

fn validate_layers(layers: &mut [Layer]) -> RouterResult<()> {
    if layers.is_empty() {
        return Err(RouterError::EmptyLayers);
    }
    if layers.len() > MAX_LAYERS_PER_SUBSCRIPTION {
        return Err(RouterError::TooManyLayers {
            len: layers.len(),
            max: MAX_LAYERS_PER_SUBSCRIPTION,
        });
    }
    layers.sort_unstable_by_key(|layer| (layer.bandwidth().as_u64(), layer.id().as_u8()));
    if layers
        .windows(2)
        .any(|window| window[0].bandwidth() == window[1].bandwidth())
    {
        return Err(RouterError::InvalidConfig {
            field: "layer_bandwidth",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(id: u8, bandwidth: u64, quality: u32) -> Layer {
        Layer::new(
            LayerId::new(id),
            BandwidthBps::new(bandwidth),
            QualityScore::new(quality),
        )
        .unwrap()
    }

    #[test]
    fn subscription_sorts_layers_by_bandwidth() {
        let subscription = Subscription::new(
            PublisherTrackId::new(1),
            SubscriberSessionId::new(2),
            IngressSsrc::new(3),
            vec![layer(2, 300, 3), layer(0, 100, 1), layer(1, 200, 2)],
        )
        .unwrap();

        assert_eq!(subscription.layers()[0].id(), LayerId::new(0));
        assert_eq!(subscription.layers()[2].id(), LayerId::new(2));
    }

    #[test]
    fn rejects_empty_and_duplicate_layers() {
        assert!(matches!(
            Subscription::new(
                PublisherTrackId::new(1),
                SubscriberSessionId::new(2),
                IngressSsrc::new(3),
                Vec::new()
            ),
            Err(RouterError::EmptyLayers)
        ));
        assert!(matches!(
            Subscription::new(
                PublisherTrackId::new(1),
                SubscriberSessionId::new(2),
                IngressSsrc::new(3),
                vec![layer(0, 100, 1), layer(1, 100, 2)]
            ),
            Err(RouterError::InvalidConfig {
                field: "layer_bandwidth"
            })
        ));
    }
}
