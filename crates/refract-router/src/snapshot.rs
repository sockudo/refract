//! Immutable routing snapshots published to hot-path readers.
//!
//! # Examples
//!
//! ```
//! # use refract_router::{IngressSsrc, RoutingSnapshot};
//! let snapshot = RoutingSnapshot::empty();
//! assert!(snapshot.routes_for(IngressSsrc::new(1)).is_empty());
//! ```

use std::{collections::HashMap, ops::Deref, sync::Arc};

use arc_swap::Guard;

use crate::{IngressSsrc, Route, Stability};

/// Immutable route map used by hot-path forwarding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingSnapshot {
    routes_by_ssrc: HashMap<IngressSsrc, Box<[Route]>>,
    route_count: usize,
}

impl RoutingSnapshot {
    /// Creates an empty routing snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingSnapshot;
    /// assert_eq!(RoutingSnapshot::empty().route_count(), 0);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a snapshot from grouped routes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingSnapshot;
    /// let snapshot = RoutingSnapshot::from_routes(Vec::new());
    /// assert_eq!(snapshot.ssrc_count(), 0);
    /// ```
    #[must_use]
    pub fn from_routes(routes: Vec<(IngressSsrc, Route)>) -> Self {
        let mut grouped: HashMap<IngressSsrc, Vec<Route>> = HashMap::new();
        for (ssrc, route) in routes {
            grouped.entry(ssrc).or_default().push(route);
        }
        let route_count = grouped.values().map(Vec::len).sum();
        let routes_by_ssrc = grouped
            .into_iter()
            .map(|(ssrc, mut routes)| {
                routes.sort_unstable_by_key(|route| {
                    (
                        route.subscriber_session().as_u64(),
                        route.publisher_track().as_u64(),
                        route.layer().id().as_u8(),
                    )
                });
                (ssrc, routes.into_boxed_slice())
            })
            .collect();
        Self {
            routes_by_ssrc,
            route_count,
        }
    }

    /// Returns routes for one ingress SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{IngressSsrc, RoutingSnapshot};
    /// assert!(
    ///     RoutingSnapshot::empty()
    ///         .routes_for(IngressSsrc::new(1))
    ///         .is_empty()
    /// );
    /// ```
    #[must_use]
    pub fn routes_for(&self, ssrc: IngressSsrc) -> &[Route] {
        self.routes_by_ssrc.get(&ssrc).map_or(&[], Deref::deref)
    }

    /// Returns the number of ingress SSRC keys.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingSnapshot;
    /// assert_eq!(RoutingSnapshot::empty().ssrc_count(), 0);
    /// ```
    #[must_use]
    pub fn ssrc_count(&self) -> usize {
        self.routes_by_ssrc.len()
    }

    /// Returns the total number of routes in the snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RoutingSnapshot;
    /// assert_eq!(RoutingSnapshot::empty().route_count(), 0);
    /// ```
    #[must_use]
    pub const fn route_count(&self) -> usize {
        self.route_count
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{RoutingSnapshot, Stability};
    /// assert_eq!(RoutingSnapshot::empty().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Guarded hot-path route view.
///
/// This type dereferences to `[Route]` and keeps the `ArcSwap` snapshot guard
/// alive for the duration of the borrow.
#[derive(Debug)]
pub struct RouteSet {
    snapshot: Guard<Arc<RoutingSnapshot>>,
    ssrc: IngressSsrc,
}

impl RouteSet {
    /// Creates a guarded route view.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use arc_swap::ArcSwap;
    /// # use refract_router::{IngressSsrc, RouteSet, RoutingSnapshot};
    /// let swap = ArcSwap::from_pointee(RoutingSnapshot::empty());
    /// let routes = RouteSet::new(swap.load(), IngressSsrc::new(1));
    /// assert!(routes.as_slice().is_empty());
    /// ```
    #[must_use]
    pub const fn new(snapshot: Guard<Arc<RoutingSnapshot>>, ssrc: IngressSsrc) -> Self {
        Self { snapshot, ssrc }
    }

    /// Returns the route slice for the guarded snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use arc_swap::ArcSwap;
    /// # use refract_router::{IngressSsrc, RouteSet, RoutingSnapshot};
    /// let swap = ArcSwap::from_pointee(RoutingSnapshot::empty());
    /// assert!(
    ///     RouteSet::new(swap.load(), IngressSsrc::new(1))
    ///         .as_slice()
    ///         .is_empty()
    /// );
    /// ```
    #[must_use]
    pub fn as_slice(&self) -> &[Route] {
        self.snapshot.routes_for(self.ssrc)
    }

    /// Returns whether there are no routes for this SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use arc_swap::ArcSwap;
    /// # use refract_router::{IngressSsrc, RouteSet, RoutingSnapshot};
    /// let swap = ArcSwap::from_pointee(RoutingSnapshot::empty());
    /// assert!(RouteSet::new(swap.load(), IngressSsrc::new(1)).is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Returns the number of routes for this SSRC.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use arc_swap::ArcSwap;
    /// # use refract_router::{IngressSsrc, RouteSet, RoutingSnapshot};
    /// let swap = ArcSwap::from_pointee(RoutingSnapshot::empty());
    /// assert_eq!(RouteSet::new(swap.load(), IngressSsrc::new(1)).len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use arc_swap::ArcSwap;
    /// # use refract_router::{IngressSsrc, RouteSet, RoutingSnapshot, Stability};
    /// let swap = ArcSwap::from_pointee(RoutingSnapshot::empty());
    /// assert_eq!(
    ///     RouteSet::new(swap.load(), IngressSsrc::new(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Deref for RouteSet {
    type Target = [Route];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[Route]> for RouteSet {
    fn as_ref(&self) -> &[Route] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BandwidthBps, Layer, LayerId, PublisherTrackId, QualityScore, SubscriberSessionId,
    };

    fn route(subscriber: u64) -> Route {
        Route::new(
            PublisherTrackId::new(1),
            SubscriberSessionId::new(subscriber),
            Layer::new(
                LayerId::new(0),
                BandwidthBps::new(100),
                QualityScore::new(1),
            )
            .unwrap(),
        )
    }

    #[test]
    fn groups_routes_by_ssrc() {
        let snapshot = RoutingSnapshot::from_routes(vec![
            (IngressSsrc::new(9), route(2)),
            (IngressSsrc::new(9), route(1)),
        ]);

        assert_eq!(snapshot.ssrc_count(), 1);
        assert_eq!(snapshot.route_count(), 2);
        assert_eq!(
            snapshot.routes_for(IngressSsrc::new(9))[0].subscriber_session(),
            SubscriberSessionId::new(1)
        );
    }
}
