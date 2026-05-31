//! Lock-free subscription routing snapshots for per-core forwarding.
//!
//! `refract-router` keeps slow-path subscription, bandwidth, and active-speaker
//! state on one core, then publishes immutable snapshots for the forwarding hot
//! path. Readers use `ArcSwap` snapshot guards and never take a lock.
//!
//! # Examples
//!
//! ```
//! # use refract_router::{
//! #     BandwidthBps, IngressSsrc, Layer, LayerId, PublisherTrackId, QualityScore,
//! #     RoutingTable, SubscriberSessionId, Subscription,
//! # };
//! let mut table = RoutingTable::new();
//! let subscription = Subscription::new(
//!     PublisherTrackId::new(7),
//!     SubscriberSessionId::new(11),
//!     IngressSsrc::new(42),
//!     vec![Layer::new(
//!         LayerId::new(0),
//!         BandwidthBps::new(100_000),
//!         QualityScore::new(10),
//!     )?],
//! )?;
//! assert!(table.add_subscription(subscription)?);
//! assert!(table.update_bwe(SubscriberSessionId::new(11), BandwidthBps::new(700_000)));
//! assert_eq!(table.routes_for(IngressSsrc::new(42)).as_slice().len(), 1);
//! # Ok::<(), refract_router::RouterError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

mod allocator;
mod error;
pub mod metrics;
mod snapshot;
mod speaker;
mod stability;
mod table;
mod types;

pub use allocator::{Allocation, LayerAllocator};
pub use error::{RouterError, RouterResult};
pub use snapshot::{RouteSet, RoutingSnapshot};
pub use speaker::{
    ACTIVE_SPEAKER_BONUS, ActiveSpeakerTracker, AudioLevel, DEFAULT_EWMA_OLD_WEIGHT,
    DEFAULT_TOP_SPEAKERS,
};
pub use stability::Stability;
pub use table::{
    DEFAULT_MAX_SUBSCRIPTIONS, DEFAULT_SUBSCRIBER_BWE, RoutingTable, RoutingTableConfig,
};
pub use types::{
    BandwidthBps, IngressSsrc, Layer, LayerId, MAX_LAYERS_PER_SUBSCRIPTION, PublisherTrackId,
    QualityScore, Route, SubscriberSessionId, Subscription,
};
