//! Stage 1 control plane for cluster membership, placement, health, and
//! snapshot-backed recovery.
//!
//! This crate defines the sacred Stage 1 [`PlacementOracle`] interface and a
//! conservative embedded implementation for the single-edge deployment. The
//! public surface is intentionally small: `OpenRaft` owns consensus semantics,
//! redb persists the local state machine, and Quinn/rustls configuration is
//! kept as a transport boundary without introducing a non-compio runtime in
//! this crate.
//!
//! # Examples
//!
//! ```
//! # use refract_core::{NodeId, RoomId};
//! # use refract_cluster::{EdgeNode, PlacementOracle, SingleEdgePlacementOracle};
//! # compio::runtime::Runtime::new()?.block_on(async {
//! let edge = EdgeNode::new(NodeId::from_raw(1), "127.0.0.1:9000".to_owned())?;
//! let oracle = SingleEdgePlacementOracle::new(edge);
//! let placement = oracle.place_room(RoomId::from_raw(7)).await?;
//! assert_eq!(placement.node(), NodeId::from_raw(1));
//! # Ok::<(), refract_cluster::ClusterError>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use openraft::Config as OpenRaftConfig;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use refract_core::{Layer, NodeId, RoomId, TrackId};
use refract_roomstore::SubscriptionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const STATE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("cluster_state_v1");
const PLACEMENT_PREFIX: &str = "placement/";
const HEALTH_PREFIX: &str = "health/";
const CAPACITY_PREFIX: &str = "capacity/";
const CONFIG_PREFIX: &str = "config/";
const SNAPSHOT_FORMAT_VERSION: u16 = 1;
const MAX_EDGE_ADDRESS_BYTES: usize = 256;
const MAX_CONFIG_KEY_BYTES: usize = 128;
const MAX_CONFIG_VALUE_BYTES: usize = 4096;
/// Maximum bytes retained from an original RTP header for mesh forwarding.
pub const MAX_FORWARDED_RTP_HEADER_BYTES: usize = 256;
/// Maximum decrypted RTP payload bytes accepted by the mesh wire format.
pub const MAX_FORWARDED_RTP_PAYLOAD_BYTES: usize = 2_048;
/// Maximum requested simulcast/SVC layers in one mesh subscription request.
pub const MAX_MESH_LAYERS: usize = 8;
/// Maximum opaque RTCP feedback bytes carried between edge nodes.
pub const MAX_RTCP_FEEDBACK_BYTES: usize = 512;
#[cfg(feature = "cluster-tests")]
const SUPPORTED_CLUSTER_SIZES: [usize; 2] = [3, 5];

/// Result alias for cluster control-plane operations.
pub type ClusterResult<T> = Result<T, ClusterError>;

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns the bounded stability label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Error taxonomy for cluster control-plane operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClusterError {
    /// A configuration field was invalid.
    #[error("invalid configuration: {field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// The configured cluster size is unsupported.
    #[error("unsupported cluster size: {nodes}")]
    InvalidClusterSize {
        /// Rejected node count.
        nodes: usize,
    },
    /// A bounded external input exceeded its limit.
    #[error("input too large: {field}")]
    InputTooLarge {
        /// Oversized field.
        field: &'static str,
    },
    /// A requested node is unknown to the membership set.
    #[error("unknown node: {node}")]
    UnknownNode {
        /// Missing node identifier.
        node: NodeId,
    },
    /// A write was rejected because this side of a partition lacks quorum.
    #[error("raft quorum unavailable for node: {node}")]
    QuorumUnavailable {
        /// Node receiving the rejected write.
        node: NodeId,
    },
    /// A write was rejected because no reachable leader can commit it.
    #[error("raft leader unavailable for node: {node}")]
    LeaderUnavailable {
        /// Node receiving the rejected write.
        node: NodeId,
    },
    /// Persistent state-machine IO failed.
    #[error("state machine storage failed: {message}")]
    Storage {
        /// Storage failure message.
        message: String,
    },
    /// Snapshot encoding or decoding failed.
    #[error("snapshot codec failed: {message}")]
    Snapshot {
        /// Snapshot codec failure message.
        message: String,
    },
    /// `OpenRaft` configuration validation failed.
    #[error("openraft configuration failed: {message}")]
    RaftConfig {
        /// `OpenRaft` validation failure message.
        message: String,
    },
    /// QUIC transport configuration failed.
    #[error("quic transport configuration failed: {message}")]
    QuicConfig {
        /// Quinn/rustls failure message.
        message: String,
    },
    /// Cross-node mesh operation was attempted in the Stage 1 local-only mesh.
    #[error("mesh forwarding is local-only in stage 1")]
    MeshLocalOnly,
}

impl ClusterError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterError;
    /// assert_eq!(
    ///     ClusterError::InvalidConfig { field: "nodes" }.error_code(),
    ///     "CLUSTER_CONFIG_0001",
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "CLUSTER_CONFIG_0001",
            Self::InvalidClusterSize { .. } => "CLUSTER_CONFIG_0002",
            Self::InputTooLarge { .. } => "CLUSTER_INPUT_0001",
            Self::UnknownNode { .. } => "CLUSTER_MEMBERSHIP_0001",
            Self::QuorumUnavailable { .. } => "CLUSTER_RAFT_0001",
            Self::LeaderUnavailable { .. } => "CLUSTER_RAFT_0002",
            Self::Storage { .. } => "CLUSTER_STORAGE_0001",
            Self::Snapshot { .. } => "CLUSTER_SNAPSHOT_0001",
            Self::RaftConfig { .. } => "CLUSTER_RAFT_0003",
            Self::QuicConfig { .. } => "CLUSTER_QUIC_0001",
            Self::MeshLocalOnly => "HSF-MESH-LOCAL",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ClusterError, Stability};
    /// assert_eq!(
    ///     ClusterError::InvalidConfig { field: "x" }.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Stage 1 `OpenRaft` tuning used by every control-plane node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RaftSettings {
    cluster_name: String,
    election_timeout_min: Duration,
    election_timeout_max: Duration,
    heartbeat_interval: Duration,
    snapshot_logs_since_last: u64,
}

impl RaftSettings {
    /// Creates validated `OpenRaft` settings for a control-plane cluster.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] when timing bounds are invalid
    /// or the cluster name is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cluster::RaftSettings;
    /// let settings = RaftSettings::new(
    ///     "refract-stage1".to_owned(),
    ///     Duration::from_millis(150),
    ///     Duration::from_millis(300),
    ///     Duration::from_millis(50),
    ///     5000,
    /// )?;
    /// assert_eq!(settings.cluster_name(), "refract-stage1");
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn new(
        cluster_name: String,
        election_timeout_min: Duration,
        election_timeout_max: Duration,
        heartbeat_interval: Duration,
        snapshot_logs_since_last: u64,
    ) -> ClusterResult<Self> {
        if cluster_name.is_empty() {
            return Err(ClusterError::InvalidConfig {
                field: "cluster_name",
            });
        }
        if election_timeout_min >= election_timeout_max {
            return Err(ClusterError::InvalidConfig {
                field: "election_timeout",
            });
        }
        if election_timeout_min <= heartbeat_interval {
            return Err(ClusterError::InvalidConfig {
                field: "heartbeat_interval",
            });
        }
        if snapshot_logs_since_last == 0 {
            return Err(ClusterError::InvalidConfig {
                field: "snapshot_logs_since_last",
            });
        }
        Ok(Self {
            cluster_name,
            election_timeout_min,
            election_timeout_max,
            heartbeat_interval,
            snapshot_logs_since_last,
        })
    }

    /// Returns the `OpenRaft` cluster name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::RaftSettings;
    /// assert_eq!(RaftSettings::default().cluster_name(), "refract-cluster");
    /// ```
    #[must_use]
    pub fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Builds a validated [`openraft::Config`] from these settings.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::RaftConfig`] if `OpenRaft` rejects the derived
    /// configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::RaftSettings;
    /// let config = RaftSettings::default().to_openraft_config()?;
    /// assert_eq!(config.cluster_name, "refract-cluster");
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn to_openraft_config(&self) -> ClusterResult<OpenRaftConfig> {
        let mut config = OpenRaftConfig::default();
        config.cluster_name.clone_from(&self.cluster_name);
        config.election_timeout_min = millis_u64(self.election_timeout_min)?;
        config.election_timeout_max = millis_u64(self.election_timeout_max)?;
        config.heartbeat_interval = millis_u64(self.heartbeat_interval)?;
        config.snapshot_policy =
            openraft::SnapshotPolicy::LogsSinceLast(self.snapshot_logs_since_last);
        config
            .validate()
            .map_err(|source| ClusterError::RaftConfig {
                message: source.to_string(),
            })
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RaftSettings, Stability};
    /// assert_eq!(RaftSettings::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Default for RaftSettings {
    fn default() -> Self {
        Self {
            cluster_name: "refract-cluster".to_owned(),
            election_timeout_min: Duration::from_millis(150),
            election_timeout_max: Duration::from_millis(300),
            heartbeat_interval: Duration::from_millis(50),
            snapshot_logs_since_last: 5000,
        }
    }
}

/// QUIC transport policy for inter-node control-plane traffic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransportPolicy {
    max_idle_timeout: Duration,
    keep_alive_interval: Duration,
}

impl QuicTransportPolicy {
    /// Creates a bounded Quinn transport policy.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] when a timeout is zero or the
    /// keep-alive interval is not lower than the idle timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cluster::QuicTransportPolicy;
    /// let policy = QuicTransportPolicy::new(Duration::from_secs(30), Duration::from_secs(5))?;
    /// assert_eq!(policy.keep_alive_interval(), Duration::from_secs(5));
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn new(max_idle_timeout: Duration, keep_alive_interval: Duration) -> ClusterResult<Self> {
        if max_idle_timeout.is_zero() {
            return Err(ClusterError::InvalidConfig {
                field: "max_idle_timeout",
            });
        }
        if keep_alive_interval.is_zero() || keep_alive_interval >= max_idle_timeout {
            return Err(ClusterError::InvalidConfig {
                field: "keep_alive_interval",
            });
        }
        Ok(Self {
            max_idle_timeout,
            keep_alive_interval,
        })
    }

    /// Returns the configured keep-alive interval.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cluster::QuicTransportPolicy;
    /// assert_eq!(
    ///     QuicTransportPolicy::default().keep_alive_interval(),
    ///     Duration::from_secs(5),
    /// );
    /// ```
    #[must_use]
    pub const fn keep_alive_interval(&self) -> Duration {
        self.keep_alive_interval
    }

    /// Applies this policy to a Quinn server config built from the shared
    /// rustls QUIC server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::QuicConfig`] if the bounded duration cannot be
    /// represented by Quinn's idle-timeout type.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use refract_cluster::QuicTransportPolicy;
    /// # fn configure(config: &mut quinn::ServerConfig) -> Result<(), refract_cluster::ClusterError> {
    /// QuicTransportPolicy::default().apply_to_server_config(config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn apply_to_server_config(
        &self,
        server_config: &mut quinn::ServerConfig,
    ) -> ClusterResult<()> {
        let idle_timeout =
            quinn::IdleTimeout::try_from(self.max_idle_timeout).map_err(|source| {
                ClusterError::QuicConfig {
                    message: source.to_string(),
                }
            })?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(idle_timeout));
        transport.keep_alive_interval(Some(self.keep_alive_interval));
        server_config.transport_config(Arc::new(transport));
        Ok(())
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{QuicTransportPolicy, Stability};
    /// assert_eq!(
    ///     QuicTransportPolicy::default().stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Default for QuicTransportPolicy {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(5),
        }
    }
}

/// Decrypted media packet carried between edge nodes.
///
/// The wire format deliberately carries the original RTP header and the
/// decrypted RTP payload only. Stage 3 receivers re-encrypt the payload with
/// their local subscriber SRTP context; SRTP keys are never shared between
/// nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardedPacket {
    original_header: [u8; MAX_FORWARDED_RTP_HEADER_BYTES],
    original_header_len: u16,
    decrypted_payload: [u8; MAX_FORWARDED_RTP_PAYLOAD_BYTES],
    decrypted_payload_len: u16,
}

impl ForwardedPacket {
    /// Creates a bounded forwarded media packet.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] when the RTP header is empty and
    /// [`ClusterError::InputTooLarge`] when either byte slice exceeds its
    /// defensive bound.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ForwardedPacket;
    /// let packet = ForwardedPacket::new(&[0x80, 0x60], &[1, 2, 3])?;
    /// assert_eq!(packet.original_header(), &[0x80, 0x60]);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn new(original_header: &[u8], decrypted_payload: &[u8]) -> ClusterResult<Self> {
        if original_header.is_empty() {
            return Err(ClusterError::InvalidConfig {
                field: "original_header",
            });
        }
        if original_header.len() > MAX_FORWARDED_RTP_HEADER_BYTES {
            return Err(ClusterError::InputTooLarge {
                field: "original_header",
            });
        }
        if decrypted_payload.len() > MAX_FORWARDED_RTP_PAYLOAD_BYTES {
            return Err(ClusterError::InputTooLarge {
                field: "decrypted_payload",
            });
        }
        let mut packet = Self {
            original_header: [0; MAX_FORWARDED_RTP_HEADER_BYTES],
            original_header_len: u16::try_from(original_header.len()).map_err(|_source| {
                ClusterError::InputTooLarge {
                    field: "original_header",
                }
            })?,
            decrypted_payload: [0; MAX_FORWARDED_RTP_PAYLOAD_BYTES],
            decrypted_payload_len: u16::try_from(decrypted_payload.len()).map_err(|_source| {
                ClusterError::InputTooLarge {
                    field: "decrypted_payload",
                }
            })?,
        };
        packet.original_header[..original_header.len()].copy_from_slice(original_header);
        packet.decrypted_payload[..decrypted_payload.len()].copy_from_slice(decrypted_payload);
        Ok(packet)
    }

    /// Returns the original RTP header bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ForwardedPacket;
    /// let packet = ForwardedPacket::new(&[1], &[2])?;
    /// assert_eq!(packet.original_header(), &[1]);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub fn original_header(&self) -> &[u8] {
        &self.original_header[..usize::from(self.original_header_len)]
    }

    /// Returns the decrypted RTP payload bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ForwardedPacket;
    /// let packet = ForwardedPacket::new(&[1], &[2, 3])?;
    /// assert_eq!(packet.decrypted_payload(), &[2, 3]);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub fn decrypted_payload(&self) -> &[u8] {
        &self.decrypted_payload[..usize::from(self.decrypted_payload_len)]
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ForwardedPacket, Stability};
    /// assert_eq!(
    ///     ForwardedPacket::new(&[1], &[])?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Bounded quality-layer request for a mesh subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerRequest {
    layers: [Option<Layer>; MAX_MESH_LAYERS],
    len: u8,
}

impl LayerRequest {
    /// Creates a bounded layer request from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] for an empty request and
    /// [`ClusterError::InputTooLarge`] when more than [`MAX_MESH_LAYERS`] are
    /// requested.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::Layer;
    /// # use refract_cluster::LayerRequest;
    /// let request = LayerRequest::new(&[Layer::new(0, 0)?])?;
    /// assert_eq!(request.len(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(layers: &[Layer]) -> ClusterResult<Self> {
        if layers.is_empty() {
            return Err(ClusterError::InvalidConfig { field: "layers" });
        }
        if layers.len() > MAX_MESH_LAYERS {
            return Err(ClusterError::InputTooLarge { field: "layers" });
        }
        let mut request = Self {
            layers: [None; MAX_MESH_LAYERS],
            len: u8::try_from(layers.len())
                .map_err(|_source| ClusterError::InputTooLarge { field: "layers" })?,
        };
        for (slot, layer) in request.layers.iter_mut().zip(layers.iter().copied()) {
            *slot = Some(layer);
        }
        Ok(request)
    }

    /// Returns the number of requested layers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::Layer;
    /// # use refract_cluster::LayerRequest;
    /// assert_eq!(LayerRequest::new(&[Layer::new(0, 0)?])?.len(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns true when there are no requested layers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::Layer;
    /// # use refract_cluster::LayerRequest;
    /// assert!(!LayerRequest::new(&[Layer::new(0, 0)?])?.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Iterates requested layers in wire order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::Layer;
    /// # use refract_cluster::LayerRequest;
    /// let layer = Layer::new(0, 0)?;
    /// let request = LayerRequest::new(&[layer])?;
    /// assert_eq!(request.iter().next(), Some(layer));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn iter(self) -> impl Iterator<Item = Layer> {
        let len = self.len();
        self.layers.into_iter().take(len).flatten()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::Layer;
    /// # use refract_cluster::{LayerRequest, Stability};
    /// assert_eq!(
    ///     LayerRequest::new(&[Layer::new(0, 0)?])?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// RTCP feedback kind carried over the mesh.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RtcpFeedbackKind {
    /// Picture loss indication.
    Pli,
    /// Full intra request.
    Fir,
    /// Generic negative acknowledgement.
    Nack,
    /// Sender report feedback.
    SenderReport,
    /// Receiver report feedback.
    ReceiverReport,
    /// Transport-wide congestion-control feedback.
    TransportWideCc,
}

impl RtcpFeedbackKind {
    /// Returns the bounded feedback label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::RtcpFeedbackKind;
    /// assert_eq!(RtcpFeedbackKind::Pli.as_str(), "pli");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pli => "pli",
            Self::Fir => "fir",
            Self::Nack => "nack",
            Self::SenderReport => "sender_report",
            Self::ReceiverReport => "receiver_report",
            Self::TransportWideCc => "transport_wide_cc",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RtcpFeedbackKind, Stability};
    /// assert_eq!(RtcpFeedbackKind::Nack.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Bounded RTCP feedback carried between edge nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtcpFeedback {
    kind: RtcpFeedbackKind,
    bytes: [u8; MAX_RTCP_FEEDBACK_BYTES],
    len: u16,
}

impl RtcpFeedback {
    /// Creates a bounded RTCP feedback message.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InputTooLarge`] when `bytes` exceeds
    /// [`MAX_RTCP_FEEDBACK_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RtcpFeedback, RtcpFeedbackKind};
    /// let feedback = RtcpFeedback::new(RtcpFeedbackKind::Pli, &[1, 2])?;
    /// assert_eq!(feedback.kind(), RtcpFeedbackKind::Pli);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn new(kind: RtcpFeedbackKind, bytes: &[u8]) -> ClusterResult<Self> {
        if bytes.len() > MAX_RTCP_FEEDBACK_BYTES {
            return Err(ClusterError::InputTooLarge {
                field: "rtcp_feedback",
            });
        }
        let mut feedback = Self {
            kind,
            bytes: [0; MAX_RTCP_FEEDBACK_BYTES],
            len: u16::try_from(bytes.len()).map_err(|_source| ClusterError::InputTooLarge {
                field: "rtcp_feedback",
            })?,
        };
        feedback.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(feedback)
    }

    /// Returns the feedback kind.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RtcpFeedback, RtcpFeedbackKind};
    /// assert_eq!(
    ///     RtcpFeedback::new(RtcpFeedbackKind::Fir, &[])?.kind(),
    ///     RtcpFeedbackKind::Fir
    /// );
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn kind(&self) -> RtcpFeedbackKind {
        self.kind
    }

    /// Returns the feedback bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RtcpFeedback, RtcpFeedbackKind};
    /// assert_eq!(
    ///     RtcpFeedback::new(RtcpFeedbackKind::Nack, &[9])?.as_bytes(),
    ///     &[9]
    /// );
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RtcpFeedback, RtcpFeedbackKind, Stability};
    /// assert_eq!(
    ///     RtcpFeedback::new(RtcpFeedbackKind::Pli, &[])?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Inbound mesh event from a peer edge node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeshEvent {
    /// A forwarded media packet arrived.
    Forwarded {
        /// Peer node that sent the packet.
        source: NodeId,
        /// Forwarded packet.
        packet: Box<ForwardedPacket>,
    },
    /// RTCP feedback arrived for a mesh subscription.
    Feedback {
        /// Peer node that sent the feedback.
        source: NodeId,
        /// Mesh subscription identifier.
        subscription: SubscriptionId,
        /// Feedback payload.
        feedback: Box<RtcpFeedback>,
    },
}

impl MeshEvent {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::{ForwardedPacket, MeshEvent, Stability};
    /// let packet = ForwardedPacket::new(&[1], &[2])?;
    /// let event = MeshEvent::Forwarded {
    ///     source: NodeId::from_raw(1),
    ///     packet: Box::new(packet),
    /// };
    /// assert_eq!(event.stability(), Stability::Stage1);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Boundary between Stage 1 local forwarding and Stage 3 cascading mesh trees.
pub trait MeshTransport: Send + Sync + 'static {
    /// Forwards a media packet to a subscriber on another node.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] when the packet cannot be forwarded.
    fn forward(
        &self,
        target: NodeId,
        packet: ForwardedPacket,
    ) -> impl Future<Output = ClusterResult<()>> + Send;

    /// Subscribes this node to a media origin on another node.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] when the subscription cannot be established.
    fn subscribe(
        &self,
        target: NodeId,
        room: RoomId,
        track: TrackId,
        layers: LayerRequest,
    ) -> impl Future<Output = ClusterResult<SubscriptionId>> + Send;

    /// Removes an existing mesh subscription.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] when the subscription cannot be removed.
    fn unsubscribe(&self, sub: SubscriptionId) -> impl Future<Output = ClusterResult<()>> + Send;

    /// Sends RTCP feedback to the node that owns a mesh subscription.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] when feedback cannot be delivered.
    fn send_feedback(
        &self,
        target: NodeId,
        sub: SubscriptionId,
        feedback: RtcpFeedback,
    ) -> impl Future<Output = ClusterResult<()>> + Send;

    /// Returns inbound forwarded packets and feedback from mesh peers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{MeshTransport, MeshTransportLocalOnly};
    /// let transport = MeshTransportLocalOnly::new();
    /// let _stream = transport.inbound();
    /// ```
    fn inbound(&self) -> impl Stream<Item = MeshEvent> + Send;
}

/// Stage 1 mesh transport for single-edge deployments.
///
/// All cross-node operations return `HSF-MESH-LOCAL` because Stage 1 has one
/// edge and must never require mesh forwarding. Stage 3 can replace this type
/// with `QuicMeshTransport` without changing callers that are coded against
/// [`MeshTransport`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MeshTransportLocalOnly;

impl MeshTransportLocalOnly {
    /// Creates the Stage 1 local-only mesh transport.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{MeshTransportLocalOnly, Stability};
    /// assert_eq!(MeshTransportLocalOnly::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{MeshTransportLocalOnly, Stability};
    /// assert_eq!(MeshTransportLocalOnly::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl MeshTransport for MeshTransportLocalOnly {
    async fn forward(&self, _target: NodeId, _packet: ForwardedPacket) -> ClusterResult<()> {
        Err(ClusterError::MeshLocalOnly)
    }

    async fn subscribe(
        &self,
        _target: NodeId,
        _room: RoomId,
        _track: TrackId,
        _layers: LayerRequest,
    ) -> ClusterResult<SubscriptionId> {
        Err(ClusterError::MeshLocalOnly)
    }

    async fn unsubscribe(&self, _sub: SubscriptionId) -> ClusterResult<()> {
        Err(ClusterError::MeshLocalOnly)
    }

    async fn send_feedback(
        &self,
        _target: NodeId,
        _sub: SubscriptionId,
        _feedback: RtcpFeedback,
    ) -> ClusterResult<()> {
        Err(ClusterError::MeshLocalOnly)
    }

    fn inbound(&self) -> impl Stream<Item = MeshEvent> + Send {
        EmptyMeshInbound
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EmptyMeshInbound;

impl Stream for EmptyMeshInbound {
    type Item = MeshEvent;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

/// Edge node advertised to the placement oracle.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EdgeNode {
    id: NodeId,
    address: String,
}

impl EdgeNode {
    /// Creates an edge node record with a bounded address string.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] for an empty address and
    /// [`ClusterError::InputTooLarge`] when the address exceeds the bound.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::EdgeNode;
    /// let edge = EdgeNode::new(NodeId::from_raw(1), "127.0.0.1:4433".to_owned())?;
    /// assert_eq!(edge.id(), NodeId::from_raw(1));
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn new(id: NodeId, address: String) -> ClusterResult<Self> {
        if address.is_empty() {
            return Err(ClusterError::InvalidConfig { field: "address" });
        }
        if address.len() > MAX_EDGE_ADDRESS_BYTES {
            return Err(ClusterError::InputTooLarge { field: "address" });
        }
        Ok(Self { id, address })
    }

    /// Returns the node identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::EdgeNode;
    /// let edge = EdgeNode::new(NodeId::from_raw(9), "edge:1".to_owned())?;
    /// assert_eq!(edge.id(), NodeId::from_raw(9));
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn id(&self) -> NodeId {
        self.id
    }

    /// Returns the advertised control-plane address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::EdgeNode;
    /// let edge = EdgeNode::new(NodeId::from_raw(1), "edge-a".to_owned())?;
    /// assert_eq!(edge.address(), "edge-a");
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::{EdgeNode, Stability};
    /// let edge = EdgeNode::new(NodeId::from_raw(1), "edge-a".to_owned())?;
    /// assert_eq!(edge.stability(), Stability::Stage1);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl fmt::Display for EdgeNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.id, self.address)
    }
}

/// Placement decision for one room.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoomPlacement {
    room: RoomId,
    node: NodeId,
}

impl RoomPlacement {
    /// Creates a room placement record.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::RoomPlacement;
    /// let placement = RoomPlacement::new(RoomId::from_raw(1), NodeId::from_raw(2));
    /// assert_eq!(placement.node(), NodeId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn new(room: RoomId, node: NodeId) -> Self {
        Self { room, node }
    }

    /// Returns the room identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::RoomPlacement;
    /// let placement = RoomPlacement::new(RoomId::from_raw(1), NodeId::from_raw(2));
    /// assert_eq!(placement.room(), RoomId::from_raw(1));
    /// ```
    #[must_use]
    pub const fn room(self) -> RoomId {
        self.room
    }

    /// Returns the edge node identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::RoomPlacement;
    /// let placement = RoomPlacement::new(RoomId::from_raw(1), NodeId::from_raw(2));
    /// assert_eq!(placement.node(), NodeId::from_raw(2));
    /// ```
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::{RoomPlacement, Stability};
    /// assert_eq!(
    ///     RoomPlacement::new(RoomId::from_raw(1), NodeId::from_raw(2)).stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Capacity reported by an edge node.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeCapacity {
    max_peers: u32,
    max_packets_per_second: u64,
}

impl NodeCapacity {
    /// Creates a bounded capacity record.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] when either value is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::NodeCapacity;
    /// let capacity = NodeCapacity::new(1000, 1_000_000)?;
    /// assert_eq!(capacity.max_peers(), 1000);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub const fn new(max_peers: u32, max_packets_per_second: u64) -> ClusterResult<Self> {
        if max_peers == 0 {
            return Err(ClusterError::InvalidConfig { field: "max_peers" });
        }
        if max_packets_per_second == 0 {
            return Err(ClusterError::InvalidConfig {
                field: "max_packets_per_second",
            });
        }
        Ok(Self {
            max_peers,
            max_packets_per_second,
        })
    }

    /// Returns the peer capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::NodeCapacity;
    /// assert_eq!(NodeCapacity::new(8, 16)?.max_peers(), 8);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn max_peers(self) -> u32 {
        self.max_peers
    }

    /// Returns packet-per-second capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::NodeCapacity;
    /// assert_eq!(NodeCapacity::new(8, 16)?.max_packets_per_second(), 16);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn max_packets_per_second(self) -> u64 {
        self.max_packets_per_second
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{NodeCapacity, Stability};
    /// assert_eq!(NodeCapacity::new(1, 1)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Health sample reported every second by an edge node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeHealth {
    cpu_millis: u16,
    memory_used_percent: u8,
    packets_per_second: u64,
    peer_count: u32,
}

impl NodeHealth {
    /// Creates a health record.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] when CPU exceeds 1000 millis or
    /// memory exceeds 100 percent.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::NodeHealth;
    /// let health = NodeHealth::new(250, 40, 25_000, 100)?;
    /// assert_eq!(health.peer_count(), 100);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub const fn new(
        cpu_millis: u16,
        memory_used_percent: u8,
        packets_per_second: u64,
        peer_count: u32,
    ) -> ClusterResult<Self> {
        if cpu_millis > 1000 {
            return Err(ClusterError::InvalidConfig {
                field: "cpu_millis",
            });
        }
        if memory_used_percent > 100 {
            return Err(ClusterError::InvalidConfig {
                field: "memory_used_percent",
            });
        }
        Ok(Self {
            cpu_millis,
            memory_used_percent,
            packets_per_second,
            peer_count,
        })
    }

    /// Returns peer count from this health sample.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::NodeHealth;
    /// assert_eq!(NodeHealth::new(1, 2, 3, 4)?.peer_count(), 4);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn peer_count(self) -> u32 {
        self.peer_count
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{NodeHealth, Stability};
    /// assert_eq!(NodeHealth::new(1, 2, 3, 4)?.stability(), Stability::Stage1);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Bounded configuration key/value replicated by the control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterConfigEntry {
    key: String,
    value: String,
}

impl ClusterConfigEntry {
    /// Creates a bounded configuration entry.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] for an empty key and
    /// [`ClusterError::InputTooLarge`] when either field exceeds its limit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterConfigEntry;
    /// let entry = ClusterConfigEntry::new("admission.mode".to_owned(), "strict".to_owned())?;
    /// assert_eq!(entry.key(), "admission.mode");
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn new(key: String, value: String) -> ClusterResult<Self> {
        if key.is_empty() {
            return Err(ClusterError::InvalidConfig { field: "key" });
        }
        if key.len() > MAX_CONFIG_KEY_BYTES {
            return Err(ClusterError::InputTooLarge { field: "key" });
        }
        if value.len() > MAX_CONFIG_VALUE_BYTES {
            return Err(ClusterError::InputTooLarge { field: "value" });
        }
        Ok(Self { key, value })
    }

    /// Returns the configuration key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterConfigEntry;
    /// let entry = ClusterConfigEntry::new("k".to_owned(), "v".to_owned())?;
    /// assert_eq!(entry.key(), "k");
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the configuration value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterConfigEntry;
    /// let entry = ClusterConfigEntry::new("k".to_owned(), "v".to_owned())?;
    /// assert_eq!(entry.value(), "v");
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ClusterConfigEntry, Stability};
    /// assert_eq!(
    ///     ClusterConfigEntry::new("k".to_owned(), "v".to_owned())?.stability(),
    ///     Stability::Stage1,
    /// );
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Sacred Stage 1 placement interface.
pub trait PlacementOracle {
    /// Places a room on an edge node.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if placement cannot be committed.
    fn place_room(&self, room: RoomId)
    -> impl Future<Output = ClusterResult<RoomPlacement>> + Send;

    /// Returns the current placement for a room.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if placement state is unavailable.
    fn get_placement(
        &self,
        room: RoomId,
    ) -> impl Future<Output = ClusterResult<RoomPlacement>> + Send;

    /// Lists edge nodes known to the oracle.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if membership state is unavailable.
    fn list_nodes(&self) -> impl Future<Output = ClusterResult<Vec<EdgeNode>>> + Send;
}

/// Stage 1 placement oracle that always chooses the single configured edge.
#[derive(Clone, Debug)]
pub struct SingleEdgePlacementOracle {
    edge: EdgeNode,
}

impl SingleEdgePlacementOracle {
    /// Creates a single-edge placement oracle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::{EdgeNode, SingleEdgePlacementOracle};
    /// let edge = EdgeNode::new(NodeId::from_raw(1), "edge-a".to_owned())?;
    /// let oracle = SingleEdgePlacementOracle::new(edge);
    /// assert_eq!(oracle.stability(), refract_cluster::Stability::Stage1);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn new(edge: EdgeNode) -> Self {
        Self { edge }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::{EdgeNode, SingleEdgePlacementOracle, Stability};
    /// let edge = EdgeNode::new(NodeId::from_raw(1), "edge-a".to_owned())?;
    /// assert_eq!(
    ///     SingleEdgePlacementOracle::new(edge).stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl PlacementOracle for SingleEdgePlacementOracle {
    async fn place_room(&self, room: RoomId) -> ClusterResult<RoomPlacement> {
        Ok(RoomPlacement::new(room, self.edge.id()))
    }

    async fn get_placement(&self, room: RoomId) -> ClusterResult<RoomPlacement> {
        Ok(RoomPlacement::new(room, self.edge.id()))
    }

    async fn list_nodes(&self) -> ClusterResult<Vec<EdgeNode>> {
        Ok(vec![self.edge.clone()])
    }
}

/// Local redb-backed state machine snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ClusterSnapshot {
    format_version: u16,
    placements: BTreeMap<u64, u64>,
    health: BTreeMap<u64, PersistedHealth>,
    capacity: BTreeMap<u64, PersistedCapacity>,
    config: BTreeMap<String, String>,
}

impl ClusterSnapshot {
    /// Creates an empty Stage 1 snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterSnapshot;
    /// assert_eq!(ClusterSnapshot::new().format_version(), 1);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            format_version: SNAPSHOT_FORMAT_VERSION,
            placements: BTreeMap::new(),
            health: BTreeMap::new(),
            capacity: BTreeMap::new(),
            config: BTreeMap::new(),
        }
    }

    /// Returns the snapshot format version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterSnapshot;
    /// assert_eq!(ClusterSnapshot::new().format_version(), 1);
    /// ```
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    /// Encodes the snapshot to bounded JSON bytes for transfer or backup.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Snapshot`] when serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterSnapshot;
    /// let bytes = ClusterSnapshot::new().to_bytes()?;
    /// assert!(!bytes.is_empty());
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn to_bytes(&self) -> ClusterResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|source| ClusterError::Snapshot {
            message: source.to_string(),
        })
    }

    /// Decodes a snapshot from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Snapshot`] when decoding fails or the snapshot
    /// format version is unsupported.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterSnapshot;
    /// let bytes = ClusterSnapshot::new().to_bytes()?;
    /// let snapshot = ClusterSnapshot::from_bytes(&bytes)?;
    /// assert_eq!(snapshot.format_version(), 1);
    /// # Ok::<(), refract_cluster::ClusterError>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> ClusterResult<Self> {
        let snapshot: Self =
            serde_json::from_slice(bytes).map_err(|source| ClusterError::Snapshot {
                message: source.to_string(),
            })?;
        if snapshot.format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(ClusterError::Snapshot {
                message: "unsupported snapshot format version".to_owned(),
            });
        }
        Ok(snapshot)
    }

    /// Returns the placement count captured in the snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::ClusterSnapshot;
    /// assert_eq!(ClusterSnapshot::new().placement_count(), 0);
    /// ```
    #[must_use]
    pub fn placement_count(&self) -> usize {
        self.placements.len()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ClusterSnapshot, Stability};
    /// assert_eq!(ClusterSnapshot::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Local embedded redb state machine used below the `OpenRaft` log.
#[derive(Debug)]
pub struct RedbStateMachine {
    path: PathBuf,
    database: Database,
    snapshot: ClusterSnapshot,
}

impl RedbStateMachine {
    /// Opens or creates a redb state machine at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Storage`] when redb cannot open, initialize, or
    /// read the database.
    ///
    /// # Examples
    ///
    /// ```
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// # use refract_cluster::RedbStateMachine;
    /// let state = RedbStateMachine::open(&path)?;
    /// assert_eq!(state.snapshot().placement_count(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn open(path: impl AsRef<Path>) -> ClusterResult<Self> {
        let path = path.as_ref().to_path_buf();
        let database = if path.exists() {
            Database::open(&path).map_err(map_storage)?
        } else {
            Database::create(&path).map_err(map_storage)?
        };
        initialize_tables(&database)?;
        let snapshot = read_snapshot(&database)?;
        Ok(Self {
            path,
            database,
            snapshot,
        })
    }

    /// Returns the redb file path.
    ///
    /// # Examples
    ///
    /// ```
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// # use refract_cluster::RedbStateMachine;
    /// let state = RedbStateMachine::open(&path)?;
    /// assert_eq!(state.path(), path.as_path());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persists a room placement.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Storage`] when redb cannot commit the update.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::{RedbStateMachine, RoomPlacement};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let mut state = RedbStateMachine::open(&path)?;
    /// state.apply_placement(RoomPlacement::new(RoomId::from_raw(1), NodeId::from_raw(2)))?;
    /// assert_eq!(
    ///     state.placement(RoomId::from_raw(1))?.node(),
    ///     NodeId::from_raw(2)
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn apply_placement(&mut self, placement: RoomPlacement) -> ClusterResult<()> {
        self.snapshot
            .placements
            .insert(placement.room().raw(), placement.node().raw());
        let key = prefixed_key(PLACEMENT_PREFIX, placement.room().raw());
        let value = placement.node().raw().to_string();
        write_entry(&self.database, &key, &value)
    }

    /// Returns a room placement from the local state machine.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::UnknownNode`] when the room has not been placed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::{RedbStateMachine, RoomPlacement};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let mut state = RedbStateMachine::open(&path)?;
    /// state.apply_placement(RoomPlacement::new(RoomId::from_raw(1), NodeId::from_raw(2)))?;
    /// assert_eq!(
    ///     state.placement(RoomId::from_raw(1))?.node(),
    ///     NodeId::from_raw(2)
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn placement(&self, room: RoomId) -> ClusterResult<RoomPlacement> {
        let node = self
            .snapshot
            .placements
            .get(&room.raw())
            .copied()
            .ok_or_else(|| ClusterError::UnknownNode {
                node: NodeId::from_raw(room.raw()),
            })?;
        Ok(RoomPlacement::new(room, NodeId::from_raw(node)))
    }

    /// Persists a one-second health report from an edge node.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Storage`] when redb cannot commit the update.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::{NodeHealth, RedbStateMachine};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let mut state = RedbStateMachine::open(&path)?;
    /// state.report_health(NodeId::from_raw(1), NodeHealth::new(10, 20, 30, 40)?)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn report_health(&mut self, node: NodeId, health: NodeHealth) -> ClusterResult<()> {
        let persisted = PersistedHealth::from(health);
        self.snapshot.health.insert(node.raw(), persisted);
        let value = serde_json::to_string(&persisted).map_err(map_snapshot)?;
        write_entry(
            &self.database,
            &prefixed_key(HEALTH_PREFIX, node.raw()),
            &value,
        )
    }

    /// Persists node capacity.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Storage`] when redb cannot commit the update.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::{NodeCapacity, RedbStateMachine};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let mut state = RedbStateMachine::open(&path)?;
    /// state.set_capacity(NodeId::from_raw(1), NodeCapacity::new(10, 20)?)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_capacity(&mut self, node: NodeId, capacity: NodeCapacity) -> ClusterResult<()> {
        let persisted = PersistedCapacity::from(capacity);
        self.snapshot.capacity.insert(node.raw(), persisted);
        let value = serde_json::to_string(&persisted).map_err(map_snapshot)?;
        write_entry(
            &self.database,
            &prefixed_key(CAPACITY_PREFIX, node.raw()),
            &value,
        )
    }

    /// Persists a bounded configuration key/value.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Storage`] when redb cannot commit the update.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ClusterConfigEntry, RedbStateMachine};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let mut state = RedbStateMachine::open(&path)?;
    /// state.set_config(ClusterConfigEntry::new(
    ///     "mode".to_owned(),
    ///     "strict".to_owned(),
    /// )?)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_config(&mut self, entry: ClusterConfigEntry) -> ClusterResult<()> {
        let ClusterConfigEntry { key, value } = entry;
        self.snapshot.config.insert(key.clone(), value.clone());
        write_entry(
            &self.database,
            &format!("{CONFIG_PREFIX}{key}"),
            value.as_str(),
        )
    }

    /// Returns the current in-memory snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::RedbStateMachine;
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let state = RedbStateMachine::open(&path)?;
    /// assert_eq!(state.snapshot().format_version(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn snapshot(&self) -> &ClusterSnapshot {
        &self.snapshot
    }

    /// Restores the local state machine from a validated snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::Storage`] when redb cannot replace the state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ClusterSnapshot, RedbStateMachine};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let mut state = RedbStateMachine::open(&path)?;
    /// state.restore(ClusterSnapshot::new())?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn restore(&mut self, snapshot: ClusterSnapshot) -> ClusterResult<()> {
        replace_all(&self.database, &snapshot)?;
        self.snapshot = snapshot;
        Ok(())
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{RedbStateMachine, Stability};
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("cluster.redb");
    /// let state = RedbStateMachine::open(&path)?;
    /// assert_eq!(state.stability(), Stability::Stage1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Membership phase represented by `OpenRaft` joint consensus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipPhase {
    /// Stable single membership set.
    Stable {
        /// Stable voters.
        voters: BTreeSet<NodeId>,
    },
    /// Joint consensus while replacing one voter set with another.
    Joint {
        /// Previous voter set.
        previous: BTreeSet<NodeId>,
        /// Next voter set.
        next: BTreeSet<NodeId>,
    },
}

impl MembershipPhase {
    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::BTreeSet;
    /// # use refract_cluster::{MembershipPhase, Stability};
    /// let membership = MembershipPhase::Stable {
    ///     voters: BTreeSet::new(),
    /// };
    /// assert_eq!(membership.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Feature-gated deterministic control-plane cluster used by Stage 1 tests.
#[cfg(feature = "cluster-tests")]
#[derive(Debug)]
pub struct InProcessCluster {
    nodes: BTreeMap<NodeId, RedbStateMachine>,
    partitions: BTreeMap<NodeId, u8>,
    leader: NodeId,
    membership: MembershipPhase,
}

#[cfg(feature = "cluster-tests")]
impl InProcessCluster {
    /// Boots a deterministic three- or five-node cluster.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if membership is invalid or redb cannot open a
    /// state machine.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// assert_eq!(cluster.node_count(), 3);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bootstrap(root: &Path, node_count: usize) -> ClusterResult<Self> {
        validate_cluster_size(node_count)?;
        let mut nodes = BTreeMap::new();
        let mut partitions = BTreeMap::new();
        let mut voters = BTreeSet::new();
        for index in 1..=node_count {
            let node = NodeId::from_raw(index as u64);
            let state = RedbStateMachine::open(root.join(format!("node-{index}.redb")))?;
            nodes.insert(node, state);
            partitions.insert(node, 0);
            voters.insert(node);
        }
        let leader = first_node(&nodes)?;
        Ok(Self {
            nodes,
            partitions,
            leader,
            membership: MembershipPhase::Stable { voters },
        })
    }

    /// Restores a cluster from a snapshot after total loss of local state.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if bootstrapping or snapshot restore fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{ClusterSnapshot, InProcessCluster};
    /// # let dir = tempfile::tempdir()?;
    /// let snapshot = ClusterSnapshot::new();
    /// let cluster = InProcessCluster::restore_from_snapshot(dir.path(), 3, &snapshot)?;
    /// assert_eq!(cluster.node_count(), 3);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn restore_from_snapshot(
        root: &Path,
        node_count: usize,
        snapshot: &ClusterSnapshot,
    ) -> ClusterResult<Self> {
        let mut cluster = Self::bootstrap(root, node_count)?;
        for state in cluster.nodes.values_mut() {
            state.restore(snapshot.clone())?;
        }
        Ok(cluster)
    }

    /// Returns the node count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// assert_eq!(InProcessCluster::bootstrap(dir.path(), 3)?.node_count(), 3);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the current leader.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// assert_eq!(
    ///     InProcessCluster::bootstrap(dir.path(), 3)?.leader(),
    ///     NodeId::from_raw(1)
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn leader(&self) -> NodeId {
        self.leader
    }

    /// Elects the lowest node in the largest quorum partition.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::QuorumUnavailable`] if no partition has quorum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let mut cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// assert_eq!(cluster.elect_leader()?, NodeId::from_raw(1));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn elect_leader(&mut self) -> ClusterResult<NodeId> {
        let quorum = quorum(self.nodes.len());
        let mut groups: BTreeMap<u8, Vec<NodeId>> = BTreeMap::new();
        for (node, group) in &self.partitions {
            groups.entry(*group).or_default().push(*node);
        }
        let candidate = groups
            .values()
            .filter(|nodes| nodes.len() >= quorum)
            .filter_map(|nodes| nodes.iter().copied().min())
            .min()
            .ok_or(ClusterError::QuorumUnavailable { node: self.leader })?;
        self.leader = candidate;
        Ok(candidate)
    }

    /// Places a room through the partition containing `origin`.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::QuorumUnavailable`] for minority partitions or
    /// [`ClusterError::LeaderUnavailable`] when the partition cannot reach the
    /// leader.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let mut cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// let placement = cluster.place_room_from(NodeId::from_raw(1), RoomId::from_raw(9))?;
    /// assert_eq!(placement.node(), NodeId::from_raw(1));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn place_room_from(
        &mut self,
        origin: NodeId,
        room: RoomId,
    ) -> ClusterResult<RoomPlacement> {
        self.ensure_committable(origin)?;
        let placement = RoomPlacement::new(room, self.leader);
        let origin_group = self.partition_of(origin)?;
        for (node, state) in &mut self.nodes {
            if self.partitions.get(node).copied() == Some(origin_group) {
                state.apply_placement(placement)?;
            }
        }
        Ok(placement)
    }

    /// Returns a placement from one node's local state machine.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if the node or placement is unavailable.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::{NodeId, RoomId};
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let mut cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// cluster.place_room_from(NodeId::from_raw(1), RoomId::from_raw(9))?;
    /// assert_eq!(
    ///     cluster
    ///         .placement_on(NodeId::from_raw(1), RoomId::from_raw(9))?
    ///         .room(),
    ///     RoomId::from_raw(9),
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn placement_on(&self, node: NodeId, room: RoomId) -> ClusterResult<RoomPlacement> {
        self.nodes
            .get(&node)
            .ok_or(ClusterError::UnknownNode { node })?
            .placement(room)
    }

    /// Moves `minority` into a partition that cannot reach the majority.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] if any node is unknown or the requested
    /// minority is not smaller than quorum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::NodeId;
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let mut cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// cluster.partition_minority(&[NodeId::from_raw(3)])?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn partition_minority(&mut self, minority: &[NodeId]) -> ClusterResult<()> {
        if minority.len() >= quorum(self.nodes.len()) {
            return Err(ClusterError::InvalidConfig { field: "minority" });
        }
        for node in minority {
            if !self.nodes.contains_key(node) {
                return Err(ClusterError::UnknownNode { node: *node });
            }
        }
        for node in self.nodes.keys() {
            let group = u8::from(minority.contains(node));
            self.partitions.insert(*node, group);
        }
        Ok(())
    }

    /// Begins an OpenRaft-style joint-consensus membership change.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError`] when the next membership size is unsupported.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::BTreeSet;
    /// # use refract_core::NodeId;
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let mut cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// let next = [1_u64, 2, 3]
    ///     .into_iter()
    ///     .map(NodeId::from_raw)
    ///     .collect::<BTreeSet<_>>();
    /// cluster.begin_joint_consensus(next)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn begin_joint_consensus(&mut self, next: BTreeSet<NodeId>) -> ClusterResult<()> {
        validate_cluster_size(next.len())?;
        let previous = match &self.membership {
            MembershipPhase::Stable { voters } => voters.clone(),
            MembershipPhase::Joint { next, .. } => next.clone(),
        };
        self.membership = MembershipPhase::Joint { previous, next };
        Ok(())
    }

    /// Commits an active joint-consensus membership change.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::InvalidConfig`] when no joint consensus is
    /// active.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::BTreeSet;
    /// # use refract_core::NodeId;
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let mut cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// let next = [1_u64, 2, 3]
    ///     .into_iter()
    ///     .map(NodeId::from_raw)
    ///     .collect::<BTreeSet<_>>();
    /// cluster.begin_joint_consensus(next)?;
    /// cluster.commit_joint_consensus()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn commit_joint_consensus(&mut self) -> ClusterResult<()> {
        let next = match &self.membership {
            MembershipPhase::Stable { .. } => {
                return Err(ClusterError::InvalidConfig {
                    field: "membership",
                });
            }
            MembershipPhase::Joint { next, .. } => next.clone(),
        };
        self.membership = MembershipPhase::Stable { voters: next };
        Ok(())
    }

    /// Captures a snapshot from the current leader's state machine.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterError::LeaderUnavailable`] if the leader is missing.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::InProcessCluster;
    /// # let dir = tempfile::tempdir()?;
    /// let cluster = InProcessCluster::bootstrap(dir.path(), 3)?;
    /// assert_eq!(cluster.snapshot()?.format_version(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn snapshot(&self) -> ClusterResult<ClusterSnapshot> {
        self.nodes
            .get(&self.leader)
            .map(|state| state.snapshot().clone())
            .ok_or(ClusterError::LeaderUnavailable { node: self.leader })
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cluster::{InProcessCluster, Stability};
    /// # let dir = tempfile::tempdir()?;
    /// assert_eq!(
    ///     InProcessCluster::bootstrap(dir.path(), 3)?.stability(),
    ///     Stability::Stage1
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn partition_of(&self, node: NodeId) -> ClusterResult<u8> {
        self.partitions
            .get(&node)
            .copied()
            .ok_or(ClusterError::UnknownNode { node })
    }

    fn ensure_committable(&self, origin: NodeId) -> ClusterResult<()> {
        let origin_group = self.partition_of(origin)?;
        let group_size = self
            .partitions
            .values()
            .filter(|group| **group == origin_group)
            .count();
        if group_size < quorum(self.nodes.len()) {
            return Err(ClusterError::QuorumUnavailable { node: origin });
        }
        if self.partition_of(self.leader)? != origin_group {
            return Err(ClusterError::LeaderUnavailable { node: origin });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
struct PersistedHealth {
    cpu_millis: u16,
    memory_used_percent: u8,
    packets_per_second: u64,
    peer_count: u32,
}

impl From<NodeHealth> for PersistedHealth {
    fn from(value: NodeHealth) -> Self {
        Self {
            cpu_millis: value.cpu_millis,
            memory_used_percent: value.memory_used_percent,
            packets_per_second: value.packets_per_second,
            peer_count: value.peer_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
struct PersistedCapacity {
    max_peers: u32,
    max_packets_per_second: u64,
}

impl From<NodeCapacity> for PersistedCapacity {
    fn from(value: NodeCapacity) -> Self {
        Self {
            max_peers: value.max_peers,
            max_packets_per_second: value.max_packets_per_second,
        }
    }
}

fn millis_u64(duration: Duration) -> ClusterResult<u64> {
    u64::try_from(duration.as_millis())
        .map_err(|_source| ClusterError::InvalidConfig { field: "duration" })
}

fn initialize_tables(database: &Database) -> ClusterResult<()> {
    let transaction = database.begin_write().map_err(map_storage)?;
    {
        let _table = transaction.open_table(STATE_TABLE).map_err(map_storage)?;
    }
    transaction.commit().map_err(map_storage)
}

fn read_snapshot(database: &Database) -> ClusterResult<ClusterSnapshot> {
    let transaction = database.begin_read().map_err(map_storage)?;
    let table = transaction.open_table(STATE_TABLE).map_err(map_storage)?;
    let mut snapshot = ClusterSnapshot::new();
    for entry in table.iter().map_err(map_storage)? {
        let (key, value) = entry.map_err(map_storage)?;
        apply_persisted_entry(&mut snapshot, key.value(), value.value())?;
    }
    Ok(snapshot)
}

fn apply_persisted_entry(
    snapshot: &mut ClusterSnapshot,
    key: &str,
    value: &str,
) -> ClusterResult<()> {
    if let Some(room) = key.strip_prefix(PLACEMENT_PREFIX) {
        let room = parse_u64(room)?;
        let node = parse_u64(value)?;
        snapshot.placements.insert(room, node);
    } else if let Some(node) = key.strip_prefix(HEALTH_PREFIX) {
        let health = serde_json::from_str(value).map_err(map_snapshot)?;
        snapshot.health.insert(parse_u64(node)?, health);
    } else if let Some(node) = key.strip_prefix(CAPACITY_PREFIX) {
        let capacity = serde_json::from_str(value).map_err(map_snapshot)?;
        snapshot.capacity.insert(parse_u64(node)?, capacity);
    } else if let Some(config_key) = key.strip_prefix(CONFIG_PREFIX) {
        snapshot
            .config
            .insert(config_key.to_owned(), value.to_owned());
    }
    Ok(())
}

fn parse_u64(value: &str) -> ClusterResult<u64> {
    value
        .parse()
        .map_err(|source: std::num::ParseIntError| ClusterError::Snapshot {
            message: source.to_string(),
        })
}

fn write_entry(database: &Database, key: &str, value: &str) -> ClusterResult<()> {
    let transaction = database.begin_write().map_err(map_storage)?;
    {
        let mut table = transaction.open_table(STATE_TABLE).map_err(map_storage)?;
        table.insert(key, value).map_err(map_storage)?;
    }
    transaction.commit().map_err(map_storage)
}

fn replace_all(database: &Database, snapshot: &ClusterSnapshot) -> ClusterResult<()> {
    let transaction = database.begin_write().map_err(map_storage)?;
    {
        let mut table = transaction.open_table(STATE_TABLE).map_err(map_storage)?;
        let keys = table
            .iter()
            .map_err(map_storage)?
            .map(|entry| entry.map(|(key, _value)| key.value().to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_storage)?;
        for key in keys {
            table.remove(key.as_str()).map_err(map_storage)?;
        }
        for (room, node) in &snapshot.placements {
            table
                .insert(
                    prefixed_key(PLACEMENT_PREFIX, *room).as_str(),
                    node.to_string().as_str(),
                )
                .map_err(map_storage)?;
        }
        for (node, health) in &snapshot.health {
            let value = serde_json::to_string(health).map_err(map_snapshot)?;
            table
                .insert(prefixed_key(HEALTH_PREFIX, *node).as_str(), value.as_str())
                .map_err(map_storage)?;
        }
        for (node, capacity) in &snapshot.capacity {
            let value = serde_json::to_string(capacity).map_err(map_snapshot)?;
            table
                .insert(
                    prefixed_key(CAPACITY_PREFIX, *node).as_str(),
                    value.as_str(),
                )
                .map_err(map_storage)?;
        }
        for (key, value) in &snapshot.config {
            table
                .insert(format!("{CONFIG_PREFIX}{key}").as_str(), value.as_str())
                .map_err(map_storage)?;
        }
    }
    transaction.commit().map_err(map_storage)
}

fn prefixed_key(prefix: &str, id: u64) -> String {
    format!("{prefix}{id}")
}

fn map_storage(source: impl fmt::Display) -> ClusterError {
    ClusterError::Storage {
        message: source.to_string(),
    }
}

fn map_snapshot(source: impl fmt::Display) -> ClusterError {
    ClusterError::Snapshot {
        message: source.to_string(),
    }
}

#[cfg(feature = "cluster-tests")]
fn validate_cluster_size(nodes: usize) -> ClusterResult<()> {
    if SUPPORTED_CLUSTER_SIZES.contains(&nodes) {
        Ok(())
    } else {
        Err(ClusterError::InvalidClusterSize { nodes })
    }
}

#[cfg(feature = "cluster-tests")]
const fn quorum(nodes: usize) -> usize {
    (nodes / 2) + 1
}

#[cfg(feature = "cluster-tests")]
fn first_node(nodes: &BTreeMap<NodeId, RedbStateMachine>) -> ClusterResult<NodeId> {
    nodes
        .keys()
        .next()
        .copied()
        .ok_or(ClusterError::InvalidClusterSize { nodes: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_edge_oracle_places_every_room_on_the_edge() {
        compio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                let edge = EdgeNode::new(NodeId::from_raw(1), "edge-a".to_owned()).expect("edge");
                let oracle = SingleEdgePlacementOracle::new(edge);

                let first = oracle
                    .place_room(RoomId::from_raw(10))
                    .await
                    .expect("first placement");
                let second = oracle
                    .get_placement(RoomId::from_raw(11))
                    .await
                    .expect("second placement");

                assert_eq!(first.node(), NodeId::from_raw(1));
                assert_eq!(second.node(), NodeId::from_raw(1));
            });
    }

    #[test]
    fn redb_state_machine_round_trips_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cluster.redb");
        let mut state = RedbStateMachine::open(&path).expect("open state");
        state
            .apply_placement(RoomPlacement::new(
                RoomId::from_raw(10),
                NodeId::from_raw(1),
            ))
            .expect("apply placement");
        state
            .report_health(
                NodeId::from_raw(1),
                NodeHealth::new(12, 34, 56, 78).expect("health"),
            )
            .expect("health report");

        let bytes = state.snapshot().to_bytes().expect("snapshot bytes");
        let restored = ClusterSnapshot::from_bytes(&bytes).expect("restore bytes");

        assert_eq!(restored.placement_count(), 1);
        assert_eq!(restored.health.len(), 1);
    }

    #[test]
    fn raft_settings_validate_openraft_config() {
        let config = RaftSettings::default()
            .to_openraft_config()
            .expect("openraft config");

        assert_eq!(config.cluster_name, "refract-cluster");
    }

    #[test]
    fn local_only_mesh_transport_returns_expected_error() {
        compio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                let transport = MeshTransportLocalOnly::new();
                let target = NodeId::from_raw(2);
                let packet =
                    ForwardedPacket::new(&[0x80, 0x60], &[1, 2, 3]).expect("forwarded packet");
                let layers =
                    LayerRequest::new(&[Layer::new(0, 0).expect("layer")]).expect("layers");
                let feedback = RtcpFeedback::new(RtcpFeedbackKind::Pli, &[]).expect("feedback");
                let sub = SubscriptionId::from_raw(9);

                let forward = transport
                    .forward(target, packet)
                    .await
                    .expect_err("forward rejected");
                let subscribe = transport
                    .subscribe(target, RoomId::from_raw(1), TrackId::from_raw(2), layers)
                    .await
                    .expect_err("subscribe rejected");
                let unsubscribe = transport
                    .unsubscribe(sub)
                    .await
                    .expect_err("unsubscribe rejected");
                let feedback = transport
                    .send_feedback(target, sub, feedback)
                    .await
                    .expect_err("feedback rejected");

                assert_eq!(forward.error_code(), "HSF-MESH-LOCAL");
                assert_eq!(subscribe.error_code(), "HSF-MESH-LOCAL");
                assert_eq!(unsubscribe.error_code(), "HSF-MESH-LOCAL");
                assert_eq!(feedback.error_code(), "HSF-MESH-LOCAL");
            });
    }

    #[test]
    fn router_cross_node_subscription_attempt_is_defensive() {
        compio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                let transport = MeshTransportLocalOnly::new();
                let layers =
                    LayerRequest::new(&[Layer::new(0, 0).expect("layer")]).expect("layers");

                let result = transport
                    .subscribe(
                        NodeId::from_raw(2),
                        RoomId::from_raw(7),
                        TrackId::from_raw(9),
                        layers,
                    )
                    .await;

                assert_eq!(
                    result.expect_err("cross-node route rejected").error_code(),
                    "HSF-MESH-LOCAL",
                );
            });
    }

    #[cfg(feature = "cluster-tests")]
    mod cluster_tests {
        use super::*;

        #[test]
        fn three_node_cluster_spinup_and_leader_election() {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut cluster = InProcessCluster::bootstrap(dir.path(), 3).expect("bootstrap");

            let leader = cluster.elect_leader().expect("elect");

            assert_eq!(cluster.node_count(), 3);
            assert_eq!(leader, NodeId::from_raw(1));
            assert_eq!(cluster.leader(), NodeId::from_raw(1));
        }

        #[test]
        fn partition_minority_rejects_writes() {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut cluster = InProcessCluster::bootstrap(dir.path(), 3).expect("bootstrap");
            cluster
                .partition_minority(&[NodeId::from_raw(3)])
                .expect("partition");

            let rejected = cluster
                .place_room_from(NodeId::from_raw(3), RoomId::from_raw(9))
                .expect_err("minority rejected");
            let accepted = cluster
                .place_room_from(NodeId::from_raw(1), RoomId::from_raw(9))
                .expect("majority accepted");

            assert_eq!(rejected.error_code(), "CLUSTER_RAFT_0001");
            assert_eq!(accepted.node(), NodeId::from_raw(1));
        }

        #[test]
        fn joint_consensus_transitions_to_stable_membership() {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut cluster = InProcessCluster::bootstrap(dir.path(), 3).expect("bootstrap");
            let next = [1_u64, 2, 3]
                .into_iter()
                .map(NodeId::from_raw)
                .collect::<BTreeSet<_>>();

            cluster
                .begin_joint_consensus(next.clone())
                .expect("joint consensus");
            cluster
                .commit_joint_consensus()
                .expect("commit joint consensus");

            assert_eq!(cluster.membership, MembershipPhase::Stable { voters: next });
        }

        #[test]
        fn disaster_recovery_restores_from_snapshot() {
            let original_dir = tempfile::tempdir().expect("original tempdir");
            let mut original =
                InProcessCluster::bootstrap(original_dir.path(), 3).expect("bootstrap");
            original
                .place_room_from(NodeId::from_raw(1), RoomId::from_raw(42))
                .expect("place room");
            let snapshot = original.snapshot().expect("snapshot");
            drop(original);
            drop(original_dir);

            let restore_dir = tempfile::tempdir().expect("restore tempdir");
            let restored =
                InProcessCluster::restore_from_snapshot(restore_dir.path(), 3, &snapshot)
                    .expect("restore");

            assert_eq!(
                restored
                    .placement_on(NodeId::from_raw(1), RoomId::from_raw(42))
                    .expect("placement")
                    .node(),
                NodeId::from_raw(1),
            );
        }
    }
}
