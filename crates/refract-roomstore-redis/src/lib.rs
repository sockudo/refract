//! Redis Sentinel-backed implementation of the Stage 1 [`RoomStore`] boundary.
//!
//! `refract-roomstore-redis` targets one Redis primary with two replicas and
//! Sentinel failover. It is intentionally not Redis Cluster. The implementation
//! uses Lua scripts for multi-key room mutations, refreshes a 24 hour TTL on
//! room keys after activity, and fails closed under degraded health or memory
//! pressure.
//!
//! # Examples
//!
//! ```
//! # use refract_roomstore_redis::RedisRoomStoreConfig;
//! let config =
//!     RedisRoomStoreConfig::new(vec!["redis://127.0.0.1:26379/".into()], "mymaster".into())?;
//! assert_eq!(config.master_name(), "mymaster");
//! # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    fmt,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        mpsc::{Receiver, TryRecvError, sync_channel},
    },
    task::{Context, Poll, Waker},
    thread,
    time::{Duration, Instant},
};

use futures_core::Stream;
use redis::Script;
use refract_core::{NodeId, PeerId, RoomId, TrackId};
use refract_roomstore::{
    AudioLevel, Cursor, DEFAULT_OPERATION_TIMEOUT, DEFAULT_ROOM_TTL, JoinHandle, Participant,
    Result as StoreResult, RoomEvent, RoomEventStream, RoomStore, RoomStoreError, SubscriptionId,
    TrackInfo, decode_record, encode_record,
};
use thiserror::Error;
use tracing::{error, info, warn};

/// Default Redis keepalive period.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Memory pressure percentage that emits an alert.
pub const MEMORY_ALERT_PERCENT: u8 = 70;

/// Memory pressure percentage that refuses writes.
pub const MEMORY_REFUSE_WRITES_PERCENT: u8 = 90;

/// Required Redis eviction policy.
pub const REQUIRED_EVICTION_POLICY: &str = "noeviction";

/// Required Redis AOF fsync policy.
pub const REQUIRED_AOF_FSYNC: &str = "everysec";

/// Global subscription index key used to implement room-less unsubscribe.
pub const GLOBAL_SUBSCRIPTIONS_KEY: &str = "roomstore:subscriptions";

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns the stable marker label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Redis implementation error taxonomy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RedisRoomStoreError {
    /// Configuration is invalid.
    #[error("invalid configuration: {field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// Redis driver returned an error.
    #[error("redis operation failed")]
    Redis {
        /// Redis source error.
        #[source]
        source: redis::RedisError,
    },
    /// Internal synchronization failed.
    #[error("internal synchronization failed")]
    InternalSync,
}

impl RedisRoomStoreError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreError;
    /// assert_eq!(
    ///     RedisRoomStoreError::InvalidConfig { field: "x" }.error_code(),
    ///     "ROOMSTORE_REDIS_CONFIG_0001",
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "ROOMSTORE_REDIS_CONFIG_0001",
            Self::Redis { .. } => "ROOMSTORE_REDIS_BACKEND_0001",
            Self::InternalSync => "ROOMSTORE_REDIS_INTERNAL_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::{RedisRoomStoreError, Stability};
    /// assert_eq!(
    ///     RedisRoomStoreError::InvalidConfig { field: "x" }.stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl From<redis::RedisError> for RedisRoomStoreError {
    fn from(source: redis::RedisError) -> Self {
        Self::Redis { source }
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for RedisRoomStoreError {
    fn from(_source: PoisonError<MutexGuard<'_, T>>) -> Self {
        Self::InternalSync
    }
}

/// Result alias for Redis room store construction and checks.
pub type RedisResult<T> = Result<T, RedisRoomStoreError>;

/// Redis Sentinel topology configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisRoomStoreConfig {
    sentinels: Box<[String]>,
    master_name: Box<str>,
    operation_timeout: Duration,
    room_ttl: Duration,
    keepalive_interval: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RedisRoomStoreConfig {
    /// Creates a Redis Sentinel room store configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RedisRoomStoreError::InvalidConfig`] when Sentinel endpoints
    /// or the master name are empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(
    ///     vec!["redis://127.0.0.1:26379/".to_owned()],
    ///     "mymaster".into(),
    /// )?;
    /// assert_eq!(config.sentinels().len(), 1);
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    pub fn new(sentinels: Vec<String>, master_name: Box<str>) -> RedisResult<Self> {
        let config = Self {
            sentinels: sentinels.into_boxed_slice(),
            master_name,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            room_ttl: DEFAULT_ROOM_TTL,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(5),
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates the Redis topology configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RedisRoomStoreError::InvalidConfig`] for empty endpoints,
    /// empty master name, or zero durations.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// config.validate()?;
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    pub fn validate(&self) -> RedisResult<()> {
        if self.sentinels.is_empty() {
            return Err(RedisRoomStoreError::InvalidConfig { field: "sentinels" });
        }
        if self.sentinels.iter().any(String::is_empty) {
            return Err(RedisRoomStoreError::InvalidConfig { field: "sentinel" });
        }
        if self.master_name.is_empty() {
            return Err(RedisRoomStoreError::InvalidConfig {
                field: "master_name",
            });
        }
        if self.operation_timeout.is_zero() {
            return Err(RedisRoomStoreError::InvalidConfig {
                field: "operation_timeout",
            });
        }
        if self.room_ttl.is_zero() {
            return Err(RedisRoomStoreError::InvalidConfig { field: "room_ttl" });
        }
        if self.keepalive_interval.is_zero() {
            return Err(RedisRoomStoreError::InvalidConfig {
                field: "keepalive_interval",
            });
        }
        if self.initial_backoff.is_zero() || self.max_backoff < self.initial_backoff {
            return Err(RedisRoomStoreError::InvalidConfig { field: "backoff" });
        }
        Ok(())
    }

    /// Returns Sentinel endpoints.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// assert_eq!(config.sentinels()[0], "redis://127.0.0.1/");
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    #[must_use]
    pub fn sentinels(&self) -> &[String] {
        &self.sentinels
    }

    /// Returns the Sentinel master name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// assert_eq!(config.master_name(), "m");
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    #[must_use]
    pub fn master_name(&self) -> &str {
        &self.master_name
    }

    /// Returns the operation timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// assert_eq!(
    ///     config.operation_timeout(),
    ///     refract_roomstore::DEFAULT_OPERATION_TIMEOUT
    /// );
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Returns the Redis key TTL.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// assert_eq!(config.room_ttl(), refract_roomstore::DEFAULT_ROOM_TTL);
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn room_ttl(&self) -> Duration {
        self.room_ttl
    }

    /// Returns the keepalive interval.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisRoomStoreConfig;
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// assert_eq!(
    ///     config.keepalive_interval(),
    ///     refract_roomstore_redis::DEFAULT_KEEPALIVE_INTERVAL
    /// );
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::{RedisRoomStoreConfig, Stability};
    /// let config = RedisRoomStoreConfig::new(vec!["redis://127.0.0.1/".to_owned()], "m".into())?;
    /// assert_eq!(config.stability(), Stability::Stage1);
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Redis key set for one room.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomKeys {
    participants: String,
    tracks: String,
    speakers: String,
    subscriptions: String,
    events: String,
}

impl RoomKeys {
    /// Builds the Redis schema keys for a room.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// let keys = RoomKeys::new(RoomId::from_raw(1));
    /// assert!(keys.participants().starts_with("room:"));
    /// ```
    #[must_use]
    pub fn new(room: RoomId) -> Self {
        Self {
            participants: format!("room:{room}:participants"),
            tracks: format!("room:{room}:tracks"),
            speakers: format!("room:{room}:speakers"),
            subscriptions: format!("room:{room}:subscriptions"),
            events: format!("room:{room}:events"),
        }
    }

    /// Returns the participant hash key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// assert!(
    ///     RoomKeys::new(RoomId::from_raw(1))
    ///         .participants()
    ///         .ends_with(":participants")
    /// );
    /// ```
    #[must_use]
    pub fn participants(&self) -> &str {
        &self.participants
    }

    /// Returns the track hash key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// assert!(
    ///     RoomKeys::new(RoomId::from_raw(1))
    ///         .tracks()
    ///         .ends_with(":tracks")
    /// );
    /// ```
    #[must_use]
    pub fn tracks(&self) -> &str {
        &self.tracks
    }

    /// Returns the active-speaker sorted set key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// assert!(
    ///     RoomKeys::new(RoomId::from_raw(1))
    ///         .speakers()
    ///         .ends_with(":speakers")
    /// );
    /// ```
    #[must_use]
    pub fn speakers(&self) -> &str {
        &self.speakers
    }

    /// Returns the room subscription index key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// assert!(
    ///     RoomKeys::new(RoomId::from_raw(1))
    ///         .subscriptions()
    ///         .ends_with(":subscriptions")
    /// );
    /// ```
    #[must_use]
    pub fn subscriptions(&self) -> &str {
        &self.subscriptions
    }

    /// Returns the room event channel.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// assert!(
    ///     RoomKeys::new(RoomId::from_raw(1))
    ///         .events()
    ///         .ends_with(":events")
    /// );
    /// ```
    #[must_use]
    pub fn events(&self) -> &str {
        &self.events
    }

    /// Returns the key list used for TTL refreshes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::RoomId;
    /// # use refract_roomstore_redis::RoomKeys;
    /// assert_eq!(RoomKeys::new(RoomId::from_raw(1)).ttl_keys().len(), 4);
    /// ```
    #[must_use]
    pub fn ttl_keys(&self) -> [&str; 4] {
        [
            &self.participants,
            &self.tracks,
            &self.speakers,
            &self.subscriptions,
        ]
    }
}

/// Redis health state used by the circuit breaker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisHealth {
    /// Redis path is healthy.
    Healthy,
    /// Redis path is degraded; reads may continue but writes fail closed.
    Degraded,
    /// Redis memory pressure requires refusing writes.
    RefusingWrites,
}

impl RedisHealth {
    /// Returns whether writes are currently allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::RedisHealth;
    /// assert!(RedisHealth::Healthy.allows_writes());
    /// assert!(!RedisHealth::RefusingWrites.allows_writes());
    /// ```
    #[must_use]
    pub const fn allows_writes(self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_roomstore_redis::{RedisHealth, Stability};
    /// assert_eq!(RedisHealth::Healthy.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Redis-backed room store.
pub struct RoomStoreRedis {
    config: RedisRoomStoreConfig,
    client: Mutex<redis::sentinel::SentinelClient>,
    health: Mutex<HealthState>,
}

impl RoomStoreRedis {
    /// Connects to the Sentinel-reported Redis primary.
    ///
    /// # Errors
    ///
    /// Returns Redis driver errors or invalid configuration errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let store = refract_roomstore_redis::RoomStoreRedis::connect(config)?;
    /// # Ok::<(), refract_roomstore_redis::RedisRoomStoreError>(())
    /// ```
    pub fn connect(config: RedisRoomStoreConfig) -> RedisResult<Self> {
        config.validate()?;
        let client = redis::sentinel::SentinelClient::build(
            config.sentinels().to_vec(),
            config.master_name().to_owned(),
            None,
            redis::sentinel::SentinelServerType::Master,
        )?;
        info!(
            event = "roomstore_redis_connect",
            master = config.master_name(),
            sentinels = config.sentinels().len(),
        );
        Ok(Self {
            config,
            client: Mutex::new(client),
            health: Mutex::new(HealthState::new()),
        })
    }

    /// Returns the configured Redis topology.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(store.config().master_name(), "mymaster");
    /// ```
    #[must_use]
    pub const fn config(&self) -> &RedisRoomStoreConfig {
        &self.config
    }

    /// Checks Redis deployment settings and keepalive health.
    ///
    /// # Errors
    ///
    /// Returns Redis backend errors or degraded deployment errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// store.health_check()?;
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub fn health_check(&self) -> StoreResult<RedisHealth> {
        let mut connection = self.connection()?;
        let pong: String = redis::cmd("PING")
            .query(&mut connection)
            .map_err(map_redis_error)?;
        if pong != "PONG" {
            self.mark_degraded("ping");
            return Err(RoomStoreError::Degraded { reason: "ping" });
        }
        let memory = query_memory(&mut connection)?;
        let policy: String = redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query::<Vec<String>>(&mut connection)
            .map_err(map_redis_error)?
            .get(1)
            .cloned()
            .unwrap_or_default();
        if policy != REQUIRED_EVICTION_POLICY {
            self.mark_degraded("eviction_policy");
            return Err(RoomStoreError::Degraded {
                reason: "eviction_policy",
            });
        }
        let appendfsync: String = redis::cmd("CONFIG")
            .arg("GET")
            .arg("appendfsync")
            .query::<Vec<String>>(&mut connection)
            .map_err(map_redis_error)?
            .get(1)
            .cloned()
            .unwrap_or_default();
        if appendfsync != REQUIRED_AOF_FSYNC {
            self.mark_degraded("appendfsync");
            return Err(RoomStoreError::Degraded {
                reason: "appendfsync",
            });
        }
        let health = memory.health();
        *self.health.lock().map_err(map_poison)? = HealthState::healthy(health);
        Ok(health)
    }

    /// Returns current circuit breaker health without network I/O.
    ///
    /// # Errors
    ///
    /// Returns internal synchronization errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let health = store.health()?;
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub fn health(&self) -> StoreResult<RedisHealth> {
        Ok(self.health.lock().map_err(map_poison)?.health)
    }

    /// Runs a keepalive ping when the configured interval has elapsed.
    ///
    /// # Errors
    ///
    /// Returns Redis backend errors or degraded errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// store.keepalive(Instant::now())?;
    /// # Ok::<(), refract_roomstore::RoomStoreError>(())
    /// ```
    pub fn keepalive(&self, now: Instant) -> StoreResult<RedisHealth> {
        {
            let health = self.health.lock().map_err(map_poison)?;
            if now.duration_since(health.last_check) < self.config.keepalive_interval() {
                return Ok(health.health);
            }
        }
        self.health_check()
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(store.stability(), refract_roomstore_redis::Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }

    fn connection(&self) -> StoreResult<redis::Connection> {
        let started = Instant::now();
        let mut client = self.client.lock().map_err(map_poison)?;
        let connection = client.get_connection().map_err(map_redis_error)?;
        drop(client);
        connection
            .set_read_timeout(Some(self.config.operation_timeout()))
            .map_err(map_redis_error)?;
        connection
            .set_write_timeout(Some(self.config.operation_timeout()))
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())?;
        Ok(connection)
    }

    fn ensure_write_allowed(&self) -> StoreResult<()> {
        match self.health()? {
            RedisHealth::Healthy => Ok(()),
            RedisHealth::Degraded => Err(RoomStoreError::Degraded {
                reason: "redis_path",
            }),
            RedisHealth::RefusingWrites => Err(RoomStoreError::MemoryPressure {
                used_percent: MEMORY_REFUSE_WRITES_PERCENT,
            }),
        }
    }

    fn mark_degraded(&self, reason: &'static str) {
        if let Ok(mut health) = self.health.lock() {
            health.mark_degraded(reason, self.config.max_backoff);
        }
        warn!(event = "roomstore_redis_degraded", reason);
    }
}

impl fmt::Debug for RoomStoreRedis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoomStoreRedis")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RoomStore for RoomStoreRedis {
    async fn join(&self, room: RoomId, p: Participant) -> StoreResult<JoinHandle> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let payload = encode_record(&p)?;
        let event = encode_room_event(&RoomEvent::ParticipantJoined {
            room,
            participant: p.clone(),
        })?;
        let mut connection = self.connection()?;
        join_script()
            .key(keys.participants())
            .key(keys.events())
            .arg(p.peer().raw().to_string())
            .arg(payload)
            .arg(self.config.room_ttl().as_secs())
            .arg(event)
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())?;
        Ok(JoinHandle::new(room, p.peer(), p.node()))
    }

    async fn leave(&self, room: RoomId, peer: PeerId) -> StoreResult<()> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let event = encode_room_event(&RoomEvent::ParticipantLeft { room, peer })?;
        let mut connection = self.connection()?;
        leave_script()
            .key(keys.participants())
            .key(keys.tracks())
            .key(keys.speakers())
            .key(keys.events())
            .key(keys.subscriptions())
            .key(GLOBAL_SUBSCRIPTIONS_KEY)
            .arg(peer.raw().to_string())
            .arg(self.config.room_ttl().as_secs())
            .arg(event)
            .arg(subscription_prefix(peer))
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())
    }

    async fn participants(
        &self,
        room: RoomId,
        limit: usize,
        cursor: Option<Cursor>,
    ) -> StoreResult<(Vec<Participant>, Option<Cursor>)> {
        refract_roomstore::validate_limit(limit)?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let mut connection = self.connection()?;
        let (next_raw, values): (u64, Vec<(String, Vec<u8>)>) = redis::cmd("HSCAN")
            .arg(keys.participants())
            .arg(cursor.map_or(0, Cursor::raw))
            .arg("COUNT")
            .arg(limit)
            .query(&mut connection)
            .map_err(map_redis_error)?;
        let mut participants = Vec::new();
        participants
            .try_reserve_exact(values.len().min(limit))
            .map_err(|_source| RoomStoreError::Backend {
                message: "participant page allocation failed".to_owned(),
            })?;
        for (_peer, payload) in values.into_iter().take(limit) {
            participants.push(decode_record::<Participant>(&payload)?);
        }
        enforce_deadline(started, self.config.operation_timeout())?;
        let next = (next_raw != 0).then_some(Cursor::from_raw(next_raw));
        Ok((participants, next))
    }

    async fn publish_track(&self, room: RoomId, peer: PeerId, track: TrackInfo) -> StoreResult<()> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let payload = encode_record(&track)?;
        let event = encode_room_event(&RoomEvent::TrackPublished {
            room,
            track: track.clone(),
        })?;
        let mut connection = self.connection()?;
        publish_track_script()
            .key(keys.participants())
            .key(keys.tracks())
            .key(keys.events())
            .arg(peer.raw().to_string())
            .arg(track.track().raw().to_string())
            .arg(payload)
            .arg(self.config.room_ttl().as_secs())
            .arg(event)
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())
    }

    async fn subscribe(
        &self,
        room: RoomId,
        sub: PeerId,
        target: TrackId,
    ) -> StoreResult<SubscriptionId> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let subscription = SubscriptionId::new(sub, target);
        let event = encode_room_event(&RoomEvent::Subscribed { room, subscription })?;
        let mut connection = self.connection()?;
        subscribe_script()
            .key(keys.participants())
            .key(keys.tracks())
            .key(keys.events())
            .key(keys.subscriptions())
            .key(GLOBAL_SUBSCRIPTIONS_KEY)
            .arg(sub.raw().to_string())
            .arg(target.raw().to_string())
            .arg(subscription.raw().to_string())
            .arg(self.config.room_ttl().as_secs())
            .arg(event)
            .arg(subscription_index_value(&keys))
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())?;
        Ok(subscription)
    }

    async fn unsubscribe(&self, sub: SubscriptionId) -> StoreResult<()> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let mut connection = self.connection()?;
        let event = encode_room_event(&RoomEvent::Unsubscribed { subscription: sub })?;
        unsubscribe_script()
            .key(GLOBAL_SUBSCRIPTIONS_KEY)
            .arg(sub.raw().to_string())
            .arg(event)
            .arg(self.config.room_ttl().as_secs())
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())
    }

    async fn report_audio_level(
        &self,
        room: RoomId,
        peer: PeerId,
        level: AudioLevel,
    ) -> StoreResult<()> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let event = encode_room_event(&RoomEvent::AudioLevel { room, peer, level })?;
        let mut connection = self.connection()?;
        audio_level_script()
            .key(keys.participants())
            .key(keys.speakers())
            .key(keys.events())
            .arg(peer.raw().to_string())
            .arg(level.loudness())
            .arg(self.config.room_ttl().as_secs())
            .arg(event)
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())
    }

    async fn watch_events(&self, room: RoomId) -> StoreResult<RoomEventStream> {
        let keys = RoomKeys::new(room);
        let connection = self.connection()?;
        spawn_pubsub_stream(
            connection,
            keys.events().to_owned(),
            self.config.operation_timeout(),
        )
    }

    async fn migrate_participant(&self, room: RoomId, peer: PeerId, to: NodeId) -> StoreResult<()> {
        self.ensure_write_allowed()?;
        let started = Instant::now();
        let keys = RoomKeys::new(room);
        let mut connection = self.connection()?;
        let old_payload: Option<Vec<u8>> = redis::cmd("HGET")
            .arg(keys.participants())
            .arg(peer.raw().to_string())
            .query(&mut connection)
            .map_err(map_redis_error)?;
        let old_payload = old_payload.ok_or(RoomStoreError::ParticipantNotFound)?;
        let mut participant = decode_record::<Participant>(&old_payload)?;
        participant.set_node(to);
        let new_payload = encode_record(&participant)?;
        let event = encode_room_event(&RoomEvent::ParticipantMigrated { room, peer, to })?;
        migrate_script()
            .key(keys.participants())
            .key(keys.events())
            .arg(peer.raw().to_string())
            .arg(old_payload)
            .arg(new_payload)
            .arg(self.config.room_ttl().as_secs())
            .arg(event)
            .invoke::<()>(&mut connection)
            .map_err(map_redis_error)?;
        enforce_deadline(started, self.config.operation_timeout())
    }
}

#[derive(Clone, Copy, Debug)]
struct HealthState {
    health: RedisHealth,
    last_check: Instant,
    failures: u32,
    backoff: Duration,
}

impl HealthState {
    fn new() -> Self {
        Self {
            health: RedisHealth::Healthy,
            last_check: Instant::now(),
            failures: 0,
            backoff: Duration::from_millis(50),
        }
    }

    fn healthy(health: RedisHealth) -> Self {
        Self {
            health,
            last_check: Instant::now(),
            failures: 0,
            backoff: Duration::from_millis(50),
        }
    }

    fn mark_degraded(&mut self, _reason: &'static str, max_backoff: Duration) {
        self.health = RedisHealth::Degraded;
        self.last_check = Instant::now();
        self.failures = self.failures.saturating_add(1);
        self.backoff = self.backoff.saturating_mul(2).min(max_backoff);
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MemorySnapshot {
    used_memory: u64,
    maxmemory: u64,
}

impl MemorySnapshot {
    fn used_percent(self) -> Option<u8> {
        if self.maxmemory == 0 {
            return None;
        }
        let percent = self.used_memory.saturating_mul(100) / self.maxmemory;
        if percent > 100 {
            Some(100)
        } else {
            Some(u8::try_from(percent).unwrap_or(100))
        }
    }

    fn health(self) -> RedisHealth {
        match self.used_percent() {
            Some(percent) if percent >= MEMORY_REFUSE_WRITES_PERCENT => {
                error!(
                    event = "roomstore_redis_memory_refuse",
                    used_percent = percent
                );
                RedisHealth::RefusingWrites
            }
            Some(percent) if percent >= MEMORY_ALERT_PERCENT => {
                warn!(
                    event = "roomstore_redis_memory_alert",
                    used_percent = percent
                );
                RedisHealth::Healthy
            }
            _ => RedisHealth::Healthy,
        }
    }
}

fn query_memory(connection: &mut redis::Connection) -> StoreResult<MemorySnapshot> {
    let info: String = redis::cmd("INFO")
        .arg("memory")
        .query(connection)
        .map_err(map_redis_error)?;
    let mut used_memory = 0;
    let mut maxmemory = 0;
    for line in info.lines() {
        if let Some(value) = line.strip_prefix("used_memory:") {
            used_memory = value.parse::<u64>().unwrap_or(0);
        }
        if let Some(value) = line.strip_prefix("maxmemory:") {
            maxmemory = value.parse::<u64>().unwrap_or(0);
        }
    }
    Ok(MemorySnapshot {
        used_memory,
        maxmemory,
    })
}

fn enforce_deadline(started: Instant, timeout: Duration) -> StoreResult<()> {
    if started.elapsed() > timeout {
        Err(RoomStoreError::Timeout { timeout })
    } else {
        Ok(())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_redis_error(source: redis::RedisError) -> RoomStoreError {
    RoomStoreError::Backend {
        message: source.to_string(),
    }
}

fn map_poison<T>(_source: PoisonError<MutexGuard<'_, T>>) -> RoomStoreError {
    RoomStoreError::InternalSync
}

fn subscription_prefix(peer: PeerId) -> String {
    format!("sub_{:016x}", peer.raw())
}

fn subscription_index_value(keys: &RoomKeys) -> String {
    format!("{}\n{}", keys.events(), keys.subscriptions())
}

const EVENT_PARTICIPANT_JOINED: u8 = 1;
const EVENT_PARTICIPANT_LEFT: u8 = 2;
const EVENT_TRACK_PUBLISHED: u8 = 3;
const EVENT_SUBSCRIBED: u8 = 4;
const EVENT_UNSUBSCRIBED: u8 = 5;
const EVENT_AUDIO_LEVEL: u8 = 6;
const EVENT_PARTICIPANT_MIGRATED: u8 = 7;
const EVENT_STREAM_QUEUE_BOUND: usize = 1024;

fn encode_room_event(event: &RoomEvent) -> StoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(64)
        .map_err(|_source| RoomStoreError::Backend {
            message: "room event allocation failed".to_owned(),
        })?;
    match event {
        RoomEvent::ParticipantJoined { room, participant } => {
            out.push(EVENT_PARTICIPANT_JOINED);
            push_u64(&mut out, room.raw());
            out.extend(encode_record(participant)?);
        }
        RoomEvent::ParticipantLeft { room, peer } => {
            out.push(EVENT_PARTICIPANT_LEFT);
            push_u64(&mut out, room.raw());
            push_u64(&mut out, peer.raw());
        }
        RoomEvent::TrackPublished { room, track } => {
            out.push(EVENT_TRACK_PUBLISHED);
            push_u64(&mut out, room.raw());
            out.extend(encode_record(track)?);
        }
        RoomEvent::Subscribed { room, subscription } => {
            out.push(EVENT_SUBSCRIBED);
            push_u64(&mut out, room.raw());
            push_u128(&mut out, subscription.raw());
        }
        RoomEvent::Unsubscribed { subscription } => {
            out.push(EVENT_UNSUBSCRIBED);
            push_u128(&mut out, subscription.raw());
        }
        RoomEvent::AudioLevel { room, peer, level } => {
            out.push(EVENT_AUDIO_LEVEL);
            push_u64(&mut out, room.raw());
            push_u64(&mut out, peer.raw());
            out.push(level.as_u8());
        }
        RoomEvent::ParticipantMigrated { room, peer, to } => {
            out.push(EVENT_PARTICIPANT_MIGRATED);
            push_u64(&mut out, room.raw());
            push_u64(&mut out, peer.raw());
            push_u64(&mut out, to.raw());
        }
        _ => {
            return Err(RoomStoreError::Serialization {
                component: "redis-event",
            });
        }
    }
    Ok(out)
}

fn decode_room_event(mut bytes: &[u8]) -> StoreResult<RoomEvent> {
    let Some((&tag, rest)) = bytes.split_first() else {
        return Err(RoomStoreError::Deserialization {
            component: "redis-event",
        });
    };
    bytes = rest;
    match tag {
        EVENT_PARTICIPANT_JOINED => {
            let room = RoomId::from_raw(read_u64(&mut bytes)?);
            let participant = decode_record::<Participant>(bytes)?;
            Ok(RoomEvent::ParticipantJoined { room, participant })
        }
        EVENT_PARTICIPANT_LEFT => {
            let event = RoomEvent::ParticipantLeft {
                room: RoomId::from_raw(read_u64(&mut bytes)?),
                peer: PeerId::from_raw(read_u64(&mut bytes)?),
            };
            ensure_empty_event_tail(bytes)?;
            Ok(event)
        }
        EVENT_TRACK_PUBLISHED => {
            let room = RoomId::from_raw(read_u64(&mut bytes)?);
            let track = decode_record::<TrackInfo>(bytes)?;
            Ok(RoomEvent::TrackPublished { room, track })
        }
        EVENT_SUBSCRIBED => {
            let event = RoomEvent::Subscribed {
                room: RoomId::from_raw(read_u64(&mut bytes)?),
                subscription: SubscriptionId::from_raw(read_u128(&mut bytes)?),
            };
            ensure_empty_event_tail(bytes)?;
            Ok(event)
        }
        EVENT_UNSUBSCRIBED => {
            let event = RoomEvent::Unsubscribed {
                subscription: SubscriptionId::from_raw(read_u128(&mut bytes)?),
            };
            ensure_empty_event_tail(bytes)?;
            Ok(event)
        }
        EVENT_AUDIO_LEVEL => {
            let room = RoomId::from_raw(read_u64(&mut bytes)?);
            let peer = PeerId::from_raw(read_u64(&mut bytes)?);
            let Some((&raw_level, rest)) = bytes.split_first() else {
                return Err(RoomStoreError::Deserialization {
                    component: "redis-event",
                });
            };
            bytes = rest;
            ensure_empty_event_tail(bytes)?;
            let level = AudioLevel::new(raw_level)?;
            Ok(RoomEvent::AudioLevel { room, peer, level })
        }
        EVENT_PARTICIPANT_MIGRATED => {
            let event = RoomEvent::ParticipantMigrated {
                room: RoomId::from_raw(read_u64(&mut bytes)?),
                peer: PeerId::from_raw(read_u64(&mut bytes)?),
                to: NodeId::from_raw(read_u64(&mut bytes)?),
            };
            ensure_empty_event_tail(bytes)?;
            Ok(event)
        }
        _ => Err(RoomStoreError::Deserialization {
            component: "redis-event",
        }),
    }
}

const fn ensure_empty_event_tail(bytes: &[u8]) -> StoreResult<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(RoomStoreError::Deserialization {
            component: "redis-event",
        })
    }
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_be_bytes());
}

fn push_u128(out: &mut Vec<u8>, value: u128) {
    out.extend(value.to_be_bytes());
}

fn read_u64(bytes: &mut &[u8]) -> StoreResult<u64> {
    Ok(u64::from_be_bytes(read_array(bytes)?))
}

fn read_u128(bytes: &mut &[u8]) -> StoreResult<u128> {
    Ok(u128::from_be_bytes(read_array(bytes)?))
}

fn read_array<const N: usize>(bytes: &mut &[u8]) -> StoreResult<[u8; N]> {
    if bytes.len() < N {
        return Err(RoomStoreError::Deserialization {
            component: "redis-event",
        });
    }
    let (head, tail) = bytes.split_at(N);
    *bytes = tail;
    let mut out = [0_u8; N];
    out.copy_from_slice(head);
    Ok(out)
}

fn spawn_pubsub_stream(
    mut connection: redis::Connection,
    channel: String,
    timeout: Duration,
) -> StoreResult<RoomEventStream> {
    let (sender, receiver) = sync_channel(EVENT_STREAM_QUEUE_BOUND);
    let waker = Arc::new(Mutex::new(None::<Waker>));
    let thread_waker = Arc::clone(&waker);
    thread::Builder::new()
        .name("refract-roomstore-redis-pubsub".to_owned())
        .spawn(move || {
            let mut pubsub = connection.as_pubsub();
            if let Err(source) = pubsub.set_read_timeout(Some(timeout)) {
                send_stream_item(&sender, &thread_waker, Err(map_redis_error(source)));
                return;
            }
            if let Err(source) = pubsub.subscribe(channel) {
                send_stream_item(&sender, &thread_waker, Err(map_redis_error(source)));
                return;
            }
            loop {
                match pubsub.get_message() {
                    Ok(message) => {
                        let event = decode_room_event(message.get_payload_bytes());
                        if !send_stream_item(&sender, &thread_waker, event) {
                            return;
                        }
                    }
                    Err(source) if source.is_timeout() => {}
                    Err(source) => {
                        send_stream_item(&sender, &thread_waker, Err(map_redis_error(source)));
                        return;
                    }
                }
            }
        })
        .map_err(|_source| RoomStoreError::Backend {
            message: "redis pubsub thread spawn failed".to_owned(),
        })?;
    Ok(RoomEventStream::new(RedisRoomEventStream::new(
        receiver, waker,
    )))
}

fn send_stream_item(
    sender: &std::sync::mpsc::SyncSender<StoreResult<RoomEvent>>,
    waker: &Mutex<Option<Waker>>,
    item: StoreResult<RoomEvent>,
) -> bool {
    if sender.send(item).is_err() {
        return false;
    }
    if let Ok(mut stored) = waker.lock()
        && let Some(waker) = stored.take()
    {
        waker.wake();
    }
    true
}

struct RedisRoomEventStream {
    receiver: Receiver<StoreResult<RoomEvent>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl RedisRoomEventStream {
    const fn new(
        receiver: Receiver<StoreResult<RoomEvent>>,
        waker: Arc<Mutex<Option<Waker>>>,
    ) -> Self {
        Self { receiver, waker }
    }
}

impl Stream for RedisRoomEventStream {
    type Item = StoreResult<RoomEvent>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.receiver.try_recv() {
            Ok(item) => Poll::Ready(Some(item)),
            Err(TryRecvError::Disconnected) => Poll::Ready(None),
            Err(TryRecvError::Empty) => {
                if let Ok(mut stored) = self.waker.lock() {
                    *stored = Some(context.waker().clone());
                }
                match self.receiver.try_recv() {
                    Ok(item) => Poll::Ready(Some(item)),
                    Err(TryRecvError::Disconnected) => Poll::Ready(None),
                    Err(TryRecvError::Empty) => Poll::Pending,
                }
            }
        }
    }
}

fn join_script() -> Script {
    Script::new(
        r"
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('PUBLISH', KEYS[2], ARGV[4])
return 1
",
    )
}

fn leave_script() -> Script {
    Script::new(
        r"
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('ZREM', KEYS[3], ARGV[1])
local subscriptions = redis.call('HKEYS', KEYS[5])
for _, subscription in ipairs(subscriptions) do
  if string.sub(subscription, 1, string.len(ARGV[4])) == ARGV[4] then
    redis.call('HDEL', KEYS[5], subscription)
    redis.call('HDEL', KEYS[6], subscription)
  end
end
redis.call('EXPIRE', KEYS[1], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[2])
redis.call('EXPIRE', KEYS[3], ARGV[2])
redis.call('EXPIRE', KEYS[5], ARGV[2])
redis.call('EXPIRE', KEYS[6], ARGV[2])
redis.call('PUBLISH', KEYS[4], ARGV[3])
return 1
",
    )
}

fn publish_track_script() -> Script {
    Script::new(
        r"
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then
  return redis.error_reply('ROOMSTORE_STATE_0001')
end
redis.call('HSET', KEYS[2], ARGV[2], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[4])
redis.call('PUBLISH', KEYS[3], ARGV[5])
return 1
",
    )
}

fn subscribe_script() -> Script {
    Script::new(
        r"
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then
  return redis.error_reply('ROOMSTORE_STATE_0001')
end
if redis.call('HEXISTS', KEYS[2], ARGV[2]) == 0 then
  return redis.error_reply('ROOMSTORE_STATE_0002')
end
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[4])
redis.call('HSET', KEYS[4], ARGV[3], ARGV[2])
redis.call('HSET', KEYS[5], ARGV[3], ARGV[6])
redis.call('EXPIRE', KEYS[4], ARGV[4])
redis.call('EXPIRE', KEYS[5], ARGV[4])
redis.call('PUBLISH', KEYS[3], ARGV[5])
return ARGV[3]
",
    )
}

fn unsubscribe_script() -> Script {
    Script::new(
        r"
local index_value = redis.call('HGET', KEYS[1], ARGV[1])
if not index_value then
  return 0
end
local separator = string.find(index_value, '\n', 1, true)
if not separator then
  redis.call('HDEL', KEYS[1], ARGV[1])
  return redis.error_reply('ROOMSTORE_STATE_0003')
end
local event_channel = string.sub(index_value, 1, separator - 1)
local room_subscriptions = string.sub(index_value, separator + 1)
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('HDEL', room_subscriptions, ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('EXPIRE', room_subscriptions, ARGV[3])
redis.call('PUBLISH', event_channel, ARGV[2])
return 1
",
    )
}

fn audio_level_script() -> Script {
    Script::new(
        r"
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then
  return redis.error_reply('ROOMSTORE_STATE_0001')
end
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('EXPIRE', KEYS[2], ARGV[3])
redis.call('PUBLISH', KEYS[3], ARGV[4])
return 1
",
    )
}

fn migrate_script() -> Script {
    Script::new(
        r"
local raw = redis.call('HGET', KEYS[1], ARGV[1])
if not raw then
  return redis.error_reply('ROOMSTORE_STATE_0001')
end
if raw ~= ARGV[2] then
  return redis.error_reply('ROOMSTORE_STATE_0004')
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('PUBLISH', KEYS[2], ARGV[5])
return 1
",
    )
}

/// Validates Redis memory pressure from raw values.
///
/// # Examples
///
/// ```
/// # use refract_roomstore_redis::{memory_health, RedisHealth};
/// assert_eq!(memory_health(91, 100), RedisHealth::RefusingWrites);
/// ```
#[must_use]
pub fn memory_health(used_memory: u64, maxmemory: u64) -> RedisHealth {
    MemorySnapshot {
        used_memory,
        maxmemory,
    }
    .health()
}

/// Parses a Redis `HSCAN` response payload into participant records.
///
/// # Errors
///
/// Returns deserialization errors when any record is malformed.
///
/// # Examples
///
/// ```
/// # use refract_core::{NodeId, PeerId};
/// # use refract_roomstore::{Participant, encode_record};
/// # use refract_roomstore_redis::decode_participants_page;
/// let participant = Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0)?;
/// let page = decode_participants_page(vec![("1".to_owned(), encode_record(&participant)?)])?;
/// assert_eq!(page, vec![participant]);
/// # Ok::<(), refract_roomstore::RoomStoreError>(())
/// ```
pub fn decode_participants_page(values: Vec<(String, Vec<u8>)>) -> StoreResult<Vec<Participant>> {
    values
        .into_iter()
        .map(|(_peer, payload)| decode_record::<Participant>(&payload))
        .collect()
}

#[cfg(test)]
mod tests {
    use refract_core::{NodeId, PeerId, RoomId, TrackId};
    use refract_roomstore::{
        AudioLevel, Participant, RoomEvent, SubscriptionId, TrackInfo, TrackKind, encode_record,
    };

    use super::{
        RedisHealth, RedisRoomStoreConfig, RoomKeys, decode_participants_page, decode_room_event,
        encode_room_event, memory_health,
    };

    #[test]
    fn config_rejects_empty_sentinel_list() {
        assert!(RedisRoomStoreConfig::new(Vec::new(), "m".into()).is_err());
    }

    #[test]
    fn keys_match_stage1_schema() {
        let keys = RoomKeys::new(RoomId::from_raw(1));

        assert!(keys.participants().starts_with("room:room_"));
        assert!(keys.participants().ends_with(":participants"));
        assert!(keys.tracks().ends_with(":tracks"));
        assert!(keys.speakers().ends_with(":speakers"));
        assert!(keys.subscriptions().ends_with(":subscriptions"));
        assert!(keys.events().ends_with(":events"));
    }

    #[test]
    fn memory_thresholds_fail_closed_at_ninety_percent() {
        assert_eq!(memory_health(69, 100), RedisHealth::Healthy);
        assert_eq!(memory_health(70, 100), RedisHealth::Healthy);
        assert_eq!(memory_health(90, 100), RedisHealth::RefusingWrites);
    }

    #[test]
    fn hscan_payload_decodes_participants() {
        let participant =
            Participant::new(PeerId::from_raw(1), NodeId::from_raw(2), 0).expect("participant");
        let page = decode_participants_page(vec![(
            "1".to_owned(),
            encode_record(&participant).expect("encode"),
        )])
        .expect("decode");

        assert_eq!(page, vec![participant]);
    }

    #[test]
    fn redis_event_payload_round_trips_room_events() {
        let room = RoomId::from_raw(1);
        let peer = PeerId::from_raw(2);
        let node = NodeId::from_raw(3);
        let track =
            TrackInfo::new(TrackId::from_raw(4), peer, TrackKind::Audio, "mic").expect("track");
        let subscription = SubscriptionId::new(peer, TrackId::from_raw(4));
        let events = [
            RoomEvent::ParticipantJoined {
                room,
                participant: Participant::new(peer, node, 0).expect("participant"),
            },
            RoomEvent::ParticipantLeft { room, peer },
            RoomEvent::TrackPublished { room, track },
            RoomEvent::Subscribed { room, subscription },
            RoomEvent::Unsubscribed { subscription },
            RoomEvent::AudioLevel {
                room,
                peer,
                level: AudioLevel::new(42).expect("level"),
            },
            RoomEvent::ParticipantMigrated {
                room,
                peer,
                to: node,
            },
        ];

        for event in events {
            let payload = encode_room_event(&event).expect("encode event");
            assert_eq!(decode_room_event(&payload).expect("decode event"), event);
        }
    }

    #[cfg(feature = "redis-integration")]
    #[test]
    #[ignore = "requires Redis 7.x plus Sentinel at REFRACT_REDIS_SENTINELS and REFRACT_REDIS_MASTER"]
    fn redis_sentinel_integration_connects_to_primary() {
        let sentinels = std::env::var("REFRACT_REDIS_SENTINELS")
            .expect("REFRACT_REDIS_SENTINELS")
            .split(',')
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let master = std::env::var("REFRACT_REDIS_MASTER").expect("REFRACT_REDIS_MASTER");
        let config = RedisRoomStoreConfig::new(sentinels, master.into()).expect("config");
        let store = super::RoomStoreRedis::connect(config).expect("connect");

        assert_eq!(store.health_check().expect("health"), RedisHealth::Healthy);
    }
}
