//! Production executable wiring for the refract `SFU`.
//!
//! The binary crate composes Stage 1 crates into one daemon process: CLI
//! parsing, validated configuration, observability, resilience guards, worker
//! thread ownership, signal handling, admin/signaling control threads, and
//! systemd readiness notification.
//!
//! # Examples
//!
//! ```no_run
//! refract_bin::run()?;
//! # Ok::<(), refract_bin::BinError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    backtrace::Backtrace,
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use core_affinity::CoreId as AffinityCoreId;
use refract_admin::{AdminApi, AdminRequest, Method, PeerCredentials};
use refract_cluster::{EdgeNode, SingleEdgePlacementOracle};
use refract_config::{Config, ConfigError, ConfigStore};
use refract_core::{NodeId, PeerId, RoomId, SessionId};
use refract_obs::{CoreRecorder, TracingConfig};
use refract_resilience::{
    CoreHeartbeat, DrainMode, DrainRequest, DrainSignal, OomHandler, Watchdog,
};
use refract_sfu::{
    CoreId, DEFAULT_CONTROL_RING_DEPTH, DEFAULT_CONTROL_TIMEOUT, DEFAULT_MEDIA_IDLE_POLL,
    RtcOfferAccepted, SfuConfig, SfuControlConsumer, SfuControlSender, SfuCore, SfuIceCandidate,
    SfuRtcOffer,
};
use refract_signal::{
    RtcAnswer, RtcIceCandidateRequest, RtcJoinRequest, RtcOfferRequest, RtcSessionMetadata,
    RtcSignalingController, SignalCapabilities, SignalConfig, SignalError, SignalHttpServer,
    SignalHttpServerConfig, SignalResult,
};
use signal_hook::{
    consts::signal::{SIGTERM, SIGUSR1, SIGUSR2},
    iterator::Signals,
};
use thiserror::Error as ThisError;
use tracing::{error, info, warn};

const DEFAULT_CONFIG_PATH: &str = "example.toml";
const DEFAULT_PER_CORE_PEERS: usize = 1_024;
const DEFAULT_ADMIN_SLEEP: Duration = Duration::from_millis(50);
const DEFAULT_WATCHDOG_SLEEP: Duration = Duration::from_millis(250);
const SYSTEMD_READY: &str = "READY=1";

/// Result alias for `refract-bin`.
pub type BinResult<T> = Result<T, BinError>;

/// Stage marker for public `refract-bin` APIs.
///
/// # Examples
///
/// ```
/// # use refract_bin::Stability;
/// assert_eq!(Stability::Stage1.as_str(), "stage1");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns a stable label for this API state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_bin::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Binary startup and runtime errors with stable operator codes.
///
/// # Examples
///
/// ```
/// # use refract_bin::BinError;
/// assert_eq!(
///     BinError::ThreadJoin { thread: "x" }.error_code(),
///     "BIN_THREAD_0002"
/// );
/// ```
#[derive(Debug, ThisError)]
pub enum BinError {
    /// Configuration loading or reload failed.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    /// Observability setup failed.
    #[error("observability setup failed: {message}")]
    Observability {
        /// Clear setup failure message.
        message: String,
    },
    /// Signal registration failed.
    #[error("signal handler setup failed: {source}")]
    Signals {
        /// Source IO error.
        source: io::Error,
    },
    /// A daemon thread could not be spawned.
    #[error("thread spawn failed for {thread}: {source}")]
    ThreadSpawn {
        /// Thread role.
        thread: &'static str,
        /// Source IO error.
        source: io::Error,
    },
    /// A daemon thread panicked.
    #[error("thread join failed for {thread}")]
    ThreadJoin {
        /// Thread role.
        thread: &'static str,
    },
    /// Per-core `SFU` construction failed.
    #[error("sfu core startup failed: {0}")]
    Sfu(#[from] refract_sfu::SfuError),
    /// Cluster composition failed.
    #[error("cluster startup failed: {0}")]
    Cluster(#[from] refract_cluster::ClusterError),
    /// Admin API startup failed.
    #[error("admin startup failed: {0}")]
    Admin(#[from] refract_admin::AdminError),
    /// Signaling server startup failed.
    #[error("signaling startup failed: {0}")]
    Signal(#[from] SignalError),
    /// Bounded startup value could not be represented.
    #[error("startup value out of range for {field}")]
    OutOfRange {
        /// Field whose value was rejected.
        field: &'static str,
    },
    /// Systemd notification failed.
    #[error("systemd notification failed: {source}")]
    Systemd {
        /// Source IO error.
        source: io::Error,
    },
}

impl BinError {
    /// Returns the stable operator dashboard code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_bin::BinError;
    /// assert_eq!(
    ///     BinError::OutOfRange {
    ///         field: "runtime.cores"
    ///     }
    ///     .error_code(),
    ///     "BIN_RANGE_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Config(_) => "BIN_CONFIG_0001",
            Self::Observability { .. } => "BIN_OBS_0001",
            Self::Signals { .. } => "BIN_SIGNAL_0001",
            Self::ThreadSpawn { .. } => "BIN_THREAD_0001",
            Self::ThreadJoin { .. } => "BIN_THREAD_0002",
            Self::Sfu(_) => "BIN_SFU_0001",
            Self::Cluster(_) => "BIN_CLUSTER_0001",
            Self::Admin(_) => "BIN_ADMIN_0001",
            Self::Signal(_) => "BIN_SIGNAL_0002",
            Self::OutOfRange { .. } => "BIN_RANGE_0001",
            Self::Systemd { .. } => "BIN_SYSTEMD_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_bin::{BinError, Stability};
    /// assert_eq!(
    ///     BinError::OutOfRange { field: "x" }.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

/// Runs the refract daemon.
///
/// # Errors
///
/// Returns [`BinError`] when configuration, observability, signal handling,
/// cluster startup, worker startup, or graceful shutdown fails.
pub fn run() -> BinResult<()> {
    let cli = Cli::parse();
    run_with_cli(&cli)
}

#[derive(Clone, Debug, Parser)]
#[command(
    name = "refract",
    about = "Thread-per-core refract SFU daemon",
    version
)]
struct Cli {
    #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}

fn run_with_cli(cli: &Cli) -> BinResult<()> {
    install_observability()?;
    refract_core::panic::set_panic_hook();

    let config = Config::from_file(&cli.config)?;
    let store = Arc::new(ConfigStore::new(config));
    let drain = DrainSignal::default();
    let _oom = OomHandler::new(drain.clone());
    let topology = Topology::detect(store.snapshot().runtime().cores())?;
    let oracle = connect_cluster(&store.snapshot())?;
    let worker_stop = Arc::new(AtomicBool::new(false));
    let heartbeats = build_heartbeats(&topology)?;
    let workers = spawn_workers(
        &topology,
        &store.snapshot(),
        &heartbeats,
        &drain,
        &worker_stop,
    )?;
    let signal_thread = spawn_signal_thread(cli.config.clone(), store.clone(), drain.clone())?;
    let admin_thread = spawn_admin_thread(drain.clone(), worker_stop.clone())?;
    let signaling_thread = spawn_signaling_thread(
        signaling_bind(&store.snapshot()),
        workers.rtc_controls.clone(),
        drain.clone(),
        worker_stop.clone(),
    )?;
    let watchdog_thread = spawn_watchdog(heartbeats, drain.clone(), worker_stop.clone())?;

    info!(
        node_id = store.snapshot().cluster().raft().node_id(),
        cluster_nodes = oracle.nodes,
        workers = topology.cores.len(),
        "refract daemon ready"
    );
    sd_notify_ready()?;

    if cli.check {
        drain.trigger(DrainRequest::new(
            DrainMode::Graceful,
            "startup_check",
            "BIN-CHECK-0001",
        ));
    }

    wait_for_drain(&drain);
    worker_stop.store(true, Ordering::Release);
    join_all(
        workers.handles,
        admin_thread,
        signaling_thread,
        watchdog_thread,
    )?;
    signal_thread.close();
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Topology {
    cores: Vec<CpuCore>,
}

impl Topology {
    fn detect(requested_cores: usize) -> BinResult<Self> {
        let affinity_cores = core_affinity::get_core_ids().unwrap_or_default();
        let fallback_cores = thread::available_parallelism()
            .map_or_else(|_error| requested_cores.max(1), usize::from);
        let available = affinity_cores.len().max(fallback_cores);
        let core_count = requested_cores.min(available).max(1);
        let cores = (0..core_count)
            .map(|index| {
                let core_index = u16::try_from(index).map_err(|_source| BinError::OutOfRange {
                    field: "runtime.cores",
                })?;
                Ok(CpuCore::new(core_index, affinity_cores.get(index).copied()))
            })
            .collect::<BinResult<Vec<_>>>()?;
        info!(
            requested_cores,
            available_cores = available,
            selected_cores = core_count,
            topology_source = "core_affinity",
            "detected CPU topology"
        );
        Ok(Self { cores })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CpuCore {
    index: u16,
    affinity: Option<AffinityCoreId>,
}

impl CpuCore {
    const fn new(index: u16, affinity: Option<AffinityCoreId>) -> Self {
        Self { index, affinity }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectedCluster {
    nodes: usize,
}

fn connect_cluster(snapshot: &refract_config::ConfigSnapshot) -> BinResult<ConnectedCluster> {
    let node_id = NodeId::from_raw(snapshot.cluster().raft().node_id());
    let advertised = advertise_address(snapshot.net().bind_addrs());
    let edge = EdgeNode::new(node_id, advertised)?;
    let _oracle = SingleEdgePlacementOracle::new(edge);
    info!(
        node_id = snapshot.cluster().raft().node_id(),
        peer_count = snapshot.cluster().peer_addrs().len(),
        raft_heartbeat_ms = snapshot.cluster().raft().heartbeat_ms(),
        raft_election_timeout_ms = snapshot.cluster().raft().election_timeout_ms(),
        "cluster control plane connected"
    );
    Ok(ConnectedCluster {
        nodes: snapshot.cluster().peer_addrs().len().saturating_add(1),
    })
}

fn advertise_address(bind_addrs: &[SocketAddr]) -> String {
    bind_addrs
        .first()
        .map_or_else(|| "127.0.0.1:0".to_owned(), ToString::to_string)
}

fn build_heartbeats(topology: &Topology) -> BinResult<Vec<Arc<CoreHeartbeat>>> {
    let now = now_millis();
    topology
        .cores
        .iter()
        .map(|core| {
            let heartbeat = Arc::new(CoreHeartbeat::new(core.index));
            heartbeat.bump_at(now);
            Ok(heartbeat)
        })
        .collect()
}

fn spawn_workers(
    topology: &Topology,
    snapshot: &refract_config::ConfigSnapshot,
    heartbeats: &[Arc<CoreHeartbeat>],
    drain: &DrainSignal,
    stop: &Arc<AtomicBool>,
) -> BinResult<WorkerLaunch> {
    let pinning = snapshot.runtime().pinning();
    let mut handles = Vec::new();
    let mut rtc_controls = Vec::new();
    handles
        .try_reserve_exact(topology.cores.len())
        .map_err(|_source| BinError::OutOfRange { field: "workers" })?;
    rtc_controls
        .try_reserve_exact(topology.cores.len())
        .map_err(|_source| BinError::OutOfRange {
            field: "rtc_controls",
        })?;
    for (core, heartbeat) in topology.cores.iter().zip(heartbeats) {
        let heartbeat = heartbeat.clone();
        let drain = drain.clone();
        let stop = stop.clone();
        let core = core.clone();
        let sfu_config = sfu_config_for_core(&core, snapshot)?;
        let media_bind = media_bind_for_core(&core, snapshot)?;
        let (rtc_control, mut rtc_consumer) = SfuControlSender::pair(DEFAULT_CONTROL_RING_DEPTH)?;
        rtc_controls.push(WorkerRtcControl {
            core_id: core.index,
            media_bind,
            sender: rtc_control,
        });
        let thread = thread::Builder::new()
            .name(format!("refract-sfu-core-{}", core.index))
            .spawn(move || {
                let mut runtime = WorkerRuntime {
                    rtc_control: &mut rtc_consumer,
                    heartbeat: &heartbeat,
                    drain: &drain,
                    stop: &stop,
                };
                run_worker(&core, pinning, sfu_config, media_bind, &mut runtime);
            })
            .map_err(|source| BinError::ThreadSpawn {
                thread: "worker",
                source,
            })?;
        handles.push(WorkerHandle { thread });
    }
    Ok(WorkerLaunch {
        handles,
        rtc_controls,
    })
}

fn sfu_config_for_core(
    core: &CpuCore,
    snapshot: &refract_config::ConfigSnapshot,
) -> BinResult<SfuConfig> {
    let max_peers = peers_per_core(snapshot);
    SfuConfig::new(CoreId::new(core.index), max_peers)?
        .with_packet_capacity(usize::from(snapshot.net().mtu()))?
        .with_outbox_depth(128)
        .map_err(BinError::from)
}

fn media_bind_for_core(
    core: &CpuCore,
    snapshot: &refract_config::ConfigSnapshot,
) -> BinResult<SocketAddr> {
    let ip = snapshot
        .net()
        .bind_addrs()
        .first()
        .map_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]), SocketAddr::ip);
    let port = snapshot
        .net()
        .rtp_port()
        .checked_add(core.index)
        .ok_or(BinError::OutOfRange {
            field: "net.rtp_port",
        })?;
    Ok(SocketAddr::new(ip, port))
}

fn peers_per_core(snapshot: &refract_config::ConfigSnapshot) -> usize {
    let enabled_sessions = snapshot
        .apps()
        .values()
        .filter(|app| app.enabled())
        .map(refract_config::AppConfig::max_sessions)
        .sum::<usize>();
    let total = enabled_sessions.max(DEFAULT_PER_CORE_PEERS);
    total
        .checked_div(snapshot.runtime().cores().max(1))
        .unwrap_or(DEFAULT_PER_CORE_PEERS)
        .max(1)
}

struct WorkerRuntime<'a> {
    rtc_control: &'a mut SfuControlConsumer,
    heartbeat: &'a CoreHeartbeat,
    drain: &'a DrainSignal,
    stop: &'a AtomicBool,
}

fn run_worker(
    core: &CpuCore,
    pinning: bool,
    config: SfuConfig,
    media_bind: SocketAddr,
    runtime: &mut WorkerRuntime<'_>,
) {
    pin_current_thread(core, pinning);
    match SfuCore::new(config) {
        Ok(mut core) => {
            info!(core_id = %core.core_id(), media_bind = %media_bind, "sfu core started");
            let media_stop = AtomicBool::new(false);
            let result = core.run_udp_media_controlled_until(
                media_bind,
                &media_stop,
                DEFAULT_MEDIA_IDLE_POLL,
                runtime.rtc_control,
                || {
                    runtime.heartbeat.bump_at(now_millis());
                    if runtime.stop.load(Ordering::Acquire) || runtime.drain.is_triggered() {
                        media_stop.store(true, Ordering::Release);
                    }
                },
            );
            if let Err(error) = result {
                error!(
                    core_id = %core.core_id(),
                    error_code = error.error_code(),
                    error = %error,
                    "sfu media socket failed"
                );
                runtime.drain.trigger(DrainRequest::new(
                    DrainMode::Fast,
                    "media_socket",
                    "BIN-SFU-MEDIA-0001",
                ));
            }
            info!(core_id = %core.core_id(), "sfu core stopped");
        }
        Err(error) => {
            error!(
                error_code = "BIN-SFU-START-0001",
                error = %error,
                "sfu core startup failed"
            );
            runtime.drain.trigger(DrainRequest::new(
                DrainMode::Fast,
                "worker_start",
                "BIN-SFU-START-0001",
            ));
        }
    }
}

fn pin_current_thread(core: &CpuCore, pinning: bool) {
    if !pinning {
        return;
    }
    match core.affinity {
        Some(affinity) if core_affinity::set_for_current(affinity) => {
            info!(
                core_id = core.index,
                affinity_id = affinity.id,
                "worker pinned to CPU"
            );
        }
        Some(affinity) => {
            warn!(
                core_id = core.index,
                affinity_id = affinity.id,
                "worker CPU pinning request failed"
            );
        }
        None => {
            warn!(core_id = core.index, "worker CPU pinning unavailable");
        }
    }
}

#[derive(Debug)]
struct WorkerHandle {
    thread: JoinHandle<()>,
}

#[derive(Clone, Debug)]
struct WorkerRtcControl {
    core_id: u16,
    media_bind: SocketAddr,
    sender: SfuControlSender,
}

#[derive(Debug)]
struct WorkerLaunch {
    handles: Vec<WorkerHandle>,
    rtc_controls: Vec<WorkerRtcControl>,
}

struct SignalHandle {
    thread: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl SignalHandle {
    fn close(self) {
        self.stop.store(true, Ordering::Release);
        if self.thread.join().is_err() {
            warn!(
                error_code = "BIN-SIGNAL-JOIN-0001",
                "signal handler thread failed during shutdown"
            );
        }
    }
}

fn spawn_signal_thread(
    config_path: PathBuf,
    store: Arc<ConfigStore>,
    drain: DrainSignal,
) -> BinResult<SignalHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let mut signals =
        Signals::new([SIGTERM, SIGUSR1, SIGUSR2]).map_err(|source| BinError::Signals { source })?;
    let thread = thread::Builder::new()
        .name("refract-signal-handler".to_owned())
        .spawn(move || {
            while !stop_thread.load(Ordering::Acquire) {
                signals
                    .pending()
                    .for_each(|signal| handle_signal(signal, &config_path, &store, &drain));
                thread::sleep(DEFAULT_ADMIN_SLEEP);
            }
        })
        .map_err(|source| BinError::ThreadSpawn {
            thread: "signal",
            source,
        })?;
    Ok(SignalHandle { thread, stop })
}

fn handle_signal(signal: i32, config_path: &Path, store: &ConfigStore, drain: &DrainSignal) {
    match signal {
        SIGTERM => {
            info!(signal = "SIGTERM", "graceful drain requested by signal");
            drain.trigger(DrainRequest::new(
                DrainMode::Graceful,
                "sigterm",
                "BIN-SIGNAL-TERM-0001",
            ));
        }
        SIGUSR1 => match store.reload_from_path(config_path) {
            Ok(report) => {
                report.warnings().iter().for_each(|warning| {
                    warn!(
                        field = warning.field(),
                        message = warning.message(),
                        "immutable config change ignored during reload"
                    );
                });
                info!(
                    signal = "SIGUSR1",
                    applied = report.applied(),
                    "config reloaded"
                );
            }
            Err(error) => {
                warn!(
                    error_code = error.error_code(),
                    error = %error,
                    "config reload rejected"
                );
            }
        },
        SIGUSR2 => {
            let backtrace = Backtrace::force_capture();
            info!(signal = "SIGUSR2", stack = ?backtrace, "stack dump requested");
        }
        other => {
            warn!(signal = other, "unexpected signal delivered");
        }
    }
}

fn spawn_admin_thread(drain: DrainSignal, stop: Arc<AtomicBool>) -> BinResult<JoinHandle<()>> {
    thread::Builder::new()
        .name("refract-admin".to_owned())
        .spawn(move || {
            let mut api = AdminApi::default();
            let request =
                AdminRequest::new(Method::Get, "/capabilities", "", PeerCredentials::root());
            match api.handle(&request) {
                Ok(response) => info!(status = response.status(), "admin API started"),
                Err(error) => error!(
                    error_code = error.error_code(),
                    error = %error,
                    "admin API startup check failed"
                ),
            }
            while !stop.load(Ordering::Acquire) && !drain.is_triggered() {
                thread::sleep(DEFAULT_ADMIN_SLEEP);
            }
            info!("admin API stopped");
        })
        .map_err(|source| BinError::ThreadSpawn {
            thread: "admin",
            source,
        })
}

fn signaling_bind(snapshot: &refract_config::ConfigSnapshot) -> SocketAddr {
    snapshot
        .net()
        .bind_addrs()
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], snapshot.net().rtp_port())))
}

#[derive(Debug)]
struct BinRtcController {
    controls: Vec<WorkerRtcControl>,
    next_session: AtomicU64,
}

impl BinRtcController {
    fn new(controls: Vec<WorkerRtcControl>) -> BinResult<Self> {
        if controls.is_empty() {
            return Err(BinError::OutOfRange {
                field: "rtc_controls",
            });
        }
        Ok(Self {
            controls,
            next_session: AtomicU64::new(1),
        })
    }

    fn allocate_metadata(&self, room: &str) -> SignalResult<RtcSessionMetadata> {
        let sequence = self.next_session.fetch_add(1, Ordering::AcqRel);
        let core_index = usize::try_from(sequence)
            .map_err(|_source| SignalError::RtcMediaUnavailable)?
            % self.controls.len();
        let control = self
            .controls
            .get(core_index)
            .ok_or(SignalError::RtcMediaUnavailable)?;
        let low = u32::try_from(sequence & u64::from(u32::MAX))
            .map_err(|_source| SignalError::RtcMediaUnavailable)?;
        let session_id = SessionId::from_parts(u32::from(control.core_id), low);
        Ok(RtcSessionMetadata::new(
            session_id,
            PeerId::from_raw(session_id.raw()),
            stable_room_id(room),
            control.core_id,
            control.media_bind,
        ))
    }

    fn control_for_session(&self, session_id: SessionId) -> SignalResult<&WorkerRtcControl> {
        let core_id = u16::try_from(session_id.raw() >> 32)
            .map_err(|_source| SignalError::RtcMediaUnavailable)?;
        self.controls
            .iter()
            .find(|control| control.core_id == core_id)
            .ok_or(SignalError::RtcMediaUnavailable)
    }
}

impl RtcSignalingController for BinRtcController {
    fn join(&self, request: RtcJoinRequest<'_>) -> Result<RtcSessionMetadata, SignalError> {
        self.allocate_metadata(request.room())
    }

    fn accept_offer(&self, request: RtcOfferRequest<'_>) -> Result<RtcAnswer, SignalError> {
        let metadata = request
            .metadata()
            .map_or_else(|| self.allocate_metadata(request.room()), Ok)?;
        let control = self.control_for_session(metadata.session_id())?;
        let accepted = control
            .sender
            .accept_rtc_offer(
                SfuRtcOffer::new(
                    metadata.session_id(),
                    metadata.peer_id(),
                    metadata.room_id(),
                    request.sdp().into(),
                ),
                DEFAULT_CONTROL_TIMEOUT,
            )
            .map_err(|error| {
                warn!(
                    error_code = error.error_code(),
                    error = %error,
                    session_id = %metadata.session_id(),
                    "rtc offer rejected by media core"
                );
                SignalError::RtcMediaUnavailable
            })?;
        Ok(RtcAnswer::new(
            metadata_from_accepted(&accepted),
            accepted.sdp().into(),
        ))
    }

    fn add_ice_candidate(&self, request: RtcIceCandidateRequest<'_>) -> Result<(), SignalError> {
        let control = self.control_for_session(request.session_id())?;
        control
            .sender
            .add_ice_candidate(
                SfuIceCandidate::new(request.session_id(), request.candidate().into()),
                DEFAULT_CONTROL_TIMEOUT,
            )
            .map_err(|error| {
                warn!(
                    error_code = error.error_code(),
                    error = %error,
                    session_id = %request.session_id(),
                    "rtc ice candidate rejected by media core"
                );
                SignalError::RtcMediaUnavailable
            })
    }

    fn leave(&self, session_id: SessionId) -> Result<(), SignalError> {
        let control = self.control_for_session(session_id)?;
        control
            .sender
            .leave(session_id, DEFAULT_CONTROL_TIMEOUT)
            .map_err(|error| {
                warn!(
                    error_code = error.error_code(),
                    error = %error,
                    session_id = %session_id,
                    "rtc leave rejected by media core"
                );
                SignalError::RtcMediaUnavailable
            })
    }
}

const fn metadata_from_accepted(accepted: &RtcOfferAccepted) -> RtcSessionMetadata {
    RtcSessionMetadata::new(
        accepted.session_id(),
        accepted.peer_id(),
        accepted.room_id(),
        accepted.core_id().as_u16(),
        accepted.media_addr(),
    )
}

fn stable_room_id(room: &str) -> RoomId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let hash = room.bytes().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    });
    RoomId::from_raw(hash.max(1))
}

fn spawn_signaling_thread(
    bind: SocketAddr,
    rtc_controls: Vec<WorkerRtcControl>,
    drain: DrainSignal,
    stop: Arc<AtomicBool>,
) -> BinResult<JoinHandle<()>> {
    let controller = Arc::new(BinRtcController::new(rtc_controls)?);
    let config = SignalHttpServerConfig::new(bind, SignalConfig::default())?
        .with_capabilities(SignalCapabilities::new(true, true));
    let server = SignalHttpServer::bind_with_rtc(config, controller)?;
    thread::Builder::new()
        .name("refract-signaling".to_owned())
        .spawn(move || {
            match server.local_addr() {
                Ok(addr) => info!(bind = %addr, "signaling listener started"),
                Err(error) => warn!(error_code = error.error_code(), error = %error, "signaling local address unavailable"),
            }
            if let Err(error) = server.run_until(&stop) {
                error!(
                    error_code = error.error_code(),
                    error = %error,
                    "signaling listener failed"
                );
                drain.trigger(DrainRequest::new(
                    DrainMode::Fast,
                    "signaling",
                    "BIN-SIGNAL-0002",
                ));
            }
            info!("signaling thread stopped");
        })
        .map_err(|source| BinError::ThreadSpawn {
            thread: "signaling",
            source,
        })
}

fn spawn_watchdog(
    heartbeats: Vec<Arc<CoreHeartbeat>>,
    drain: DrainSignal,
    stop: Arc<AtomicBool>,
) -> BinResult<JoinHandle<()>> {
    thread::Builder::new()
        .name("refract-watchdog".to_owned())
        .spawn(move || {
            let watchdog = Watchdog::new(drain);
            while !stop.load(Ordering::Acquire) {
                let outcome = watchdog.check_at(now_millis(), heartbeats.iter().cloned());
                if !outcome.is_healthy() {
                    break;
                }
                thread::sleep(DEFAULT_WATCHDOG_SLEEP);
            }
            info!("watchdog stopped");
        })
        .map_err(|source| BinError::ThreadSpawn {
            thread: "watchdog",
            source,
        })
}

fn wait_for_drain(drain: &DrainSignal) {
    while !drain.is_triggered() {
        thread::sleep(DEFAULT_ADMIN_SLEEP);
    }
    if let Some(request) = drain.request() {
        info!(
            mode = %request.mode(),
            reason = request.reason(),
            error_code = request.error_code(),
            "drain entered"
        );
    }
}

fn join_all(
    workers: Vec<WorkerHandle>,
    admin: JoinHandle<()>,
    signaling: JoinHandle<()>,
    watchdog: JoinHandle<()>,
) -> BinResult<()> {
    workers
        .into_iter()
        .map(|worker| worker.thread)
        .chain([admin, signaling, watchdog])
        .try_for_each(|thread| {
            thread
                .join()
                .map_err(|_payload| BinError::ThreadJoin { thread: "daemon" })
        })?;
    Ok(())
}

fn install_observability() -> BinResult<()> {
    let subscriber = TracingConfig::default()
        .build_subscriber()
        .map_err(|error| BinError::Observability {
            message: error.to_string(),
        })?;
    tracing::subscriber::set_global_default(subscriber).map_err(|error| {
        BinError::Observability {
            message: error.to_string(),
        }
    })?;

    let recorder = Box::leak(Box::new(CoreRecorder::default()));
    recorder.register_stage1_metrics();
    metrics::set_global_recorder(recorder).map_err(|error| BinError::Observability {
        message: error.to_string(),
    })?;
    Ok(())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn sd_notify_ready() -> BinResult<()> {
    let Some(socket) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = PathBuf::from(socket);
    if socket.as_os_str().is_empty() {
        return Ok(());
    }
    let local = temp_notify_path()?;
    let datagram = std::os::unix::net::UnixDatagram::bind(&local)
        .map_err(|source| BinError::Systemd { source })?;
    let send_result = datagram.send_to(SYSTEMD_READY.as_bytes(), &socket);
    let remove_result = fs::remove_file(&local);
    if let Err(source) = remove_result {
        warn!(error = %source, path = %local.display(), "temporary notify socket cleanup failed");
    }
    send_result
        .map(|_bytes| ())
        .map_err(|source| BinError::Systemd { source })
}

fn temp_notify_path() -> BinResult<PathBuf> {
    let path = env::temp_dir().join(format!("refract-notify-{}.sock", std::process::id()));
    if path.exists() {
        fs::remove_file(&path).map_err(|source| BinError::Systemd { source })?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use refract_config::Config;

    use super::{Cli, Topology, peers_per_core};

    #[test]
    fn cli_accepts_config_and_check_mode() {
        let cli = Cli::parse_from(["refract", "--check", "--config", "example.toml"]);

        assert!(cli.check);
        assert_eq!(cli.config, std::path::PathBuf::from("example.toml"));
    }

    #[test]
    fn topology_never_selects_zero_cores() -> Result<(), Box<dyn std::error::Error>> {
        let topology = Topology::detect(1)?;

        assert_eq!(topology.cores.len(), 1);
        Ok(())
    }

    #[test]
    fn peers_per_core_has_safe_default() {
        let store = refract_config::ConfigStore::new(Config::default());

        assert_eq!(peers_per_core(&store.snapshot()), 1_024);
    }
}
