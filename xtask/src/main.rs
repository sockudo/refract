//! Build, verification, fuzz, and release helper entry point.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    env,
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use xshell::{Shell, cmd};

type XtaskResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

const MSRV_TOOLCHAIN: &str = "1.95.0";
const COVERAGE_THRESHOLD: u8 = 80;

#[derive(Debug, Parser)]
#[command(name = "xtask")]
#[command(about = "refract workspace automation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Fmt,
    Lint,
    Test,
    Bench,
    Fuzz {
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    Coverage,
    Audit,
    Deny,
    Msrv,
    Preflight,
    SignalLoadgen {
        #[arg(long, default_value_t = refract_loadgen::DEFAULT_SIGNAL_LOAD_CONNECTIONS)]
        connections: usize,
        #[arg(long, default_value_t = refract_loadgen::DEFAULT_SIGNAL_MESSAGES_PER_CONNECTION)]
        messages_per_connection: usize,
    },
    XdpLoad {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value_t = 50_000)]
        port: u16,
        #[arg(long, default_value_t = refract_xdp::DEFAULT_STUN_RATE_PER_SECOND)]
        stun_rate: u32,
        #[arg(long, default_value_t = refract_xdp::DEFAULT_STUN_BURST)]
        stun_burst: u32,
        #[arg(long)]
        generic: bool,
        #[arg(long)]
        hardware: bool,
        #[arg(long, default_value_t = 30)]
        hold_seconds: u64,
        #[arg(long)]
        object: Option<PathBuf>,
        #[arg(long)]
        skip_build: bool,
    },
    Release {
        #[arg(long)]
        native: bool,
    },
    InstallHooks,
}

fn main() -> XtaskResult<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;

    match cli.command {
        Command::Fmt => run_fmt(&sh),
        Command::Lint => run_lint(&sh),
        Command::Test => run_test(&sh),
        Command::Bench => run_bench(&sh),
        Command::Fuzz { seconds } => run_fuzz(&sh, seconds),
        Command::Coverage => run_coverage(&sh),
        Command::Audit => run_audit(&sh),
        Command::Deny => run_deny(&sh),
        Command::Msrv => run_msrv(&sh),
        Command::Preflight => {
            print_preflight();
            Ok(())
        }
        Command::SignalLoadgen {
            connections,
            messages_per_connection,
        } => run_signal_loadgen(connections, messages_per_connection),
        Command::XdpLoad {
            interface,
            port,
            stun_rate,
            stun_burst,
            generic,
            hardware,
            hold_seconds,
            object,
            skip_build,
        } => run_xdp_load(
            &sh,
            XdpLoadArgs {
                interface,
                port,
                stun_rate,
                stun_burst,
                generic,
                hardware,
                hold_seconds,
                object,
                skip_build,
            },
        ),
        Command::Release { native } => run_release(&sh, native),
        Command::InstallHooks => install_hooks(),
    }
}

fn run_fmt(sh: &Shell) -> XtaskResult<()> {
    cmd!(sh, "cargo fmt --all --check").run()?;
    Ok(())
}

fn run_lint(sh: &Shell) -> XtaskResult<()> {
    run_fmt(sh)?;
    cmd!(
        sh,
        "cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::pedantic -D clippy::nursery -D clippy::perf -D clippy::cargo -A clippy::module_name_repetitions -A clippy::missing_errors_doc"
    )
    .run()?;
    Ok(())
}

fn run_test(sh: &Shell) -> XtaskResult<()> {
    cmd!(sh, "cargo test --workspace --all-targets --all-features").run()?;
    cmd!(sh, "cargo test --workspace --doc --all-features").run()?;
    Ok(())
}

fn run_bench(sh: &Shell) -> XtaskResult<()> {
    cmd!(sh, "cargo bench --workspace --all-features").run()?;
    Ok(())
}

fn run_signal_loadgen(connections: usize, messages_per_connection: usize) -> XtaskResult<()> {
    let config = refract_loadgen::SignalLoadgenConfig::new(
        refract_signal_config(),
        connections,
        messages_per_connection,
    )?;
    let report = refract_loadgen::run_signal_open_signal_close(config)?;
    println!(
        "signal loadgen passed={} target_connections={} opened_connections={} signaled_messages={} closed_connections={} rejected_connections={} elapsed_ms={}",
        report.passed(),
        report.target_connections(),
        report.opened_connections(),
        report.signaled_messages(),
        report.closed_connections(),
        report.rejected_connections(),
        report.elapsed().as_millis(),
    );
    if report.passed() {
        Ok(())
    } else {
        Err("signal loadgen did not meet open/signal/close counts".into())
    }
}

#[derive(Debug)]
struct XdpLoadArgs {
    interface: Option<String>,
    port: u16,
    stun_rate: u32,
    stun_burst: u32,
    generic: bool,
    hardware: bool,
    hold_seconds: u64,
    object: Option<PathBuf>,
    skip_build: bool,
}

#[cfg(target_os = "linux")]
fn run_xdp_load(sh: &Shell, args: XdpLoadArgs) -> XtaskResult<()> {
    use std::{thread, time::Duration};

    let object = args.object.unwrap_or_else(|| {
        Path::new("target")
            .join("refract-xdp")
            .join("refract_xdp.bpf.o")
    });
    if !args.skip_build {
        build_xdp_object(sh, &object)?;
    }

    let interface = args
        .interface
        .or_else(|| env::var("REFRACT_XDP_INTERFACE").ok())
        .unwrap_or_else(|| "eth0".to_owned());
    let attach_mode = if args.hardware {
        refract_xdp::AttachMode::Hardware
    } else if args.generic {
        refract_xdp::AttachMode::Generic
    } else {
        refract_xdp::AttachMode::Driver
    };
    let config = refract_xdp::XdpConfig::new(
        refract_xdp::InterfaceName::try_from(interface.as_str())?,
        refract_xdp::ListenPort::try_from(args.port)?,
    )
    .with_attach_mode(attach_mode)
    .with_stun_limit(refract_xdp::StunRateLimit::new(
        args.stun_rate,
        args.stun_burst,
    )?);
    let mut loaded = refract_xdp::LoadedXdp::load_from_path(config, &object)?;

    println!(
        "xdp loaded interface={} port={} stun_rate={} stun_burst={} hold_seconds={} object={}",
        interface,
        args.port,
        args.stun_rate,
        args.stun_burst,
        args.hold_seconds,
        object.display()
    );
    thread::sleep(Duration::from_secs(args.hold_seconds));

    let stats = loaded.stats()?;
    println!(
        "xdp stats passed={} dropped_unsupported_udp={} dropped_fragmented={} dropped_stun_rate_limited={} accepted_stun_binding={}",
        stats.passed(),
        stats.dropped_unsupported_udp(),
        stats.dropped_fragmented(),
        stats.dropped_stun_rate_limited(),
        stats.accepted_stun_binding()
    );
    loaded.detach()?;
    println!("xdp detached interface={interface}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_xdp_load(_sh: &Shell, args: XdpLoadArgs) -> XtaskResult<()> {
    let XdpLoadArgs {
        interface,
        port,
        stun_rate,
        stun_burst,
        generic,
        hardware,
        hold_seconds,
        object,
        skip_build,
    } = args;
    drop((
        interface,
        port,
        stun_rate,
        stun_burst,
        generic,
        hardware,
        hold_seconds,
        object,
        skip_build,
    ));
    Err(refract_xdp::XdpError::UnsupportedPlatform.into())
}

#[cfg(target_os = "linux")]
fn build_xdp_object(sh: &Shell, object: &Path) -> XtaskResult<()> {
    require_tool("clang", "install clang with BPF target support")?;
    let parent = object
        .parent()
        .ok_or("xdp object path must have a parent directory")?;
    fs::create_dir_all(parent)?;

    let source = Path::new("crates")
        .join("refract-xdp")
        .join("ebpf")
        .join("refract_xdp.bpf.c");
    let arch_define = xdp_arch_define()?;
    cmd!(
        sh,
        "clang -O2 -g -target bpf -D{arch_define} -Wall -Wextra -Werror -c {source} -o {object}"
    )
    .run()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn xdp_arch_define() -> XtaskResult<&'static str> {
    match env::consts::ARCH {
        "x86_64" => Ok("__TARGET_ARCH_x86"),
        "aarch64" => Ok("__TARGET_ARCH_arm64"),
        "riscv64" => Ok("__TARGET_ARCH_riscv"),
        arch => Err(format!("unsupported xdp build architecture: arch={arch}").into()),
    }
}

fn refract_signal_config() -> refract_signal::SignalConfig {
    refract_signal::SignalConfig::default()
}

fn run_fuzz(sh: &Shell, seconds: u64) -> XtaskResult<()> {
    let targets = fuzz_targets()?;
    if targets.is_empty() {
        println!("no fuzz targets registered under fuzz/fuzz_targets");
        return Ok(());
    }

    require_tool("cargo-fuzz", "cargo install cargo-fuzz")?;
    let max_total_time = format!("{seconds}");

    for target in targets {
        cmd!(
            sh,
            "cargo fuzz run {target} -- -max_total_time={max_total_time}"
        )
        .run()?;
    }

    Ok(())
}

fn run_coverage(sh: &Shell) -> XtaskResult<()> {
    require_tool("cargo-llvm-cov", "cargo install cargo-llvm-cov --locked")?;
    let threshold = COVERAGE_THRESHOLD.to_string();
    cmd!(
        sh,
        "cargo llvm-cov --workspace --all-targets --all-features --exclude xtask --fail-under-lines {threshold}"
    )
    .run()?;
    Ok(())
}

fn run_audit(sh: &Shell) -> XtaskResult<()> {
    require_tool(
        "cargo-audit",
        "cargo install cargo-audit --version 0.22.0 --locked",
    )?;
    cmd!(
        sh,
        "cargo audit -D warnings -D unmaintained -D yanked -D unsound"
    )
    .run()?;
    Ok(())
}

fn run_deny(sh: &Shell) -> XtaskResult<()> {
    require_tool(
        "cargo-deny",
        "cargo install cargo-deny --version 0.19.6 --locked",
    )?;
    cmd!(sh, "cargo deny check all").run()?;
    Ok(())
}

fn run_msrv(sh: &Shell) -> XtaskResult<()> {
    let toolchain = format!("+{MSRV_TOOLCHAIN}");
    cmd!(
        sh,
        "cargo {toolchain} check --workspace --all-targets --all-features"
    )
    .run()?;
    Ok(())
}

fn run_release(sh: &Shell, native: bool) -> XtaskResult<()> {
    run_lint(sh)?;
    run_test(sh)?;
    run_audit(sh)?;
    run_deny(sh)?;

    if native {
        cmd!(
            sh,
            "cargo rustc --workspace --profile release-native -- -C target-cpu=native"
        )
        .run()?;
    } else {
        cmd!(sh, "cargo build --workspace --profile release-lto").run()?;
    }

    Ok(())
}

fn print_preflight() {
    println!("refract Stage 1 preflight checklist");
    println!("[ ] cargo fmt --all --check");
    println!("[ ] cargo clippy --workspace --all-targets --all-features -- -D warnings");
    println!("[ ] cargo test --workspace --all-targets --all-features");
    println!("[ ] cargo audit -D warnings -D unmaintained -D yanked -D unsound");
    println!("[ ] cargo deny check all");
    println!("[ ] cargo xtask signal-loadgen");
    println!("[ ] sudo cargo xtask xdp-load --interface <nic> --port 50000");
    println!("[ ] cargo llvm-cov --exclude xtask --fail-under-lines {COVERAGE_THRESHOLD}");
    println!("[ ] cargo +{MSRV_TOOLCHAIN} check --workspace --all-targets --all-features");
    println!("[ ] typos --config typos.toml");
    println!("[ ] cargo doc --workspace --no-deps --all-features");
}

fn install_hooks() -> XtaskResult<()> {
    let hook_path = Path::new(".git").join("hooks").join("pre-commit");
    let hook = "#!/bin/sh\nset -eu\ncargo xtask fmt\ncargo xtask lint\ncargo xtask test\n";
    fs::write(&hook_path, hook)?;

    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&hook_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook_path, permissions)?;
    }

    println!("installed {}", hook_path.display());
    Ok(())
}

fn fuzz_targets() -> XtaskResult<Vec<String>> {
    let target_dir = Path::new("fuzz").join("fuzz_targets");
    if !target_dir.exists() {
        return Ok(Vec::new());
    }

    let mut targets = fs::read_dir(target_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    Ok(targets)
}

fn require_tool(binary: &str, install_hint: &str) -> XtaskResult<()> {
    if command_exists(binary) {
        return Ok(());
    }

    Err(format!("required tool `{binary}` not found; install with `{install_hint}`").into())
}

fn command_exists(binary: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths)
            .any(|path| executable_candidates(&path, binary).any(|candidate| candidate.is_file()))
    })
}

fn executable_candidates(path: &Path, binary: &str) -> impl Iterator<Item = PathBuf> {
    let mut candidates = vec![path.join(binary)];

    if cfg!(windows) {
        candidates.extend(pathexts().map(|extension| path.join(format!("{binary}{extension}"))));
    }

    candidates.into_iter()
}

fn pathexts() -> impl Iterator<Item = String> {
    env::var_os("PATHEXT").into_iter().flat_map(|value| {
        env::split_paths(&value)
            .map(path_to_extension)
            .collect::<Vec<_>>()
    })
}

fn path_to_extension(path: PathBuf) -> String {
    let raw: OsString = path.into_os_string();
    raw.to_string_lossy().into_owned()
}
