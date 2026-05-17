//! Build, verification, fuzz, and release helper entry point.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
