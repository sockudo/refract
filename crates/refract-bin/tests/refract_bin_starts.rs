//! Binary startup regression coverage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

use std::{fs, process::Command};

#[test]
fn refract_binary_boots_and_exits_in_check_mode() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("example.toml");
    fs::write(&config, EXAMPLE_CONFIG)?;

    let status = Command::new(env!("CARGO_BIN_EXE_refract"))
        .arg("--check")
        .arg("--config")
        .arg(config)
        .status()?;

    assert!(status.success());
    Ok(())
}

const EXAMPLE_CONFIG: &str = r#"
[runtime]
cores = 1
pinning = false
hugepages = false

[net]
bind_addrs = ["127.0.0.1:50000"]
rtp_port = 50000
rtcp_port = 50001
mtu = 1200

[crypto]
cert_path = "certs/refract.pem"
dtls_timeout_ms = 1000

[cluster]
peer_addrs = []

[cluster.raft]
node_id = 1
election_timeout_ms = 1500
heartbeat_ms = 250

[obs]
metric_exporter_targets = []

[apps.echo]
enabled = true
max_sessions = 64

[apps.echo.settings]
mode = "loopback"
"#;
