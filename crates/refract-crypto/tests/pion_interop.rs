//! Pion DTLS interop harness.
//!
//! This test is ignored by default because CI does not ship a Pion client
//! binary. Set `PION_DTLS_CLIENT` to an executable that exits successfully after
//! completing a DTLS 1.3 handshake with the configured refract crypto policy.

#![forbid(unsafe_code)]

use std::{env, process::Command};

#[test]
#[ignore = "requires external Pion DTLS client binary via PION_DTLS_CLIENT"]
fn pion_dtls_client_interop() {
    let Ok(client) = env::var("PION_DTLS_CLIENT") else {
        panic!("PION_DTLS_CLIENT is required for ignored interop test");
    };
    let status = Command::new(client)
        .status()
        .expect("pion dtls client starts");

    assert!(status.success(), "pion dtls client handshake failed");
}
