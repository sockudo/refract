//! Binary startup regression coverage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

use std::process::Command;

#[test]
fn refract_binary_exits_successfully() -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(env!("CARGO_BIN_EXE_refract")).status()?;

    assert!(status.success());
    Ok(())
}
