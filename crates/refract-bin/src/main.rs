//! refract `SFU` executable entry point.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match refract_bin::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "error_code={} message={error}",
                refract_bin::BinError::error_code(&error)
            );
            ExitCode::FAILURE
        }
    }
}
