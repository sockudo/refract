//! Fuzz target for bounded signaling JSON parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use refract_signal::{SignalConfig, parse_client_message};

fuzz_target!(|data: &[u8]| {
    let config = SignalConfig::default();
    let _result = parse_client_message(data, &config);
});
