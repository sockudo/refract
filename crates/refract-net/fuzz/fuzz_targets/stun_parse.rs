//! Fuzz target for bounded STUN parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use refract_net::stun::StunMessage;

fuzz_target!(|data: &[u8]| {
    let _ = StunMessage::parse(data);
});
