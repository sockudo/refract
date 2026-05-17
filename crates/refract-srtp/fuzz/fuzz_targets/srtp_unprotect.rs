//! Fuzzes SRTP RTP unprotect parsing and authentication failure handling.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use refract_srtp::{SrtpContext, SrtpKeys, SrtpProfile};

fuzz_target!(|data: &[u8]| {
    if let Ok(keys) = SrtpKeys::new(SrtpProfile::AeadAes128Gcm, [7; 32], [9; 24]) {
        if let Ok(mut ctx) = SrtpContext::new(keys, 64) {
            let mut packet = data.to_vec();
            let _result = ctx.ingress.unprotect_rtp(&mut packet);
        }
    }
});
