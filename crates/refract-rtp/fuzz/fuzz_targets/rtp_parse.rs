#![no_main]

use libfuzzer_sys::fuzz_target;
use refract_rtp::extensions::{ExtensionRegistry, RtpExtensions};
use refract_rtp::header::RtpHeader;
use refract_rtp::rtcp::RtcpCompound;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = RtpHeader::parse(data) {
        if let Some(extension) = header.extension() {
            if let Ok(iter) =
                RtpExtensions::new(extension.profile(), extension.payload(), ExtensionRegistry::new())
            {
                for item in iter {
                    let _ = item;
                }
            }
        }
    }

    if let Ok(compound) = RtcpCompound::parse(data) {
        for item in compound {
            let _ = item;
        }
    }
});
