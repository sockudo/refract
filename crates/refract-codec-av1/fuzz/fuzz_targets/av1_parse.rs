#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = refract_codec_av1::parse(data);
    let _ = refract_codec_av1::parse_obu(data);
    let _ = refract_codec_av1::parse_dependency_descriptor(data);
});
