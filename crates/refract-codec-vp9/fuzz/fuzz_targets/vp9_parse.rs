#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = refract_codec_vp9::parse(data);
    let _ = refract_codec_vp9::parse_descriptor(data);
});
