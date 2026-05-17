#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = refract_codec_vp8::parse(data);
    let _ = refract_codec_vp8::parse_descriptor(data);
});
