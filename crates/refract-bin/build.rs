//! Build-time feature validation for the refract executable.

#![forbid(unsafe_code)]

use std::env;

const APP_PREFIX: &str = "CARGO_FEATURE_APP_";
const CODEC_PREFIX: &str = "CARGO_FEATURE_CODEC_";

fn main() {
    assert!(
        env::var_os("CARGO_FEATURE_RUNTIME_COMPIO").is_some(),
        "refract-bin requires the runtime-compio feature"
    );

    assert!(
        enabled_features_with_prefix(APP_PREFIX) != 0,
        "refract-bin requires at least one app-* feature"
    );

    assert!(
        enabled_features_with_prefix(CODEC_PREFIX) != 0,
        "refract-bin requires at least one codec-* feature"
    );
}

fn enabled_features_with_prefix(prefix: &str) -> usize {
    env::vars_os()
        .filter(|(key, _value)| key.to_string_lossy().starts_with(prefix))
        .count()
}
