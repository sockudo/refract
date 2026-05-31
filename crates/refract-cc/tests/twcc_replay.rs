//! Replay tests for captured TWCC bandwidth-estimation traces.

use refract_cc::DelayBasedBwe;

const REFERENCE_FINAL_BPS: u64 = 227_045;

#[test]
fn replay_fixture_matches_reference_output_within_five_percent() {
    let mut bwe = DelayBasedBwe::new(300_000);
    let mut estimate = bwe.estimate();

    for line in include_str!("fixtures/twcc_replay.csv").lines().skip(1) {
        let mut columns = line.split(',');
        let send_ms = columns
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap();
        let arrival_ms = columns
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap();
        let payload_bytes = columns
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap();
        estimate = bwe.update(send_ms, arrival_ms, payload_bytes);
    }

    let diff = estimate.bitrate_bps.abs_diff(REFERENCE_FINAL_BPS);
    assert!(
        diff.saturating_mul(100) <= REFERENCE_FINAL_BPS.saturating_mul(5),
        "estimate={} reference={REFERENCE_FINAL_BPS}",
        estimate.bitrate_bps
    );
}
