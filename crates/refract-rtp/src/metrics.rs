//! Metrics helpers for RTP and RTCP parse paths.
//!
//! Hot-path callers record bounded-cardinality counters without logging.
//!
//! # Examples
//!
//! ```
//! # use refract_rtp::{metrics::record_parse_error, RtpError};
//! record_parse_error(&RtpError::ZeroPadding);
//! ```

use crate::RtpError;

/// Records a parse or rewrite error with bounded labels.
///
/// # Examples
///
/// ```
/// # use refract_rtp::{metrics::record_parse_error, RtpError};
/// record_parse_error(&RtpError::PacketTooShort { len: 4 });
/// ```
pub fn record_parse_error(error: &RtpError) {
    metrics::counter!(
        "refract.rtp.parse.errors",
        "error_code" => error.error_code(),
        "kind" => error_kind(error),
    )
    .increment(1);
}

/// Records a successfully parsed RTP packet.
///
/// # Examples
///
/// ```
/// # use refract_rtp::metrics::record_rtp_packet_parsed;
/// record_rtp_packet_parsed(120);
/// ```
pub fn record_rtp_packet_parsed(bytes: usize) {
    metrics::counter!("refract.rtp.parse.packets").increment(1);
    metrics::counter!("refract.rtp.parse.bytes")
        .increment(u64::try_from(bytes).unwrap_or(u64::MAX));
}

/// Records a successful RTP header rewrite.
///
/// # Examples
///
/// ```
/// # use refract_rtp::metrics::record_rewrite;
/// record_rewrite();
/// ```
pub fn record_rewrite() {
    metrics::counter!("refract.rtp.rewrite.packets").increment(1);
}

/// Returns the Stage 1 stability marker for this public module API.
///
/// # Examples
///
/// ```
/// # use refract_rtp::{metrics::stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> crate::Stability {
    crate::Stability::Stage1
}

const fn error_kind(error: &RtpError) -> &'static str {
    match error {
        RtpError::PacketTooShort { .. }
        | RtpError::InvalidVersion { .. }
        | RtpError::CsrcListTruncated { .. }
        | RtpError::ExtensionHeaderTruncated { .. }
        | RtpError::ExtensionPayloadTruncated { .. }
        | RtpError::ZeroPadding
        | RtpError::PaddingTooLarge { .. }
        | RtpError::PacketTooLarge { .. } => "rtp_parse",
        RtpError::MalformedExtension { .. } => "rtp_extension",
        RtpError::RewriteNoSpace { .. } | RtpError::RewriteTargetMissing { .. } => "rtp_rewrite",
        RtpError::RtcpPacketTooShort { .. }
        | RtpError::RtcpLengthTooLarge { .. }
        | RtpError::RtcpCompoundTooLarge { .. }
        | RtpError::MalformedRtcp { .. } => "rtcp_parse",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_is_bounded() {
        assert_eq!(error_kind(&RtpError::ZeroPadding), "rtp_parse");
        assert_eq!(
            error_kind(&RtpError::RewriteTargetMissing {
                target: "extension"
            }),
            "rtp_rewrite"
        );
    }
}
