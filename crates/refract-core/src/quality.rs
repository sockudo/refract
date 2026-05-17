//! Media quality layer metadata.

use core::fmt;

use ordered_float::NotNan;

use crate::{Error, Result, limits};

/// Spatial and temporal quality layer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Layer {
    spatial: u8,
    temporal: u8,
}

impl Layer {
    /// Creates a bounded quality layer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] when either layer index exceeds the configured
    /// layer bound.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::Layer;
    ///
    /// let layer = Layer::new(1, 2)?;
    /// assert_eq!(layer.spatial(), 1);
    /// # Ok::<(), refract_core::Error>(())
    /// ```
    pub const fn new(spatial: u8, temporal: u8) -> Result<Self> {
        if spatial > limits::MAX_SPATIAL_LAYER {
            return Err(Error::Parse {
                context: "quality_layer.spatial",
                message: "spatial layer exceeds configured bound",
            });
        }

        if temporal > limits::MAX_TEMPORAL_LAYER {
            return Err(Error::Parse {
                context: "quality_layer.temporal",
                message: "temporal layer exceeds configured bound",
            });
        }

        Ok(Self { spatial, temporal })
    }

    /// Returns the spatial layer index.
    #[must_use]
    pub const fn spatial(self) -> u8 {
        self.spatial
    }

    /// Returns the temporal layer index.
    #[must_use]
    pub const fn temporal(self) -> u8 {
        self.temporal
    }
}

/// Frame metadata associated with a quality layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerInfo {
    layer: Layer,
    frame_number: u64,
    rtp_timestamp: u32,
    keyframe: bool,
}

impl LayerInfo {
    /// Creates layer metadata for a media frame.
    #[must_use]
    pub const fn new(layer: Layer, frame_number: u64, rtp_timestamp: u32, keyframe: bool) -> Self {
        Self {
            layer,
            frame_number,
            rtp_timestamp,
            keyframe,
        }
    }

    /// Returns the quality layer.
    #[must_use]
    pub const fn layer(self) -> Layer {
        self.layer
    }

    /// Returns the monotonically increasing frame number.
    #[must_use]
    pub const fn frame_number(self) -> u64 {
        self.frame_number
    }

    /// Returns the RTP timestamp associated with the frame.
    #[must_use]
    pub const fn rtp_timestamp(self) -> u32 {
        self.rtp_timestamp
    }

    /// Returns whether the frame is a keyframe.
    #[must_use]
    pub const fn is_keyframe(self) -> bool {
        self.keyframe
    }
}

/// Normalized quality score that rejects `NaN`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub struct QualityScore(NotNan<f32>);

impl QualityScore {
    /// Creates a bounded normalized score.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] when `value` is outside `0.0..=1.0` or is
    /// `NaN`.
    ///
    /// # Examples
    ///
    /// ```
    /// use refract_core::QualityScore;
    ///
    /// let score = QualityScore::new(0.95)?;
    /// assert_eq!(score.get(), 0.95);
    /// # Ok::<(), refract_core::Error>(())
    /// ```
    pub fn new(value: f32) -> Result<Self> {
        if !(limits::QUALITY_SCORE_MIN..=limits::QUALITY_SCORE_MAX).contains(&value) {
            return Err(Error::Parse {
                context: "quality_score",
                message: "quality score is outside normalized range",
            });
        }

        NotNan::new(value)
            .map(Self)
            .map_err(|_source| Error::Parse {
                context: "quality_score",
                message: "quality score is NaN",
            })
    }

    /// Returns the raw floating-point score.
    #[must_use]
    pub fn get(self) -> f32 {
        self.0.into_inner()
    }
}

impl fmt::Display for QualityScore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Layer, LayerInfo, QualityScore};

    #[test]
    fn layers_are_strictly_ordered_by_spatial_then_temporal() {
        let low = Layer::new(0, 1).expect("valid low layer");
        let high = Layer::new(1, 0).expect("valid high layer");

        assert!(low < high);
    }

    #[test]
    fn layer_info_exposes_frame_metadata() {
        let layer = Layer::new(1, 2).expect("valid layer");
        let info = LayerInfo::new(layer, 99, 12_345, true);

        assert_eq!(info.layer(), layer);
        assert_eq!(info.frame_number(), 99);
        assert_eq!(info.rtp_timestamp(), 12_345);
        assert!(info.is_keyframe());
    }

    #[test]
    fn quality_score_rejects_nan_and_out_of_range_values() {
        assert!(QualityScore::new(0.5).is_ok());
        assert!(QualityScore::new(f32::NAN).is_err());
        assert!(QualityScore::new(-0.1).is_err());
        assert!(QualityScore::new(1.1).is_err());
    }
}
