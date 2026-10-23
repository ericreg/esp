//! Image limits and aspect-ratio-preserving sizing.
use anyhow::{Result, ensure};
use serde::Serialize;
pub(super) const MAX_SOURCE_AXIS: u32 = 4096;
pub(super) const MAX_SOURCE_PIXELS: u64 = 16_000_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    pub fn validate_source(self) -> Result<Self> {
        ensure!(
            self.width >= 2 && self.height >= 2,
            "display is smaller than 2 by 2 pixels"
        );
        ensure!(
            self.width <= MAX_SOURCE_AXIS && self.height <= MAX_SOURCE_AXIS,
            "display exceeds the 4096-pixel source axis limit"
        );
        ensure!(
            u64::from(self.width) * u64::from(self.height) <= MAX_SOURCE_PIXELS,
            "display exceeds the 16-megapixel source limit"
        );
        Ok(self)
    }

    /// Fit the physical pixels, never logical/DPI-scaled dimensions, within an
    /// encoder bound. Round down to even dimensions for 4:2:0 chroma planes.
    pub fn fit(self, bounds: Self) -> Result<Self> {
        self.validate_source()?;
        ensure!(
            bounds.width >= 2 && bounds.height >= 2,
            "video bounds must be at least 2 by 2 pixels"
        );
        let width = self.width.min(bounds.width);
        let height = self.height.min(bounds.height);
        let (width, height) = if u64::from(width) * u64::from(self.height)
            <= u64::from(height) * u64::from(self.width)
        {
            (
                width,
                (u64::from(self.height) * u64::from(width) / u64::from(self.width)) as u32,
            )
        } else {
            (
                (u64::from(self.width) * u64::from(height) / u64::from(self.height)) as u32,
                height,
            )
        };
        let result = Self {
            width: width & !1,
            height: height & !1,
        };
        ensure!(
            result.width >= 2 && result.height >= 2,
            "display aspect ratio cannot fit the video bounds"
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fit_preserves_physical_aspect_ratio_without_upscaling() {
        let bounds = Size {
            width: 1920,
            height: 1080,
        };
        assert_eq!(
            Size {
                width: 3840,
                height: 2160
            }
            .fit(bounds)
            .unwrap(),
            bounds
        );
        assert_eq!(
            Size {
                width: 1280,
                height: 720
            }
            .fit(bounds)
            .unwrap(),
            Size {
                width: 1280,
                height: 720
            }
        );
        let portrait = Size {
            width: 2160,
            height: 3840,
        }
        .fit(bounds)
        .unwrap();
        assert_eq!(
            portrait,
            Size {
                width: 606,
                height: 1080
            }
        );
        let odd = Size {
            width: 1919,
            height: 1079,
        }
        .fit(bounds)
        .unwrap();
        assert_eq!(
            odd,
            Size {
                width: 1918,
                height: 1078
            }
        );
    }

    #[test]
    fn size_limits_reject_overflow_and_unrepresentable_streams() {
        let bounds = Size {
            width: 1920,
            height: 1080,
        };
        for size in [
            Size {
                width: 0,
                height: 1080,
            },
            Size {
                width: u32::MAX,
                height: u32::MAX,
            },
            Size {
                width: 4096,
                height: 4096,
            },
        ] {
            assert!(size.fit(bounds).is_err());
        }
        assert!(
            Size {
                width: 2,
                height: 4096
            }
            .fit(bounds)
            .is_err()
        );
    }
}
