//! Display identity and image sizing, independent of desktop and media libraries.

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) const MAX_SOURCE_AXIS: u32 = 4096;
pub(super) const MAX_SOURCE_PIXELS: u64 = 16_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Identity {
    pub connector: String,
    pub vendor: String,
    pub product: String,
    pub serial: String,
}

impl Identity {
    /// Include every backend identity field, so a changed reported identity on
    /// the same connector cannot silently inherit a saved selection. Devices
    /// reporting identical identities still need hotplug/generation tracking.
    pub fn id(&self) -> String {
        let mut hash = Sha256::new();
        for field in [&self.connector, &self.vendor, &self.product, &self.serial] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        format!("mutter:{}", URL_SAFE_NO_PAD.encode(hash.finalize()))
    }
}

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

    pub fn transformed(self, transform: u32) -> Result<Self> {
        ensure!(transform <= 7, "unknown display transform {transform}");
        Ok(if transform % 2 == 1 {
            Self {
                width: self.height,
                height: self.width,
            }
        } else {
            self
        })
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

#[derive(Debug, Clone, Serialize)]
pub(super) struct Mode {
    pub id: String,
    pub pixels: Size,
    pub refresh_hz: f64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Placement {
    pub x: i32,
    pub y: i32,
    pub scale: f64,
    pub transform: u32,
    pub primary: bool,
    pub mirrored_connectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Display {
    pub id: String,
    pub identity: Identity,
    pub name: String,
    pub active: bool,
    pub mode: Option<Mode>,
    pub placement: Option<Placement>,
    pub suggested_stream_size: Option<Size>,
    pub source_unavailable_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_identity_detects_replacement_and_has_unambiguous_fields() {
        let identity = Identity {
            connector: "DP-1".into(),
            vendor: "Vendor".into(),
            product: "Monitor".into(),
            serial: "123".into(),
        };
        let mut replacement = identity.clone();
        replacement.serial = "456".into();
        assert_ne!(identity.id(), replacement.id());
        replacement = identity.clone();
        replacement.connector = "DP-2".into();
        assert_ne!(identity.id(), replacement.id());
        let mut a = identity.clone();
        a.vendor = "ab".into();
        a.product = "c".into();
        let mut b = identity.clone();
        b.vendor = "a".into();
        b.product = "bc".into();
        assert_ne!(a.id(), b.id());
        assert_eq!(identity.clone().id(), identity.id());
    }

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
            width: 3840,
            height: 2160,
        }
        .transformed(1)
        .unwrap()
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
        assert!(bounds.transformed(8).is_err());
        for transform in 0..8 {
            let result = bounds.transformed(transform).unwrap();
            assert_eq!(
                (result.width, result.height),
                if transform % 2 == 1 {
                    (1080, 1920)
                } else {
                    (1920, 1080)
                }
            );
        }
    }
}
