//! Window content constraints. Pixel aspect and window decorations stay separate.
use anyhow::Result;
use winit::{dpi::PhysicalSize, window::Window};

pub fn constrain(
    size: PhysicalSize<u32>,
    previous: Option<PhysicalSize<u32>>,
    ratio: PhysicalSize<u32>,
) -> PhysicalSize<u32> {
    if size.width == 0 || size.height == 0 || ratio.width == 0 || ratio.height == 0 {
        return size;
    }
    let r = f64::from(ratio.width) / f64::from(ratio.height);
    // One physical pixel of tolerance prevents resize feedback from rounding,
    // including fractional desktop scale factors.
    if (f64::from(size.width) - f64::from(size.height) * r).abs() <= r.max(1.) {
        return size;
    }
    let width_driven = previous.is_none_or(|last| {
        f64::from(size.width.abs_diff(last.width))
            >= f64::from(size.height.abs_diff(last.height)) * r
    });
    if width_driven {
        PhysicalSize::new(
            size.width,
            (f64::from(size.width) / r).round().max(1.) as u32,
        )
    } else {
        PhysicalSize::new(
            (f64::from(size.height) * r).round().max(1.) as u32,
            size.height,
        )
    }
}

#[cfg(target_os = "macos")]
pub fn set_native_aspect(window: &Window, ratio: Option<PhysicalSize<u32>>) -> Result<()> {
    use anyhow::Context as _;
    use objc2_app_kit::NSView;
    use objc2_foundation::NSSize;
    use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let handle = window.window_handle()?;
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        anyhow::bail!("expected an AppKit window");
    };
    // SAFETY: winit supplies the live NSView pointer. Called only from its
    // main-thread event loop, and the borrowed Window outlives this operation.
    let view = unsafe { &*handle.ns_view.as_ptr().cast::<NSView>() };
    let native = view.window().context("viewer has no native window")?;
    if let Some(ratio) = ratio {
        // Content ratio excludes the title bar. Equal X/Y Retina scaling cancels
        // out, so stream dimensions can be used directly as a dimensionless ratio.
        unsafe {
            native.setContentAspectRatio(NSSize::new(
                f64::from(ratio.width),
                f64::from(ratio.height),
            ));
        }
    } else {
        // Reset resize increments to clear the previous AppKit aspect constraint.
        native.setResizeIncrements(NSSize::new(1., 1.));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn set_native_aspect(_: &Window, _: Option<PhysicalSize<u32>>) -> Result<()> {
    // winit has no portable native aspect hint. The event handler corrects
    // resized dimensions, subject to the window manager accepting size requests.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dragging_either_axis_preserves_video_ratio() {
        let ratio = PhysicalSize::new(1920, 1080);
        let old = Some(PhysicalSize::new(960, 540));
        assert_eq!(
            constrain(PhysicalSize::new(1280, 540), old, ratio),
            PhysicalSize::new(1280, 720)
        );
        assert_eq!(
            constrain(PhysicalSize::new(960, 720), old, ratio),
            PhysicalSize::new(1280, 720)
        );
        assert_eq!(
            constrain(PhysicalSize::new(800, 540), old, ratio),
            PhysicalSize::new(800, 450)
        );
        assert_eq!(
            constrain(PhysicalSize::new(960, 450), old, ratio),
            PhysicalSize::new(800, 450)
        );
    }
    #[test]
    fn rounding_dpi_portrait_and_minimized_sizes_are_stable() {
        for ratio in [
            PhysicalSize::new(1920, 1080),
            PhysicalSize::new(1080, 1920),
            PhysicalSize::new(4, 3),
        ] {
            for size in [
                PhysicalSize::new(533, 711),
                PhysicalSize::new(1440, 811),
                PhysicalSize::new(1920, 1080),
            ] {
                let corrected = constrain(size, None, ratio);
                assert_eq!(constrain(corrected, Some(size), ratio), corrected);
            }
        }
        assert_eq!(
            constrain(PhysicalSize::new(0, 0), None, PhysicalSize::new(16, 9)),
            PhysicalSize::new(0, 0)
        );
    }
}
