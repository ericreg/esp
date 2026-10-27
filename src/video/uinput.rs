//! Linux virtual keyboard/mouse. Device lifetime is bounded by the console worker.
use super::input::{Event, Held};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

#[repr(C)]
struct Setup {
    bus: u16,
    vendor: u16,
    product: u16,
    version: u16,
    name: [u8; 80],
    effects: u32,
}
// SAFETY: kernel uinput ABI is fixed; these wrappers only accept known ioctl constants.
fn ioctl(file: &File, request: libc::c_ulong, value: libc::c_ulong) -> Result<()> {
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), request, value) };
    ensure!(rc >= 0, "uinput ioctl: {}", std::io::Error::last_os_error());
    Ok(())
}
struct KernelDevice(File);
impl KernelDevice {
    fn new(mouse: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .open("/dev/uinput")
            .context("open /dev/uinput (enable the uinput module and device permissions)")?;
        // EV_REP is keyboard-only: combining devices makes held mouse buttons
        // autorepeat too, and complicates compositor device classification.
        for kind in [1, if mouse { 2 } else { 20 }] {
            ioctl(&file, 0x40045564, kind)?;
        }
        for code in if mouse { 0x110..=0x114 } else { 1..=248 } {
            ioctl(&file, 0x40045565, code)?;
        }
        if mouse {
            for axis in [0, 1, 6, 8] {
                ioctl(&file, 0x40045566, axis)?;
            }
        }
        let mut setup = Setup {
            bus: 3,
            vendor: 0x4553,
            product: if mouse { 2 } else { 1 },
            version: 1,
            name: [0; 80],
            effects: 0,
        };
        let name: &[u8] = if mouse {
            b"ESP remote console mouse"
        } else {
            b"ESP remote console keyboard"
        };
        setup.name[..name.len()].copy_from_slice(name);
        ioctl(&file, 0x405c5503, (&setup as *const Setup) as libc::c_ulong)?;
        ioctl(&file, 0x5501, 0)?;
        Ok(Self(file))
    }
}
impl Drop for KernelDevice {
    fn drop(&mut self) {
        let _ = ioctl(&self.0, 0x5502, 0);
    }
}
pub struct Device {
    keyboard: KernelDevice,
    mouse: KernelDevice,
    held: Held,
    epoch: u64,
    last: Instant,
}
impl Device {
    pub fn new() -> Result<Self> {
        Ok(Self {
            keyboard: KernelDevice::new(false)?,
            mouse: KernelDevice::new(true)?,
            held: Held::default(),
            epoch: 0,
            last: Instant::now(),
        })
    }
    pub fn event(&mut self, epoch: u64, event: Event) -> Result<()> {
        if epoch < self.epoch {
            return Ok(());
        }
        if epoch > self.epoch {
            self.release()?;
            self.epoch = epoch;
        }
        self.last = Instant::now();
        self.apply(event)
    }
    fn apply(&mut self, event: Event) -> Result<()> {
        self.held.apply(event, |kind, code, value| {
            let event = libc::input_event {
                time: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                type_: kind,
                code,
                value,
            };
            // SAFETY: every input_event field, including timeval, is initialized.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&event as *const libc::input_event).cast(),
                    std::mem::size_of::<libc::input_event>(),
                )
            };
            if kind == 0 {
                self.keyboard.0.write_all(bytes)?;
                self.mouse.0.write_all(bytes)?;
            } else if kind == 2 || (kind == 1 && code >= 0x110) {
                self.mouse.0.write_all(bytes)?;
            } else {
                self.keyboard.0.write_all(bytes)?;
            }
            Ok(())
        })
    }
    pub fn release(&mut self) -> Result<()> {
        self.apply(Event::Release)
    }
    pub fn watchdog(&mut self) -> Result<()> {
        if self.last.elapsed() > Duration::from_secs(2) {
            self.release()?;
            self.last = Instant::now();
        }
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
