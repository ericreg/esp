//! Portable, bounded input messages. Key codes use Linux evdev physical positions.
use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Capture,
    Release,
    Heartbeat,
    Key { code: u16, down: bool },
    Button { button: u8, down: bool },
    Motion { x: i32, y: i32 },
    Scroll { x: i32, y: i32 },
}
impl Event {
    pub fn validate(self) -> Result<()> {
        match self {
            Self::Key { code, .. } => ensure!((1..=248).contains(&code), "invalid physical key"),
            Self::Button { button, .. } => ensure!(button < 5, "invalid mouse button"),
            Self::Motion { x, y } | Self::Scroll { x, y } => {
                ensure!(
                    (-32767..=32767).contains(&x) && (-32767..=32767).contains(&y),
                    "input delta out of range"
                );
            }
            _ => {}
        }
        Ok(())
    }
    pub fn bytes(self) -> Result<[u8; 12]> {
        self.validate()?;
        let mut b = [0; 12];
        match self {
            Self::Capture => b[0] = 1,
            Self::Release => b[0] = 2,
            Self::Heartbeat => b[0] = 3,
            Self::Key { code, down } => {
                b[0] = 4;
                b[1] = down.into();
                b[2..4].copy_from_slice(&code.to_be_bytes());
            }
            Self::Button { button, down } => {
                b[0] = 5;
                b[1] = down.into();
                b[2] = button;
            }
            Self::Motion { x, y } | Self::Scroll { x, y } => {
                b[0] = if matches!(self, Self::Motion { .. }) {
                    6
                } else {
                    7
                };
                b[4..8].copy_from_slice(&x.to_be_bytes());
                b[8..12].copy_from_slice(&y.to_be_bytes());
            }
        }
        Ok(b)
    }
    pub fn from_bytes(b: [u8; 12]) -> Result<Self> {
        let e = match b[0] {
            1 => Self::Capture,
            2 => Self::Release,
            3 => Self::Heartbeat,
            4 => Self::Key {
                code: u16::from_be_bytes([b[2], b[3]]),
                down: b[1] != 0,
            },
            5 => Self::Button {
                button: b[2],
                down: b[1] != 0,
            },
            6 => Self::Motion {
                x: i32::from_be_bytes(b[4..8].try_into()?),
                y: i32::from_be_bytes(b[8..12].try_into()?),
            },
            7 => Self::Scroll {
                x: i32::from_be_bytes(b[4..8].try_into()?),
                y: i32::from_be_bytes(b[8..12].try_into()?),
            },
            _ => bail!("unknown input event"),
        };
        ensure!(e.bytes()? == b, "noncanonical input message");
        Ok(e)
    }
}
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Event> {
    let mut b = [0; 12];
    r.read_exact(&mut b).await?;
    Event::from_bytes(b)
}
pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, event: Event) -> Result<()> {
    w.write_all(&event.bytes()?).await?;
    Ok(())
}

/// Tracks held keys independently of the device so disconnect cleanup is testable.
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
pub struct Held {
    active: bool,
    keys: std::collections::BTreeSet<u16>,
}
#[cfg(any(target_os = "linux", test))]
impl Held {
    pub fn apply(
        &mut self,
        event: Event,
        mut emit: impl FnMut(u16, u16, i32) -> Result<()>,
    ) -> Result<()> {
        event.validate()?;
        if matches!(event, Event::Release | Event::Capture) {
            self.active = false;
            for code in std::mem::take(&mut self.keys) {
                emit(1, code, 0)?;
            }
            emit(0, 0, 0)?;
            self.active = event == Event::Capture;
            return Ok(());
        }
        if !self.active {
            return Ok(());
        }
        match event {
            Event::Key { code, down } => {
                if if down {
                    self.keys.insert(code)
                } else {
                    self.keys.remove(&code)
                } {
                    emit(1, code, down.into())?;
                }
            }
            Event::Button { button, down } => {
                let code = 0x110 + u16::from(button);
                if if down {
                    self.keys.insert(code)
                } else {
                    self.keys.remove(&code)
                } {
                    emit(1, code, down.into())?;
                }
            }
            Event::Motion { x, y } => {
                emit(2, 0, x)?;
                emit(2, 1, y)?;
            }
            Event::Scroll { x, y } => {
                emit(2, 6, x)?;
                emit(2, 8, y)?;
            }
            _ => {}
        }
        emit(0, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_canonical_wire() {
        for e in [
            Event::Capture,
            Event::Release,
            Event::Heartbeat,
            Event::Key {
                code: 29,
                down: true,
            },
            Event::Button {
                button: 4,
                down: false,
            },
            Event::Motion {
                x: -32767,
                y: 32767,
            },
            Event::Scroll { x: 1, y: -1 },
        ] {
            assert_eq!(Event::from_bytes(e.bytes().unwrap()).unwrap(), e);
        }
        let mut b = Event::Capture.bytes().unwrap();
        b[11] = 1;
        assert!(Event::from_bytes(b).is_err());
        assert!(
            Event::Key {
                code: 0,
                down: true
            }
            .bytes()
            .is_err()
        );
        assert!(Event::Motion { x: i32::MAX, y: 0 }.bytes().is_err());
    }
    #[test]
    fn capture_and_release_do_not_leave_stuck_keys() {
        let mut held = Held::default();
        let mut events = vec![];
        for e in [
            Event::Key {
                code: 30,
                down: true,
            },
            Event::Capture,
            Event::Key {
                code: 29,
                down: true,
            },
            Event::Key {
                code: 29,
                down: true,
            },
            Event::Button {
                button: 0,
                down: true,
            },
            Event::Release,
            Event::Key {
                code: 30,
                down: true,
            },
        ] {
            held.apply(e, |t, c, v| {
                events.push((t, c, v));
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(events.iter().filter(|e| **e == (1, 29, 1)).count(), 1);
        assert!(events.contains(&(1, 29, 0)) && events.contains(&(1, 0x110, 0)));
        assert!(!events.iter().any(|e| e.0 == 1 && e.1 == 30));
    }
}
