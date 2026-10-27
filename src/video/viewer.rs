use super::{codec::Av1Decoder, input, keymap, protocol::*, service};
use anyhow::{Context as _, Result, ensure};
use std::{
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, DeviceId, ElementState, MouseButton, MouseScrollDelta, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    keyboard::{Key, KeyCode, NamedKey, PhysicalKey},
    window::{CursorGrabMode, Fullscreen, Window, WindowId},
};

struct Image {
    width: u32,
    height: u32,
    pixels: Vec<u32>,
}
#[derive(Default)]
struct State {
    image: Option<Image>,
    status: String,
    failure: Option<String>,
    ack: Option<(u64, tokio::sync::mpsc::Sender<u64>)>,
    input: Option<tokio::sync::mpsc::Sender<input::Event>>,
    input_failed: bool,
    generation: u64,
}
struct App {
    state: Arc<Mutex<State>>,
    window: Option<Arc<Window>>,
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    error: Option<String>,
    captured: bool,
    locked: bool,
    generation: u64,
    pressed: std::collections::HashSet<KeyCode>,
    cursor: Option<(f64, f64)>,
    motion_remainder: (f64, f64),
    scroll_remainder: (f64, f64),
    queued_motion: (i32, i32),
    last_motion: Instant,
}
impl App {
    fn send(&mut self, event: input::Event) {
        if !matches!(event, input::Event::Motion { .. }) {
            self.flush_motion();
        }
        let failed = {
            let mut state = self.state.lock().unwrap();
            let failed = state
                .input
                .as_ref()
                .is_none_or(|tx| tx.try_send(event).is_err());
            if failed {
                state.input_failed = true;
            }
            failed
        };
        if failed {
            self.ungrab();
        }
    }
    fn flush_motion(&mut self) {
        let (x, y) = std::mem::take(&mut self.queued_motion);
        if self.captured && (x != 0 || y != 0) {
            self.last_motion = Instant::now();
            self.send(input::Event::Motion {
                x: x.clamp(-32767, 32767),
                y: y.clamp(-32767, 32767),
            });
        }
    }
    fn ungrab(&mut self) {
        self.queued_motion = (0, 0);
        self.captured = false;
        self.cursor = None;
        self.motion_remainder = (0., 0.);
        self.scroll_remainder = (0., 0.);
        if let Some(window) = &self.window {
            let _ = window.set_cursor_grab(CursorGrabMode::None);
            window.set_cursor_visible(true);
        }
    }
    fn release(&mut self) {
        if self.captured {
            self.send(input::Event::Release);
        }
        self.ungrab();
    }
    fn capture(&mut self) {
        let state = self.state.lock().unwrap();
        if state.input.is_none() || state.image.is_none() {
            return;
        }
        self.generation = state.generation;
        drop(state);
        let Some(window) = &self.window else {
            return;
        };
        self.locked = window.set_cursor_grab(CursorGrabMode::Locked).is_ok();
        if !self.locked && window.set_cursor_grab(CursorGrabMode::Confined).is_err() {
            return;
        }
        window.set_cursor_visible(false);
        self.cursor = None;
        self.captured = true;
        self.send(input::Event::Capture);
    }
    fn motion(&mut self, x: f64, y: f64) {
        self.motion_remainder.0 += x;
        self.motion_remainder.1 += y;
        let x = self.motion_remainder.0.clamp(-32767., 32767.).trunc() as i32;
        let y = self.motion_remainder.1.clamp(-32767., 32767.).trunc() as i32;
        self.motion_remainder.0 -= f64::from(x);
        self.motion_remainder.1 -= f64::from(y);
        if x != 0 || y != 0 {
            self.queued_motion.0 = self.queued_motion.0.saturating_add(x);
            self.queued_motion.1 = self.queued_motion.1.saturating_add(y);
        }
    }
    fn draw(&mut self) -> Result<()> {
        let Some(window) = &self.window else {
            return Ok(());
        };
        let size = window.inner_size();
        let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) else {
            return Ok(());
        };
        let surface = self.surface.as_mut().unwrap();
        surface
            .resize(w, h)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let mut buffer = surface
            .buffer_mut()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        buffer.fill(0);
        let mut state = self.state.lock().unwrap();
        let input_status = if self.captured {
            "Input captured — Ctrl+Alt+G releases"
        } else if state.input.is_some() {
            "Click video to control"
        } else {
            "View only"
        };
        window.set_title(&format!("ESP Video — {} — {input_status}", state.status));
        if let Some(image) = &state.image {
            let scale = (size.width as f64 / image.width as f64)
                .min(size.height as f64 / image.height as f64);
            let dw = (image.width as f64 * scale).floor().max(1.0) as usize;
            let dh = (image.height as f64 * scale).floor().max(1.0) as usize;
            let ox = (size.width as usize - dw) / 2;
            let oy = (size.height as usize - dh) / 2;
            for y in 0..dh {
                for x in 0..dw {
                    buffer[(y + oy) * size.width as usize + x + ox] =
                        image.pixels[(y * image.height as usize / dh) * image.width as usize
                            + x * image.width as usize / dw];
                }
            }
        }
        let ack = state.ack.take();
        drop(state);
        buffer
            .present()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if let Some((sequence, sender)) = ack {
            let _ = sender.try_send(sequence);
        }
        Ok(())
    }
}
impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let result = (|| -> Result<_> {
            let window = Arc::new(
                event_loop.create_window(
                    Window::default_attributes()
                        .with_title("ESP Video")
                        .with_inner_size(winit::dpi::LogicalSize::new(960., 540.)),
                )?,
            );
            let context = softbuffer::Context::new(window.clone())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let surface = softbuffer::Surface::new(&context, window.clone())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            Ok((window, surface))
        })();
        match result {
            Ok((window, surface)) => {
                self.window = Some(window);
                self.surface = Some(surface);
            }
            Err(e) => {
                self.error = Some(e.to_string());
                event_loop.exit();
            }
        }
    }
    fn window_event(&mut self, event_loop: &ActiveEventLoop, _: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                self.release();
                event_loop.exit();
            }
            WindowEvent::Focused(false) => {
                self.release();
                self.pressed.clear();
            }
            WindowEvent::KeyboardInput {
                event,
                is_synthetic,
                ..
            } if !is_synthetic => {
                if let PhysicalKey::Code(code) = event.physical_key {
                    let down = event.state == ElementState::Pressed;
                    if down {
                        self.pressed.insert(code);
                    } else {
                        self.pressed.remove(&code);
                    }
                    let ctrl = self.pressed.contains(&KeyCode::ControlLeft)
                        || self.pressed.contains(&KeyCode::ControlRight);
                    let alt = self.pressed.contains(&KeyCode::AltLeft)
                        || self.pressed.contains(&KeyCode::AltRight);
                    if self.captured && down && code == KeyCode::KeyG && ctrl && alt {
                        self.release();
                        return;
                    }
                    if self.captured && !event.repeat {
                        if let Some(code) = keymap::evdev(code) {
                            self.send(input::Event::Key { code, down });
                        }
                    } else if !self.captured
                        && down
                        && !event.repeat
                        && event.logical_key == Key::Named(NamedKey::F11)
                    {
                        if let Some(window) = &self.window {
                            window.set_fullscreen(if window.fullscreen().is_some() {
                                None
                            } else {
                                Some(Fullscreen::Borderless(window.current_monitor()))
                            });
                        }
                    }
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                if !self.captured {
                    if state == ElementState::Pressed && button == MouseButton::Left {
                        self.capture();
                    }
                } else {
                    let button = match button {
                        MouseButton::Left => Some(0),
                        MouseButton::Right => Some(1),
                        MouseButton::Middle => Some(2),
                        MouseButton::Back => Some(3),
                        MouseButton::Forward => Some(4),
                        _ => None,
                    };
                    if let Some(button) = button {
                        self.send(input::Event::Button {
                            button,
                            down: state == ElementState::Pressed,
                        });
                    }
                }
            }
            WindowEvent::MouseWheel { delta, .. } if self.captured => {
                let (x, y) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => (f64::from(x), f64::from(y)),
                    MouseScrollDelta::PixelDelta(p) => (p.x / 40., p.y / 40.),
                };
                self.scroll_remainder.0 += x;
                self.scroll_remainder.1 += y;
                let x = self.scroll_remainder.0.clamp(-32767., 32767.).trunc() as i32;
                let y = self.scroll_remainder.1.clamp(-32767., 32767.).trunc() as i32;
                self.scroll_remainder.0 -= f64::from(x);
                self.scroll_remainder.1 -= f64::from(y);
                if x != 0 || y != 0 {
                    self.send(input::Event::Scroll { x, y });
                }
            }
            WindowEvent::RedrawRequested => {
                if let Err(e) = self.draw() {
                    self.error = Some(e.to_string());
                    event_loop.exit();
                }
            }
            _ => {}
        }
    }
    fn device_event(&mut self, _: &ActiveEventLoop, _: DeviceId, event: DeviceEvent) {
        if self.captured {
            if let DeviceEvent::MouseMotion { delta: (x, y) } = event {
                self.motion(x, y);
            }
        }
    }
    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if self.last_motion.elapsed() >= Duration::from_millis(8) {
            self.flush_motion();
        }
        let lost = {
            let s = self.state.lock().unwrap();
            s.input.is_none() || s.generation != self.generation || s.input_failed
        };
        if self.captured && lost {
            self.ungrab();
        }
        if let Some(window) = &self.window {
            window.request_redraw();
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(
            Instant::now() + Duration::from_millis(16),
        ));
    }
}
pub async fn run(network: String, host: String) -> Result<()> {
    let event_loop = EventLoop::new()?;
    let state = Arc::new(Mutex::new(State {
        image: None,
        status: "connecting".into(),
        ack: None,
        ..State::default()
    }));
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let mut resume = None;
        let mut failed_since = None;
        let mut last_reported = None;
        loop {
            let started = Instant::now();
            let result = session(&network, &host, &mut resume, task_state.clone()).await;
            let terminal = result.as_ref().err().is_some_and(|e| e.is::<Rejected>());
            if started.elapsed() > Duration::from_secs(5) {
                failed_since = None;
                last_reported = None;
            }
            let error = match result {
                Err(error) => format!("{error:#}"),
                Ok(()) => "video session ended".into(),
            };
            // Always report errors, even without RUST_LOG. Keep the complete
            // anyhow cause chain out of the window title, where it gets truncated.
            if last_reported.as_ref() != Some(&error) {
                eprintln!("ESP video ({network}/{host}): {error}");
                last_reported = Some(error.clone());
            }
            let first = *failed_since.get_or_insert_with(Instant::now);
            let done = terminal || first.elapsed() > Duration::from_secs(30);
            {
                let mut s = task_state.lock().unwrap();
                s.input = None;
                s.image = None;
                s.ack = None;
                s.failure = Some(error);
                s.status = if done {
                    "Disconnected — see terminal"
                } else {
                    "Reconnecting — see terminal"
                }
                .into();
            }
            if done {
                eprintln!(
                    "ESP video: stopped reconnecting; fix the reported error and run the viewer again."
                );
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let mut app = App {
        state,
        window: None,
        surface: None,
        error: None,
        captured: false,
        locked: false,
        generation: 0,
        pressed: Default::default(),
        cursor: None,
        motion_remainder: (0., 0.),
        scroll_remainder: (0., 0.),
        queued_motion: (0, 0),
        last_motion: Instant::now(),
    };
    let result = event_loop.run_app(&mut app);
    task.abort();
    let _ = task.await;
    result?;
    if let Some(e) = app.error {
        anyhow::bail!(e);
    }
    if let Some(e) = app.state.lock().unwrap().failure.take() {
        anyhow::bail!(e);
    }
    Ok(())
}
async fn session(
    network: &str,
    host: &str,
    resume: &mut Option<String>,
    state: Arc<Mutex<State>>,
) -> Result<()> {
    let (mut stream, reply) = service::connect_local(
        network,
        LocalRequest::View {
            host: host.into(),
            resume: resume.clone(),
        },
    )
    .await?;
    let Reply::Ready {
        share,
        format,
        allow_input,
    } = reply
    else {
        anyhow::bail!("unexpected video viewer response");
    };
    ensure!(
        resume.as_ref().is_none_or(|id| *id == share),
        "host share changed; run view again"
    );
    *resume = Some(share);
    let mut codec = Av1Decoder::new(format)?;
    let mut first = true;
    let (acks, mut ack_rx) = tokio::sync::mpsc::channel::<u64>(2);
    let (inputs, mut input_rx) = tokio::sync::mpsc::channel(128);
    {
        let mut s = state.lock().unwrap();
        s.generation += 1;
        s.input_failed = false;
        s.input = allow_input.then_some(inputs);
    }
    let (mut read, mut write) = stream.split();
    let decode = async {
        loop {
            let frame = tokio::time::timeout(LIVENESS, read_frame(&mut read)).await??;
            frame.validate(format, first)?;
            first = false;
            let sequence = frame.sequence;
            // At most one decode worker and one replaceable presentation image.
            let (returned, pixels) = tokio::task::spawn_blocking(move || -> Result<_> {
                let pixels = codec.decode(&frame.data, frame.key)?;
                Ok((codec, pixels))
            })
            .await
            .context("video decoder worker failed")??;
            codec = returned;
            let mut s = state.lock().unwrap();
            s.failure = None;
            s.image = Some(Image {
                width: format.width,
                height: format.height,
                pixels,
            });
            s.status = format!(
                "{}×{} · {} FPS · F11 fullscreen",
                format.width, format.height, format.fps
            );
            s.ack = Some((sequence, acks.clone()));
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let feedback = async {
        let mut heartbeat = tokio::time::interval(Duration::from_millis(500));
        loop {
            let message = tokio::select! {
                Some(sequence)=ack_rx.recv()=>Ok(sequence),
                Some(event)=input_rx.recv(), if allow_input =>Err(event),
                _=heartbeat.tick(), if allow_input => {
                    ensure!(!state.lock().unwrap().input_failed,"input queue overflow; releasing control");
                    Err(input::Event::Heartbeat)
                }
            };
            tokio::time::timeout(Duration::from_millis(500), async {
                match message {
                    Ok(sequence) => {
                        write.write_all(&[1]).await?;
                        write.write_all(&sequence.to_be_bytes()).await?;
                    }
                    Err(event) => {
                        write.write_all(&[2]).await?;
                        input::write(&mut write, event).await?;
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
            .await??;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {result=decode=>result,result=feedback=>result}
}
