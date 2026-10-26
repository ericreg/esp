use super::{codec::Av1Decoder, protocol::*, service};
use anyhow::{Context as _, Result, ensure};
use std::{
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use winit::{
    application::ApplicationHandler,
    event::{ElementState, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    keyboard::{Key, NamedKey},
    window::{Fullscreen, Window, WindowId},
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
    ack: Option<(u64, tokio::sync::mpsc::Sender<u64>)>,
}
struct App {
    state: Arc<Mutex<State>>,
    window: Option<Arc<Window>>,
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    error: Option<String>,
}
impl App {
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
        window.set_title(&format!("ESP Video — {}", state.status));
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
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::KeyboardInput { event, .. }
                if event.state == ElementState::Pressed && !event.repeat =>
            {
                if event.logical_key == Key::Named(NamedKey::F11) {
                    if let Some(window) = &self.window {
                        window.set_fullscreen(if window.fullscreen().is_some() {
                            None
                        } else {
                            Some(Fullscreen::Borderless(window.current_monitor()))
                        });
                    }
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
    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
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
    }));
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let mut resume = None;
        let mut failed_since = None;
        loop {
            let started = Instant::now();
            let result = session(&network, &host, &mut resume, task_state.clone()).await;
            let terminal = result.as_ref().err().is_some_and(|e| e.is::<Rejected>());
            if started.elapsed() > Duration::from_secs(5) {
                failed_since = None;
            }
            {
                let mut s = task_state.lock().unwrap();
                s.image = None;
                s.ack = None;
                s.status = format!(
                    "disconnected: {}",
                    result.err().map(|e| e.to_string()).unwrap_or_default()
                );
            }
            if terminal {
                break;
            }
            let first = *failed_since.get_or_insert_with(Instant::now);
            if first.elapsed() > Duration::from_secs(30) {
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
    };
    let result = event_loop.run_app(&mut app);
    task.abort();
    let _ = task.await;
    result?;
    if let Some(e) = app.error {
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
    let Reply::Ready { share, format } = reply else {
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
        while let Some(sequence) = ack_rx.recv().await {
            write.write_all(&[1]).await?;
            write.write_all(&sequence.to_be_bytes()).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {result=decode=>result,result=feedback=>result}
}
