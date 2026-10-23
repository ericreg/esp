use super::{
    codec::{self, Codec},
    display::Size,
    driver,
    protocol::*,
    service,
};
use anyhow::{Context, Result, ensure};
use std::{
    io::IsTerminal,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

pub async fn run(
    network: String,
    display: String,
    peer: String,
    fps: u32,
    max_size: String,
    kbps: u32,
) -> Result<()> {
    ensure!(
        std::io::stdin().is_terminal(),
        "video share needs an interactive terminal for local mirror confirmation"
    );
    let (w, h) = max_size
        .split_once('x')
        .context("--max-size must be WIDTHxHEIGHT")?;
    let bounds = Size {
        width: w.parse()?,
        height: h.parse()?,
    };
    ensure!(
        (2..=1920).contains(&bounds.width) && (2..=1080).contains(&bounds.height),
        "maximum encoded size is 1920x1080"
    );
    let store = crate::networks::Store::local()?;
    let cfg = store.select(&network)?;
    cfg.ensure_active()?;
    crate::ensure_completed_join(&cfg)?;
    cfg.resolve_peer(&peer)?;
    service::connect_local(&network, LocalRequest::Capabilities).await?;
    let source = driver::select(&display)?;
    let session = tokio::time::timeout(Duration::from_secs(5), driver::Session::graphical())
        .await
        .context("graphical session discovery timed out")??;
    let mut capture = driver::Capture::connect(&source)?;
    let driver_size = capture.size;
    let size = capture.size.fit(bounds)?;
    let format = Format {
        width: size.width,
        height: size.height,
        fps,
        kbps,
    };
    format.validate()?;
    println!(
        "Virtual monitor connected. In your display settings, mirror {} to the ESP virtual output.",
        source.connector
    );
    println!(
        "No video is being sent. Check the mirror configuration, then type {} to confirm the source:",
        source.connector
    );
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let mut confirmation = String::new();
    tokio::select! {
        result=input.read_line(&mut confirmation)=>{result?;},
        _=tokio::signal::ctrl_c()=>return Ok(()),
    }
    ensure!(
        confirmation.trim() == source.connector,
        "mirror confirmation did not match selected source"
    );
    session.check().await?;
    driver::verify_virtual(capture.size)?;
    ensure!(
        driver::select(&display)? == source,
        "source display changed during setup"
    );
    println!("Waiting for the virtual monitor's first frame…");
    let wait_for_frame = async {
        loop {
            if let Some(frame) = capture.read()? {
                break Ok::<_, anyhow::Error>(frame);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    let first_frame = tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(15),wait_for_frame)
            =>result.context("virtual monitor did not produce a frame; check display settings")??,
        _=tokio::signal::ctrl_c()=>return Ok(()),
    };
    let (mut stream, reply) = service::connect_local(
        &network,
        LocalRequest::Share {
            peer,
            display: display.clone(),
            format,
        },
    )
    .await?;
    let Reply::Ready { share, .. } = reply else {
        anyhow::bail!("unexpected video registration response");
    };
    println!("Ready — share {share}; Ctrl-C stops sharing and disconnects the virtual monitor.");
    let quality = Arc::new(AtomicU32::new(0));
    let worker_quality = quality.clone();
    let force = Arc::new(AtomicBool::new(true));
    let worker_force = force.clone();
    let (frames, mut encoded) = tokio::sync::mpsc::channel::<Result<Frame>>(1);
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = cancelled.clone();
    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let cancel = Cancel(cancelled);
    // Device access and CPU encoding never run on Tokio's networking workers.
    let worker = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut current = format;
        let mut codec = Codec::encoder(current)?;
        let mut applied_quality = 0;
        let start = Instant::now();
        let mut seq = 0u64;
        let mut period = Duration::from_secs_f64(1.0 / fps as f64);
        let mut deadline = Instant::now();
        let mut last = Some(first_frame);
        let mut dirty = true;
        let mut last_output = Instant::now();
        while !worker_cancelled.load(Ordering::Acquire) {
            let desired = worker_quality.load(Ordering::Acquire);
            if desired != applied_quality {
                let reduced = format.reduced(desired);
                ensure!(
                    reduced != current,
                    "network too slow at minimum video rate; start a new local share to retry"
                );
                current = reduced;
                codec = Codec::encoder(current)?;
                period = Duration::from_secs_f64(1.0 / current.fps as f64);
                applied_quality = desired;
                worker_force.store(true, Ordering::Release);
            }
            if let Some(raw) = capture.read()? {
                last = Some(raw);
                dirty = true;
            }
            if let Some(raw) = &last
                && (dirty
                    || worker_force.load(Ordering::Acquire)
                    || last_output.elapsed() >= Duration::from_secs(5))
            {
                // Acquire queue capacity before advancing interframe references.
                if let Ok(permit) = frames.try_reserve() {
                    let yuv =
                        codec::xrgb_to_yuv(raw, capture.size.width, capture.size.height, format)?;
                    let (data, key) = codec.encode(
                        &yuv,
                        seq as i64,
                        worker_force.swap(false, Ordering::AcqRel),
                    )?;
                    let frame = Frame {
                        sequence: seq,
                        timestamp_us: start.elapsed().as_micros() as u64,
                        key,
                        data: data.into(),
                    };
                    frame.validate(format, seq == 0)?;
                    permit.send(Ok(frame));
                    seq += 1;
                    last_output = Instant::now();
                    dirty = false;
                }
            }
            ensure!(
                last_output.elapsed() < Duration::from_secs(15),
                "virtual monitor is not producing frames"
            );
            deadline += period;
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            } else {
                deadline = now;
            }
        }
        Ok(())
    });
    let (mut read, mut write) = stream.split();
    let transmit = async {
        while let Some(frame) = encoded.recv().await {
            tokio::time::timeout(Duration::from_millis(500), write_frame(&mut write, &frame?))
                .await??;
        }
        anyhow::bail!("video capture/encoder stopped")
    };
    let requests = async {
        loop {
            let message = match read.read_u8().await {
                Ok(value) => value,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            match message {
                1 => force.store(true, Ordering::Release),
                2 => {
                    quality.fetch_add(1, Ordering::AcqRel);
                    force.store(true, Ordering::Release);
                }
                _ => anyhow::bail!("invalid local video feedback"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let monitor = async {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        loop {
            interval.tick().await;
            tokio::time::timeout(Duration::from_secs(2), session.check()).await??;
            driver::verify_virtual(driver_size)?;
            ensure!(
                driver::select(&display)? == source,
                "source display changed or disconnected; start a new local share"
            );
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! {
        result=transmit=>result,
        result=requests=>result,
        result=monitor=>result,
        _=tokio::signal::ctrl_c()=>Ok(()),
    };
    drop(cancel);
    // Nonblocking capture exits within one frame interval and closes the fd.
    let worker_result = worker.await.context("video worker panicked")?;
    worker_result.and(result)
}
