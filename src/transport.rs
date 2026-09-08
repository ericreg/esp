//! One on-demand client transport shared by all local proxy processes.

use super::*;
use std::{fs::TryLockError, os::fd::AsFd, process::Stdio};

const START_TIMEOUT: Duration = Duration::from_secs(30);

pub fn try_lock(socket: &Path) -> Result<Option<fs::File>> {
    // Never unlink this file: every contender must lock the same inode, including
    // after a crash. Closing the last descriptor releases the OS lock.
    let path = socket.with_extension("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(CONFIG_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("failed to open transport lock {}", path.display()))?;
    validate_config_metadata(&path, &file.metadata()?)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(err)) => Err(err).context("failed to lock esp transport"),
    }
}

fn spawn(executable: &Path, lock: fs::File) -> Result<tokio::process::Child> {
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("proxy-transport")
        // Hand the already-held lock to the child through stdin. There is no
        // unlock/relock gap in which another proxy could start an endpoint.
        .stdin(Stdio::from(lock.try_clone()?))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: setsid is async-signal-safe and this closure allocates nothing.
    // The helper must survive the originating SSH session's terminal signals.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match command.spawn() {
        Ok(child) => Ok(child),
        Err(err) => {
            // A failed exec may briefly retain inherited descriptors while the
            // child exits. Release ownership immediately when startup failed.
            let _ = lock.unlock();
            Err(err).context("failed to start shared esp transport")
        }
    }
}

pub async fn connect_or_start(
    socket: &Path,
    config: &Path,
    executable: &Path,
) -> Result<UnixStream> {
    timeout(START_TIMEOUT, async {
        let mut child_exit: Option<oneshot::Receiver<std::io::Result<std::process::Output>>> = None;
        loop {
            match UnixStream::connect(socket).await {
                Ok(stream) => return Ok(stream),
                Err(err) if is_local_control_unavailable(&err) => {}
                Err(err) => return Err(err).context("failed to connect to local esp transport"),
            }
            if let Some(receiver) = &mut child_exit {
                match receiver.try_recv() {
                    Ok(result) => {
                        let output: std::process::Output = result?;
                        bail!(
                            "shared esp transport exited during startup ({}): {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr).trim()
                        );
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(err) => return Err(err).context("lost shared esp transport startup task"),
                }
            } else {
                // Fail before spawning anything if this host is not configured.
                let cfg = Config::load(config)?;
                ensure_completed_join(&cfg)?;
                if let Some(lock) = try_lock(socket)? {
                    // A daemon using the socket may have become ready meanwhile.
                    if let Ok(stream) = UnixStream::connect(socket).await {
                        return Ok(stream);
                    }
                    let child = spawn(executable, lock)?;
                    let (sender, receiver) = oneshot::channel();
                    // Reap the helper if it exits while this proxy is still alive.
                    // It remains independent if this proxy exits first.
                    tokio::spawn(async move {
                        let _ = sender.send(child.wait_with_output().await);
                    });
                    child_exit = Some(receiver);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("timed out starting or connecting to shared esp transport")?
}

pub async fn open_proxy(
    socket: &Path,
    config: &Path,
    executable: &Path,
    target: String,
    port: u16,
) -> Result<UnixStream> {
    for attempt in 0..2 {
        let stream = connect_or_start(socket, config, executable).await?;
        let id = Config::load(config)?.network_id;
        match networks::request_proxy(stream, id, target.clone(), port).await {
            Err(err) if attempt == 0 && connection_closed(&err) => {
                // The idle helper can exit just as a new client connects. Retry
                // setup only; no SSH bytes have been sent at this point.
                continue;
            }
            result => return result,
        }
    }
    unreachable!("the second setup attempt always returns")
}

fn connection_closed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|err| {
            matches!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )
        })
    })
}

pub async fn run() -> Result<()> {
    let socket = local_control_socket_path()?;
    let mut lock = fs::File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let inherited = lock.metadata()?;
    let expected = fs::metadata(socket.with_extension("lock"))?;
    if inherited.dev() != expected.dev()
        || inherited.ino() != expected.ino()
        || try_lock(&socket)?.is_some()
    {
        bail!("proxy-transport must be started by esp proxy with its transport lock");
    }
    lock.set_len(0)?;
    writeln!(lock, "{}", std::process::id())?;

    let store = networks::Store::local()?;
    store.prepare()?;
    let (listener, _socket_guard) = prepare_local_control_socket()?;
    networks::serve(
        listener,
        store,
        false,
        networks::TransportOverrides::default(),
        PROXY_TRANSPORT_IDLE_TIMEOUT,
    )
    .await
}

#[cfg(test)]
#[allow(dead_code)]
pub async fn serve(
    listener: UnixListener,
    actor: ConfigActorHandle,
    endpoint: Endpoint,
    idle_timeout: Duration,
) -> Result<()> {
    info!(node_id = %endpoint.id(), "shared esp proxy transport ready");
    let result = tokio::select! {
        _ = run_local_control_server(listener, actor.clone(), endpoint.clone(), Some(idle_timeout)) => Ok(()),
        result = run_acceptor(endpoint.clone(), actor, Vec::new(), DEFAULT_MAX_CONNECTIONS_PER_PEER) => result,
        result = shutdown_signal() => result,
    };
    endpoint.close().await;
    result
}
