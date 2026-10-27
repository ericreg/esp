//! Ephemeral viewing grants and bounded bridges; no codecs or device access here.
use super::input;
use super::protocol::Format;
use super::protocol::*;
use crate::*;
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};

#[derive(Clone, Default)]
pub struct Service(Arc<Mutex<Option<Arc<Share>>>>);
struct Share {
    id: String,
    peer: EndpointId,
    display: String,
    format: Format,
    allow_input: bool,
    input: mpsc::Sender<(u64, input::Event)>,
    input_epoch: AtomicU64,
    frames: broadcast::Sender<Frame>,
    stop: watch::Sender<bool>,
    keyframe: mpsc::Sender<u8>,
    busy: AtomicBool,
    sent: AtomicU64,
    bytes: AtomicU64,
    ack_us: AtomicU64,
    reductions: AtomicU32,
    connection: Mutex<Option<Connection>>,
}
struct Owner {
    service: Service,
    share: Arc<Share>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let mut slot = self.service.0.lock().unwrap();
        if slot.as_ref().is_some_and(|s| s.id == self.share.id) {
            *slot = None;
        }
        self.share.stop.send_replace(true);
    }
}
struct Viewer(Arc<Share>, u64);
impl Drop for Viewer {
    fn drop(&mut self) {
        if self.0.allow_input {
            let _ = self.0.input.try_send((self.1, input::Event::Release));
        }
        *self.0.connection.lock().unwrap() = None;
        self.0.busy.store(false, Ordering::Release);
    }
}
impl Service {
    pub fn reset_viewer(&self, reason: &str) {
        if let Ok(share) = self.current() {
            if let Some(conn) = share.connection.lock().unwrap().as_ref() {
                conn.close(GRACEFUL_CLOSE, reason.as_bytes());
            }
        }
    }
    pub fn stop(&self) {
        if let Some(share) = self.0.lock().unwrap().take() {
            share.stop.send_replace(true);
        }
    }
    fn current(&self) -> Result<Arc<Share>> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("no active video share"))
    }
    pub fn status(&self) -> serde_json::Value {
        match self.current() {
            Ok(s) => {
                let connection = s.connection.lock().unwrap();
                serde_json::json!({ "share":s.id,"display":s.display,"peer":s.peer.to_string(),
                    "state":if s.busy.load(Ordering::Acquire) {"streaming"} else {"ready"},
                    "allow_input":s.allow_input,"format_limits":s.format,"encoder_target":s.format.reduced(s.reductions.load(Ordering::Relaxed)),
                    "frames_sent":s.sent.load(Ordering::Relaxed),"bytes_sent":s.bytes.load(Ordering::Relaxed),
                    "last_presentation_roundtrip_ms":s.ack_us.load(Ordering::Relaxed)/1000,
                    "path":connection.as_ref().map(|c| c.paths().iter().find(|p|p.is_selected()).map(|p|if p.is_relay(){"relayed"}else{"direct"}).unwrap_or("connecting").to_string()) })
            }
            Err(_) => serde_json::json!({"state":"stopped"}),
        }
    }
}

async fn snapshot(actor: &ConfigActorHandle) -> Result<Config> {
    let cfg = actor
        .request(|respond| ConfigActorCommand::Snapshot { respond })
        .await?;
    cfg.ensure_active()?;
    ensure_completed_join(&cfg)?;
    Ok(cfg)
}
async fn authenticate(
    actor: &ConfigActorHandle,
    node: EndpointId,
    hello: Hello,
    expected: Option<Peer>,
) -> Result<Hello> {
    // Video cannot consume invitations or complete bootstrap membership.
    anyhow::ensure!(
        hello.membership.is_some() && hello.invite_proof.is_none(),
        "video requires completed membership"
    );
    snapshot(actor).await?;
    let response = actor.control_sync(node, hello, expected).await?;
    let (hello, grant) = response.into_ok()?;
    anyhow::ensure!(
        grant.is_none() && hello.membership.is_some(),
        "incomplete video membership"
    );
    Ok(hello)
}

pub async fn local(
    mut stream: UnixStream,
    actor: ConfigActorHandle,
    endpoint: Endpoint,
    request: LocalRequest,
) -> Result<()> {
    match request {
        LocalRequest::Capabilities => {
            reply(
                &mut stream,
                Reply::Report("{\"version\":1,\"codec\":\"av1\"}".into()),
            )
            .await
        }
        LocalRequest::Status => {
            reply(&mut stream, Reply::Report(actor.video.status().to_string())).await
        }
        LocalRequest::Stop => {
            actor.video.stop();
            reply(&mut stream, Reply::Report("{\"state\":\"stopped\"}".into())).await
        }
        LocalRequest::Share {
            peer,
            display,
            format,
            allow_input,
        } => {
            let setup = async {
                format.validate()?;
                anyhow::ensure!(
                    !display.is_empty() && display.len() <= 1024,
                    "invalid display identity"
                );
                let cfg = snapshot(&actor).await?;
                let peer = cfg.resolve_peer(&peer)?.node_id;
                let active = actor.register_connection(peer).await?;
                let (input, input_requests) = mpsc::channel(128);
                let (frames, _) = broadcast::channel(2);
                let (stop, _) = watch::channel(false);
                let (keyframe, key_requests) = mpsc::channel(1);
                let share = Arc::new(Share {
                    id: Uuid::new_v4().to_string(),
                    peer,
                    display,
                    format,
                    allow_input,
                    input,
                    input_epoch: AtomicU64::new(0),
                    frames,
                    stop,
                    keyframe,
                    busy: AtomicBool::new(false),
                    sent: AtomicU64::new(0),
                    bytes: AtomicU64::new(0),
                    ack_us: AtomicU64::new(0),
                    reductions: AtomicU32::new(0),
                    connection: Mutex::new(None),
                });
                {
                    let mut slot = actor.video.0.lock().unwrap();
                    anyhow::ensure!(
                        slot.is_none(),
                        "a video share is already active on this network"
                    );
                    *slot = Some(share.clone());
                }
                Ok::<_, anyhow::Error>((
                    Owner {
                        service: actor.video.clone(),
                        share,
                    },
                    active,
                    key_requests,
                    input_requests,
                ))
            }
            .await;
            let (owner, mut active, mut key_requests, mut input_requests) = match setup {
                Ok(value) => value,
                Err(e) => return reply(&mut stream, Reply::Error(format!("{e:#}"))).await,
            };
            let share = owner.share.clone();
            reply(
                &mut stream,
                Reply::Ready {
                    share: share.id.clone(),
                    format,
                    allow_input,
                },
            )
            .await?;
            let (mut read, mut write) = stream.into_split();
            let mut stop = share.stop.subscribe();
            anyhow::ensure!(!*stop.borrow_and_update(), "video share stopped");
            let ingest = async {
                let mut previous = None;
                loop {
                    let frame = timeout(LIVENESS, read_frame(&mut read)).await??;
                    frame.validate(format, previous.is_none())?;
                    anyhow::ensure!(
                        previous.is_none_or(|seq| frame.sequence > seq),
                        "non-monotonic owner frame"
                    );
                    previous = Some(frame.sequence);
                    let _ = share.frames.send(frame);
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! {
                result = ingest => result,
                result = async {
                    loop {
                        tokio::select! {
                            Some(request)=key_requests.recv()=>write.write_all(&[request]).await?,
                            Some((epoch,event))=input_requests.recv()=> {
                                write.write_all(&[3]).await?;
                                write.write_all(&epoch.to_be_bytes()).await?;
                                input::write(&mut write,event).await?;
                            }
                        }
                    }
                    #[allow(unreachable_code)] Ok::<(),anyhow::Error>(())
                } => result,
                _ = stop.changed() => Ok(()),
                _ = active.cancelled() => bail!("video share permission revoked"),
            }
        }
        LocalRequest::View { host, resume } => {
            let setup = timeout(SETUP, async {
                let cfg = snapshot(&actor).await?;
                let peer = cfg.resolve_peer(&host)?.clone();
                let active = actor.register_connection(peer.node_id).await?;
                let connection = endpoint.connect(peer.node_id, ALPN).await?;
                let close = CloseConnectionOnDrop(connection.clone());
                connection.set_max_concurrent_uni_streams(VarInt::from_u32(1));
                connection.set_max_concurrent_bi_streams(VarInt::from_u32(0));
                let (mut send, mut recv) = connection.open_bi().await?;
                let hello = ClientHello {
                    identity: hello_from_config(&cfg)?,
                    resume,
                };
                write_cbor_frame(&mut send, &hello, CONTROL_LIMIT, "video hello").await?;
                let remote: ServerResponse =
                    read_cbor_frame(&mut recv, CONTROL_LIMIT, "video server hello").await?;
                let remote = match remote {
                    ServerResponse::Ready(hello) => hello,
                    ServerResponse::Rejected(message) => return Err(Rejected(message).into()),
                };
                remote.format.validate()?;
                Uuid::parse_str(&remote.share)?;
                authenticate(&actor, connection.remote_id(), remote.identity, Some(peer)).await?;
                active.connected().await?;
                // No media is released until both sides have checked membership.
                send.write_all(&[1]).await?;
                Ok::<_, anyhow::Error>((
                    close,
                    send,
                    recv,
                    remote.share,
                    remote.format,
                    remote.allow_input,
                    active,
                ))
            })
            .await
            .context("video connection setup timed out")
            .and_then(|v| v);
            let (connection, mut send, mut recv, share, format, allow_input, mut active) =
                match setup {
                    Ok(v) => v,
                    Err(e) => {
                        let rejection = if e.is::<Rejected>() {
                            Reply::Rejected(e.to_string())
                        } else {
                            Reply::Error(format!("{e:#}"))
                        };
                        return reply(&mut stream, rejection).await;
                    }
                };
            reply(
                &mut stream,
                Reply::Ready {
                    share,
                    format,
                    allow_input,
                },
            )
            .await?;
            let (mut local_read, mut local_write) = stream.into_split();
            let (acks, mut ack_rx) = mpsc::channel::<u64>(2);
            let (inputs, mut input_rx) = mpsc::channel(128);
            let media = async {
                let mut media = timeout(SETUP, connection.0.accept_uni()).await??;
                let mut previous = None;
                loop {
                    let frame = timeout(LIVENESS, read_frame(&mut media)).await??;
                    frame.validate(format, previous.is_none())?;
                    anyhow::ensure!(
                        previous.is_none_or(|seq: u64| seq.checked_add(1) == Some(frame.sequence)),
                        "non-monotonic video frame"
                    );
                    previous = Some(frame.sequence);
                    timeout(
                        Duration::from_millis(500),
                        write_frame(&mut local_write, &frame),
                    )
                    .await??;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            };
            let feedback = async {
                loop {
                    match local_read.read_u8().await? {
                        1 => acks
                            .send(local_read.read_u64().await?)
                            .await
                            .map_err(|_| anyhow!("video control stopped"))?,
                        2 => {
                            anyhow::ensure!(allow_input, "host did not grant input control");
                            let event = input::read(&mut local_read).await?;
                            timeout(Duration::from_millis(100), inputs.send(event)).await??;
                        }
                        _ => bail!("invalid local viewer message"),
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            };
            let input_stream = async {
                if !allow_input {
                    return std::future::pending::<Result<()>>().await;
                }
                let mut output = connection.0.open_uni().await?;
                while let Some(event) = input_rx.recv().await {
                    timeout(Duration::from_millis(500), input::write(&mut output, event)).await??;
                }
                Ok::<(), anyhow::Error>(())
            };
            let control = async {
                let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tokio::select! {
                        _ = heartbeat.tick() => {
                            send.write_all(&[0]).await?;
                            anyhow::ensure!(timeout(LIVENESS,recv.read_u8()).await?? == 0,"invalid video heartbeat");
                        }
                        Some(sequence) = ack_rx.recv() => {
                            send.write_all(&[1]).await?;
                            send.write_all(&sequence.to_be_bytes()).await?;
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! {
                result = media => result,
                result = control => result,
                result = feedback => result,
                result = input_stream => result,
                _ = active.cancelled() => bail!("video host revoked"),
            }
        }
    }
}
pub async fn reply(stream: &mut UnixStream, value: Reply) -> Result<()> {
    write_cbor_frame(stream, &value, CONTROL_LIMIT, "local video response").await
}

pub async fn incoming(conn: Connection, actor: ConfigActorHandle, presence: Uuid) -> Result<()> {
    conn.set_max_concurrent_uni_streams(VarInt::from_u32(1));
    conn.set_max_concurrent_bi_streams(VarInt::from_u32(1));
    let (mut send, mut recv, viewer, mut frames) = timeout(SETUP, async {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let admitted = async {
            let client: ClientHello =
                read_cbor_frame(&mut recv, CONTROL_LIMIT, "video client hello").await?;
            let share = actor.video.current()?;
            anyhow::ensure!(
                conn.remote_id() == share.peer,
                "peer has no local video viewing grant"
            );
            anyhow::ensure!(
                client.resume.as_ref().is_none_or(|id| *id == share.id),
                "video share has changed"
            );
            let identity = authenticate(&actor, conn.remote_id(), client.identity, None).await?;
            let current = actor.video.current()?;
            anyhow::ensure!(
                current.id == share.id && !*share.stop.borrow(),
                "video share stopped"
            );
            anyhow::ensure!(
                share
                    .busy
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok(),
                "video share already has a viewer"
            );
            let epoch = share.input_epoch.fetch_add(1, Ordering::AcqRel) + 1;
            let viewer = Viewer(share.clone(), epoch);
            let frames = share.frames.subscribe();
            let hello = ServerHello {
                identity,
                share: share.id.clone(),
                format: share.format,
                allow_input: share.allow_input,
            };
            Ok::<_, anyhow::Error>((viewer, frames, hello))
        }
        .await;
        let (viewer, frames, hello) = match admitted {
            Ok(ready) => ready,
            Err(error) => {
                write_cbor_frame(
                    &mut send,
                    &ServerResponse::Rejected(error.to_string()),
                    CONTROL_LIMIT,
                    "video rejection",
                )
                .await?;
                send.finish()?;
                let _ = timeout(Duration::from_secs(1), send.stopped()).await;
                return Err(error);
            }
        };
        let share = viewer.0.clone();
        write_cbor_frame(
            &mut send,
            &ServerResponse::Ready(hello),
            CONTROL_LIMIT,
            "video server hello",
        )
        .await?;
        anyhow::ensure!(
            recv.read_u8().await? == 1,
            "invalid video ready acknowledgement"
        );
        actor.connected(conn.remote_id(), presence).await?;
        let _ = share.keyframe.try_send(1);
        *share.connection.lock().unwrap() = Some(conn.clone());
        Ok::<_, anyhow::Error>((send, recv, viewer, frames))
    })
    .await
    .context("video server setup timed out")??;
    let acknowledged = AtomicBool::new(false);
    let flight = Arc::new(Semaphore::new(2));
    let pending = Mutex::new(VecDeque::<(u64, std::time::Instant, OwnedSemaphorePermit)>::new());
    let share = viewer.0.clone();
    let mut stop = share.stop.subscribe();
    anyhow::ensure!(!*stop.borrow_and_update(), "video share stopped");

    let media = async {
        let mut media = conn.open_uni().await?;
        let mut first = true;
        let mut previous = None;
        loop {
            // Lag ends the decoding timeline; never forward dependent frames after a gap.
            let frame = timeout(LIVENESS, frames.recv()).await??;
            if first && !frame.key {
                continue;
            }
            frame.validate(share.format, first)?;
            anyhow::ensure!(
                previous.is_none_or(|seq| frame.sequence == seq + 1),
                "video encoder sequence gap"
            );
            first = false;
            previous = Some(frame.sequence);
            let deadline = if acknowledged.load(Ordering::Acquire) {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            };
            let permit = timeout(deadline, flight.clone().acquire_owned())
                .await
                .context("video presentation too slow")??;
            {
                let mut pending = pending.lock().unwrap();
                anyhow::ensure!(
                    pending
                        .front()
                        .is_none_or(|(_, at, _)| at.elapsed() < deadline),
                    "video presentation backlog exceeded"
                );
                pending.push_back((frame.sequence, std::time::Instant::now(), permit));
            }
            timeout(deadline, write_frame(&mut media, &frame))
                .await
                .context("video network too slow")??;
            share.sent.fetch_add(1, Ordering::Relaxed);
            share
                .bytes
                .fetch_add(frame.data.len() as u64, Ordering::Relaxed);
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let input_stream = async {
        let mut stream = conn.accept_uni().await?;
        anyhow::ensure!(share.allow_input, "input control not authorized");
        let mut window = std::time::Instant::now();
        let mut count = 0;
        loop {
            let event = timeout(Duration::from_secs(2), input::read(&mut stream)).await??;
            if window.elapsed() >= Duration::from_secs(1) {
                window = std::time::Instant::now();
                count = 0;
            }
            count += 1;
            anyhow::ensure!(count <= 2000, "input rate exceeded");
            timeout(
                Duration::from_millis(100),
                share.input.send((viewer.1, event)),
            )
            .await??;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let control = async {
        let mut previous_ack = None;
        loop {
            match timeout(LIVENESS, recv.read_u8()).await?? {
                0 => send.write_all(&[0]).await?,
                1 => {
                    let sequence = timeout(LIVENESS, recv.read_u64()).await??;
                    anyhow::ensure!(
                        previous_ack.is_none_or(|seq| sequence > seq),
                        "stale presentation acknowledgement"
                    );
                    let mut pending = pending.lock().unwrap();
                    anyhow::ensure!(
                        pending.iter().any(|(seq, _, _)| *seq == sequence),
                        "invalid presentation acknowledgement"
                    );
                    if let Some((_, at, _)) = pending.iter().find(|(seq, _, _)| *seq == sequence) {
                        share
                            .ack_us
                            .store(at.elapsed().as_micros() as u64, Ordering::Relaxed);
                    }
                    while pending.front().is_some_and(|(seq, _, _)| *seq <= sequence) {
                        pending.pop_front();
                    }
                    previous_ack = Some(sequence);
                    acknowledged.store(true, Ordering::Release);
                }
                _ => bail!("invalid video control message"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = media => {
            if result.is_err() && share.keyframe.try_send(2).is_ok() {share.reductions.fetch_add(1,Ordering::Relaxed);}
            result
        },
        result = control => result,
        result = input_stream => result,
        _ = stop.changed() => Ok(()),
    }
}

pub async fn connect_local(network: &str, request: LocalRequest) -> Result<(UnixStream, Reply)> {
    let store = networks::Store::local()?;
    let cfg = store.select(network)?;
    let socket = local_control_socket_path()?;
    let mut stream = transport::connect_or_start(
        &socket,
        &store.path(&cfg.network_id)?,
        &std::env::current_exe()?,
    )
    .await?;
    let request = networks::Request::Video {
        id: cfg.network_id,
        request,
    };
    let response = timeout(SETUP, async {
        write_cbor_frame(
            &mut stream,
            &request,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local video request",
        )
        .await?;
        read_cbor_frame(
            &mut stream,
            CONTROL_LIMIT,
            "local video response (restart older ESP helpers to enable video)",
        )
        .await
    })
    .await
    .context("local video request timed out")??;
    match &response {
        Reply::Error(message) => bail!("{message}"),
        Reply::Rejected(message) => return Err(Rejected(message.clone()).into()),
        _ => {}
    }
    Ok((stream, response))
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
