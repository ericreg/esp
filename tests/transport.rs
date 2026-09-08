#![cfg(unix)]
#![allow(dead_code)]

include!("../src/main.rs");

struct TransportHome {
    dir: PathBuf,
}

impl TransportHome {
    fn new() -> Self {
        // Leave room for ~/.esp/.esp.sock within macOS's Unix socket path limit.
        let dir = std::env::temp_dir().join(format!(
            "esp-t-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        fs::create_dir(&dir).unwrap();
        let key = SecretKey::generate();
        let cfg = create_creator_config(
            "Test network",
            &key,
            Uuid::new_v4().to_string(),
            "local".to_string(),
            "ABC123".to_string(),
            DEFAULT_MAX_KNOWN_PEERS,
        )
        .unwrap();
        let store = networks::Store {
            root: dir.join(ESP_DIR),
        };
        store.prepare().unwrap();
        cfg.save(&store.path(&cfg.network_id).unwrap()).unwrap();
        Self { dir }
    }

    fn network(&self) -> PathBuf {
        let store = networks::Store {
            root: self.dir.join(ESP_DIR),
        };
        let cfg = store.select("Test network").unwrap();
        store.path(&cfg.network_id).unwrap()
    }

    fn socket(&self) -> PathBuf {
        self.dir.join(ESP_DIR).join(LOCAL_CONTROL_SOCKET_FILE)
    }

    fn pid(&self) -> i32 {
        fs::read_to_string(self.socket().with_extension("lock"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_esp"));
        command
            .env("HOME", &self.dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        command
    }

    async fn proxy(&self) -> std::process::Output {
        timeout(
            Duration::from_secs(10),
            self.command()
                .args(["proxy", "Test network", "unknown-host", "22"])
                .output(),
        )
        .await
        .expect("proxy inherited background process stdio or startup hung")
        .unwrap()
    }

    async fn wait_until_unlocked(&self) {
        timeout(Duration::from_secs(10), async {
            while transport::try_lock(&self.socket()).unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("transport did not release its lock");
    }

    async fn stop(&self) {
        // SAFETY: this PID belongs to the helper launched in this test's private HOME.
        assert_eq!(unsafe { libc::kill(self.pid(), libc::SIGTERM) }, 0);
        self.wait_until_unlocked().await;
        assert!(!self.socket().exists());
        for log in fs::read_dir(self.dir.join(ESP_DIR).join(LOG_DIR)).unwrap() {
            let text = fs::read_to_string(log.unwrap().path()).unwrap();
            assert!(!text.contains("Endpoint dropped"), "{text}");
        }
    }
}

impl Drop for TransportHome {
    fn drop(&mut self) {
        // Also clean up helpers if an assertion fails.
        if transport::try_lock(&self.socket()).is_ok_and(|lock| lock.is_none())
            && let Some(pid) = fs::read_to_string(self.socket().with_extension("lock"))
                .ok()
                .and_then(|text| text.trim().parse::<i32>().ok())
                .filter(|pid| *pid > 1)
        {
            // SAFETY: only our test helper can hold this private directory's lock.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn assert_reached_transport(output: &std::process::Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // No network lookup is needed: the real background actor rejects this name.
    assert!(
        stderr.contains("no configured esp peer named unknown-host"),
        "{stderr}"
    );
    assert!(!stderr.contains("Endpoint dropped"), "{stderr}");
}

#[tokio::test]
async fn originator_invite_commands_issue_fresh_codes_without_transport() {
    let home = TransportHome::new();
    let path = home.network();
    let mut codes = HashSet::new();
    let mut ids = HashSet::new();
    let mut secrets = HashSet::new();

    for count in 1..=3 {
        let output = timeout(
            Duration::from_secs(5),
            home.command()
                .args([
                    "invite",
                    "Test network",
                    "Test peer",
                    "--format",
                    "json",
                    "--no-color",
                ])
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let code = report["invite_code"].as_str().unwrap().to_owned();
        let invite = Invite::decode(&code).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(invite.creator_node_id, invite.inviter_node_id);
        assert_eq!(invite.creator_node_id, cfg.creator_node_id);
        assert_eq!(cfg.invites.len(), count);
        assert!(
            cfg.invite_grant_for_proof(Some(&InviteProof {
                invite_id: invite.invite_id.clone(),
                invite_secret: invite.invite_secret.clone(),
            }))
            .unwrap()
            .is_some()
        );
        assert!(codes.insert(code));
        assert!(ids.insert(invite.invite_id));
        assert!(secrets.insert(invite.invite_secret));
        assert!(!home.socket().exists());
    }
}

#[tokio::test]
async fn simultaneous_proxy_processes_start_and_reuse_one_background_transport() {
    let home = TransportHome::new();
    let mut children = Vec::new();
    for _ in 0..8 {
        children.push(
            home.command()
                .args(["proxy", "Test network", "unknown-host", "22"])
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        let output = timeout(Duration::from_secs(10), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert_reached_transport(&output);
    }
    assert_eq!(
        fs::read_dir(home.dir.join(ESP_DIR).join(LOG_DIR))
            .unwrap()
            .count(),
        1
    );
    let pid = home.pid();
    assert!(!home.dir.join(".esp.sock").exists());
    assert!(!home.dir.join(".esp.lock").exists());
    let socket_inode = fs::metadata(home.socket()).unwrap().ino();
    assert!(transport::try_lock(&home.socket()).unwrap().is_none());
    for path in [home.socket(), home.socket().with_extension("lock")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // All originating proxies have exited. A later proxy still reuses the helper.
    assert_reached_transport(&home.proxy().await);
    assert_eq!(home.pid(), pid);
    assert_eq!(fs::metadata(home.socket()).unwrap().ino(), socket_inode);
    let status = send_local_control_request_to_path(&home.socket(), LocalControlRequest::Status)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(status, LocalControlOk::Status { .. }));

    let initialized = home
        .command()
        .args(["init", "Shared network", "--format", "json", "--no-color"])
        .output()
        .await
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(report["network_label"], "Shared network");
    assert_eq!(
        Config::load(&home.network())
            .unwrap()
            .network_policy
            .admin_label
            .as_deref(),
        Some("Test network")
    );

    // Promotion retains the helper PID; another foreground owner is rejected.
    let mut foreground = home.command().arg("daemon").spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(home.pid(), pid);
    let output = home.command().arg("daemon").output().await.unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already running"));
    foreground.kill().await.unwrap();
    home.wait_until_unlocked().await;
}

#[tokio::test]
async fn proxy_restarts_after_helper_crash_and_recovers_stale_socket() {
    let home = TransportHome::new();
    assert_reached_transport(&home.proxy().await);
    let old_pid = home.pid();
    let lock_inode = fs::metadata(home.socket().with_extension("lock"))
        .unwrap()
        .ino();
    // SAFETY: kill only the helper created in this test's private HOME.
    assert_eq!(unsafe { libc::kill(old_pid, libc::SIGKILL) }, 0);
    home.wait_until_unlocked().await;
    assert!(home.socket().exists(), "crash should leave a stale socket");
    assert_reached_transport(&home.proxy().await);
    assert_ne!(home.pid(), old_pid);
    assert_eq!(
        fs::metadata(home.socket().with_extension("lock"))
            .unwrap()
            .ino(),
        lock_inode
    );
    home.stop().await;
}

#[tokio::test]
async fn startup_failure_preserves_non_socket_file_and_releases_lock() {
    let home = TransportHome::new();
    fs::write(home.socket(), "keep this file").unwrap();
    let output = home.proxy().await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-socket") || stderr.contains("exists and is not a socket"),
        "{stderr}"
    );
    assert_eq!(fs::read_to_string(home.socket()).unwrap(), "keep this file");
    assert!(transport::try_lock(&home.socket()).unwrap().is_some());
}

#[tokio::test]
async fn spawn_failure_releases_transport_lock() {
    let home = TransportHome::new();
    let err = transport::connect_or_start(
        &home.socket(),
        &home.network(),
        &home.dir.join("missing-esp-executable"),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("failed to start shared esp transport"));
    assert!(transport::try_lock(&home.socket()).unwrap().is_some());
    assert!(!home.socket().exists());
}

#[tokio::test]
async fn helper_startup_failure_is_reported_and_releases_lock() {
    let home = TransportHome::new();
    fs::write(home.dir.join(ESP_DIR).join(LOG_DIR), "keep this file").unwrap();
    let output = home.proxy().await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("exited during startup"), "{stderr}");
    assert!(stderr.contains("not a directory"), "{stderr}");
    assert!(transport::try_lock(&home.socket()).unwrap().is_some());
    assert!(!home.socket().exists());
}

#[tokio::test(start_paused = true)]
async fn waiting_for_another_transport_to_start_is_bounded() {
    let home = TransportHome::new();
    let _owner = transport::try_lock(&home.socket()).unwrap().unwrap();
    let err = transport::connect_or_start(
        &home.socket(),
        &home.network(),
        Path::new(env!("CARGO_BIN_EXE_esp")),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("timed out starting or connecting"));
    assert!(!home.socket().exists());
    assert!(!home.dir.join(ESP_DIR).join(LOG_DIR).exists());
}

#[tokio::test]
async fn setup_retries_when_transport_closes_before_ready() {
    let home = TransportHome::new();
    let listener = bind_local_control_socket(&home.socket()).unwrap();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let _: networks::Request =
            read_cbor_frame(&mut first, MAX_LOCAL_CONTROL_MESSAGE_LEN, "first request")
                .await
                .unwrap();
        drop(first); // Simulate shutdown before the readiness reply.
        let (mut second, _) = listener.accept().await.unwrap();
        let request: networks::Request =
            read_cbor_frame(&mut second, MAX_LOCAL_CONTROL_MESSAGE_LEN, "retry")
                .await
                .unwrap();
        assert!(
            matches!(request, networks::Request::Network { request: LocalControlRequest::Proxy { target, port: 22 }, .. } if target == "remote-host")
        );
        write_cbor_frame(
            &mut second,
            &LocalProxyResponse::Ready,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "ready",
        )
        .await
        .unwrap();
        second.write_all(b"SSH-2.0-retry\r\n").await.unwrap();
    });
    let mut stream = timeout(
        Duration::from_secs(5),
        transport::open_proxy(
            &home.socket(),
            &home.network(),
            &home.dir.join("unused-executable"),
            "remote-host".to_string(),
            22,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let mut banner = String::new();
    stream.read_to_string(&mut banner).await.unwrap();
    assert_eq!(banner, "SSH-2.0-retry\r\n");
    server.await.unwrap();
}

/// A real controlling terminal, isolated from the developer's terminal and config.
struct AdminPty {
    master: fs::File,
    slave: fs::File,
    output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    cursor: usize,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for AdminPty {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl AdminPty {
    fn new() -> Self {
        use std::os::fd::FromRawFd;
        let mut master = -1;
        let mut slave = -1;
        let mut size = libc::winsize {
            ws_row: 30,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty initializes both owned descriptors; the optional name/termios are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &raw mut size,
                )
            },
            0
        );
        // SAFETY: fcntl operates on the valid master descriptor, preserving its existing flags.
        unsafe {
            let flags = libc::fcntl(master, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
        }
        // SAFETY: the descriptors were created above and transferred to File exactly once.
        let (master, slave) =
            unsafe { (fs::File::from_raw_fd(master), fs::File::from_raw_fd(slave)) };
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = output.clone();
        let mut input = master.try_clone().unwrap();
        // Keep draining even while assertions wait for child state. Otherwise the
        // terminal's small output buffer can block rendering before input is read.
        let reader = tokio::spawn(async move {
            loop {
                let mut bytes = [0; 8192];
                match input.read(&mut bytes) {
                    Ok(count) => captured.lock().unwrap().extend_from_slice(&bytes[..count]),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        Self {
            master,
            slave,
            output,
            cursor: 0,
            reader,
        }
    }

    fn flags(&self) -> libc::tcflag_t {
        use std::os::fd::AsRawFd;
        let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr initializes the output on success.
        assert_eq!(
            unsafe { libc::tcgetattr(self.master.as_raw_fd(), attributes.as_mut_ptr()) },
            0
        );
        unsafe { attributes.assume_init() }.c_lflag
    }

    fn spawn(&self, fixture: &TransportHome) -> tokio::process::Child {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let mut command = fixture.command();
        command
            .env("TERM", "xterm-256color")
            .arg("admin")
            .stdin(self.slave.try_clone().unwrap())
            .stdout(self.slave.try_clone().unwrap())
            .stderr(self.slave.try_clone().unwrap());
        let slave_fd = self.slave.as_raw_fd();
        // SAFETY: only async-signal-safe syscalls are called in the forked child.
        unsafe {
            command.as_std_mut().pre_exec(move || {
                if libc::setsid() == -1 || libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    async fn until(&mut self, expected: &str) -> String {
        let mut output = Vec::new();
        let result = timeout(Duration::from_secs(10), async {
            loop {
                output = self.output.lock().unwrap()[self.cursor..].to_vec();
                let text = String::from_utf8_lossy(&output);
                let mut state = 0;
                let plain: String = text
                    .chars()
                    .filter(|&ch| match state {
                        0 if ch == '\x1b' => {
                            state = 1;
                            false
                        }
                        1 => {
                            state = if ch == '[' { 2 } else { 0 };
                            false
                        }
                        2 => {
                            if ('@'..='~').contains(&ch) {
                                state = 0;
                            }
                            false
                        }
                        _ => !ch.is_whitespace(),
                    })
                    .collect();
                let found = if expected.starts_with('\x1b') {
                    text.contains(expected)
                } else {
                    plain.contains(
                        &expected
                            .chars()
                            .filter(|ch| !ch.is_whitespace())
                            .collect::<String>(),
                    )
                };
                if found {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "missing {expected:?} in PTY output: {}",
            String::from_utf8_lossy(&output)
        );
        self.cursor += output.len();
        String::from_utf8_lossy(&output).into_owned()
    }
}

#[tokio::test]
async fn admin_terminal_reconnects_confirms_revocation_and_restores_terminal() {
    let fixture = TransportHome::new();
    let path = fixture.network();
    let mut cfg = Config::load(&path).unwrap();
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "test-host".into(),
        connection_id: "OTHER1".into(),
    };
    let key = cfg.secret_key().unwrap();
    cfg.memberships.push(
        MembershipCertificate::issue(&cfg, &key, &peer, &[22], MembershipRole::Peer).unwrap(),
    );
    cfg.peers.push(peer.clone());
    cfg.save(&path).unwrap();
    let mut pty = AdminPty::new();
    let original_flags = pty.flags();
    let mut child = pty.spawn(&fixture);
    pty.until("read only").await;
    assert_eq!(pty.flags() & (libc::ECHO | libc::ICANON), 0);

    let mut server = fixture.command().arg("daemon").spawn().unwrap();
    // The unchanged transport key is not repainted when the status changes.
    pty.until("0 connected").await;
    pty.master.write_all(b"r").unwrap();
    pty.until("Confirm revocation").await;
    pty.master.write_all(b"\r").unwrap(); // Default is Cancel.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(Config::load(&path).unwrap().peers.len(), 1);
    pty.master.write_all(b"r").unwrap();
    pty.until("Confirm revocation").await;
    pty.master.write_all(b"y").unwrap();
    timeout(Duration::from_secs(5), async {
        while !Config::load(&path).unwrap().peers.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(is_node_revoked(&Config::load(&path).unwrap(), peer.node_id));
    // Graceful signal only to this fixture daemon.
    unsafe {
        libc::kill(server.id().unwrap() as i32, libc::SIGTERM);
    }
    server.wait().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    pty.master.write_all(b"r").unwrap();
    pty.until("disabled:").await;
    pty.master.write_all(b"q").unwrap();
    assert!(
        timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    pty.until("\x1b[?1049l").await;
    assert_eq!(pty.flags(), original_flags);
}

#[tokio::test]
async fn admin_requires_a_terminal_and_ctrl_c_restores_it() {
    let fixture = TransportHome::new();
    let output = fixture.command().arg("admin").output().await.unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
    assert!(output.stdout.is_empty());
    let mut pty = AdminPty::new();
    let original_flags = pty.flags();
    let mut child = pty.spawn(&fixture);
    pty.until("esp admin").await;
    pty.master.write_all(&[3]).unwrap();
    assert!(
        timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    pty.until("\x1b[?1049l").await;
    assert_eq!(pty.flags(), original_flags);
}
