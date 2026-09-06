#![cfg(unix)]
#![allow(dead_code)]

include!("../src/main.rs");

struct TransportHome {
    dir: PathBuf,
}

impl TransportHome {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("esp-t-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let key = SecretKey::generate();
        let cfg = create_creator_config(
            &key,
            Uuid::new_v4().to_string(),
            "local".to_string(),
            "ABC123".to_string(),
            DEFAULT_MAX_KNOWN_PEERS,
        )
        .unwrap();
        cfg.save(&dir.join(ESP_DIR).join(CONFIG_FILE)).unwrap();
        Self { dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join(LOCAL_CONTROL_SOCKET_FILE)
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
                .args(["proxy", "unknown-host", "22"])
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
async fn simultaneous_proxy_processes_start_and_reuse_one_background_transport() {
    let home = TransportHome::new();
    let mut children = Vec::new();
    for _ in 0..8 {
        children.push(
            home.command()
                .args(["proxy", "unknown-host", "22"])
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

    // Starting a server must not create a competing endpoint under the same key.
    let output = timeout(
        Duration::from_secs(5),
        home.command().arg("daemon").output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already running"));
    assert_eq!(home.pid(), pid);
    home.stop().await;
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
        &home.dir.join(ESP_DIR).join(CONFIG_FILE),
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
        &home.dir.join(ESP_DIR).join(CONFIG_FILE),
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
        let _: LocalControlRequest =
            read_cbor_frame(&mut first, MAX_LOCAL_CONTROL_MESSAGE_LEN, "first request")
                .await
                .unwrap();
        drop(first); // Simulate shutdown before the readiness reply.
        let (mut second, _) = listener.accept().await.unwrap();
        let request: LocalControlRequest =
            read_cbor_frame(&mut second, MAX_LOCAL_CONTROL_MESSAGE_LEN, "retry")
                .await
                .unwrap();
        assert_eq!(
            request,
            LocalControlRequest::Proxy {
                target: "remote-host".to_string(),
                port: 22
            }
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
            &home.dir.join("unused-config"),
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
