#![cfg(unix)]
#![allow(dead_code)]
include!("../src/main.rs");

#[test]
fn share_cli_defaults_and_allowlist_syntax() {
    for arguments in [
        vec!["esp", "share", "net", "files", "/tmp"],
        vec![
            "esp", "share", "net", "files", "/tmp", "--access", "rw", "--peers", "a,b", "--peers",
            "c",
        ],
    ] {
        let args = Cli::try_parse_from(arguments.clone()).unwrap();
        let Some(Command::Files(shares::Commands::Share { access, peers, .. })) = args.command
        else {
            panic!("wrong command");
        };
        if arguments.len() == 5 {
            assert_eq!(access, shares::Access::Ro);
            assert!(peers.is_none());
        } else {
            assert_eq!(access, shares::Access::Rw);
            assert_eq!(peers.unwrap(), vec!["a", "b", "c"]);
        }
    }
}

#[test]
fn shares_are_idempotent_and_network_scoped() {
    let dir = std::env::temp_dir().join(format!("esp-share-{}", Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let make = || {
        create_creator_config(
            "network",
            &SecretKey::generate(),
            Uuid::new_v4().to_string(),
            "host".into(),
            "ABC123".into(),
            DEFAULT_MAX_KNOWN_PEERS,
        )
        .unwrap()
    };
    let (mut a, mut b) = (make(), make());
    let update = || shares::Update::Put {
        name: "files".into(),
        path: dir.clone(),
        access: shares::Access::Ro,
        peers: None,
    };
    shares::apply(&mut a, update()).unwrap();
    let id = a.shares[0].id.clone();
    shares::apply(&mut a, update()).unwrap();
    assert_eq!(a.shares.len(), 1);
    assert_eq!(a.shares[0].id, id);
    shares::apply(&mut b, update()).unwrap();
    assert_ne!(b.shares[0].id, id);
    assert_eq!(a.shares[0].path, b.shares[0].path);
    let node = SecretKey::generate().public();
    assert!(a.shares[0].allows(node));
    a.shares[0].peers = Some(vec![a.creator_node_id]);
    assert!(!a.shares[0].allows(node));
    let yaml = serde_yaml::to_string(&a).unwrap();
    let decoded: Config = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(decoded.shares, a.shares);
    shares::apply(
        &mut a,
        shares::Update::Remove {
            name: "files".into(),
        },
    )
    .unwrap();
    assert!(a.shares.is_empty());
    assert_eq!(b.shares.len(), 1);
    fs::remove_dir(dir).unwrap();
}

// Run only in an explicitly privileged test job. Uses no nfs-utils or nfsd.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root, a kernel NFS client, and permission to create a temporary mount"]
async fn kernel_nfs_mount() {
    use std::os::unix::fs::DirBuilderExt;
    assert_eq!(unsafe { libc::geteuid() }, 0, "run the test binary as root");
    let dir = std::env::temp_dir().join(format!("esp-kernel-nfs-{}", Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    for name in ["export", "mount"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join(name))
            .unwrap();
    }
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let target = self.0.join("mount");
            if shares::mounts::is_mounted(&target).unwrap_or(true) {
                let path = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::umount2(path.as_ptr(), libc::MNT_DETACH);
                }
                #[cfg(target_os = "macos")]
                unsafe {
                    libc::unmount(path.as_ptr(), libc::MNT_FORCE);
                }
            }
            if !shares::mounts::is_mounted(&target).unwrap_or(true) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let server = std::sync::Arc::new(
        nfs::Server::open(&dir.join("export"), &dir.join("state"))
            .await
            .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let writable = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let live = writable.clone();
    let listener_task = tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let server = server.clone();
            let live = live.clone();
            tokio::spawn(async move {
                while let Some(request) = nfs::xdr::read_record(&mut tcp).await.unwrap() {
                    let response = server
                        .rpc(
                            "kernel-test",
                            0,
                            0,
                            live.load(std::sync::atomic::Ordering::SeqCst),
                            &request,
                        )
                        .await
                        .unwrap();
                    nfs::xdr::write_record(&mut tcp, &response).await.unwrap();
                }
            });
        }
    });
    let registration = shares::mounts::Registration {
        id: Uuid::new_v4().to_string(),
        network: Uuid::new_v4().to_string(),
        peer: SecretKey::generate().public(),
        share: Uuid::new_v4().to_string(),
        name: "files".into(),
        mountpoint: dir.join("mount"),
        port,
        uid: 0,
        gid: 0,
        access: shares::Access::Rw,
        created: true,
        last_error: None,
    };
    let command = serde_json::json!({"Mount":{"registration":registration}}).to_string();
    tokio::task::spawn_blocking(move || shares::mounts::privileged(&command))
        .await
        .unwrap()
        .unwrap();
    let mount = dir.join("mount");
    assert!(shares::mounts::is_mounted(&mount).unwrap());
    fs::write(mount.join("hello"), b"hello NFS").unwrap();
    assert_eq!(fs::read(mount.join("hello")).unwrap(), b"hello NFS");
    fs::rename(mount.join("hello"), mount.join("renamed")).unwrap();
    fs::hard_link(mount.join("renamed"), mount.join("linked")).unwrap();
    assert_eq!(fs::read(dir.join("export/linked")).unwrap(), b"hello NFS");
    fs::create_dir(mount.join("directory")).unwrap();
    fs::remove_dir(mount.join("directory")).unwrap();
    writable.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(fs::write(mount.join("denied"), b"no").is_err());
    let command =
        serde_json::json!({"Unmount":{"registration":registration,"force":false}}).to_string();
    tokio::task::spawn_blocking(move || shares::mounts::privileged(&command))
        .await
        .unwrap()
        .unwrap();
    listener_task.abort();
}
