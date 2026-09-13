use super::*;
use args::Owner;

fn request(xid: u32, minor: u32, ops: &[Encoder]) -> Vec<u8> {
    let mut e = Encoder::default();
    for v in [xid, 0, 2, 100003, 4, 1, 1] {
        e.u32(v);
    }
    let mut auth = Encoder::default();
    auth.u32(0);
    auth.string("client");
    auth.u32(123);
    auth.u32(456);
    auth.u32(0);
    e.opaque(&auth.0);
    e.u32(0);
    e.opaque(&[]);
    e.string("");
    e.u32(minor);
    e.u32(ops.len() as u32);
    for op in ops {
        e.fixed(&op.0);
    }
    e.0
}
fn header(data: &[u8], expected: u32, count: u32) -> Decoder<'_> {
    let mut d = Decoder::new(data);
    d.u32().unwrap();
    for v in [1, 0, 0, 0, 0, expected] {
        assert_eq!(d.u32().unwrap(), v, "{data:?}");
    }
    assert_eq!(d.string(1024).unwrap(), "");
    assert_eq!(d.u32().unwrap(), count);
    d
}
fn op(code: u32, encode: impl FnOnce(&mut Encoder)) -> Encoder {
    let mut e = Encoder::default();
    e.u32(code);
    encode(&mut e);
    e
}
fn seq(session: Id, n: u32, cache: bool) -> Encoder {
    op(53, |e| {
        e.fixed(&session);
        e.u32(n);
        e.u32(0);
        e.u32(0);
        e.boolean(cache);
    })
}
async fn session(s: &Server, who: &str, minor: u32, cached: u32) -> (u64, Id) {
    let bytes = s
        .rpc(
            who,
            123,
            456,
            true,
            &request(
                1,
                minor,
                &[op(42, |e| {
                    e.fixed(&[1; 8]);
                    e.opaque(b"owner");
                    e.u32(0);
                    e.u32(0);
                    e.u32(0);
                })],
            ),
        )
        .await
        .unwrap();
    let mut d = header(&bytes, 0, 1);
    assert_eq!(d.u32().unwrap(), 42);
    assert_eq!(d.u32().unwrap(), 0);
    let client = d.u64().unwrap();
    let sequence = d.u32().unwrap();
    let bytes = s
        .rpc(
            who,
            123,
            456,
            true,
            &request(
                2,
                minor,
                &[op(43, |e| {
                    e.u64(client);
                    e.u32(sequence);
                    e.u32(0);
                    channel(e, &[0, MAX_RECORD as u32, MAX_RECORD as u32, cached, 64, 8]);
                    channel(e, &[0, 4096, 4096, 0, 2, 1]);
                    e.u32(0);
                    e.u32(0);
                })],
            ),
        )
        .await
        .unwrap();
    let mut d = header(&bytes, 0, 1);
    assert_eq!(d.u32().unwrap(), 43);
    assert_eq!(d.u32().unwrap(), 0);
    (client, d.fixed(16).unwrap().try_into().unwrap())
}
async fn setup() -> (tempfile::TempDir, Server) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("export")).unwrap();
    let s = Server::open(&dir.path().join("export"), &dir.path().join("state"))
        .await
        .unwrap();
    (dir, s)
}
fn context(client: u64, file: Id, writable: bool) -> Context<'static> {
    Context {
        principal: "peer",
        uid: 123,
        gid: 456,
        writable,
        client: Some(client),
        current: Some(file),
        saved: None,
        current_state: None,
        error_body: Encoder::default(),
    }
}
async fn operation(
    s: &mut ServerState,
    ctx: &mut Context<'_>,
    code: u32,
    arg: Arg,
) -> NResult<Encoder> {
    ctx.error_body = Encoder::default();
    s.operation(&Op { code, arg }, ctx, [0; 32]).await
}
async fn open_file(
    s: &mut ServerState,
    ctx: &mut Context<'_>,
    name: &str,
    access: u32,
    create: bool,
) -> [u8; 16] {
    let result = operation(
        s,
        ctx,
        18,
        Arg::Open {
            access,
            deny: 0,
            owner: Owner {
                client: ctx.client.unwrap(),
                owner: b"open-owner".to_vec(),
            },
            create: create.then_some((0, None, Attrs::default())),
            claim: 0,
            name: Some(name.into()),
        },
    )
    .await
    .unwrap();
    result.0[..16].try_into().unwrap()
}

#[tokio::test]
async fn wire_sessions_replay_and_limits() {
    let (_dir, s) = setup().await;
    for minor in [1, 2] {
        let who = format!("peer-{minor}");
        let (_, id) = session(&s, &who, minor, 4096).await;
        let ops = [seq(id, 1, true), op(24, |_| {}), op(10, |_| {})];
        let bytes = s
            .rpc(&who, 123, 456, true, &request(3, minor, &ops))
            .await
            .unwrap();
        header(&bytes, 0, 3);
        let replay = s
            .rpc(&who, 123, 456, true, &request(4, minor, &ops))
            .await
            .unwrap();
        assert_eq!(bytes[4..], replay[4..]);
        let wrong = s
            .rpc("different-peer", 123, 456, true, &request(5, minor, &ops))
            .await
            .unwrap();
        header(&wrong, 10082, 1);
        let altered = s
            .rpc(
                &who,
                123,
                456,
                true,
                &request(6, minor, &[seq(id, 1, true), op(24, |_| {})]),
            )
            .await
            .unwrap();
        header(&altered, 10076, 1);
        let out_of_order = s
            .rpc(
                &who,
                123,
                456,
                true,
                &request(7, minor, &[seq(id, 3, true)]),
            )
            .await
            .unwrap();
        header(&out_of_order, 10063, 1);
        let uncached = [seq(id, 2, false)];
        let bytes = s
            .rpc(&who, 123, 456, true, &request(8, minor, &uncached))
            .await
            .unwrap();
        header(&bytes, 0, 1);
        let bytes = s
            .rpc(&who, 123, 456, true, &request(9, minor, &uncached))
            .await
            .unwrap();
        header(&bytes, 10068, 1);
        let bytes = s
            .rpc(
                &who,
                123,
                456,
                true,
                &request(10, minor, &[seq(id, 3, true), op(69, |_| {})]),
            )
            .await
            .unwrap();
        header(&bytes, 10004, 2);
        let bytes = s
            .rpc(
                &who,
                123,
                456,
                true,
                &request(11, minor, &[seq(id, 4, true), op(1000, |_| {})]),
            )
            .await
            .unwrap();
        header(&bytes, 10044, 2);
    }
}

#[tokio::test]
async fn file_operations_readonly_and_write_only_close() {
    let (dir, s) = setup().await;
    let (client, _) = session(&s, "peer", 2, 4096).await;
    let mut state = s.inner.lock().await;
    let root = state.fs.root_id;
    let mut ctx = context(client, root, true);
    let sid = open_file(&mut state, &mut ctx, "hello", 3, true).await;
    let file = ctx.file().unwrap();
    let write = Arg::Write {
        state: sid,
        offset: 0,
        stable: 0,
        bytes: b"hello world".to_vec(),
    };
    operation(&mut state, &mut ctx, 38, write.clone())
        .await
        .unwrap();
    let result = operation(
        &mut state,
        &mut ctx,
        25,
        Arg::Read {
            state: sid,
            offset: 6,
            count: 64,
        },
    )
    .await
    .unwrap();
    let mut d = Decoder::new(&result.0);
    assert!(d.boolean().unwrap());
    assert_eq!(d.opaque(64).unwrap(), b"world");
    ctx.writable = false;
    assert_eq!(
        operation(&mut state, &mut ctx, 38, write)
            .await
            .unwrap_err(),
        30
    );
    ctx.writable = true;
    ctx.current = Some(root);
    ctx.saved = Some(file);
    operation(&mut state, &mut ctx, 11, Arg::Name("linked".into()))
        .await
        .unwrap();
    assert_eq!(state.fs.lookup(root, "linked").await.unwrap(), file);
    ctx.saved = Some(root);
    operation(
        &mut state,
        &mut ctx,
        29,
        Arg::Rename("hello".into(), "renamed".into()),
    )
    .await
    .unwrap();
    assert_eq!(state.fs.lookup(root, "renamed").await.unwrap(), file);
    ctx.current = Some(file);
    operation(&mut state, &mut ctx, 4, Arg::Close(sid))
        .await
        .unwrap();
    ctx.current = Some(root);
    let sid = open_file(&mut state, &mut ctx, "renamed", 2, false).await;
    operation(&mut state, &mut ctx, 4, Arg::Close(sid))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("export/linked")).unwrap(),
        b"hello world"
    );
}

#[tokio::test]
async fn persistent_handles_external_changes_and_confinement() {
    let (dir, s) = setup().await;
    std::fs::write(dir.path().join("export/host"), b"data").unwrap();
    std::os::unix::fs::symlink("/etc", dir.path().join("export/escape")).unwrap();
    let file = {
        let mut state = s.inner.lock().await;
        let root = state.fs.root_id;
        let file = state.fs.lookup(root, "host").await.unwrap();
        assert!(state.fs.lookup(root, "..").await.is_err());
        let link = state.fs.lookup(root, "escape").await.unwrap();
        assert!(state.fs.lookup(link, "passwd").await.is_err());
        assert_eq!(state.fs.readlink(link).await.unwrap(), b"/etc");
        file
    };
    std::fs::rename(
        dir.path().join("export/host"),
        dir.path().join("export/moved"),
    )
    .unwrap();
    assert_eq!(
        s.inner.lock().await.fs.read(file, 0, 100).await.unwrap().0,
        b"data"
    );
    drop(s);
    let s = Server::open(&dir.path().join("export"), &dir.path().join("state"))
        .await
        .unwrap();
    assert_eq!(
        s.inner.lock().await.fs.read(file, 0, 100).await.unwrap().0,
        b"data"
    );
    std::fs::remove_file(dir.path().join("export/moved")).unwrap();
    assert_eq!(
        s.inner
            .lock()
            .await
            .fs
            .read(file, 0, 100)
            .await
            .unwrap_err(),
        70
    );
}

#[tokio::test]
async fn locks_and_restart_reclaim() {
    let (dir, s) = setup().await;
    let (a, _) = session(&s, "peer", 2, 4096).await;
    let (b, _) = session(&s, "other-peer", 2, 4096).await;
    let file;
    {
        let mut state = s.inner.lock().await;
        let root = state.fs.root_id;
        let mut ctx = context(a, root, true);
        let sid = open_file(&mut state, &mut ctx, "locked", 3, true).await;
        file = ctx.file().unwrap();
        let lock = Arg::Lock {
            kind: 2,
            reclaim: false,
            offset: 0,
            length: 10,
            state: sid,
            owner: Some(Owner {
                client: a,
                owner: b"locker".to_vec(),
            }),
        };
        let locked = operation(&mut state, &mut ctx, 12, lock).await.unwrap();
        let mut other = context(b, file, true);
        other.principal = "other-peer";
        assert_eq!(
            operation(
                &mut state,
                &mut other,
                13,
                Arg::LockTest {
                    kind: 2,
                    offset: 0,
                    length: 5,
                    owner: Owner {
                        client: b,
                        owner: b"other".to_vec()
                    }
                }
            )
            .await
            .unwrap_err(),
            10010
        );
        let lockid = locked.0[..16].try_into().unwrap();
        operation(
            &mut state,
            &mut ctx,
            14,
            Arg::Unlock {
                kind: 2,
                state: lockid,
                offset: 0,
                length: 10,
            },
        )
        .await
        .unwrap();
    }
    drop(s);
    let s = Server::open(&dir.path().join("export"), &dir.path().join("state"))
        .await
        .unwrap();
    let (a, _) = session(&s, "peer", 2, 4096).await;
    let mut state = s.inner.lock().await;
    assert!(state.grace());
    let mut ctx = context(a, file, true);
    operation(
        &mut state,
        &mut ctx,
        18,
        Arg::Open {
            access: 3,
            deny: 0,
            owner: Owner {
                client: a,
                owner: b"open-owner".to_vec(),
            },
            create: None,
            claim: 1,
            name: None,
        },
    )
    .await
    .unwrap();
    operation(&mut state, &mut ctx, 58, Arg::Bool(false))
        .await
        .unwrap();
    assert_eq!(
        operation(&mut state, &mut ctx, 58, Arg::Bool(false))
            .await
            .unwrap_err(),
        10054
    );
}

#[tokio::test]
async fn malformed_records_never_panic_or_mutate() {
    let (_dir, s) = setup().await;
    let bytes = request(
        1,
        2,
        &[op(42, |e| {
            e.fixed(&[0; 8]);
            e.opaque(b"peer");
            e.u32(0);
            e.u32(0);
            e.u32(0);
        })],
    );
    for n in 0..bytes.len() {
        let _ = s.rpc("peer", 0, 0, false, &bytes[..n]).await;
    }
    for i in 0..bytes.len() {
        let mut data = bytes.clone();
        data[i] = 255;
        let _ = s.rpc("peer", 0, 0, false, &data).await;
    }
    assert!(s.inner.lock().await.opens.is_empty());
}

#[tokio::test]
async fn named_attributes_and_unlink_while_open() {
    let (dir, s) = setup().await;
    let (client, _) = session(&s, "peer", 2, 4096).await;
    let mut state = s.inner.lock().await;
    let root = state.fs.root_id;
    let mut ctx = context(client, root, true);
    let sid = open_file(&mut state, &mut ctx, "file", 3, true).await;
    let file = ctx.file().unwrap();
    operation(&mut state, &mut ctx, 19, Arg::Bool(true))
        .await
        .unwrap();
    let attrs = ctx.file().unwrap();
    assert_eq!(state.fs.attribute_kind(attrs), Some(8));
    let attr_sid = open_file(&mut state, &mut ctx, "com.apple.FinderInfo", 3, true).await;
    let attr = ctx.file().unwrap();
    operation(
        &mut state,
        &mut ctx,
        38,
        Arg::Write {
            state: attr_sid,
            offset: 0,
            stable: 2,
            bytes: vec![42; 32],
        },
    )
    .await
    .unwrap();
    assert_eq!(state.fs.read(attr, 0, 100).await.unwrap().0, vec![42; 32]);
    assert_eq!(
        state.fs.children(attrs).await.unwrap(),
        vec![("com.apple.FinderInfo".into(), attr)]
    );
    ctx.writable = false;
    assert_eq!(
        operation(
            &mut state,
            &mut ctx,
            38,
            Arg::Write {
                state: attr_sid,
                offset: 0,
                stable: 2,
                bytes: vec![]
            }
        )
        .await
        .unwrap_err(),
        30
    );
    ctx.writable = true;
    operation(&mut state, &mut ctx, 4, Arg::Close(attr_sid))
        .await
        .unwrap();
    ctx.current = Some(root);
    operation(&mut state, &mut ctx, 28, Arg::Name("file".into()))
        .await
        .unwrap();
    assert!(!dir.path().join("export/file").exists());
    ctx.current = Some(file);
    operation(
        &mut state,
        &mut ctx,
        38,
        Arg::Write {
            state: sid,
            offset: 0,
            stable: 2,
            bytes: b"unlinked but open".to_vec(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        state.fs.read(file, 0, 100).await.unwrap().0,
        b"unlinked but open"
    );
    operation(&mut state, &mut ctx, 4, Arg::Close(sid))
        .await
        .unwrap();
    assert_eq!(state.fs.metadata(file).await.unwrap_err(), 70);
}

#[tokio::test]
async fn live_downgrade_inside_compound_and_lease_expiry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_dir, s) = setup().await;
    let (client, id) = session(&s, "peer", 2, 4096).await;
    let policy_calls = AtomicUsize::new(0);
    let policy = || Some(policy_calls.fetch_add(1, Ordering::SeqCst) < 3);
    let bytes = s
        .rpc_authorized(
            "peer",
            123,
            456,
            &policy,
            &request(
                4,
                2,
                &[
                    seq(id, 1, true),
                    op(24, |_| {}),
                    op(6, |e| {
                        e.u32(2);
                        e.string("denied");
                        e.bitmap(&[]);
                        e.opaque(&[]);
                    }),
                ],
            ),
        )
        .await
        .unwrap();
    header(&bytes, 30, 3);
    let mut state = s.inner.lock().await;
    let root = state.fs.root_id;
    assert_eq!(state.fs.lookup(root, "denied").await.unwrap_err(), 2);
    state.clients.get_mut(&client).unwrap().last = Instant::now() - LEASE - Duration::from_secs(1);
    state.expire().await;
    assert!(!state.sessions.contains_key(&id));
}
