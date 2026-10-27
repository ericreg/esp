//! Iroh integration contracts needed before adding a persistent address cache.
use super::*;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures_util::{
    StreamExt,
    future::BoxFuture,
    stream::{self, BoxStream},
};
use iroh::{
    address_lookup::{
        AddressLookup, AddressLookupBuilder, DnsAddressLookup, EndpointInfo, Error as LookupError,
        Item, PkarrPublisher, PkarrResolver,
    },
    dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData},
};

/// No system DNS or external network access: unknown names stay pending so that
/// tests can observe which Iroh clients use the injected resolver.
#[derive(Clone, Debug, Default)]
struct ControlledDns {
    queries: Arc<Mutex<Vec<(&'static str, String)>>>,
    txt: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl ControlledDns {
    fn record(&self, kind: &'static str, host: &str) {
        self.queries.lock().unwrap().push((kind, host.to_string()));
    }

    fn queried(&self, kind: &str, host: &str) -> bool {
        self.queries
            .lock()
            .unwrap()
            .iter()
            .any(|(k, h)| *k == kind && h == host)
    }
}

impl Resolver for ControlledDns {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv4Addr>, DnsError>> {
        self.record("A", &host);
        Box::pin(async move {
            if host == "relay.esp.invalid" {
                Ok(Box::new(std::iter::once(Ipv4Addr::LOCALHOST)) as BoxIter<_>)
            } else {
                std::future::pending().await
            }
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<'static, Result<BoxIter<Ipv6Addr>, DnsError>> {
        self.record("AAAA", &host);
        Box::pin(async move {
            if host == "relay.esp.invalid" {
                Ok(Box::new(std::iter::empty()) as BoxIter<_>)
            } else {
                std::future::pending().await
            }
        })
    }

    fn lookup_txt(
        &self,
        host: String,
    ) -> BoxFuture<'static, Result<BoxIter<TxtRecordData>, DnsError>> {
        self.record("TXT", &host);
        let records = self.txt.lock().unwrap().get(&host).cloned();
        Box::pin(async move {
            match records {
                Some(records) => Ok(Box::new(
                    records
                        .into_iter()
                        .map(|s| TxtRecordData::from(vec![s.into_bytes().into_boxed_slice()])),
                ) as BoxIter<_>),
                None => std::future::pending().await,
            }
        })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
struct DelayedLookup {
    addr: EndpointAddr,
    started: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
}

impl DelayedLookup {
    fn new(addr: EndpointAddr) -> Self {
        Self {
            addr,
            started: Arc::new(AtomicUsize::new(0)),
            completed: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AddressLookup for DelayedLookup {
    fn resolve(&self, id: EndpointId) -> Option<BoxStream<'static, Result<Item, LookupError>>> {
        assert_eq!(id, self.addr.id);
        self.started.fetch_add(1, Ordering::SeqCst);
        let addr = self.addr.clone();
        let completed = self.completed.clone();
        Some(
            stream::once(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(Item::new(addr.into(), "controlled_fresh_lookup", None))
            })
            .boxed(),
        )
    }
}

/// Verify endpoint identity, ESP authorization, and application bytes through the
/// real remote proxy handler. Both endpoints have IP transport disabled.
async fn assert_relay_proxy(fixture: &ProxyFixture, addr: EndpointAddr) {
    timeout(Duration::from_secs(10), async {
        let conn = fixture.local.connect(addr, TCP_ALPN).await.unwrap();
        assert_eq!(conn.remote_id(), fixture.remote.id());
        let _close = CloseConnectionOnDrop(conn.clone());
        let (_, request) = fixture
            .actor
            .prepare_proxy("remote-host".into(), fixture.port)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        write_proxy_request(&mut send, &request).await.unwrap();
        let response: LocalProxyResponse = read_cbor_frame(
            &mut recv,
            MAX_PROXY_REQUEST_LEN,
            "discovery test proxy response",
        )
        .await
        .unwrap();
        assert!(matches!(response, LocalProxyResponse::Ready));
        let (mut tcp, _) = fixture.tcp.accept().await.unwrap();
        let payload = b"SSH data over a discovered relay";
        send.write_all(payload).await.unwrap();
        let mut request = vec![0; payload.len()];
        tcp.read_exact(&mut request).await.unwrap();
        assert_eq!(request, payload);
        tcp.write_all(&request).await.unwrap();
        let mut response = vec![0; payload.len()];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(response, payload);
    })
    .await
    .expect("discovery and ESP setup exceeded the proxy setup budget");
}

#[tokio::test]
async fn explicit_relay_connects_without_any_lookup_service() {
    let fixture = ProxyFixture::new(8).await;
    fixture.local.address_lookup().unwrap().clear();
    fixture.remote.address_lookup().unwrap().clear();
    assert_relay_proxy(
        &fixture,
        EndpointAddr::new(fixture.remote.id()).with_relay_url(fixture.relay.http_url().unwrap()),
    )
    .await;
    fixture.close().await;
}

#[tokio::test]
async fn fresh_lookup_recovers_from_stale_explicit_relay() {
    let fixture = ProxyFixture::new(8).await;
    // A bound listener that never accepts gives a deterministic stalled relay,
    // without depending on a closed port being unused or public routing.
    let stalled = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let stale = EndpointAddr::new(fixture.remote.id()).with_relay_url(
        format!("http://{}", stalled.local_addr().unwrap())
            .parse()
            .unwrap(),
    );
    let fresh = DelayedLookup::new(
        EndpointAddr::new(fixture.remote.id()).with_relay_url(fixture.relay.http_url().unwrap()),
    );
    fixture.local.address_lookup().unwrap().clear();
    fixture.local.address_lookup().unwrap().add(fresh.clone());
    assert_relay_proxy(&fixture, stale).await;
    assert_eq!(fresh.started.load(Ordering::SeqCst), 1);
    assert_eq!(fresh.completed.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test]
async fn stale_memory_result_does_not_hide_slower_fresh_lookup() {
    let fixture = ProxyFixture::new(8).await;
    let stalled = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let memory = MemoryLookup::new();
    memory.add_endpoint_info(
        EndpointAddr::new(fixture.remote.id()).with_relay_url(
            format!("http://{}", stalled.local_addr().unwrap())
                .parse()
                .unwrap(),
        ),
    );
    let fresh = DelayedLookup::new(
        EndpointAddr::new(fixture.remote.id()).with_relay_url(fixture.relay.http_url().unwrap()),
    );
    fixture.local.address_lookup().unwrap().clear();
    fixture.local.address_lookup().unwrap().add(memory);
    fixture.local.address_lookup().unwrap().add(fresh.clone());
    assert_relay_proxy(&fixture, EndpointAddr::new(fixture.remote.id())).await;
    assert_eq!(fresh.started.load(Ordering::SeqCst), 1);
    assert_eq!(fresh.completed.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test]
async fn injected_dns_covers_txt_pkarr_publishing_lookup_and_relay_hosts() {
    let dns = ControlledDns::default();
    let fixture =
        ProxyFixture::with_resolver(8, None, Some(DnsResolver::custom(dns.clone()))).await;
    let peer = EndpointInfo::from(fixture.remote.addr());
    let txt_name = format!(
        "_iroh.{}.discovery.esp.invalid.",
        fixture.remote.id().to_z32()
    );
    dns.txt
        .lock()
        .unwrap()
        .insert(txt_name.clone(), peer.to_txt_strings());

    fixture.local.address_lookup().unwrap().clear();
    // These builders inherit the endpoint resolver, just like the N0 preset.
    // Separate HTTPS hosts distinguish publication from lookup. They stop in
    // DNS; successful TLS/DoH transactions belong to the DNS fallback phase.
    fixture.local.address_lookup().unwrap().add(
        PkarrPublisher::builder("https://publish.esp.invalid/pkarr".parse().unwrap())
            .into_address_lookup(&fixture.local)
            .unwrap(),
    );
    fixture.local.address_lookup().unwrap().add(
        PkarrResolver::builder("https://lookup.esp.invalid/pkarr".parse().unwrap())
            .into_address_lookup(&fixture.local)
            .unwrap(),
    );
    fixture.local.address_lookup().unwrap().add(
        DnsAddressLookup::builder("discovery.esp.invalid.".to_string())
            .into_address_lookup(&fixture.local)
            .unwrap(),
    );

    assert_relay_proxy(&fixture, EndpointAddr::new(fixture.remote.id())).await;
    timeout(Duration::from_secs(5), async {
        loop {
            if dns.queried("TXT", &txt_name)
                && dns.queried("A", "relay.esp.invalid")
                && dns.queried("A", "publish.esp.invalid")
                && dns.queried("AAAA", "publish.esp.invalid")
                && dns.queried("A", "lookup.esp.invalid")
                && dns.queried("AAAA", "lookup.esp.invalid")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "missing DNS injection coverage: {:?}",
            dns.queries.lock().unwrap()
        )
    });
    fixture.close().await;
}

#[test]
fn memory_lookup_updates_merge_addresses_so_cache_replacement_must_remove_first() {
    let memory = MemoryLookup::new();
    let id = SecretKey::generate().public();
    let stale = EndpointAddr::new(id).with_relay_url("https://old.esp.invalid".parse().unwrap());
    let fresh = EndpointAddr::new(id).with_relay_url("https://new.esp.invalid".parse().unwrap());
    memory.add_endpoint_info(stale);
    memory.add_endpoint_info(fresh.clone());
    assert_eq!(
        memory.get_endpoint_info(id).unwrap().relay_urls().count(),
        2
    );
    memory.remove_endpoint_info(id);
    memory.add_endpoint_info(fresh.clone());
    assert_eq!(
        memory.get_endpoint_info(id).unwrap().into_endpoint_addr(),
        fresh
    );
}

#[derive(Debug, Clone, Default)]
struct PendingLookup(Arc<tokio::sync::Notify>);

impl AddressLookup for PendingLookup {
    fn resolve(&self, _: EndpointId) -> Option<BoxStream<'static, Result<Item, LookupError>>> {
        self.0.notify_one();
        Some(stream::pending().boxed())
    }
}

#[tokio::test(start_paused = true)]
async fn proxy_setup_deadline_bounds_a_lookup_that_never_finishes() {
    // Keep Tokio from auto-advancing past the deadline while Unix socket I/O
    // becomes ready. Only the explicit advances below should move this clock.
    let clock_guard = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let key = SecretKey::generate();
    let mut cfg = create_creator_config(
        "Deadline test",
        &key,
        Uuid::new_v4().to_string(),
        "local".into(),
        "ABC123".into(),
        DEFAULT_MAX_KNOWN_PEERS,
    )
    .unwrap();
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "remote-host".into(),
        connection_id: "DEF456".into(),
    };
    cfg.memberships.push(
        MembershipCertificate::issue(&cfg, &key, &peer, &[22], MembershipRole::Peer).unwrap(),
    );
    cfg.peers.push(peer);
    let actor = spawn_config_actor(
        std::env::temp_dir().join(format!("esp-unused-{}", Uuid::new_v4())),
        cfg,
    );
    let lookup = PendingLookup::default();
    let endpoint = discovery::endpoint_builder(key)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .address_lookup(lookup.clone())
        .bind()
        .await
        .unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(handle_local_proxy_connection(
        server,
        actor.clone(),
        endpoint.clone(),
        "remote-host".into(),
        22,
    ));
    lookup.0.notified().await;
    tokio::time::advance(LOCAL_CONTROL_SETUP_TIMEOUT - Duration::from_millis(1)).await;
    assert!(!task.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    let response: LocalProxyResponse = read_cbor_frame(
        &mut client,
        MAX_LOCAL_CONTROL_MESSAGE_LEN,
        "deadline test response",
    )
    .await
    .unwrap();
    let LocalProxyResponse::Error(message) = response else {
        panic!("unexpected success")
    };
    assert!(message.contains("timed out opening esp proxy"), "{message}");
    assert_eq!(
        tokio::time::Instant::now() - started,
        LOCAL_CONTROL_SETUP_TIMEOUT
    );
    assert!(task.await.unwrap().is_err());
    actor.status().await.unwrap();
    clock_guard.abort();
    endpoint.close().await;
}
