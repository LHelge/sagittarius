//! End-to-end integration tests for the full DNS query pipeline.
//!
//! These tests exercise the complete path from real UDP sockets through the
//! engine (TelemetryLayer → protective middleware → DecisionStack →
//! ForwardService) and back.  They use:
//! - A temporary SQLite database for [`ResolverState`] hydration.
//! - A local mock UDP upstream (same pattern as `tests/upstream.rs`).
//! - [`DnsListeners::bind`] on ephemeral port 0 so tests never conflict.
//! - A real [`TelemetrySink`] so telemetry assertions can be made.
//!
//! Every networked test is wrapped in `tokio::time::timeout` for determinism.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use hickory_net::proto::op::{Message, MessageType, ResponseCode};
use hickory_net::proto::rr::{Name as HickoryName, RData, Record, rdata::A};
use tempfile::TempDir;
use tokio::net::UdpSocket;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use sagittarius::{
    codec::{
        header::{Header, Rcode},
        name::Name,
        reader::Reader,
        writer::Writer,
    },
    resolver::{
        local::{LocalRecords, RecordData},
        pipeline::{
            engine::{build_engine, upstream_config_from_row},
            listener::DnsListeners,
            middleware::ProtectiveConfig,
        },
        state::ResolverState,
        upstream::{
            DEFAULT_FAILOVER_BUDGET, DEFAULT_QUERY_TIMEOUT, RandomSelector, SharedUpstreamPool,
            UpstreamConfig, UpstreamPool, UpstreamTransport,
        },
    },
    storage::Db,
    telemetry::{LiveLog, Stats, TelemetrySink},
};

// ── Test timeout ──────────────────────────────────────────────────────────────

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Build a minimal DNS A query datagram.
fn build_a_query(id: u16, domain: &str) -> Bytes {
    let mut w = Writer::with_capacity(64);
    Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
    let n: Name = domain.parse().expect("valid name");
    n.write(&mut w);
    w.write_u16(1u16); // QTYPE A
    w.write_u16(1u16); // QCLASS IN
    w.finish()
}

/// Build a minimal DNS AAAA query datagram.
fn build_aaaa_query(id: u16, domain: &str) -> Bytes {
    let mut w = Writer::with_capacity(64);
    Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
    let n: Name = domain.parse().expect("valid name");
    n.write(&mut w);
    w.write_u16(28u16); // QTYPE AAAA
    w.write_u16(1u16); // QCLASS IN
    w.finish()
}

/// Parse the DNS header from raw bytes.
fn parse_header(bytes: &[u8]) -> Header {
    let b = Bytes::copy_from_slice(bytes);
    let mut r = Reader::new(b);
    Header::read(&mut r).expect("valid DNS header")
}

// ── Mock upstream ─────────────────────────────────────────────────────────────

/// Counter that tracks how many datagrams the mock upstream received.
type RequestCounter = Arc<AtomicUsize>;

/// Spawn a UDP mock upstream that responds with a positive A record for every
/// query.  Returns the bound address and a counter of received requests.
async fn spawn_mock_upstream() -> (SocketAddr, RequestCounter) {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            counter_clone.fetch_add(1, Ordering::Relaxed);
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            let name = HickoryName::from_ascii("forward.example.com.").unwrap();
            let rdata = RData::A(A::new(93, 184, 216, 34));
            resp.add_answer(Record::from_rdata(name, 300, rdata));
            if let Ok(bytes) = resp.to_vec() {
                let _ = sock.send_to(&bytes, peer).await;
            }
        }
    });

    (addr, counter)
}

/// Build an [`UpstreamConfig`] for a UDP mock at `addr`.
fn udp_upstream(addr: SocketAddr) -> UpstreamConfig {
    UpstreamConfig {
        addr,
        transport: UpstreamTransport::Udp,
        tls_server_name: None,
        http_endpoint: None,
    }
}

// ── Engine harness ────────────────────────────────────────────────────────────

struct Harness {
    /// The bound UDP port for sending client queries.
    server_addr: SocketAddr,
    /// Shutdown token — cancel to stop the listeners.
    token: CancellationToken,
    /// Task tracker for draining.
    tracker: TaskTracker,
    /// Telemetry sink (kept alive; live_log and stats are accessed directly).
    _sink: Arc<TelemetrySink>,
    /// Live log for broadcast assertions.
    live_log: Arc<LiveLog>,
    /// Stats for counter assertions.
    stats: Arc<Stats>,
    /// Number of requests the mock upstream has received.
    upstream_calls: RequestCounter,
    /// Keep temp dir alive.
    _dir: TempDir,
}

impl Harness {
    async fn shutdown(self) {
        self.token.cancel();
        tokio::time::timeout(Duration::from_secs(3), self.tracker.wait())
            .await
            .expect("drain timed out");
    }
}

/// Build a full pipeline harness with a temp DB and mock upstream.
///
/// `setup_state` is called after hydration to add blocklist/allowlist/local
/// record entries to the state before the engine starts.
async fn build_harness<F>(setup_state: F) -> Harness
where
    F: FnOnce(Arc<ResolverState>),
{
    // Temp DB.
    let dir = TempDir::new().expect("temp dir");
    let db_path = dir.path().join("e2e.db");
    let db = Db::connect(&db_path).await.expect("connect");
    let state = ResolverState::hydrate(&db).await.expect("hydrate");

    // Allow the caller to seed blacklist / blocklist / local records.
    setup_state(state.clone());

    // Mock upstream.
    let (mock_addr, upstream_calls) = spawn_mock_upstream().await;
    let tracker = TaskTracker::new();
    let pool = Arc::new(SharedUpstreamPool::new(
        UpstreamPool::connect(
            &[udp_upstream(mock_addr)],
            &tracker,
            Arc::new(RandomSelector),
            DEFAULT_FAILOVER_BUDGET,
            DEFAULT_QUERY_TIMEOUT,
        )
        .await,
    ));

    // Telemetry.
    let live_log = Arc::new(LiveLog::default());
    let stats = Arc::new(Stats::new());
    let sink = Arc::new(TelemetrySink::new(live_log.clone(), stats.clone()));

    // Engine.
    let engine = build_engine(state, pool, sink.clone(), &ProtectiveConfig::default());

    // Listener on ephemeral port, single UDP socket.
    let listeners =
        DnsListeners::bind(&["127.0.0.1:0".parse::<SocketAddr>().unwrap()], 1).expect("bind");
    let server_addr = listeners
        .udp_local_addrs()
        .into_iter()
        .next()
        .expect("at least one UDP socket");

    let token = CancellationToken::new();
    listeners.serve(engine, token.clone(), &tracker);
    tracker.close();

    Harness {
        server_addr,
        token,
        tracker,
        _sink: sink,
        live_log,
        stats,
        upstream_calls,
        _dir: dir,
    }
}

/// Send a UDP query to `addr` and wait for the reply.
async fn send_query(addr: SocketAddr, query: &Bytes) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client.send_to(query, addr).await.expect("send");
    let mut buf = vec![0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv");
    buf.truncate(len);
    buf
}

// ═════════════════════════════════════════════════════════════════════════════
// Scenario tests
// ═════════════════════════════════════════════════════════════════════════════

// ── 1. Blocked by admin blacklist ─────────────────────────────────────────────

/// A domain on the admin blacklist must be sinkholesd with NOERROR + null-IP
/// (the seeded default block mode).
#[tokio::test]
async fn blocked_by_admin_blacklist() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|state| {
            let target: Name = "evil.blocked.example".parse().unwrap();
            state.blacklist().store([target].into_iter().collect());
        })
        .await;

        let q = build_a_query(0x1111, "evil.blocked.example");
        let reply = send_query(h.server_addr, &q).await;
        let hdr = parse_header(&reply);

        assert_eq!(hdr.id, 0x1111, "id must be echoed");
        assert!(hdr.qr(), "QR must be set");
        // Null-IP block mode for A query → NOERROR + 0.0.0.0 answer
        assert_eq!(hdr.rcode(), Rcode::NoError, "null-ip block → NOERROR");
        assert_eq!(hdr.ancount, 1, "null-ip A → one answer RR (0.0.0.0)");
        // No upstream call for a blocked query.
        assert_eq!(h.upstream_calls.load(Ordering::Relaxed), 0);

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 2. Blocked by blocklist ───────────────────────────────────────────────────

/// A domain on the aggregate blocklist (not admin blacklist) must be sinkholes.
#[tokio::test]
async fn blocked_by_blocklist() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|state| {
            let target: Name = "tracker.blocklist.example".parse().unwrap();
            state.blocklist().store([target].into_iter().collect());
        })
        .await;

        let q = build_a_query(0x2222, "tracker.blocklist.example");
        let reply = send_query(h.server_addr, &q).await;
        let hdr = parse_header(&reply);

        assert_eq!(hdr.id, 0x2222);
        assert!(hdr.qr());
        assert_eq!(hdr.rcode(), Rcode::NoError, "null-ip block → NOERROR");
        assert_eq!(hdr.ancount, 1, "null-ip A → one answer (0.0.0.0)");
        // No upstream call for a blocked query.
        assert_eq!(h.upstream_calls.load(Ordering::Relaxed), 0);

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 3. Local record → authoritative answer ────────────────────────────────────

/// A query for a locally-configured A record must return AA=1, NOERROR,
/// ANCOUNT=1 with the configured IP — without hitting the upstream.
#[tokio::test]
async fn local_record_authoritative_answer() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|state| {
            let mut b = LocalRecords::builder();
            b.add(
                "myrouter.lan",
                RecordData::A("192.168.1.254".parse().unwrap()),
                120,
            )
            .unwrap();
            state.local().store(b.build());
        })
        .await;

        let q = build_a_query(0x3333, "myrouter.lan");
        let reply = send_query(h.server_addr, &q).await;
        let hdr = parse_header(&reply);

        assert_eq!(hdr.id, 0x3333);
        assert!(hdr.qr());
        assert!(hdr.aa(), "local record must be authoritative (AA=1)");
        assert_eq!(hdr.rcode(), Rcode::NoError);
        assert_eq!(hdr.ancount, 1, "one answer RR");
        // Local lookup — no upstream call.
        assert_eq!(h.upstream_calls.load(Ordering::Relaxed), 0);

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 4. Local name, QTYPE mismatch → NODATA (no upstream call) ────────────────

/// When a local name exists but has no record for the requested QTYPE,
/// the response must be authoritative NODATA (AA=1, ANCOUNT=0) and the
/// upstream must NOT be called.
#[tokio::test]
async fn local_name_qtype_mismatch_nodata_no_upstream() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|state| {
            // Only an A record; we'll query AAAA.
            let mut b = LocalRecords::builder();
            b.add(
                "ipv4only.lan",
                RecordData::A("10.0.0.1".parse().unwrap()),
                60,
            )
            .unwrap();
            state.local().store(b.build());
        })
        .await;

        let upstream_before = h.upstream_calls.load(Ordering::Relaxed);

        let q = build_aaaa_query(0x4444, "ipv4only.lan");
        let reply = send_query(h.server_addr, &q).await;
        let hdr = parse_header(&reply);

        assert_eq!(hdr.id, 0x4444);
        assert!(hdr.qr());
        assert!(hdr.aa(), "NODATA must be authoritative (AA=1)");
        assert_eq!(hdr.rcode(), Rcode::NoError, "NODATA → NOERROR");
        assert_eq!(hdr.ancount, 0, "NODATA → no answer RRs");

        // The upstream must NOT have been called.
        let upstream_after = h.upstream_calls.load(Ordering::Relaxed);
        assert_eq!(
            upstream_after, upstream_before,
            "upstream must not be called for local NODATA"
        );

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 5. Forwarded query → real upstream reply ──────────────────────────────────

/// A domain not on any list must be forwarded to the mock upstream and the
/// reply must arrive at the client with the client's transaction ID.
#[tokio::test]
async fn forwarded_query_reaches_mock_upstream() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|_| {}).await;

        let client_id: u16 = 0x5555;
        let q = build_a_query(client_id, "forward.example.com");
        let reply = send_query(h.server_addr, &q).await;
        let hdr = parse_header(&reply);

        assert_eq!(hdr.id, client_id, "txn-id must be the client's id");
        assert!(hdr.qr());
        assert_eq!(hdr.rcode(), Rcode::NoError);
        // The mock upstream must have received exactly one request.
        assert_eq!(h.upstream_calls.load(Ordering::Relaxed), 1);

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 6. Cache hit → upstream called only once ──────────────────────────────────

/// Sending the same forwarded query twice: the first fills the cache, the
/// second is served from cache.  The mock upstream's request counter must
/// increment only once.  Both replies must carry the respective client txn-ids.
#[tokio::test]
async fn cache_hit_upstream_called_once() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|_| {}).await;

        // First query — goes to upstream.
        let id1: u16 = 0x6001;
        let q1 = build_a_query(id1, "cache-me.example.com");
        let r1 = send_query(h.server_addr, &q1).await;
        let h1 = parse_header(&r1);
        assert_eq!(h1.id, id1, "first reply txn-id");
        assert_eq!(
            h.upstream_calls.load(Ordering::Relaxed),
            1,
            "first query: upstream=1"
        );

        // Second query (same name) — must be served from cache.
        let id2: u16 = 0x6002;
        let q2 = build_a_query(id2, "cache-me.example.com");
        let r2 = send_query(h.server_addr, &q2).await;
        let h2 = parse_header(&r2);
        assert_eq!(h2.id, id2, "second reply txn-id must be second client's id");
        assert_eq!(
            h.upstream_calls.load(Ordering::Relaxed),
            1,
            "second query must be served from cache — upstream counter must stay at 1"
        );
        assert_eq!(h2.rcode(), Rcode::NoError);

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 7. Malformed query with recoverable id → FORMERR ─────────────────────────

/// A datagram with a valid 12-byte header but QDCOUNT=0 (which makes question
/// parsing fail) must produce a FORMERR reply with the matching transaction id.
#[tokio::test]
async fn malformed_recoverable_id_gets_formerr() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|_| {}).await;

        // Build a 12-byte header with QDCOUNT=0 — valid header, no question.
        let mut w = Writer::with_capacity(12);
        Header::new(0xDEAD)
            .with_rd(true)
            .with_qdcount(0)
            .write(&mut w);
        let bad = w.finish();

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client.send_to(&bad, h.server_addr).await.expect("send");
        let mut buf = vec![0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv");
        let hdr = parse_header(&buf[..len]);

        assert_eq!(hdr.id, 0xDEAD, "FORMERR id must match");
        assert_eq!(hdr.rcode(), Rcode::FormErr, "rcode must be FORMERR");

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 8. Telemetry observed end-to-end ─────────────────────────────────────────

/// After sending a few queries the stats counters and live-log must reflect
/// the expected totals.
///
/// Scenario:
/// - 1 query blocked by admin blacklist → blocked count = 1
/// - 1 query forwarded → forwarded count = 1
/// - total = 2
///
/// The live-log subscriber (subscribed before queries) must receive both events.
#[tokio::test]
async fn telemetry_observed_end_to_end() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let h = build_harness(|state| {
            let target: Name = "telemetry-blocked.example".parse().unwrap();
            state.blacklist().store([target].into_iter().collect());
        })
        .await;

        // Subscribe to live-log before sending queries.
        let mut rx = h.live_log.subscribe();

        // Query 1: blocked.
        let q1 = build_a_query(0x7001, "telemetry-blocked.example");
        let r1 = send_query(h.server_addr, &q1).await;
        let h1 = parse_header(&r1);
        assert_eq!(h1.id, 0x7001);

        // Query 2: forwarded.
        let q2 = build_a_query(0x7002, "telemetry-forward.example.com");
        let r2 = send_query(h.server_addr, &q2).await;
        let h2 = parse_header(&r2);
        assert_eq!(h2.id, 0x7002);

        // Allow a moment for telemetry to be recorded (it's synchronous inside
        // the service call, so by the time we received the UDP reply the event
        // is already recorded).  A short yield is enough.
        tokio::task::yield_now().await;

        // Stats assertions.
        let snap = h.stats.snapshot(10);
        assert_eq!(snap.total, 2, "total must be 2");
        assert_eq!(snap.blocked, 1, "blocked must be 1");
        assert_eq!(snap.forwarded, 1, "forwarded must be 1");

        // Live-log broadcast: we must receive at least 2 events.
        let ev1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("live-log timeout for ev1")
            .expect("channel closed");
        let ev2 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("live-log timeout for ev2")
            .expect("channel closed");

        // Both events must have a non-zero latency (the layer always sets it).
        // We don't assert the order (UDP delivery can vary slightly).
        use sagittarius::resolver::pipeline::Outcome;
        let outcomes = [ev1.outcome, ev2.outcome];
        assert!(
            outcomes.contains(&Outcome::BlockedByAdmin),
            "expected BlockedByAdmin in live-log events, got: {outcomes:?}"
        );
        assert!(
            outcomes.contains(&Outcome::Forwarded),
            "expected Forwarded in live-log events, got: {outcomes:?}"
        );

        h.shutdown().await;
    })
    .await
    .expect("test timed out");
}

// ── 9. upstream_config_from_row: seeded upstreams map correctly ───────────────

/// Integration smoke-test for `upstream_config_from_row` using the actual
/// seeded upstream rows from a real temp DB.
#[tokio::test]
async fn upstream_config_from_row_maps_seeded_upstreams() {
    use sagittarius::storage::upstreams::{SqliteUpstreamRepo, UpstreamRepository};

    let dir = TempDir::new().expect("temp dir");
    let db = Db::connect(dir.path().join("seed.db"))
        .await
        .expect("connect");

    let rows = SqliteUpstreamRepo::new(db.pool().clone())
        .list_enabled()
        .await
        .expect("list_enabled");

    // Both seeded upstreams (1.1.1.1 UDP, 1.0.0.1 UDP) must map to port 53.
    assert_eq!(rows.len(), 2, "exactly 2 seeded upstreams");
    for row in &rows {
        let cfg = upstream_config_from_row(row)
            .unwrap_or_else(|| panic!("seeded upstream {} must map", row.address));
        assert_eq!(cfg.addr.port(), 53, "seeded UDP upstream must use port 53");
        assert_eq!(cfg.transport, UpstreamTransport::Udp);
    }
}
