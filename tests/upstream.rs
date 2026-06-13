//! End-to-end integration tests for the upstream DNS client and pool.
//!
//! Tests exercise the public crate API only — no internal access.  The key new
//! coverage over the unit tests is:
//!
//! - A **real TCP round-trip** (unit tests only construct the TCP client).
//! - Every path exercised through the public API (UpstreamClient, UpstreamPool,
//!   SharedUpstreamPool).
//! - Negative-caching surface (is_negative + negative_ttl) verified end-to-end.
//! - DoT and DoH live tests gated with `#[ignore]` (skipped by default).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_net::proto::op::{Message, MessageType, ResponseCode};
use hickory_net::proto::rr::{Name, RData, Record, rdata::A, rdata::SOA};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::task::TaskTracker;

use sagittarius::codec::message::{Qclass, Qtype, Question};
use sagittarius::codec::ttl::TtlScan;
use sagittarius::resolver::upstream::{
    DEFAULT_FAILOVER_BUDGET, DEFAULT_QUERY_TIMEOUT, Error, ForwardResult, SharedUpstreamPool,
    UpstreamClient, UpstreamConfig, UpstreamHealth, UpstreamObservation, UpstreamPool,
    UpstreamSelector, UpstreamTransport,
};

// ── Mock harness ──────────────────────────────────────────────────────────────

/// Spawn a UDP mock upstream on an ephemeral port.
///
/// For each datagram received the request is parsed, handed to `handler`,
/// and — if it returns `Some(response)` — the response is serialised and sent
/// back to the peer.  `None` ⇒ send nothing (simulates a silent/dead upstream).
///
/// Returns the bound `SocketAddr`.
async fn spawn_udp<F>(mut handler: F) -> SocketAddr
where
    F: FnMut(Message) -> Option<Message> + Send + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            if let Some(resp) = handler(req)
                && let Ok(resp_bytes) = resp.to_vec()
            {
                let _ = sock.send_to(&resp_bytes, peer).await;
            }
            // None → send nothing (timeout path)
        }
    });

    addr
}

/// Spawn a TCP mock upstream on an ephemeral port.
///
/// Accepts connections in a loop, spawning a task per connection.
/// **DNS-over-TCP framing**: each message is prefixed with a 2-byte big-endian
/// length.  Per message: read 2 length bytes → read that many payload bytes →
/// parse with hickory → call `handler` → if `Some(resp)`, write 2-byte length
/// prefix + response bytes; loop until the peer closes.
///
/// `None` ⇒ write nothing for that message (exercises timeout).
///
/// Returns the bound `SocketAddr`.
async fn spawn_tcp<F>(handler: F) -> SocketAddr
where
    F: Fn(Message) -> Option<Message> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                loop {
                    // Read 2-byte length prefix.
                    let mut len_buf = [0u8; 2];
                    match stream.read_exact(&mut len_buf).await {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(_) => break,
                    }
                    let msg_len = u16::from_be_bytes(len_buf) as usize;

                    // Read the message payload.
                    let mut payload = vec![0u8; msg_len];
                    match stream.read_exact(&mut payload).await {
                        Ok(_) => {}
                        Err(_) => break,
                    }

                    let Ok(req) = Message::from_vec(&payload) else {
                        break;
                    };

                    if let Some(resp) = handler(req)
                        && let Ok(resp_bytes) = resp.to_vec()
                    {
                        let resp_len = resp_bytes.len() as u16;
                        // Write 2-byte length prefix followed by payload.
                        if stream.write_all(&resp_len.to_be_bytes()).await.is_err() {
                            break;
                        }
                        if stream.write_all(&resp_bytes).await.is_err() {
                            break;
                        }
                    }
                    // None → write nothing for this message (timeout path)
                }
            });
        }
    });

    addr
}

// ── Response-builder helpers ──────────────────────────────────────────────────

/// Build a NOERROR response with one A record (TTL 300) from the given request.
///
/// Copies the request's ID and question section so hickory correctly matches
/// the response to the outstanding request by ID + question.
fn positive_a(req: Message) -> Option<Message> {
    let mut resp = req.clone();
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NoError;
    let name = Name::from_ascii("example.com.").unwrap();
    let rdata = RData::A(A::new(93, 184, 216, 34));
    resp.add_answer(Record::from_rdata(name, 300, rdata));
    Some(resp)
}

/// Build an NXDOMAIN response with an SOA in authority (TTL=120, minimum=60).
///
/// RFC 2308 negative_ttl = min(120, 60) = 60.
fn nxdomain_soa(req: Message) -> Option<Message> {
    let mut resp = req.clone();
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NXDomain;
    let zone = Name::from_ascii("example.com.").unwrap();
    let mname = Name::from_ascii("ns1.example.com.").unwrap();
    let rname = Name::from_ascii("hostmaster.example.com.").unwrap();
    let soa = SOA::new(mname, rname, 1, 3600, 900, 604800, 60);
    resp.add_authority(Record::from_rdata(zone, 120, RData::SOA(soa)));
    Some(resp)
}

/// Return `None` for every request — simulates a silent/dead upstream.
fn silent(_req: Message) -> Option<Message> {
    None
}

// ── Deterministic test selector ───────────────────────────────────────────────

/// Selector that always returns indices in order `0, 1, 2, …`
///
/// Used in pool tests to ensure deterministic failover: index 0 is tried first.
#[derive(Debug)]
struct InOrder;

impl UpstreamSelector for InOrder {
    fn order(&self, upstreams: &[UpstreamObservation]) -> Vec<usize> {
        (0..upstreams.len()).collect()
    }
}

// ── Shared question ───────────────────────────────────────────────────────────

/// Build the standard `example.com A IN` question used in every test.
fn example_com_a() -> Question {
    Question {
        name: "example.com".parse().unwrap(),
        qtype: Qtype::A,
        qclass: Qclass::In,
    }
}

// ── Helper: build a UDP UpstreamConfig pointing at addr ──────────────────────

fn udp_config(addr: SocketAddr) -> UpstreamConfig {
    UpstreamConfig {
        addr,
        transport: UpstreamTransport::Udp,
        tls_server_name: None,
        http_endpoint: None,
    }
}

// ── Helper: assert bytes re-parse via project codec ──────────────────────────

/// Assert that `result.bytes`:
/// - scan with `TtlScan` succeeds and `min_ttl == expected_ttl`
/// - parse with `CodecQuery::try_from` succeeds and the first question name
///   matches `expected_name` (FQDN with trailing dot)
fn assert_bytes_reparse(result: &ForwardResult, expected_ttl: Option<u32>, expected_name: &str) {
    let scan =
        TtlScan::scan(&result.bytes).expect("TtlScan must succeed on upstream response bytes");
    assert_eq!(
        scan.min_ttl, expected_ttl,
        "TtlScan min_ttl mismatch: expected {expected_ttl:?}, got {:?}",
        scan.min_ttl
    );

    let query = sagittarius::codec::message::Query::try_from(result.bytes.clone())
        .expect("Query::try_from must succeed on upstream response bytes");
    assert_eq!(
        query.question().name.to_string(),
        expected_name,
        "codec question name mismatch"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Scenario tests
// ═════════════════════════════════════════════════════════════════════════════

// ── 1. UDP success ────────────────────────────────────────────────────────────

/// Connect a UDP `UpstreamClient` to a `positive_a` mock and forward a question.
///
/// Asserts:
/// - `!is_negative`
/// - `negative_ttl == None`
/// - raw bytes re-parse: `TtlScan` min_ttl=300, `CodecQuery` name matches
#[tokio::test]
async fn udp_success_positive_a() {
    let addr = spawn_udp(positive_a).await;
    let cfg = UpstreamConfig {
        addr,
        transport: UpstreamTransport::Udp,
        tls_server_name: None,
        http_endpoint: None,
    };

    let (client, bg) = UpstreamClient::connect(&cfg)
        .await
        .expect("UDP connect failed");
    tokio::spawn(bg);

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.forward(&q, DEFAULT_QUERY_TIMEOUT),
    )
    .await
    .expect("safety timeout")
    .expect("forward must succeed");

    assert!(
        !result.is_negative,
        "positive A answer must not be negative"
    );
    assert_eq!(
        result.negative_ttl, None,
        "positive answer has no SOA → no negative_ttl"
    );

    assert_bytes_reparse(&result, Some(300), "example.com.");
}

// ── 2. TCP success — the important new coverage ────────────────────────────────

/// Connect a TCP `UpstreamClient` to a `positive_a` TCP mock and forward.
///
/// This is the **first real TCP round-trip** test in the project — the unit
/// tests only verify that a TCP client can be constructed.  This test proves
/// the TCP transport actually carries a query and a response end-to-end with
/// correct 2-byte DNS-over-TCP length framing.
///
/// Asserts:
/// - The round-trip completes without error.
/// - `!is_negative`
/// - raw bytes re-parse: `TtlScan` min_ttl=300, `CodecQuery` name matches
#[tokio::test]
async fn tcp_success_positive_a() {
    let addr = spawn_tcp(positive_a).await;
    let cfg = UpstreamConfig {
        addr,
        transport: UpstreamTransport::Tcp,
        tls_server_name: None,
        http_endpoint: None,
    };

    let (client, bg) = UpstreamClient::connect(&cfg)
        .await
        .expect("TCP connect failed");
    tokio::spawn(bg);

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.forward(&q, DEFAULT_QUERY_TIMEOUT),
    )
    .await
    .expect("safety timeout")
    .expect("TCP forward must succeed");

    assert!(
        !result.is_negative,
        "positive A answer must not be negative"
    );
    assert_eq!(
        result.negative_ttl, None,
        "positive answer has no negative_ttl"
    );

    assert_bytes_reparse(&result, Some(300), "example.com.");
}

// ── 3. Timeout → failover via UpstreamPool ────────────────────────────────────

/// Pool over [silent_udp, positive_udp] with InOrder selector and budget=1.
///
/// The first upstream (index 0) is silent and will time out; the pool then
/// fails over to index 1 which returns a positive A answer.
///
/// Asserts: `pool.forward()` returns `Ok` with a positive answer.
#[tokio::test]
async fn pool_timeout_failover_to_second_upstream() {
    let silent_addr = spawn_udp(silent).await;
    let answer_addr = spawn_udp(positive_a).await;

    let configs = vec![udp_config(silent_addr), udp_config(answer_addr)];
    let tracker = TaskTracker::new();
    let pool = UpstreamPool::connect(
        &configs,
        &tracker,
        Arc::new(InOrder),
        DEFAULT_FAILOVER_BUDGET, // budget=1 → max_attempts=2
        Duration::from_millis(150),
    )
    .await;

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(5), // outer safety net
        pool.forward(&q, &UpstreamHealth::new()),
    )
    .await
    .expect("safety timeout: failover took too long")
    .expect("pool.forward must succeed after failover");

    assert!(
        !result.is_negative,
        "failover result must be a positive answer"
    );
}

// ── 4. All-fail ───────────────────────────────────────────────────────────────

/// Pool over two silent UDP upstreams with budget=1.
///
/// Both upstreams time out → AllUpstreamsFailed { attempts: 2 }.
#[tokio::test]
async fn pool_all_fail_returns_all_upstreams_failed() {
    let s0 = spawn_udp(silent).await;
    let s1 = spawn_udp(silent).await;

    let configs = vec![udp_config(s0), udp_config(s1)];
    let tracker = TaskTracker::new();
    let pool = UpstreamPool::connect(
        &configs,
        &tracker,
        Arc::new(InOrder),
        1, // budget=1 → max_attempts=2
        Duration::from_millis(150),
    )
    .await;

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        pool.forward(&q, &UpstreamHealth::new()),
    )
    .await
    .expect("safety timeout");

    assert!(
        matches!(result, Err(Error::AllUpstreamsFailed { attempts: 2 })),
        "expected AllUpstreamsFailed {{ attempts: 2 }}, got: {result:?}"
    );
}

// ── 5. Negative-caching surface ───────────────────────────────────────────────

/// UDP client against `nxdomain_soa` mock.
///
/// Asserts:
/// - `is_negative == true`
/// - `negative_ttl == Some(_)` (SOA-derived TTL, min(120, 60) = 60)
///
/// Confirms the cache-store seam (E6) receives the information it needs to
/// cache negative responses correctly.
#[tokio::test]
async fn udp_nxdomain_soa_negative_caching_surface() {
    let addr = spawn_udp(nxdomain_soa).await;
    let cfg = UpstreamConfig {
        addr,
        transport: UpstreamTransport::Udp,
        tls_server_name: None,
        http_endpoint: None,
    };

    let (client, bg) = UpstreamClient::connect(&cfg).await.expect("UDP connect");
    tokio::spawn(bg);

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.forward(&q, DEFAULT_QUERY_TIMEOUT),
    )
    .await
    .expect("safety timeout")
    .expect("forward must succeed");

    assert!(
        result.is_negative,
        "NXDOMAIN must be classified as negative"
    );
    assert!(
        result.negative_ttl.is_some(),
        "SOA in authority must yield a negative_ttl; got None"
    );
    // RFC 2308: min(soa_ttl=120, soa_minimum=60) = 60
    assert_eq!(
        result.negative_ttl,
        Some(60),
        "negative_ttl must be min(120, 60) = 60"
    );
}

// ── 6. SharedUpstreamPool forward ─────────────────────────────────────────────

/// Wrap a pool in a SharedUpstreamPool and forward via the shared handle.
///
/// Verifies the SharedUpstreamPool::forward public API works end-to-end.
#[tokio::test]
async fn shared_pool_forward_succeeds() {
    let addr = spawn_udp(positive_a).await;
    let tracker = TaskTracker::new();
    let pool = UpstreamPool::connect_with_defaults(&[udp_config(addr)], &tracker).await;
    let shared = SharedUpstreamPool::new(pool);

    let q = example_com_a();
    let result = tokio::time::timeout(Duration::from_secs(5), shared.forward(&q))
        .await
        .expect("safety timeout")
        .expect("shared pool forward must succeed");

    assert!(
        !result.is_negative,
        "shared pool must return positive answer"
    );
}

// ── 7. RandomSelector (production selector) ───────────────────────────────────

/// Pool built with `connect_with_defaults` (uses RandomSelector) and a single
/// upstream — verifies the default selector path reaches the upstream correctly.
#[tokio::test]
async fn pool_connect_with_defaults_random_selector() {
    let addr = spawn_udp(positive_a).await;
    let tracker = TaskTracker::new();
    let pool = UpstreamPool::connect_with_defaults(&[udp_config(addr)], &tracker).await;

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        pool.forward(&q, &UpstreamHealth::new()),
    )
    .await
    .expect("safety timeout")
    .expect("forward must succeed with RandomSelector");

    assert!(!result.is_negative);
}

// ═════════════════════════════════════════════════════════════════════════════
// Live network tests (ignored by default)
// ═════════════════════════════════════════════════════════════════════════════

/// Connect a DoT client to Cloudflare (1.1.1.1:853), forward an A query for
/// example.com, and assert the response is Ok and not negative.
#[ignore = "requires network access to 1.1.1.1:853"]
#[tokio::test]
async fn dot_live_forward_example_com() {
    let cfg = UpstreamConfig {
        addr: "1.1.1.1:853".parse().unwrap(),
        transport: UpstreamTransport::Dot,
        tls_server_name: Some("cloudflare-dns.com".to_owned()),
        http_endpoint: None,
    };

    let (client, bg) = UpstreamClient::connect(&cfg)
        .await
        .expect("DoT connect failed");
    tokio::spawn(bg);

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.forward(&q, Duration::from_secs(5)),
    )
    .await
    .expect("safety timeout")
    .expect("DoT forward must succeed");

    assert!(
        !result.is_negative,
        "example.com A must be a positive answer"
    );
}

/// Connect a DoH client to Cloudflare (1.1.1.1:443), forward an A query for
/// example.com, and assert the response is Ok and not negative.
#[ignore = "requires network access to 1.1.1.1:443"]
#[tokio::test]
async fn doh_live_forward_example_com() {
    let cfg = UpstreamConfig {
        addr: "1.1.1.1:443".parse().unwrap(),
        transport: UpstreamTransport::Doh,
        tls_server_name: Some("cloudflare-dns.com".to_owned()),
        http_endpoint: Some("/dns-query".to_owned()),
    };

    let (client, bg) = UpstreamClient::connect(&cfg)
        .await
        .expect("DoH connect failed");
    tokio::spawn(bg);

    let q = example_com_a();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.forward(&q, Duration::from_secs(5)),
    )
    .await
    .expect("safety timeout")
    .expect("DoH forward must succeed");

    assert!(
        !result.is_negative,
        "example.com A must be a positive answer"
    );
}
