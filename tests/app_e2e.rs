//! Full-stack end-to-end scenario suite (E9.2).
//!
//! These tests prove the whole product works by driving the **assembled
//! [`App`]** — the exact subsystem composition that `main` runs — over its real
//! DNS and admin surfaces. The runtime is launched in-process on ephemeral
//! ports via [`App::run_until_ready`], which surfaces the OS-chosen ports so the
//! harness can reach both surfaces. Running in-process (rather than spawning the
//! compiled binary) keeps the suite deterministic and network-free in CI while
//! exercising identical wiring.
//!
//! Each scenario is configured through the **admin HTTP API** (first-run wizard
//! → login → CSRF-protected mutations), so the real write-through + atomic-swap
//! paths into the live [`ResolverState`] / upstream pool are what take effect on
//! the next DNS query. The single non-HTTP setup step is pointing the resolver
//! at a local mock UDP upstream, seeded into the temp database before launch so
//! forwarding is deterministic and offline.
//!
//! Scenarios (epic E9.2):
//! 1. Blocked domain → configured sinkhole answer (null-IP).
//! 2. Allowlisted domain bypasses the blocklist and resolves.
//! 3. Local / wildcard record resolves authoritatively.
//! 4. Local qtype mismatch → authoritative NODATA without hitting upstream.
//! 5. Repeat query served from cache.
//! 6. Cache-miss forwarded and resolved via the mock upstream.
//! 7. One-click whitelist from the live log takes effect on the next query.

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
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle, time::timeout};

use sagittarius::{
    app::{App, RuntimeAddrs},
    codec::{
        header::{Header, Rcode},
        name::Name,
        reader::Reader,
        writer::Writer,
    },
    config::{Config, SessionCookieSecurePolicy},
    error::Result,
    storage::{
        Db,
        upstreams::{NewUpstream, SqliteUpstreamRepo, Transport, UpstreamRepository},
    },
};

// ── Constants ───────────────────────────────────────────────────────────────

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// The A address the mock upstream returns for every forwarded query.
const FORWARDED_IP: [u8; 4] = [198, 51, 100, 7];
/// The null-IP a blocked A query is sinkholed to (seeded default block mode).
const NULL_IP: [u8; 4] = [0, 0, 0, 0];

// ── Mock upstream ─────────────────────────────────────────────────────────────

/// Spawn a UDP mock upstream that answers every query with one A record
/// ([`FORWARDED_IP`]) carrying the queried name. Returns its address and a
/// counter of received requests (used to prove cache hits and block/local
/// short-circuits never reach upstream).
async fn spawn_mock_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

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
            let name = req
                .queries
                .first()
                .map(|q| q.name().clone())
                .unwrap_or_else(|| HickoryName::from_ascii("example.com.").unwrap());
            resp.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(A::new(
                    FORWARDED_IP[0],
                    FORWARDED_IP[1],
                    FORWARDED_IP[2],
                    FORWARDED_IP[3],
                )),
            ));
            if let Ok(bytes) = resp.to_vec() {
                let _ = sock.send_to(&bytes, peer).await;
            }
        }
    });

    (addr, counter)
}

// ── DNS wire helpers ──────────────────────────────────────────────────────────

/// Build a minimal DNS query datagram for `domain` / `qtype`.
fn build_query(id: u16, domain: &str, qtype: u16) -> Bytes {
    let mut w = Writer::with_capacity(64);
    Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
    let n: Name = domain.parse().expect("valid name");
    n.write(&mut w);
    w.write_u16(qtype);
    w.write_u16(1u16); // QCLASS IN
    w.finish()
}

/// Parse the DNS header from a raw response.
fn parse_header(bytes: &[u8]) -> Header {
    let mut r = Reader::new(Bytes::copy_from_slice(bytes));
    Header::read(&mut r).expect("valid DNS header")
}

/// Advance past a DNS name starting at `pos`, returning the offset just after
/// it. Handles a compression pointer (2 bytes) or a sequence of length-prefixed
/// labels terminated by a zero octet.
fn skip_name(buf: &[u8], mut pos: usize) -> usize {
    loop {
        let len = buf[pos];
        if len & 0xC0 == 0xC0 {
            return pos + 2; // compression pointer
        }
        if len == 0 {
            return pos + 1; // root label
        }
        pos += 1 + len as usize;
    }
}

/// Extract the A-record address from the first answer RR, if it is an A record.
///
/// Walks header → question → first RR by the fixed RFC 1035 layout
/// (`name`, type(2), class(2), ttl(4), rdlength(2), rdata).
fn first_a_answer(resp: &[u8]) -> Option<[u8; 4]> {
    let mut pos = 12; // skip header
    pos = skip_name(resp, pos); // question QNAME
    pos += 4; // QTYPE + QCLASS
    pos = skip_name(resp, pos); // RR owner name (usually a pointer)
    let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    let rdata = pos + 10;
    if rtype == QTYPE_A && rdlen == 4 {
        Some([
            resp[rdata],
            resp[rdata + 1],
            resp[rdata + 2],
            resp[rdata + 3],
        ])
    } else {
        None
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// A launched [`App`] plus an authenticated admin client and a mock upstream.
struct Harness {
    addrs: RuntimeAddrs,
    base: String,
    client: reqwest::Client,
    cookie: String,
    csrf: String,
    upstream_calls: Arc<AtomicUsize>,
    stop_tx: Option<oneshot::Sender<()>>,
    handle: JoinHandle<Result<()>>,
    _dir: TempDir,
}

impl Harness {
    /// Launch the full stack against a temp DB whose only enabled upstream is a
    /// fresh mock, complete the first-run wizard, log in, and capture the
    /// session cookie + CSRF token for subsequent mutations.
    async fn start() -> Self {
        let (mock_addr, upstream_calls) = spawn_mock_upstream().await;

        // Temp DB: replace the seeded default upstreams with the mock so
        // forwarding is deterministic and offline.
        let dir = TempDir::new().expect("temp dir");
        let db_path = dir.path().join("e2e.db");
        let db = Db::connect(&db_path).await.expect("connect");
        let repo = SqliteUpstreamRepo::new(db.pool().clone());
        for u in repo.list().await.expect("list upstreams") {
            repo.delete(u.id).await.expect("delete default upstream");
        }
        repo.insert(NewUpstream {
            address: mock_addr.to_string(),
            transport: Transport::Udp,
            tls_server_name: None,
            enabled: true,
            sort_order: 0,
        })
        .await
        .expect("insert mock upstream");
        drop(db);

        let config = Config {
            dns_addrs: vec!["127.0.0.1:0".parse().unwrap()],
            admin_addr: "127.0.0.1:0".parse().unwrap(),
            db_path,
            session_cookie_secure: SessionCookieSecurePolicy::Never,
        };

        let app = App::new(config).with_drain_timeout(Duration::from_secs(2));
        let (ready_tx, ready_rx) = oneshot::channel::<RuntimeAddrs>();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            app.run_until_ready(
                async move {
                    let _ = stop_rx.await;
                },
                move |addrs| {
                    let _ = ready_tx.send(addrs);
                },
            )
            .await
        });
        let addrs = timeout(TEST_TIMEOUT, ready_rx)
            .await
            .expect("startup")
            .expect("ready");

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let base = format!("http://{}", addrs.admin);

        // Complete the first-run wizard, then log in for a session.
        let r = client
            .post(format!("{base}/setup"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &base)
            .body("username=admin&password=correcthorse&confirm=correcthorse")
            .send()
            .await
            .expect("setup");
        assert_eq!(r.status(), 303, "wizard submit redirects to /login");

        let r = client
            .post(format!("{base}/login"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &base)
            .body("username=admin&password=correcthorse")
            .send()
            .await
            .expect("login");
        assert_eq!(r.status(), 303, "login redirects to /");
        let cookie = r
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|c| c.split(';').next())
            .expect("session cookie")
            .to_owned();

        // Scrape the session-bound CSRF token from a rendered page.
        let html = client
            .get(format!("{base}/upstreams"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("upstreams page")
            .text()
            .await
            .expect("body");
        let csrf = scrape_csrf(&html);

        Self {
            addrs,
            base,
            client,
            cookie,
            csrf,
            upstream_calls,
            stop_tx: Some(stop_tx),
            handle,
            _dir: dir,
        }
    }

    /// POST a urlencoded form to the admin API with the session cookie + CSRF
    /// token, asserting a non-error status. `path` may carry a query string.
    async fn admin_post(&self, path: &str, body: &str) {
        let r = self
            .client
            .post(format!("{}{path}", self.base))
            .header("cookie", &self.cookie)
            .header("x-csrf-token", &self.csrf)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.to_owned())
            .send()
            .await
            .expect("admin post");
        assert!(
            r.status().is_success() || r.status().is_redirection(),
            "admin POST {path} failed: {}",
            r.status()
        );
    }

    /// Send a DNS query over UDP and return the raw response datagram.
    async fn dns(&self, domain: &str, qtype: u16) -> Vec<u8> {
        let id = 0x4242;
        let q = build_query(id, domain, qtype);
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
        sock.connect(self.addrs.dns_udp[0]).await.expect("connect");
        sock.send(&q).await.expect("send");
        let mut buf = vec![0u8; 512];
        let n = timeout(TEST_TIMEOUT, sock.recv(&mut buf))
            .await
            .expect("dns response")
            .expect("recv");
        let resp = buf[..n].to_vec();
        assert_eq!(parse_header(&resp).id, id, "txn id echoed");
        resp
    }

    /// GET an admin page body (authenticated).
    async fn admin_get(&self, path: &str) -> String {
        self.client
            .get(format!("{}{path}", self.base))
            .header("cookie", &self.cookie)
            .send()
            .await
            .expect("admin get")
            .text()
            .await
            .expect("body")
    }

    fn upstream_calls(&self) -> usize {
        self.upstream_calls.load(Ordering::Relaxed)
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = timeout(TEST_TIMEOUT, self.handle).await;
    }
}

/// Pull the hex CSRF token out of a rendered page's hidden `csrf_token` field.
fn scrape_csrf(html: &str) -> String {
    let needle = "name=\"csrf_token\" value=\"";
    let start = html.find(needle).expect("csrf token in page") + needle.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("csrf token end");
    rest[..end].to_owned()
}

// ── Scenarios ─────────────────────────────────────────────────────────────────

/// 1. A domain on the admin blacklist is sinkholed (NOERROR + null-IP) and
///    never reaches upstream.
#[tokio::test]
async fn blocked_domain_is_sinkholed() {
    let h = Harness::start().await;
    h.admin_post("/blacklist/add", "domain=blocked.example")
        .await;

    let resp = h.dns("blocked.example", QTYPE_A).await;
    let hdr = parse_header(&resp);
    assert_eq!(hdr.rcode(), Rcode::NoError, "null-ip block → NOERROR");
    assert_eq!(hdr.ancount, 1, "null-ip A → one synthesized answer");
    assert_eq!(
        first_a_answer(&resp),
        Some(NULL_IP),
        "answer must be 0.0.0.0"
    );
    assert_eq!(h.upstream_calls(), 0, "blocked query must not forward");

    h.shutdown().await;
}

/// 2. A domain on the aggregated (third-party) blocklist is sinkholed, but
///    adding it to the allowlist bypasses the blocklist so it resolves again.
///
/// This exercises the real fetch → parse → aggregate → atomic-swap path (E7)
/// driven through the admin blocklist-source API (E8.10), plus the allowlist
/// bypass precedence (allowlist suppresses the blocklist, not the admin
/// blacklist — see `DecisionStack`).
#[tokio::test]
async fn allowlist_bypasses_aggregated_blocklist() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let h = Harness::start().await;

    // Serve a hosts-format blocklist containing the domain.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"0.0.0.0 ads.example\n".to_vec()))
        .mount(&server)
        .await;
    let url = format!("{}/hosts.txt", server.uri());

    // Subscribe to it; the add fires a background refresh.
    h.admin_post("/blocklists/add", &format!("url={url}&format=hosts"))
        .await;

    // Wait for the refresh to converge by watching the source's last-updated
    // flip off "never" on the admin page (no DNS query yet → no cache to fight).
    let mut converged = false;
    for _ in 0..200 {
        if !h.admin_get("/blocklists").await.contains("<td>never</td>") {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(converged, "blocklist source must fetch + aggregate");

    // Blocked by the aggregated list, with no upstream forward.
    let resp = h.dns("ads.example", QTYPE_A).await;
    assert_eq!(first_a_answer(&resp), Some(NULL_IP), "blocked by blocklist");
    assert_eq!(h.upstream_calls(), 0, "blocked query must not forward");

    // Allowlist it → bypasses the blocklist and resolves via upstream.
    h.admin_post("/allowlist/add", "domain=ads.example").await;
    let resp = h.dns("ads.example", QTYPE_A).await;
    assert_eq!(
        first_a_answer(&resp),
        Some(FORWARDED_IP),
        "allowlist bypasses the blocklist; domain resolves via upstream",
    );
    assert_eq!(h.upstream_calls(), 1, "allowlisted query now forwards");

    h.shutdown().await;
}

/// 3. Local and wildcard records resolve authoritatively without upstream.
#[tokio::test]
async fn local_and_wildcard_records_resolve_authoritatively() {
    let h = Harness::start().await;
    h.admin_post(
        "/local/add",
        "name=router.home.lan&type=A&value=192.168.1.1&ttl=300",
    )
    .await;
    h.admin_post(
        "/local/add",
        "name=*.home.lan&type=A&value=192.168.1.2&ttl=60",
    )
    .await;

    let resp = h.dns("router.home.lan", QTYPE_A).await;
    assert_eq!(parse_header(&resp).rcode(), Rcode::NoError);
    assert_eq!(first_a_answer(&resp), Some([192, 168, 1, 1]), "exact match");

    let resp = h.dns("anything.home.lan", QTYPE_A).await;
    assert_eq!(
        first_a_answer(&resp),
        Some([192, 168, 1, 2]),
        "wildcard match",
    );
    assert_eq!(h.upstream_calls(), 0, "local records must not forward");

    h.shutdown().await;
}

/// 4. A query for a known local name but unconfigured qtype returns
///    authoritative NODATA (AA=1, ANCOUNT=0) and never reaches upstream.
#[tokio::test]
async fn local_qtype_mismatch_is_authoritative_nodata() {
    let h = Harness::start().await;
    h.admin_post(
        "/local/add",
        "name=ipv4only.home.lan&type=A&value=10.0.0.5&ttl=300",
    )
    .await;

    let resp = h.dns("ipv4only.home.lan", QTYPE_AAAA).await;
    let hdr = parse_header(&resp);
    assert!(hdr.aa(), "NODATA must be authoritative (AA=1)");
    assert_eq!(hdr.rcode(), Rcode::NoError, "NODATA → NOERROR");
    assert_eq!(hdr.ancount, 0, "NODATA → no answer RRs");
    assert_eq!(h.upstream_calls(), 0, "local NODATA must not forward");

    h.shutdown().await;
}

/// 5 & 6. A cache miss is forwarded to and resolved by the upstream; an
///    immediate repeat is served from cache (upstream counter unchanged).
#[tokio::test]
async fn cache_miss_forwards_then_repeat_is_cached() {
    let h = Harness::start().await;

    // (6) Cache miss → forwarded and resolved via the mock upstream.
    let resp = h.dns("fresh.example.com", QTYPE_A).await;
    assert_eq!(parse_header(&resp).rcode(), Rcode::NoError);
    assert_eq!(
        first_a_answer(&resp),
        Some(FORWARDED_IP),
        "resolved upstream"
    );
    assert_eq!(h.upstream_calls(), 1, "cache miss forwards exactly once");

    // (5) Repeat → served from cache, upstream not hit again.
    let resp = h.dns("fresh.example.com", QTYPE_A).await;
    assert_eq!(parse_header(&resp).rcode(), Rcode::NoError);
    assert_eq!(first_a_answer(&resp), Some(FORWARDED_IP));
    assert_eq!(
        h.upstream_calls(),
        1,
        "repeat query must be served from cache",
    );

    h.shutdown().await;
}

/// 7. One-click whitelist from the live log makes a blocked domain resolve on
///    the next query.
#[tokio::test]
async fn one_click_whitelist_takes_effect_next_query() {
    let h = Harness::start().await;
    h.admin_post("/blacklist/add", "domain=oneclick.example")
        .await;

    // Confirmed blocked first.
    let resp = h.dns("oneclick.example", QTYPE_A).await;
    assert_eq!(
        first_a_answer(&resp),
        Some(NULL_IP),
        "blocked before unblock"
    );
    assert_eq!(h.upstream_calls(), 0);

    // One-click unblock from the live log (POST /log/unblock?domain=…).
    h.admin_post("/log/unblock?domain=oneclick.example", "")
        .await;

    let resp = h.dns("oneclick.example", QTYPE_A).await;
    assert_eq!(
        first_a_answer(&resp),
        Some(FORWARDED_IP),
        "unblocked domain resolves via upstream on the next query",
    );
    assert_eq!(h.upstream_calls(), 1, "unblocked query now forwards");

    h.shutdown().await;
}
