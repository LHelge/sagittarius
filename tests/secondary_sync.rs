//! End-to-end secondary/fallback mirroring (SPEC §13, E18.11).
//!
//! Drives two fully-assembled [`App`]s in-process: a **primary** configured
//! through its real admin HTTP API (wizard → login → mint API key → add a
//! blacklist entry), and a **secondary** pointed at the primary via
//! `--primary-url` / `--primary-api-key`.  It proves that:
//!
//! 1. The secondary mirrors the primary's blacklist and **sinkholes** the
//!    blocked domain over its own DNS listener (fallback resolution works from a
//!    fresh secondary DB — E18.10 bootstrap).
//! 2. The secondary's admin UI is **read-only**: a mutating POST is refused with
//!    403 while safe reads still work.
//! 3. The config-sync API requires a valid bearer key (401 without one).

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use tempfile::TempDir;
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle, time::timeout};

use sagittarius::{
    app::{App, RuntimeAddrs},
    codec::{header::Header, name::Name, reader::Reader, writer::Writer},
    config::{Config, InstanceMode, Secret, SessionCookieSecurePolicy},
    error::Result,
    storage::Db,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const QTYPE_A: u16 = 1;
/// The null-IP a blocked A query is sinkholed to (seeded default block mode).
const NULL_IP: [u8; 4] = [0, 0, 0, 0];

// ── DNS wire helpers (self-contained; integration crates can't share) ──────────

fn build_query(id: u16, domain: &str, qtype: u16) -> Bytes {
    let mut w = Writer::with_capacity(64);
    Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
    let n: Name = domain.parse().expect("valid name");
    n.write(&mut w);
    w.write_u16(qtype);
    w.write_u16(1u16); // QCLASS IN
    w.finish()
}

fn parse_header_id(bytes: &[u8]) -> u16 {
    let mut r = Reader::new(Bytes::copy_from_slice(bytes));
    Header::read(&mut r).expect("valid DNS header").id
}

fn skip_name(buf: &[u8], mut pos: usize) -> usize {
    loop {
        let len = buf[pos];
        if len & 0xC0 == 0xC0 {
            return pos + 2;
        }
        if len == 0 {
            return pos + 1;
        }
        pos += 1 + len as usize;
    }
}

fn first_a_answer(resp: &[u8]) -> Option<[u8; 4]> {
    let mut pos = 12;
    pos = skip_name(resp, pos);
    pos += 4;
    pos = skip_name(resp, pos);
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

async fn dns_query(dns_addr: SocketAddr, domain: &str) -> Vec<u8> {
    let id = 0x4242;
    let q = build_query(id, domain, QTYPE_A);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
    sock.connect(dns_addr).await.expect("connect");
    sock.send(&q).await.expect("send");
    let mut buf = vec![0u8; 512];
    let n = timeout(TEST_TIMEOUT, sock.recv(&mut buf))
        .await
        .expect("dns response")
        .expect("recv");
    let resp = buf[..n].to_vec();
    assert_eq!(parse_header_id(&resp), id, "txn id echoed");
    resp
}

// ── HTML scraping helpers ──────────────────────────────────────────────────────

fn scrape_csrf(html: &str) -> String {
    let needle = "name=\"csrf_token\" value=\"";
    let start = html.find(needle).expect("csrf token in page") + needle.len();
    let rest = &html[start..];
    rest[..rest.find('"').expect("csrf end")].to_owned()
}

/// Scrape the one-time plaintext API key from the create-key response.
fn scrape_api_key(html: &str) -> String {
    let needle = "<pre class=\"sgt-mono\"><code>";
    let start = html.find(needle).expect("api key in page") + needle.len();
    let rest = &html[start..];
    rest[..rest.find("</code>").expect("key end")]
        .trim()
        .to_owned()
}

// ── App launch helper ──────────────────────────────────────────────────────────

struct LaunchedApp {
    addrs: RuntimeAddrs,
    stop_tx: Option<oneshot::Sender<()>>,
    handle: JoinHandle<Result<()>>,
    _dir: TempDir,
}

impl LaunchedApp {
    async fn launch(config: Config, dir: TempDir) -> Self {
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
        Self {
            addrs,
            stop_tx: Some(stop_tx),
            handle,
            _dir: dir,
        }
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = timeout(TEST_TIMEOUT, self.handle).await;
    }
}

fn base_config(db_path: std::path::PathBuf, mode: InstanceMode, key: Option<&str>) -> Config {
    Config {
        dns_addrs: vec!["127.0.0.1:0".parse().unwrap()],
        admin_addr: "127.0.0.1:0".parse().unwrap(),
        db_path,
        session_cookie_secure: SessionCookieSecurePolicy::Never,
        instance_mode: mode,
        primary_api_key: key.map(|k| Secret::new(k.to_owned())),
    }
}

// ── The test ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn secondary_mirrors_primary_and_is_read_only() {
    // ── Primary: launch, complete wizard, log in. ──────────────────────────────
    let pdir = TempDir::new().expect("temp dir");
    let pdb_path = pdir.path().join("primary.db");
    Db::connect(&pdb_path).await.expect("create primary db"); // run migrations/seed
    let primary =
        LaunchedApp::launch(base_config(pdb_path, InstanceMode::Primary, None), pdir).await;
    let pbase = format!("http://{}", primary.addrs.admin);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let r = client
        .post(format!("{pbase}/setup"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("origin", &pbase)
        .body("username=admin&password=correcthorse&confirm=correcthorse")
        .send()
        .await
        .expect("setup");
    assert_eq!(r.status(), 303);

    let r = client
        .post(format!("{pbase}/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("origin", &pbase)
        .body("username=admin&password=correcthorse")
        .send()
        .await
        .expect("login");
    assert_eq!(r.status(), 303);
    let cookie = r
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .expect("session cookie")
        .to_owned();

    let csrf = scrape_csrf(
        &client
            .get(format!("{pbase}/apikeys"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("apikeys page")
            .text()
            .await
            .expect("body"),
    );

    // Mint an API key for the secondary (shown once).
    let key = scrape_api_key(
        &client
            .post(format!("{pbase}/apikeys/create"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
            .header("content-type", "application/x-www-form-urlencoded")
            .body("label=fallback")
            .send()
            .await
            .expect("create key")
            .text()
            .await
            .expect("body"),
    );
    assert!(key.contains('.'), "minted key must be id.token: {key:?}");

    // Add a blacklist entry on the primary.
    let r = client
        .post(format!("{pbase}/blacklist/add"))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("domain=blocked.example.com")
        .send()
        .await
        .expect("blacklist add");
    assert_eq!(r.status(), 303);

    // ── Secondary: launch pointed at the primary. ──────────────────────────────
    let sdir = TempDir::new().expect("temp dir");
    let sdb_path = sdir.path().join("secondary.db");
    let secondary = LaunchedApp::launch(
        base_config(
            sdb_path,
            InstanceMode::Secondary {
                primary_url: pbase.clone(),
            },
            Some(&key),
        ),
        sdir,
    )
    .await;
    let sbase = format!("http://{}", secondary.addrs.admin);
    let sdns = secondary.addrs.dns_udp[0];

    // The secondary syncs on startup; poll its DNS until the mirrored blacklist
    // takes effect and the domain is sinkholed to the null IP.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut blocked = false;
    while tokio::time::Instant::now() < deadline {
        let resp = dns_query(sdns, "blocked.example.com").await;
        if first_a_answer(&resp) == Some(NULL_IP) {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        blocked,
        "secondary must mirror the primary's blacklist and sinkhole the domain"
    );

    // ── Read-only enforcement on the secondary. ────────────────────────────────
    // A mutating POST is refused (403) — regardless of auth — by the read-only
    // guard, while a safe GET still renders.
    let r = client
        .post(format!("{sbase}/blacklist/add"))
        .header("origin", &sbase)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("domain=nope.example.com")
        .send()
        .await
        .expect("secondary mutation");
    assert_eq!(
        r.status(),
        403,
        "a mutating request on a read-only secondary must be refused"
    );

    let r = client
        .get(format!("{sbase}/login"))
        .send()
        .await
        .expect("secondary login page");
    assert_eq!(
        r.status(),
        200,
        "safe reads must still work on the secondary"
    );

    // The config-sync API requires a valid key.
    let r = client
        .get(format!("{sbase}/api/v1/config"))
        .send()
        .await
        .expect("secondary api without key");
    assert_eq!(r.status(), 401);

    secondary.shutdown().await;
    primary.shutdown().await;
}
