//! Shared test-only helpers.
//!
//! Centralizes fixtures otherwise repeated across the module test suites:
//! the throwaway-database setup, DNS wire-format query builders, and the mock
//! UDP upstream used by the forwarding/pool/pipeline tests.

use std::net::SocketAddr;

use bytes::Bytes;
use hickory_net::proto::op::{Message, MessageType, ResponseCode};
use hickory_net::proto::rr::rdata::{A, SOA};
use hickory_net::proto::rr::{Name as HickoryName, RData, Record};
use tempfile::TempDir;
use tokio::net::UdpSocket;

use crate::{
    codec::{
        header::Header,
        message::{Qclass, Qtype, Question},
        name::Name,
        writer::Writer,
    },
    storage::Db,
};

// ── Database ──────────────────────────────────────────────────────────────────

/// Open a fresh, migrated SQLite database in a throwaway temp directory.
///
/// Returns the [`TempDir`] guard — keep it alive for the duration of the test,
/// since dropping it deletes the database file — and the open [`Db`].
pub(crate) async fn temp_db() -> (TempDir, Db) {
    let dir = TempDir::new().expect("create temp dir");
    let db = Db::connect(dir.path().join("test.db"))
        .await
        .expect("connect to a fresh test database");
    (dir, db)
}

// ── Wire-format query builders ────────────────────────────────────────────────

/// Build a minimal DNS query datagram: header (QDCOUNT=1, RD=1) + one
/// question for `name` with the given raw `qtype` and QCLASS IN.
pub(crate) fn wire_query(id: u16, name: &str, qtype: u16) -> Bytes {
    let mut w = Writer::with_capacity(64);
    Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
    let n: Name = name.parse().expect("valid name in test helper");
    n.write(&mut w);
    w.write_u16(qtype);
    w.write_u16(1u16); // QCLASS IN
    w.finish()
}

/// Build a minimal A query datagram for `name`.
pub(crate) fn a_query(id: u16, name: &str) -> Bytes {
    wire_query(id, name, 1)
}

/// Build a minimal AAAA query datagram for `name`.
pub(crate) fn aaaa_query(id: u16, name: &str) -> Bytes {
    wire_query(id, name, 28)
}

/// Build a minimal PTR query datagram for the reverse-zone `name`
/// (e.g. `1.1.168.192.in-addr.arpa`).
pub(crate) fn ptr_query(id: u16, name: &str) -> Bytes {
    wire_query(id, name, 12)
}

/// The stock question used across the forwarding tests: `example.com. A IN`.
pub(crate) fn stock_question() -> Question {
    Question {
        name: "example.com".parse().expect("valid name"),
        qtype: Qtype::A,
        qclass: Qclass::In,
    }
}

// ── Mock UDP upstream ─────────────────────────────────────────────────────────

/// Spawn a UDP mock upstream on an ephemeral port.
///
/// For each datagram received the request is parsed with hickory, handed to
/// `handler`, and — if it returns `Some(response)` — the response is
/// serialised and sent back to the peer.  Returning `None` simulates a dead /
/// silent upstream (nothing is sent, so forwarding times out).
///
/// Returns the bound [`SocketAddr`] so the caller can point an upstream
/// config at it.
pub(crate) async fn mock_udp_upstream<F>(mut handler: F) -> SocketAddr
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

/// Turn `req` into a response shell: QR=1 with the given response code.
fn response_shell(mut req: Message, code: ResponseCode) -> Message {
    req.metadata.message_type = MessageType::Response;
    req.metadata.response_code = code;
    req
}

/// Mock handler: NOERROR with one `example.com. 300 IN A 93.184.216.34`.
pub(crate) fn positive_a_handler(req: Message) -> Option<Message> {
    let mut resp = response_shell(req, ResponseCode::NoError);
    let name = HickoryName::from_ascii("example.com.").unwrap();
    let rdata = RData::A(A::new(93, 184, 216, 34));
    resp.add_answer(Record::from_rdata(name, 300, rdata));
    Some(resp)
}

/// Mock handler: NXDOMAIN with a SOA in authority (RR TTL 120, minimum 60 →
/// RFC 2308 negative TTL 60).
pub(crate) fn nxdomain_with_soa_handler(req: Message) -> Option<Message> {
    let mut resp = response_shell(req, ResponseCode::NXDomain);
    let zone = HickoryName::from_ascii("example.com.").unwrap();
    let mname = HickoryName::from_ascii("ns1.example.com.").unwrap();
    let rname = HickoryName::from_ascii("hostmaster.example.com.").unwrap();
    let soa = SOA::new(mname, rname, 1, 3600, 900, 604800, 60);
    resp.add_authority(Record::from_rdata(zone, 120, RData::SOA(soa)));
    Some(resp)
}

/// Mock handler: NXDOMAIN with **no** SOA (negative TTL unknown).
pub(crate) fn nxdomain_handler(req: Message) -> Option<Message> {
    Some(response_shell(req, ResponseCode::NXDomain))
}

/// Mock handler: never replies (simulates a dead / timing-out upstream).
pub(crate) fn silent_handler(_req: Message) -> Option<Message> {
    None
}
