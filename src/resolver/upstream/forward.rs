//! Forwarding logic: map a project [`Question`] to a hickory DNS request,
//! send it through an [`UpstreamClient`], and return the raw-bytes result the
//! cache-store seam (E6) needs.
//!
//! Each call is bounded by a caller-supplied per-attempt [`Duration`]; the
//! module constant [`DEFAULT_QUERY_TIMEOUT`] is the recommended value and is
//! what E5.3 (pool / failover) will pass in.

use std::time::Duration;

use bytes::Bytes;
use hickory_net::proto::op::{DnsRequest, DnsRequestOptions, Message, Query, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RecordType};
use hickory_net::xfer::{DnsHandle, FirstAnswer as _};

use crate::codec::message::{Qclass, Qtype, Question};

use super::{Error, Result, UpstreamClient};

// ── Default timeout ───────────────────────────────────────────────────────────

/// Default per-attempt query timeout.
///
/// E5.3 will pass this as the `timeout` argument to [`UpstreamClient::forward`]
/// unless the operator has configured a different value.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

// ── ForwardResult ─────────────────────────────────────────────────────────────

/// The result of forwarding a single DNS question to an upstream resolver.
///
/// Contains everything the cache-store seam (E6) needs:
/// - the exact upstream wire bytes (no re-serialization),
/// - the RFC 2308 negative TTL for negative-response caching, and
/// - a flag that classifies the response as negative or positive.
#[derive(Debug, Clone)]
pub struct ForwardResult {
    /// The upstream response, exact wire bytes (no re-serialization).
    pub bytes: Bytes,
    /// RFC 2308 negative TTL (`min(SOA.ttl, SOA.minimum)`); `None` when no SOA.
    pub negative_ttl: Option<u32>,
    /// `true` for NXDOMAIN, or NOERROR with no answer records (NODATA).
    pub is_negative: bool,
}

// ── UpstreamClient::forward ───────────────────────────────────────────────────

impl UpstreamClient {
    /// Forward `question` to the upstream resolver and return the raw-bytes
    /// result.
    ///
    /// The request is built with **RD=1** (recursion desired) and **DO=0**
    /// (no DNSSEC).  The call is bounded by `timeout`; if the upstream does
    /// not respond within that window, [`Error::Timeout`] is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::Transport`] — the question name could not be encoded as an
    ///   ASCII DNS name (should never happen for a name that arrived via the
    ///   project codec).
    /// - [`Error::Timeout`] — the upstream did not respond within `timeout`.
    /// - [`Error::Exchange`] — hickory reported a send/receive failure.
    pub async fn forward(&self, question: &Question, timeout: Duration) -> Result<ForwardResult> {
        // ── Map project Question → hickory types ─────────────────────────────

        let name = Name::from_ascii(question.name.to_string()).map_err(|e| {
            Error::Transport(format!(
                "invalid question name {:?}: {e}",
                question.name.to_string()
            ))
        })?;

        let record_type = match question.qtype {
            Qtype::A => RecordType::A,
            Qtype::Aaaa => RecordType::AAAA,
            Qtype::Other(v) => RecordType::from(v),
        };

        let dns_class = match question.qclass {
            Qclass::In => DNSClass::IN,
            Qclass::Other(v) => DNSClass::from(v),
        };

        let mut query = Query::query(name, record_type);
        query.set_query_class(dns_class);

        let mut message = Message::query();
        message.add_query(query);
        message.metadata.recursion_desired = true; // RD=1

        let mut options = DnsRequestOptions::default();
        options.recursion_desired = true;
        options.edns_set_dnssec_ok = false; // DO=0

        let request = DnsRequest::new(message, options);

        // ── Send and await the first response ─────────────────────────────────

        let response = tokio::time::timeout(timeout, self.handle().send(request).first_answer())
            .await
            .map_err(|_| Error::Timeout {
                transport: self.transport(),
            })?
            .map_err(|source| Error::Exchange {
                transport: self.transport(),
                source,
            })?;

        // ── Extract metadata before consuming the response ───────────────────

        let negative_ttl = response.negative_ttl();
        let rcode = response.metadata.response_code;
        let is_negative = rcode == ResponseCode::NXDomain
            || (rcode == ResponseCode::NoError && !response.contains_answer());

        let bytes = Bytes::from(response.into_buffer());

        Ok(ForwardResult {
            bytes,
            negative_ttl,
            is_negative,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use hickory_net::proto::op::{Message, MessageType, ResponseCode};
    use hickory_net::proto::rr::rdata::{A, SOA};
    use hickory_net::proto::rr::{Name, RData, Record};
    use tokio::net::UdpSocket;

    use super::*;
    use crate::codec::message::{Qclass, Qtype, Question};
    use crate::resolver::upstream::{UpstreamConfig, UpstreamTransport};

    // ── Mock UDP upstream ─────────────────────────────────────────────────────

    /// Spawn a UDP mock upstream on an ephemeral port.
    ///
    /// For each datagram received, the request is parsed with hickory, handed
    /// to `handler`, and — if it returns `Some(response)` — the response is
    /// serialized and sent back to the peer.  Returning `None` simulates a
    /// dead upstream (nothing is sent, so `forward()` will time out).
    ///
    /// Returns the bound [`SocketAddr`] so the caller can build an
    /// [`UpstreamConfig::Udp`] pointing at it.
    async fn spawn_mock_udp<F>(mut handler: F) -> SocketAddr
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

    /// Build the stock question used in every test:
    /// `example.com. A IN`
    fn stock_question() -> Question {
        Question {
            name: "example.com".parse().unwrap(),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }
    }

    /// Helper: connect a UDP `UpstreamClient` to `addr` and spawn its background.
    async fn udp_client(addr: SocketAddr) -> UpstreamClient {
        let cfg = UpstreamConfig {
            addr,
            transport: UpstreamTransport::Udp,
            tls_server_name: None,
            http_endpoint: None,
        };
        let (client, bg) = UpstreamClient::connect(&cfg).await.unwrap();
        tokio::spawn(bg);
        client
    }

    // ── Test: positive A answer ───────────────────────────────────────────────

    /// Mock returns one A record with TTL 300.
    /// Asserts: `!is_negative`, `negative_ttl == None`, and the returned bytes
    /// re-parse with both the hickory TtlScan and the project codec.
    #[tokio::test]
    async fn positive_a_answer() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;

            let name = Name::from_ascii("example.com.").unwrap();
            let rdata = RData::A(A::new(93, 184, 216, 34));
            resp.add_answer(Record::from_rdata(name, 300, rdata));
            Some(resp)
        })
        .await;

        let client = udp_client(addr).await;
        let result = client
            .forward(&stock_question(), Duration::from_secs(5))
            .await
            .expect("forward must succeed");

        assert!(!result.is_negative, "A response must not be negative");
        assert_eq!(result.negative_ttl, None, "positive answer has no SOA");

        // bytes must re-parse with the project TTL scanner
        let scan = crate::codec::ttl::TtlScan::scan(&result.bytes)
            .expect("TtlScan must succeed on returned bytes");
        assert_eq!(scan.min_ttl, Some(300), "TTL from bytes must be 300");

        // bytes must re-parse with the project Query codec (proves it is a
        // well-formed DNS message with at least a valid header + question)
        let query = crate::codec::message::Query::try_from(result.bytes.clone())
            .expect("Query::try_from must succeed on returned bytes");
        assert_eq!(
            query.question().name.to_string(),
            "example.com.",
            "question name in parsed bytes must match queried name"
        );
    }

    // ── Test: NXDOMAIN with SOA ───────────────────────────────────────────────

    /// NXDOMAIN + SOA in authority (ttl=120, minimum=60).
    /// RFC 2308: negative_ttl = min(120, 60) = 60.
    #[tokio::test]
    async fn nxdomain_with_soa() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NXDomain;

            let zone = Name::from_ascii("example.com.").unwrap();
            let mname = Name::from_ascii("ns1.example.com.").unwrap();
            let rname = Name::from_ascii("hostmaster.example.com.").unwrap();
            let soa = SOA::new(mname, rname, 1, 3600, 900, 604800, 60);
            resp.add_authority(Record::from_rdata(zone, 120, RData::SOA(soa)));
            Some(resp)
        })
        .await;

        let client = udp_client(addr).await;
        let result = client
            .forward(&stock_question(), Duration::from_secs(5))
            .await
            .expect("forward must succeed");

        assert!(result.is_negative, "NXDOMAIN must be negative");
        assert_eq!(
            result.negative_ttl,
            Some(60),
            "negative_ttl must be min(soa_ttl=120, soa_minimum=60) = 60"
        );
    }

    // ── Test: SOA-less NXDOMAIN ───────────────────────────────────────────────

    /// NXDOMAIN with no SOA in authority → negative_ttl is None.
    #[tokio::test]
    async fn nxdomain_without_soa() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NXDomain;
            // No SOA added
            Some(resp)
        })
        .await;

        let client = udp_client(addr).await;
        let result = client
            .forward(&stock_question(), Duration::from_secs(5))
            .await
            .expect("forward must succeed");

        assert!(result.is_negative, "NXDOMAIN must be negative");
        assert_eq!(
            result.negative_ttl, None,
            "NXDOMAIN without SOA must have no negative_ttl"
        );
    }

    // ── Test: NODATA ──────────────────────────────────────────────────────────

    /// NOERROR with no answer records (NODATA) → is_negative.
    #[tokio::test]
    async fn nodata_noerror_no_answer() {
        let addr = spawn_mock_udp(|req| {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            // No answers — NODATA
            Some(resp)
        })
        .await;

        let client = udp_client(addr).await;
        let result = client
            .forward(&stock_question(), Duration::from_secs(5))
            .await
            .expect("forward must succeed");

        assert!(
            result.is_negative,
            "NODATA (NOERROR, no answers) must be negative"
        );
    }

    // ── Test: per-attempt timeout ─────────────────────────────────────────────

    /// Mock never replies.  forward() must return Error::Timeout quickly.
    #[tokio::test]
    async fn timeout_when_upstream_silent() {
        let addr = spawn_mock_udp(|_req| None /* never reply */).await;

        let client = udp_client(addr).await;

        let result = tokio::time::timeout(
            Duration::from_secs(5), // safety net — test must never take this long
            client.forward(&stock_question(), Duration::from_millis(150)),
        )
        .await
        .expect("safety timeout: test took too long");

        assert!(
            matches!(result, Err(Error::Timeout { .. })),
            "expected Error::Timeout, got: {result:?}"
        );
    }
}
