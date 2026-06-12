//! DNS transport listeners: UDP pool (SO_REUSEPORT) and TCP (RFC 7766).
//!
//! This module binds UDP and TCP sockets, pumps incoming messages through a
//! generic [`tower::Service`] pipeline, and handles graceful drain on shutdown.
//!
//! # Architecture
//!
//! [`DnsListeners`] owns a [`UdpListenerPool`] (N SO_REUSEPORT sockets per
//! address, one per CPU) and a [`TcpListenerSet`] (one socket per address).
//! [`DnsListeners::serve`] spawns one loop task per socket on the app
//! [`TaskTracker`].  Each loop task owns an inner [`TaskTracker`] for its
//! per-message / per-connection handler tasks so shutdown can drain in-flight
//! work cleanly.
//!
//! # Service contract
//!
//! The service generic `S` must be
//! `tower::Service<DnsRequest, Response = PipelineResponse, Error = BoxError>
//!  + Clone + Send + 'static` with `S::Future: Send + 'static`.
//!
//! The service is cloned once per handler (datagram or TCP connection).
//!
//! # UDP size / TC bit
//!
//! Per RFC 6891, replies that exceed the client-advertised UDP payload size
//! (or 512 bytes when no EDNS OPT is present, capped to 1232 bytes) are
//! replaced with a minimal TC=1 response, signalling the client to retry
//! over TCP.
//!
//! # TCP pipelining (RFC 7766)
//!
//! Each TCP connection handler loops reading length-prefixed messages until
//! EOF, idle timeout, or an unrecoverable parse error.

use std::{io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower::{Service, ServiceExt as _};
use tracing::{debug, trace, warn};

use crate::{
    codec::{framing, message::Query, synth::Response},
    resolver::pipeline::{BoxError, DnsRequest, PipelineResponse, middleware::ClassifyRejection},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// TCP backlog for `listen(2)` calls.
const TCP_BACKLOG: i32 = 128;

/// Idle timeout on a TCP connection between reads (RFC 7766 §6.2.3).
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard floor for UDP reply size when no EDNS OPT is present.
const UDP_DEFAULT_LIMIT: usize = 512;

/// Recommended DNS-over-UDP payload ceiling (DNS Flag Day 2020 / RFC 8906).
const UDP_MAX_LIMIT: usize = 1232;

/// Maximum concurrent UDP datagram handlers per socket.
///
/// Tower's protective middleware still enforces the global query budget, but
/// this cap prevents unbounded task creation before a datagram reaches tower.
const UDP_HANDLER_CONCURRENCY: usize = 1024;

enum TcpRead {
    Complete,
    Shutdown,
    Idle,
    Eof,
    Error(io::Error),
}

// ── UdpListenerPool ───────────────────────────────────────────────────────────

/// A pool of SO_REUSEPORT UDP sockets, one per (address × CPU core).
///
/// The kernel fans incoming datagrams across all sockets bound to the same
/// address/port via SO_REUSEPORT, distributing load across CPU cores without
/// any application-level coordination.
pub struct UdpListenerPool {
    sockets: Vec<UdpSocket>,
}

impl UdpListenerPool {
    /// Bind N UDP sockets per address, all with `SO_REUSEPORT`.
    ///
    /// If `SO_REUSEPORT` is not available on the platform, a warning is logged
    /// and a single socket is bound for that address instead.
    ///
    /// # Errors
    ///
    /// Returns the first I/O error encountered while binding.
    pub fn bind(addrs: &[SocketAddr], sockets_per_addr: usize) -> io::Result<Self> {
        let mut sockets = Vec::with_capacity(addrs.len() * sockets_per_addr);

        for &addr in addrs {
            let n = Self::bind_for_addr(addr, sockets_per_addr, &mut sockets)?;
            debug!(addr = %addr, sockets = n, "UDP sockets bound");
        }

        Ok(Self { sockets })
    }

    /// Bind UDP sockets for a single address, using the default socket count
    /// (number of logical CPUs).
    ///
    /// # Errors
    ///
    /// Returns the first I/O error encountered while binding.
    pub fn bind_default(addrs: &[SocketAddr]) -> io::Result<Self> {
        let n = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        Self::bind(addrs, n)
    }

    /// Attempt to bind `count` SO_REUSEPORT sockets for `addr`.
    ///
    /// Falls back to a single socket (without SO_REUSEPORT) if the platform
    /// does not support it.
    fn bind_for_addr(
        addr: SocketAddr,
        count: usize,
        out: &mut Vec<UdpSocket>,
    ) -> io::Result<usize> {
        // Try binding with SO_REUSEPORT.
        match Self::try_bind_reuseport(addr) {
            Ok(first) => {
                out.push(first);
                // Remaining sockets with SO_REUSEPORT.
                for _ in 1..count {
                    out.push(Self::try_bind_reuseport(addr)?);
                }
                Ok(count)
            }
            Err(e) if Self::is_reuseport_unsupported(&e) => {
                warn!(
                    addr = %addr,
                    error = %e,
                    "SO_REUSEPORT unavailable; falling back to a single UDP socket"
                );
                out.push(Self::bind_single_udp(addr)?);
                Ok(1)
            }
            Err(e) => Err(e),
        }
    }

    /// Bind one UDP socket with SO_REUSEPORT.
    fn try_bind_reuseport(addr: SocketAddr) -> io::Result<UdpSocket> {
        let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_reuse_port(true)?;
        if addr.is_ipv6() {
            sock.set_only_v6(true)?;
        }
        sock.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = sock.into();
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }

    /// Bind a single UDP socket without SO_REUSEPORT (fallback).
    fn bind_single_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
        let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        if addr.is_ipv6() {
            sock.set_only_v6(true)?;
        }
        sock.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = sock.into();
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }

    /// Number of bound sockets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// `true` if there are no bound sockets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    /// Returns `true` if the error indicates SO_REUSEPORT is not supported.
    fn is_reuseport_unsupported(e: &io::Error) -> bool {
        // ENOPROTOOPT (92 on Linux, 42 on macOS/BSD) means the socket option is
        // not known to the kernel — i.e. SO_REUSEPORT is not supported.
        // We also match InvalidInput as a belt-and-suspenders fallback.
        #[cfg(target_os = "linux")]
        const ENOPROTOOPT: i32 = 92;
        #[cfg(target_os = "macos")]
        const ENOPROTOOPT: i32 = 42;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        const ENOPROTOOPT: i32 = 42; // Reasonable default for other Unix targets.

        e.raw_os_error() == Some(ENOPROTOOPT) || e.kind() == io::ErrorKind::InvalidInput
    }
}

// ── TcpListenerSet ────────────────────────────────────────────────────────────

/// One TCP listener per address.
///
/// DNS over TCP does **not** use SO_REUSEPORT — each address gets exactly one
/// listener socket.
pub struct TcpListenerSet {
    listeners: Vec<TcpListener>,
}

impl TcpListenerSet {
    /// Bind one TCP listener per address.
    ///
    /// # Errors
    ///
    /// Returns the first I/O error encountered while binding.
    pub fn bind(addrs: &[SocketAddr]) -> io::Result<Self> {
        let mut listeners = Vec::with_capacity(addrs.len());

        for &addr in addrs {
            let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
            sock.set_reuse_address(true)?;
            if addr.is_ipv6() {
                sock.set_only_v6(true)?;
            }
            sock.bind(&addr.into())?;
            sock.listen(TCP_BACKLOG)?;
            let std_listener: std::net::TcpListener = sock.into();
            std_listener.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std_listener)?;
            debug!(addr = %addr, "TCP listener bound");
            listeners.push(listener);
        }

        Ok(Self { listeners })
    }

    /// Number of bound listeners.
    #[must_use]
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// `true` if there are no bound listeners.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

// ── DnsListeners ─────────────────────────────────────────────────────────────

/// Owns all bound DNS transport sockets and drives the serve loops.
pub struct DnsListeners {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
}

impl DnsListeners {
    /// Bind all DNS listeners: N UDP sockets per address and one TCP listener
    /// per address.
    ///
    /// # Errors
    ///
    /// Returns the first I/O error encountered while binding.
    pub fn bind(addrs: &[SocketAddr], udp_sockets_per_addr: usize) -> io::Result<Self> {
        let pool = UdpListenerPool::bind(addrs, udp_sockets_per_addr)?;
        let set = TcpListenerSet::bind(addrs)?;
        Ok(Self {
            udp: pool.sockets,
            tcp: set.listeners,
        })
    }

    /// Return the local socket addresses of all bound UDP sockets.
    ///
    /// Useful in tests (and for metrics) to learn the ephemeral port assigned
    /// when `0` was passed as the port in the bind address.
    pub fn udp_local_addrs(&self) -> Vec<SocketAddr> {
        self.udp
            .iter()
            .filter_map(|s| s.local_addr().ok())
            .collect()
    }

    /// Spawn all serve loops on `tracker`, cancellable via `token`.
    ///
    /// One tokio task is spawned per UDP socket and per TCP listener.  Each
    /// loop task owns an inner [`TaskTracker`] for per-message/per-connection
    /// handler tasks and drains it before the loop task returns, ensuring
    /// in-flight work completes before the outer drain timeout fires.
    pub fn serve<S>(self, service: S, token: CancellationToken, tracker: &TaskTracker)
    where
        S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        for socket in self.udp {
            let serve = ServeLoop::new(service.clone(), token.clone());
            tracker.spawn(serve.run_udp(socket));
        }
        for listener in self.tcp {
            let serve = ServeLoop::new(service.clone(), token.clone());
            tracker.spawn(serve.run_tcp(listener));
        }
    }
}

// ── ServeLoop ───────────────────────────────────────────────────────────────

/// Drives one bound socket's serve loop and its per-message handler tasks.
///
/// Holds the dependencies every handler needs — the cloneable pipeline
/// `service` and the shutdown `token` — so the UDP/TCP loops and their datagram
/// / connection handlers read as methods on one cohesive component rather than
/// a cluster of free functions threading the same arguments.  A fresh clone is
/// spawned per socket (and cheaply re-cloned per datagram/connection).
#[derive(Clone)]
struct ServeLoop<S> {
    service: S,
    token: CancellationToken,
}

impl<S> ServeLoop<S>
where
    S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    fn new(service: S, token: CancellationToken) -> Self {
        Self { service, token }
    }

    async fn read_tcp_exact(
        stream: &mut TcpStream,
        token: &CancellationToken,
        buf: &mut [u8],
    ) -> TcpRead {
        let read_result = tokio::select! {
            biased;
            _ = token.cancelled() => return TcpRead::Shutdown,
            r = tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(buf)) => r,
        };

        match read_result {
            Err(_elapsed) => TcpRead::Idle,
            Ok(Ok(_)) => TcpRead::Complete,
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => TcpRead::Eof,
            Ok(Err(e)) => TcpRead::Error(e),
        }
    }

    /// Drive `service` for a successfully-parsed request.
    ///
    /// Takes the (already-cloned) service by value so the returned future
    /// borrows nothing from `self` — keeping the per-handler futures `Send`
    /// without requiring `S: Sync`.  Service errors are mapped to synthesized
    /// error responses via [`ClassifyRejection::rejection_policy`].
    async fn run_service(service: S, req: &DnsRequest) -> Bytes {
        match service.oneshot(req.clone()).await {
            Ok(PipelineResponse { bytes, .. }) => bytes,
            Err(boxerr) => {
                let (_, rcode) = boxerr.rejection_policy();
                Response::error_response(req.query(), rcode, req.edns())
            }
        }
    }

    /// UDP datagram serve loop for a single socket.
    async fn run_udp(self, socket: UdpSocket) {
        let socket = Arc::new(socket);
        let handlers = TaskTracker::new();
        let permits = Arc::new(Semaphore::new(UDP_HANDLER_CONCURRENCY));
        let mut buf = vec![0u8; 65535];

        loop {
            let permit = tokio::select! {
                biased;
                _ = self.token.cancelled() => break,
                permit = permits.clone().acquire_owned() => {
                    match permit {
                        Ok(permit) => permit,
                        Err(_closed) => break,
                    }
                }
            };

            tokio::select! {
                biased;
                _ = self.token.cancelled() => break,
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer)) => {
                            let raw = Bytes::copy_from_slice(&buf[..len]);
                            let handler = self.clone();
                            let sock = socket.clone();

                            handlers.spawn(async move {
                                let _permit = permit;
                                handler.handle_datagram(raw, peer, sock).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "UDP recv_from error");
                        }
                    }
                }
            }
        }

        handlers.close();
        let _ = handlers.wait().await;
    }

    /// Handle a single UDP datagram: parse → service → size check → send.
    async fn handle_datagram(self, raw: Bytes, peer: SocketAddr, socket: Arc<UdpSocket>) {
        let query = match Query::try_from(raw) {
            Ok(q) => q,
            Err(e) => {
                if let Some(id) = e.id {
                    trace!(peer = %peer, id, "UDP FORMERR");
                    let formerr = Response::formerr(id);
                    let _ = socket.send_to(&formerr, peer).await;
                } else {
                    trace!(peer = %peer, "UDP datagram too short to recover id; dropping");
                }
                return;
            }
        };

        let req = DnsRequest::new(query, peer);
        let reply = Self::run_service(self.service.clone(), &req).await;

        // UDP size check: truncate if reply exceeds the client-advertised limit.
        let limit = req
            .edns()
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(UDP_DEFAULT_LIMIT)
            .min(UDP_MAX_LIMIT);

        let final_reply = if reply.len() > limit {
            debug!(
                peer = %peer,
                reply_len = reply.len(),
                limit,
                "UDP reply exceeds limit; sending TC=1"
            );
            Response::truncated(req.query(), req.edns())
        } else {
            reply
        };

        let _ = socket.send_to(&final_reply, peer).await;
        trace!(peer = %peer, reply_len = final_reply.len(), "UDP reply sent");
    }

    /// TCP listener serve loop for a single [`TcpListener`].
    async fn run_tcp(self, listener: TcpListener) {
        let handlers = TaskTracker::new();

        loop {
            tokio::select! {
                biased;
                _ = self.token.cancelled() => break,
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let handler = self.clone();
                            handlers.spawn(async move {
                                handler.handle_connection(stream, peer).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "TCP accept error");
                        }
                    }
                }
            }
        }

        handlers.close();
        let _ = handlers.wait().await;
    }

    /// Handle a single TCP connection — RFC 7766 pipelined length-prefixed messages.
    ///
    /// The shutdown token is checked on each read so the connection is abandoned
    /// promptly when the server is shutting down.
    async fn handle_connection(self, mut stream: TcpStream, peer: SocketAddr) {
        loop {
            // ── Read 2-byte length prefix with idle timeout ────────────────────
            let mut len_buf = [0u8; 2];
            match Self::read_tcp_exact(&mut stream, &self.token, &mut len_buf).await {
                TcpRead::Complete => {}
                TcpRead::Shutdown => {
                    trace!(peer = %peer, "TCP connection closed: shutdown");
                    return;
                }
                TcpRead::Idle => {
                    trace!(peer = %peer, "TCP connection idle; closing");
                    return;
                }
                TcpRead::Eof => {
                    trace!(peer = %peer, "TCP clean EOF; closing");
                    return;
                }
                TcpRead::Error(e) => {
                    debug!(peer = %peer, error = %e, "TCP read error; closing");
                    return;
                }
            }

            let msg_len = u16::from_be_bytes(len_buf) as usize;

            // ── Read the message body ──────────────────────────────────────────
            let mut body = BytesMut::with_capacity(msg_len);
            body.resize(msg_len, 0);
            match Self::read_tcp_exact(&mut stream, &self.token, &mut body).await {
                TcpRead::Complete => {}
                TcpRead::Shutdown => {
                    trace!(peer = %peer, "TCP connection closed while reading body: shutdown");
                    return;
                }
                TcpRead::Idle => {
                    trace!(peer = %peer, "TCP body read idle; closing");
                    return;
                }
                TcpRead::Eof => {
                    trace!(peer = %peer, "TCP clean EOF while reading body; closing");
                    return;
                }
                TcpRead::Error(e) => {
                    debug!(peer = %peer, error = %e, "TCP body read error; closing");
                    return;
                }
            }
            let raw = body.freeze();

            // ── Parse → service → reply ────────────────────────────────────────
            let query = match Query::try_from(raw) {
                Ok(q) => q,
                Err(e) => {
                    if let Some(id) = e.id {
                        // Recoverable FORMERR — send it and continue the pipeline.
                        let formerr = Response::formerr(id);
                        let framed = match framing::tcp::try_encode_length_prefix(&formerr) {
                            Ok(frame) => frame,
                            Err(e) => {
                                debug!(peer = %peer, error = %e, "TCP FORMERR too large to frame");
                                return;
                            }
                        };
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                        continue;
                    } else {
                        // Unrecoverable — close the connection.
                        trace!(peer = %peer, "TCP unrecoverable parse error; closing");
                        return;
                    }
                }
            };

            // TCP: no size limit, no TC bit — send the full reply.
            let req = DnsRequest::new(query, peer);
            let reply = Self::run_service(self.service.clone(), &req).await;
            let framed = match framing::tcp::try_encode_length_prefix(&reply) {
                Ok(frame) => frame,
                Err(e) => {
                    debug!(peer = %peer, reply_len = reply.len(), error = %e, "TCP reply too large to frame");
                    return;
                }
            };
            if stream.write_all(&framed).await.is_err() {
                return;
            }
            trace!(peer = %peer, reply_len = reply.len(), "TCP reply sent");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket as TokioUdpSocket};
    use tokio_util::{sync::CancellationToken, task::TaskTracker};

    use super::*;
    use crate::{
        codec::{
            framing,
            header::{Header, Rcode},
            name::Name,
            reader::Reader,
            synth::Response,
            writer::Writer,
        },
        resolver::pipeline::{BoxError, DnsRequest, Outcome, PipelineResponse},
    };

    // ── Query builders ────────────────────────────────────────────────────────

    fn build_a_query(id: u16, name: &str) -> Bytes {
        let mut w = Writer::with_capacity(64);
        Header::new(id).with_qdcount(1).with_rd(true).write(&mut w);
        let n: Name = name.parse().expect("valid name");
        n.write(&mut w);
        w.write_u16(1u16); // QTYPE A
        w.write_u16(1u16); // QCLASS IN
        w.finish()
    }

    fn parse_header(buf: &[u8]) -> Header {
        let mut r = Reader::new(Bytes::copy_from_slice(buf));
        Header::read(&mut r).expect("valid header")
    }

    // ── Stub services ─────────────────────────────────────────────────────────

    /// NoError stub: synthesizes a NOERROR/NODATA response.
    fn noerror_service(req: DnsRequest) -> std::future::Ready<Result<PipelineResponse, BoxError>> {
        let bytes = Response::error_response(req.query(), Rcode::NoError, req.edns());
        std::future::ready(Ok(PipelineResponse::new(bytes, Outcome::Forwarded)))
    }

    /// RateLimited stub: always returns a RateLimited error.
    fn rate_limited_service(
        _req: DnsRequest,
    ) -> std::future::Ready<Result<PipelineResponse, BoxError>> {
        std::future::ready(Err(
            Box::new(crate::resolver::pipeline::middleware::RateLimited) as BoxError,
        ))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Spawn listeners and return the cancellation token + tracker.
    fn spawn_listeners<S>(listeners: DnsListeners, service: S) -> (CancellationToken, TaskTracker)
    where
        S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        listeners.serve(service, token.clone(), &tracker);
        tracker.close();
        (token, tracker)
    }

    /// Cancel the token and wait for all tasks to drain (bounded by 2s).
    async fn shutdown(token: CancellationToken, tracker: TaskTracker) {
        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), tracker.wait())
            .await
            .expect("drain timed out");
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// UDP round-trip: send a valid A query, receive a reply with matching id.
    #[tokio::test]
    async fn udp_round_trip() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.udp[0].local_addr().expect("local_addr");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));

            let client = TokioUdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client bind");
            let query = build_a_query(0x1234, "example.com");
            client.send_to(&query, server_addr).await.expect("send");

            let mut buf = vec![0u8; 512];
            let (len, _) = client.recv_from(&mut buf).await.expect("recv");
            let hdr = parse_header(&buf[..len]);

            assert!(hdr.qr(), "QR must be set");
            assert_eq!(hdr.id, 0x1234, "id must match");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// TCP round-trip: connect, write length-prefixed query, read length-prefixed reply.
    #[tokio::test]
    async fn tcp_round_trip() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.tcp[0].local_addr().expect("local_addr");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));

            let mut stream = TcpStream::connect(server_addr).await.expect("connect");
            let query = build_a_query(0xBEEF, "tcp.example.com");
            let framed = framing::tcp::encode_length_prefix(&query);
            stream.write_all(&framed).await.expect("write");

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.expect("read len");
            let reply_len = u16::from_be_bytes(len_buf) as usize;
            let mut reply = vec![0u8; reply_len];
            stream.read_exact(&mut reply).await.expect("read reply");

            let hdr = parse_header(&reply);
            assert!(hdr.qr(), "QR must be set");
            assert_eq!(hdr.id, 0xBEEF, "id must match");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// Shutdown while a TCP client is stalled mid-frame must drain promptly.
    #[tokio::test]
    async fn tcp_body_read_observes_shutdown() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.tcp[0].local_addr().expect("local_addr");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));

            let mut stream = TcpStream::connect(server_addr).await.expect("connect");
            stream
                .write_all(&42u16.to_be_bytes())
                .await
                .expect("write length prefix");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// TCP pipelining: two queries on one connection, two replies in order.
    #[tokio::test]
    async fn tcp_pipelining() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.tcp[0].local_addr().expect("local_addr");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));

            let mut stream = TcpStream::connect(server_addr).await.expect("connect");

            // Send two queries back-to-back.
            let q1 = build_a_query(0x0001, "first.example.com");
            let q2 = build_a_query(0x0002, "second.example.com");
            stream
                .write_all(&framing::tcp::encode_length_prefix(&q1))
                .await
                .expect("write q1");
            stream
                .write_all(&framing::tcp::encode_length_prefix(&q2))
                .await
                .expect("write q2");

            // Receive first reply.
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.expect("read len1");
            let len1 = u16::from_be_bytes(len_buf) as usize;
            let mut r1 = vec![0u8; len1];
            stream.read_exact(&mut r1).await.expect("read reply1");

            // Receive second reply.
            stream.read_exact(&mut len_buf).await.expect("read len2");
            let len2 = u16::from_be_bytes(len_buf) as usize;
            let mut r2 = vec![0u8; len2];
            stream.read_exact(&mut r2).await.expect("read reply2");

            let h1 = parse_header(&r1);
            let h2 = parse_header(&r2);

            assert_eq!(h1.id, 0x0001, "first reply id");
            assert_eq!(h2.id, 0x0002, "second reply id");
            assert!(h1.qr() && h2.qr(), "both must be responses");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// Malformed UDP with recoverable id → FORMERR with matching id.
    ///
    /// A datagram with a 12-byte header but QDCOUNT=0 (parse fails after header)
    /// should produce a FORMERR reply.
    #[tokio::test]
    async fn udp_malformed_recoverable_id_gets_formerr() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.udp[0].local_addr().expect("local_addr");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));

            // Build a 12-byte header with QDCOUNT=0 (parse fails after header).
            let mut w = Writer::with_capacity(12);
            Header::new(0xDEAD)
                .with_rd(true)
                .with_qdcount(0)
                .write(&mut w);
            let bad_query = w.finish();

            let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("bind");
            client.send_to(&bad_query, server_addr).await.expect("send");

            let mut buf = vec![0u8; 512];
            let (len, _) = client.recv_from(&mut buf).await.expect("recv");
            let hdr = parse_header(&buf[..len]);

            assert_eq!(hdr.id, 0xDEAD, "FORMERR id must match");
            assert_eq!(hdr.rcode(), Rcode::FormErr, "rcode must be FORMERR");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// Malformed UDP with no recoverable id → no response.
    ///
    /// A datagram shorter than 12 bytes cannot yield an id, so nothing is sent.
    #[tokio::test]
    async fn udp_malformed_no_id_gets_no_response() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.udp[0].local_addr().expect("local_addr");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));

            // 5 bytes — too short to read the header.
            let short = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05]);

            let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("bind");
            client.send_to(&short, server_addr).await.expect("send");

            // No reply should arrive.
            let mut buf = vec![0u8; 512];
            let result =
                tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
            assert!(
                result.is_err(),
                "no reply expected for unrecoverable parse failure"
            );

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// Service error → REFUSED on UDP.
    #[tokio::test]
    async fn udp_service_error_returns_refused() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.udp[0].local_addr().expect("local_addr");

            let (token, tracker) =
                spawn_listeners(listeners, tower::service_fn(rate_limited_service));

            let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let query = build_a_query(0x5678, "refused.example.com");
            client.send_to(&query, server_addr).await.expect("send");

            let mut buf = vec![0u8; 512];
            let (len, _) = client.recv_from(&mut buf).await.expect("recv");
            let hdr = parse_header(&buf[..len]);

            assert_eq!(hdr.id, 0x5678, "id must be preserved");
            assert_eq!(hdr.rcode(), Rcode::Refused, "rcode must be REFUSED");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// TC bit on oversized UDP reply.
    ///
    /// The stub returns a padded 600-byte response when the query has no EDNS
    /// (limit = 512).  The UDP handler must replace the oversized reply with a
    /// TC=1 minimal response.
    #[tokio::test]
    async fn udp_oversized_reply_gets_tc_bit() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");
            let server_addr = listeners.udp[0].local_addr().expect("local_addr");

            // Stub: build a proper NOERROR response, then pad it to 600 bytes.
            // No EDNS → limit = 512.  600 > 512 → TC=1 truncation.
            let (token, tracker) = spawn_listeners(
                listeners,
                tower::service_fn(|req: DnsRequest| {
                    let mut resp =
                        Response::error_response(req.query(), Rcode::NoError, req.edns()).to_vec();
                    resp.resize(600, 0u8);
                    let bytes = Bytes::from(resp);
                    std::future::ready(Ok::<_, BoxError>(PipelineResponse::new(
                        bytes,
                        Outcome::Forwarded,
                    )))
                }),
            );

            let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("bind");
            // No EDNS OPT → limit = 512.
            let query = build_a_query(0xABCD, "big.example.com");
            client.send_to(&query, server_addr).await.expect("send");

            let mut buf = vec![0u8; 1500];
            let (len, _) = client.recv_from(&mut buf).await.expect("recv");
            let hdr = parse_header(&buf[..len]);

            assert_eq!(hdr.id, 0xABCD, "id must be preserved in TC response");
            assert!(hdr.tc(), "TC must be set");
            assert_eq!(hdr.ancount, 0, "ancount must be 0 in TC response");

            shutdown(token, tracker).await;
        })
        .await
        .expect("test timed out");
    }

    /// Shutdown drains: after cancel, tracker.wait() completes within timeout.
    #[tokio::test]
    async fn shutdown_drains() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listeners = DnsListeners::bind(&[bind_addr], 1).expect("bind");

            let (token, tracker) = spawn_listeners(listeners, tower::service_fn(noerror_service));
            shutdown(token, tracker).await;
            // If we reach here, drain completed within the timeout.
        })
        .await
        .expect("test timed out");
    }
}
