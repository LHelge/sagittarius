//! Hickory-backed upstream client factory and handle type.
//!
//! [`UpstreamClient::connect`] builds a transport-specific stream, wraps it in
//! a hickory [`Client`], and returns the handle together with a background
//! driver future that the caller must [`tokio::spawn`].

use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_net::client::Client;
use hickory_net::runtime::TokioRuntimeProvider;

use super::{Error, Result, UpstreamConfig, UpstreamTransport};

/// Default connect / request timeout for stream transports.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ── UpstreamBackground ────────────────────────────────────────────────────────

/// Boxed background driver future.
///
/// Each hickory transport returns a concrete `DnsExchangeBackground<S, P::Timer>`
/// with a different `S` type argument; we erase it here so callers can store or
/// spawn the future uniformly.
pub type UpstreamBackground =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

// ── UpstreamClient ────────────────────────────────────────────────────────────

/// A cheaply cloneable hickory client handle for a single upstream resolver.
///
/// Wraps `hickory_net::client::Client<TokioRuntimeProvider>` together with the
/// transport that was used to connect it (useful for logging / diagnostics).
#[derive(Clone)]
pub struct UpstreamClient {
    handle: Client<TokioRuntimeProvider>,
    transport: UpstreamTransport,
    /// The upstream's address, retained so the pool can attribute an answer (and
    /// its latency) to a specific resolver (E15).
    addr: SocketAddr,
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamClient")
            .field("transport", &self.transport)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl UpstreamClient {
    /// Connect to the upstream resolver described by `config` and return the
    /// client handle plus the background driver future.
    ///
    /// The caller **must** spawn the returned `UpstreamBackground` future
    /// (e.g. via `tokio::spawn(bg)`) before sending any queries through the
    /// returned `UpstreamClient`; the background task drives all I/O.
    pub async fn connect(config: &UpstreamConfig) -> Result<(Self, UpstreamBackground)> {
        match config.transport {
            UpstreamTransport::Udp => Self::connect_udp(config).await,
            UpstreamTransport::Tcp => Self::connect_tcp(config).await,
            UpstreamTransport::Dot => Self::connect_dot(config).await,
            UpstreamTransport::Doh => Self::connect_doh(config).await,
        }
    }

    /// Returns a reference to the underlying hickory client handle.
    pub fn handle(&self) -> &Client<TokioRuntimeProvider> {
        &self.handle
    }

    /// Returns the transport that was used to build this client.
    pub fn transport(&self) -> UpstreamTransport {
        self.transport
    }

    /// Returns the address of the upstream resolver this client targets.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    // ── per-transport builders ────────────────────────────────────────────────

    async fn connect_udp(config: &UpstreamConfig) -> Result<(Self, UpstreamBackground)> {
        use hickory_net::udp::UdpClientStream;

        let provider = TokioRuntimeProvider::default();
        let stream = UdpClientStream::builder(config.addr, provider)
            .with_timeout(Some(CONNECT_TIMEOUT))
            .build();
        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        Ok((
            Self {
                handle: client,
                transport: config.transport,
                addr: config.addr,
            },
            Box::pin(bg),
        ))
    }

    async fn connect_tcp(config: &UpstreamConfig) -> Result<(Self, UpstreamBackground)> {
        use hickory_net::tcp::TcpClientStream;

        let provider = TokioRuntimeProvider::default();
        let (connect, handle) =
            TcpClientStream::new(config.addr, None, Some(CONNECT_TIMEOUT), provider);
        let stream = connect.await.map_err(|e| Error::Connect {
            transport: UpstreamTransport::Tcp,
            source: e,
        })?;
        let (client, bg) = Client::<TokioRuntimeProvider>::new(stream, handle);
        Ok((
            Self {
                handle: client,
                transport: config.transport,
                addr: config.addr,
            },
            Box::pin(bg),
        ))
    }

    async fn connect_dot(config: &UpstreamConfig) -> Result<(Self, UpstreamBackground)> {
        use hickory_net::tls::tls_client_connect;

        let name = config
            .tls_server_name
            .clone()
            .ok_or_else(|| Error::InvalidServerName("DoT requires tls_server_name".into()))?;
        let server_name = rustls_pki_types::ServerName::try_from(name.clone())
            .map_err(|_| Error::InvalidServerName(name))?;
        let tls_config = Arc::new(
            hickory_net::tls::client_config().map_err(|e| Error::Transport(e.to_string()))?,
        );
        let provider = TokioRuntimeProvider::default();
        let (connect, handle) = tls_client_connect(config.addr, server_name, tls_config, provider);
        let stream = connect.await.map_err(|e| Error::Connect {
            transport: UpstreamTransport::Dot,
            source: e,
        })?;
        let (client, bg) = Client::<TokioRuntimeProvider>::new(stream, handle);
        Ok((
            Self {
                handle: client,
                transport: config.transport,
                addr: config.addr,
            },
            Box::pin(bg),
        ))
    }

    async fn connect_doh(config: &UpstreamConfig) -> Result<(Self, UpstreamBackground)> {
        use hickory_net::h2::HttpsClientStream;

        let name = config
            .tls_server_name
            .clone()
            .ok_or_else(|| Error::InvalidServerName("DoH requires tls_server_name".into()))?;
        let path = config
            .http_endpoint
            .clone()
            .unwrap_or_else(|| "/dns-query".to_owned());
        let tls_config = Arc::new(
            hickory_net::tls::client_config().map_err(|e| Error::Transport(e.to_string()))?,
        );
        let provider = TokioRuntimeProvider::default();
        let stream = HttpsClientStream::builder(tls_config, provider)
            .build(
                config.addr,
                Arc::from(name.as_str()),
                Arc::from(path.as_str()),
            )
            .await
            .map_err(|e| Error::Connect {
                transport: UpstreamTransport::Doh,
                source: e,
            })?;
        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        Ok((
            Self {
                handle: client,
                transport: config.transport,
                addr: config.addr,
            },
            Box::pin(bg),
        ))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tokio::time::timeout;

    use super::*;
    use crate::resolver::upstream::UpstreamConfig;

    // ── UDP ───────────────────────────────────────────────────────────────────

    /// Stand up a minimal UDP responder, connect a UDP `UpstreamClient` to it,
    /// send a query through the hickory handle, and assert we get a response back.
    #[tokio::test]
    async fn udp_client_construction_and_roundtrip() {
        use hickory_net::proto::op::{DnsRequest, DnsRequestOptions, Message, Query};
        use hickory_net::proto::rr::{Name, RecordType};
        use hickory_net::xfer::{DnsHandle, FirstAnswer as _};
        use tokio::net::UdpSocket;

        // Bind an ephemeral UDP socket that will echo back a minimal DNS response.
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        // Spawn a task that reads one datagram and echoes back a QR=1 copy.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let (len, peer) = server_sock.recv_from(&mut buf).await.unwrap();
            // Set the QR bit (0x80 in byte 2, i.e. the flags high byte).
            // DNS header: [id(2)] [flags(2)] [qdcount(2)] [ancount(2)] [nscount(2)] [arcount(2)]
            if len >= 3 {
                buf[2] |= 0x80; // set QR bit
            }
            server_sock.send_to(&buf[..len], peer).await.unwrap();
        });

        let cfg = UpstreamConfig {
            addr: server_addr,
            transport: UpstreamTransport::Udp,
            tls_server_name: None,
            http_endpoint: None,
        };

        let (client, bg) = UpstreamClient::connect(&cfg).await.unwrap();
        tokio::spawn(bg);

        // Build a minimal query for example.com A.
        let name = Name::from_ascii("example.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        let mut msg = Message::query();
        msg.add_query(query);
        let request = DnsRequest::new(msg, DnsRequestOptions::default());

        // Send the query and drive the response stream to its first item. The mock
        // echoes our datagram back with the QR bit set, so this exercises the full
        // round-trip: handle.send → mock → hickory matches the response to the
        // request by id + question → yields it. Bounded by a timeout so a
        // regression can never hang CI.
        let response = timeout(
            Duration::from_secs(5),
            client.handle().send(request).first_answer(),
        )
        .await
        .expect("timed out waiting for a UDP response from the local mock")
        .expect("expected a DNS response from the local mock upstream");

        // `into_buffer()` yields the exact upstream wire bytes (the method E5.2
        // will use). The mock set the QR bit (byte 2, high bit) on the echo, so
        // its presence confirms the reply was matched back to our request.
        let buf = response.into_buffer();
        assert!(buf.len() >= 3, "response datagram too short: {}", buf.len());
        assert_eq!(buf[2] & 0x80, 0x80, "QR bit must be set on the response");
    }

    // ── TCP ───────────────────────────────────────────────────────────────────

    /// Verify TCP construction: bind a listener, connect the client, assert
    /// the handle + background are created without error.
    #[tokio::test]
    async fn tcp_client_construction() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept and immediately drop the connection (we only test construction).
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let cfg = UpstreamConfig {
            addr,
            transport: UpstreamTransport::Tcp,
            tls_server_name: None,
            http_endpoint: None,
        };

        let result = timeout(Duration::from_secs(5), UpstreamClient::connect(&cfg)).await;
        assert!(result.is_ok(), "timeout during TCP connect");
        let (_client, bg) = result.expect("timeout").expect("TCP connect failed");
        // Prove the background can be spawned without panic.
        tokio::spawn(bg);
    }

    // ── DoT (network, opt-in) ─────────────────────────────────────────────────

    #[ignore = "requires network access to 1.1.1.1:853"]
    #[tokio::test]
    async fn dot_client_connects_to_cloudflare() {
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
        assert_eq!(client.transport(), UpstreamTransport::Dot);
    }

    // ── DoH (network, opt-in) ─────────────────────────────────────────────────

    #[ignore = "requires network access to 1.1.1.1:443"]
    #[tokio::test]
    async fn doh_client_connects_to_cloudflare() {
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
        assert_eq!(client.transport(), UpstreamTransport::Doh);
    }
}
