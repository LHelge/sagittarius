//! Upstream transport clients for DNS forwarding (SPEC §7).
//!
//! Provides hickory-backed client handles over all four transports supported by
//! Sagittarius: plain UDP (port 53), plain TCP (port 53), DNS-over-TLS (DoT,
//! port 853), and DNS-over-HTTPS (DoH, port 443).
//!
//! The caller is responsible for:
//! - Selecting the right `UpstreamTransport` and filling in `UpstreamConfig`.
//! - Applying default ports at the wiring boundary (53 / 853 / 443).
//! - Spawning the `UpstreamBackground` future returned by [`client::UpstreamClient::connect`].

use std::fmt;

pub mod client;
pub mod forward;

pub use client::{UpstreamBackground, UpstreamClient};
pub use forward::{DEFAULT_QUERY_TIMEOUT, ForwardResult};

// ── Transport enum ────────────────────────────────────────────────────────────

/// The network transport to use when forwarding queries to an upstream resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTransport {
    /// Plain DNS over UDP (RFC 1035).
    Udp,
    /// Plain DNS over TCP (RFC 1035).
    Tcp,
    /// DNS over TLS (DoT, RFC 7858).
    Dot,
    /// DNS over HTTPS (DoH, RFC 8484).
    Doh,
}

impl fmt::Display for UpstreamTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => f.write_str("UDP"),
            Self::Tcp => f.write_str("TCP"),
            Self::Dot => f.write_str("DoT"),
            Self::Doh => f.write_str("DoH"),
        }
    }
}

// ── Runtime config ─────────────────────────────────────────────────────────────

/// DB-decoupled runtime configuration for a single upstream resolver.
///
/// Default ports (53 for Udp/Tcp, 853 for Dot, 443 for Doh) must be applied
/// by the caller when building the [`std::net::SocketAddr`].
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Remote address (IP + port) of the upstream resolver.
    pub addr: std::net::SocketAddr,
    /// Transport to use when connecting.
    pub transport: UpstreamTransport,
    /// TLS SNI hostname; required for [`UpstreamTransport::Dot`] and
    /// [`UpstreamTransport::Doh`], ignored for UDP/TCP.
    pub tls_server_name: Option<String>,
    /// DoH request path; defaults to `/dns-query` when `None`.
    /// Only used for [`UpstreamTransport::Doh`].
    pub http_endpoint: Option<String>,
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can arise while building or operating an upstream transport client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A stream transport (TCP / DoT) failed to connect.
    #[error("failed to connect upstream {transport} transport: {source}")]
    Connect {
        transport: UpstreamTransport,
        #[source]
        source: hickory_net::NetError,
    },

    /// A TLS SNI name is missing or syntactically invalid (required for DoT/DoH).
    #[error("invalid or missing TLS server name: {0}")]
    InvalidServerName(String),

    /// A generic transport-level error not covered by the variants above.
    #[error("upstream transport error: {0}")]
    Transport(String),

    /// The per-attempt query timeout elapsed before the upstream responded.
    #[error("upstream {transport} query timed out")]
    Timeout { transport: UpstreamTransport },

    /// Hickory reported a send/receive failure during the DNS exchange.
    #[error("upstream {transport} exchange failed: {source}")]
    Exchange {
        transport: UpstreamTransport,
        #[source]
        source: hickory_net::NetError,
    },
}

/// Convenience alias for `Result<T, upstream::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn transport_display() {
        assert_eq!(UpstreamTransport::Udp.to_string(), "UDP");
        assert_eq!(UpstreamTransport::Tcp.to_string(), "TCP");
        assert_eq!(UpstreamTransport::Dot.to_string(), "DoT");
        assert_eq!(UpstreamTransport::Doh.to_string(), "DoH");
    }

    #[test]
    fn config_construction() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853);
        let cfg = UpstreamConfig {
            addr,
            transport: UpstreamTransport::Dot,
            tls_server_name: Some("one.one.one.one".to_owned()),
            http_endpoint: None,
        };
        assert_eq!(cfg.addr, addr);
        assert_eq!(cfg.transport, UpstreamTransport::Dot);
        assert_eq!(cfg.tls_server_name.as_deref(), Some("one.one.one.one"));
        assert!(cfg.http_endpoint.is_none());
    }

    #[tokio::test]
    async fn dot_missing_server_name_returns_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853);
        let cfg = UpstreamConfig {
            addr,
            transport: UpstreamTransport::Dot,
            tls_server_name: None,
            http_endpoint: None,
        };
        let result = UpstreamClient::connect(&cfg).await;
        assert!(
            matches!(result, Err(Error::InvalidServerName(_))),
            "expected InvalidServerName error"
        );
    }

    #[tokio::test]
    async fn doh_missing_server_name_returns_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let cfg = UpstreamConfig {
            addr,
            transport: UpstreamTransport::Doh,
            tls_server_name: None,
            http_endpoint: None,
        };
        let result = UpstreamClient::connect(&cfg).await;
        assert!(
            matches!(result, Err(Error::InvalidServerName(_))),
            "expected InvalidServerName error"
        );
    }
}
