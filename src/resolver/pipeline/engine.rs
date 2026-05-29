//! Engine assembly: wires the full DNS pipeline into a single cloneable service.
//!
//! This module provides:
//!
//! - [`TelemetryLayer`] / [`TelemetryService`] — the **outermost** layer that
//!   records a [`QueryEvent`] for every query (including ones rejected by the
//!   protective layers before reaching the decision stack).
//!
//! - [`build_engine`] — composes the complete pipeline:
//!   `TelemetryLayer` → `protective middleware` → `DecisionStack` → `ForwardService`
//!   and returns a [`tower::util::BoxCloneService`] ready for the DNS listener.
//!
//! - [`upstream_config_from_row`] — maps a persisted [`storage::upstreams::Upstream`]
//!   row to a runtime [`UpstreamConfig`], applying default ports per transport
//!   and returning `None` for rows that cannot be resolved to an IP:port (e.g.
//!   hostname-only DoH URLs, which are out of scope for v0.1).

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use tower::{Layer, Service, ServiceExt as _};

use crate::{
    resolver::{
        pipeline::{
            BoxError, DnsRequest, PipelineResponse,
            forward::ForwardService,
            layers::DecisionStack,
            middleware::{ProtectiveConfig, build_protective_service, classify_rejection},
        },
        state::ResolverState,
        upstream::{SharedUpstreamPool, UpstreamConfig, UpstreamTransport},
    },
    storage::upstreams::{Transport, Upstream},
    telemetry::{QueryEvent, TelemetrySink},
};

// ── TelemetryLayer ────────────────────────────────────────────────────────────

/// A [`tower::Layer`] that wraps a service with [`TelemetryService`].
///
/// Place this as the **outermost** layer so every query — including those
/// rejected by rate-limiting or load-shedding before the decision stack — is
/// logged.
pub struct TelemetryLayer {
    sink: Arc<TelemetrySink>,
}

impl TelemetryLayer {
    /// Create a new [`TelemetryLayer`] backed by `sink`.
    pub fn new(sink: Arc<TelemetrySink>) -> Self {
        Self { sink }
    }
}

impl<S> Layer<S> for TelemetryLayer {
    type Service = TelemetryService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TelemetryService {
            sink: self.sink.clone(),
            inner,
        }
    }
}

// ── TelemetryService ──────────────────────────────────────────────────────────

/// The service produced by [`TelemetryLayer`].
///
/// Records a [`QueryEvent`] for every query processed by the pipeline,
/// including error paths (rate-limited, load-shed, timeout).
#[derive(Clone)]
pub struct TelemetryService<S> {
    sink: Arc<TelemetrySink>,
    inner: S,
}

impl<S> Service<DnsRequest> for TelemetryService<S>
where
    S: Service<DnsRequest, Response = PipelineResponse, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = PipelineResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<PipelineResponse, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: DnsRequest) -> Self::Future {
        let start = Instant::now();
        let client = req.client();
        let qname = req.question().name.clone();
        let qtype = req.question().qtype;
        let sink = self.sink.clone();

        // Clone-and-replace pattern: move the poll_ready'd service into the
        // future and leave a fresh clone in `self`.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let result = inner.call(req).await;

            let latency = start.elapsed();
            let (outcome, rcode) = match &result {
                Ok(resp) => (resp.outcome, None),
                Err(e) => {
                    let (o, rc) = classify_rejection(e);
                    (o, Some(rc))
                }
            };

            let mut ev = QueryEvent::new(client, qname, qtype, outcome).with_latency(latency);
            if let Some(rc) = rcode {
                ev = ev.with_rcode(rc);
            }
            sink.record(ev);

            // Propagate the result unchanged; the listener maps Err → wire bytes.
            result
        })
    }
}

// ── build_engine ──────────────────────────────────────────────────────────────

/// Compose the full DNS engine into a single cloneable service.
///
/// Layer order (outermost → innermost):
/// 1. [`TelemetryLayer`] — records every query (including protective rejections)
/// 2. Protective middleware (`rate-limit`, `load-shed`, `concurrency`, `timeout`)
/// 3. [`DecisionStack`] — local / blacklist / allowlist / blocklist / cache
/// 4. [`ForwardService`] — upstream forwarding + cache-store leaf
///
/// The returned [`tower::util::BoxCloneService`] is cloned once per datagram
/// by the UDP listener (see `DnsListeners::serve`).
pub fn build_engine(
    state: Arc<ResolverState>,
    pool: Arc<SharedUpstreamPool>,
    telemetry: Arc<TelemetrySink>,
    config: &ProtectiveConfig,
) -> tower::util::BoxCloneService<DnsRequest, PipelineResponse, BoxError> {
    let forward = ForwardService::new(pool, state.clone());
    let decision = DecisionStack::new(state, forward);
    let protected = build_protective_service(config, decision);

    TelemetryLayer::new(telemetry)
        .layer(protected)
        .boxed_clone()
}

// ── upstream_config_from_row ──────────────────────────────────────────────────

/// Map a persisted [`Upstream`] row to a runtime [`UpstreamConfig`].
///
/// Default ports are applied per transport:
/// - UDP / TCP → 53
/// - DoT → 853
/// - DoH → 443
///
/// Address parsing:
/// - If `row.address` parses as `SocketAddr` (explicit port), use it as-is.
/// - If `row.address` parses as `IpAddr`, combine with the default port.
/// - Otherwise (e.g. a DoH URL / hostname) → returns `None`; the caller
///   should log a warning and skip the row.
///
/// The seeded upstreams (1.1.1.1 and 1.0.0.1, UDP) both parse as `IpAddr`
/// and are mapped correctly.
pub fn upstream_config_from_row(row: &Upstream) -> Option<UpstreamConfig> {
    let transport = match row.transport {
        Transport::Udp => UpstreamTransport::Udp,
        Transport::Tcp => UpstreamTransport::Tcp,
        Transport::Dot => UpstreamTransport::Dot,
        Transport::Doh => UpstreamTransport::Doh,
    };

    let default_port = match transport {
        UpstreamTransport::Udp | UpstreamTransport::Tcp => 53u16,
        UpstreamTransport::Dot => 853,
        UpstreamTransport::Doh => 443,
    };

    let addr: SocketAddr = if let Ok(sa) = row.address.parse::<SocketAddr>() {
        // Already has an explicit port — use as-is.
        sa
    } else if let Ok(ip) = row.address.parse::<IpAddr>() {
        // Bare IP — attach the default port for this transport.
        SocketAddr::new(ip, default_port)
    } else {
        // Unparseable (e.g. a DoH URL or hostname) — skip.
        return None;
    };

    Some(UpstreamConfig {
        addr,
        transport,
        tls_server_name: row.tls_server_name.clone(),
        http_endpoint: None, // defaults to /dns-query for DoH
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::storage::upstreams::{Transport, Upstream};

    fn make_row(address: &str, transport: Transport, tls_server_name: Option<&str>) -> Upstream {
        Upstream {
            id: 1,
            address: address.to_owned(),
            transport,
            tls_server_name: tls_server_name.map(|s| s.to_owned()),
            enabled: true,
            sort_order: 0,
        }
    }

    // ── upstream_config_from_row unit tests ───────────────────────────────────

    /// Bare IP "1.1.1.1" with UDP transport → default port 53.
    #[test]
    fn udp_bare_ip_gets_default_port_53() {
        let row = make_row("1.1.1.1", Transport::Udp, None);
        let cfg = upstream_config_from_row(&row).expect("must map");
        assert_eq!(cfg.addr, "1.1.1.1:53".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.transport, UpstreamTransport::Udp);
        assert!(cfg.tls_server_name.is_none());
    }

    /// Explicit port "9.9.9.9:8053" with UDP → port preserved.
    #[test]
    fn udp_explicit_port_preserved() {
        let row = make_row("9.9.9.9:8053", Transport::Udp, None);
        let cfg = upstream_config_from_row(&row).expect("must map");
        assert_eq!(cfg.addr, "9.9.9.9:8053".parse::<SocketAddr>().unwrap());
    }

    /// DoT bare IP with SNI → default port 853, tls_server_name carried through.
    #[test]
    fn dot_bare_ip_gets_default_port_853_with_sni() {
        let row = make_row("1.1.1.1", Transport::Dot, Some("cloudflare-dns.com"));
        let cfg = upstream_config_from_row(&row).expect("must map");
        assert_eq!(
            cfg.addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853)
        );
        assert_eq!(cfg.transport, UpstreamTransport::Dot);
        assert_eq!(cfg.tls_server_name.as_deref(), Some("cloudflare-dns.com"));
    }

    /// A DoH URL / hostname ("https://cloudflare-dns.com/dns-query") → `None`.
    #[test]
    fn doh_url_hostname_returns_none() {
        let row = make_row(
            "https://cloudflare-dns.com/dns-query",
            Transport::Doh,
            Some("cloudflare-dns.com"),
        );
        let cfg = upstream_config_from_row(&row);
        assert!(
            cfg.is_none(),
            "DoH URL / hostname must not map to an UpstreamConfig in v0.1"
        );
    }

    /// A plain hostname without port → `None`.
    #[test]
    fn plain_hostname_returns_none() {
        let row = make_row("dns.quad9.net", Transport::Udp, None);
        let cfg = upstream_config_from_row(&row);
        assert!(cfg.is_none(), "plain hostname must return None");
    }
}
