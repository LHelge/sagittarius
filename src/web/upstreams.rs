//! Upstream resolver management (SPEC §9, §7).
//!
//! List / add / remove / enable-disable upstream resolvers, written through to
//! E3.4.  Every change **rebuilds the live upstream pool** (E5) from the enabled
//! rows and atomically swaps it into the shared
//! [`SharedUpstreamPool`](crate::resolver::upstream::SharedUpstreamPool), so
//! forwarding starts using the new set immediately while in-flight queries
//! finish on the old snapshot.
//!
//! v0.1 only forwards to upstreams addressable as an IP (optionally with a
//! port); hostname / DoH-URL upstreams are not yet supported (see
//! [`upstream_config_from_row`]) and are rejected at add time so an entry can
//! never be silently ineffective.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    resolver::upstream::{
        DEFAULT_FAILOVER_BUDGET, DEFAULT_QUERY_TIMEOUT, RandomSelector, UpstreamConfig,
        UpstreamPool,
    },
    storage::upstreams::{NewUpstream, Transport, Upstream, UpstreamRepository},
    web::{
        AppState, Chrome,
        auth::CurrentUser,
        render::{WebError, WebResult},
    },
};

impl AppState {
    /// Rebuild the live upstream pool from the enabled rows and swap it in.
    async fn rebuild_upstream_pool(&self) -> WebResult<()> {
        let rows = self.db.upstreams().list_enabled().await?;
        let configs: Vec<_> = rows
            .iter()
            .filter_map(|r| UpstreamConfig::try_from(r).ok())
            .collect();
        let new_pool = UpstreamPool::connect(
            &configs,
            &self.tracker,
            Arc::new(RandomSelector),
            DEFAULT_FAILOVER_BUDGET,
            DEFAULT_QUERY_TIMEOUT,
        )
        .await;
        self.upstream_pool.store(new_pool);
        Ok(())
    }

    async fn render_upstreams(
        &self,
        user: &CurrentUser,
        error: Option<String>,
    ) -> WebResult<UpstreamsPageTemplate> {
        let upstreams = self
            .db
            .upstreams()
            .list()
            .await?
            .into_iter()
            .map(|u| UpstreamView {
                id: u.id,
                address: u.address,
                transport: u.transport.as_str(),
                server_name: u.tls_server_name.unwrap_or_default(),
                enabled: u.enabled,
            })
            .collect();
        Ok(UpstreamsPageTemplate {
            chrome: self.chrome("upstreams", user).await,
            upstreams,
            error,
        })
    }

    /// `GET /upstreams`.
    pub async fn upstreams_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        Ok(state.render_upstreams(&user, None).await?.into_response())
    }

    /// `POST /upstreams/add`.
    pub async fn upstream_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<AddUpstreamForm>,
    ) -> WebResult<Response> {
        match state.add_upstream(form).await {
            Ok(()) => Ok(Redirect::to("/upstreams").into_response()),
            // A validation error re-renders the form with the message and a 400.
            Err(WebError::BadRequest(msg)) => {
                let page = state.render_upstreams(&user, Some(msg)).await?;
                Ok((StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    async fn add_upstream(&self, form: AddUpstreamForm) -> WebResult<()> {
        let transport: Transport = form
            .transport
            .parse()
            .map_err(|_| WebError::bad_request("Transport must be one of udp, tcp, dot, doh."))?;
        let address = form.address.trim().to_owned();
        let server_name = match form.server_name.trim() {
            "" => None,
            s => Some(s.to_owned()),
        };

        if matches!(transport, Transport::Dot | Transport::Doh) && server_name.is_none() {
            return Err(WebError::bad_request(
                "A TLS server name is required for DoT and DoH upstreams.",
            ));
        }

        // Reject anything the engine could not actually use, so an upstream is
        // never silently ineffective.
        let probe = Upstream {
            id: 0,
            address: address.clone(),
            transport,
            tls_server_name: server_name.clone(),
            enabled: true,
            sort_order: 0,
        };
        if UpstreamConfig::try_from(&probe).is_err() {
            return Err(WebError::bad_request(
                "Address must be an IP address (optionally with :port); hostnames and DoH URLs are not supported in v0.1.",
            ));
        }

        self.db
            .upstreams()
            .insert(NewUpstream {
                address,
                transport,
                tls_server_name: server_name,
                enabled: true,
                sort_order: 0,
            })
            .await?;
        self.rebuild_upstream_pool().await
    }

    /// `POST /upstreams/remove`.
    pub async fn upstream_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<UpstreamIdForm>,
    ) -> WebResult<Response> {
        state.db.upstreams().delete(form.id).await?;
        state.rebuild_upstream_pool().await?;
        Ok(Redirect::to("/upstreams").into_response())
    }

    /// `POST /upstreams/toggle`.
    pub async fn upstream_toggle(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<ToggleUpstreamForm>,
    ) -> WebResult<Response> {
        state
            .db
            .upstreams()
            .set_enabled(form.id, form.enabled)
            .await?;
        state.rebuild_upstream_pool().await?;
        Ok(Redirect::to("/upstreams").into_response())
    }
}

/// Add-upstream form payload.
#[derive(Debug, Deserialize)]
pub struct AddUpstreamForm {
    address: String,
    transport: String,
    #[serde(default)]
    server_name: String,
}

/// Form payload carrying just an upstream id.
#[derive(Debug, Deserialize)]
pub struct UpstreamIdForm {
    id: i64,
}

/// Enable/disable form payload.
#[derive(Debug, Deserialize)]
pub struct ToggleUpstreamForm {
    id: i64,
    enabled: bool,
}

/// One upstream row for display.
struct UpstreamView {
    id: i64,
    address: String,
    transport: &'static str,
    server_name: String,
    enabled: bool,
}

/// The upstreams management page.
#[derive(Template, WebTemplate)]
#[template(path = "upstreams.html")]
struct UpstreamsPageTemplate {
    chrome: Chrome,
    upstreams: Vec<UpstreamView>,
    error: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let (dir, db) = crate::test_support::temp_db().await;
        (dir, AppState::for_test(db).await)
    }

    fn form(address: &str, transport: &str, sni: &str) -> AddUpstreamForm {
        AddUpstreamForm {
            address: address.to_owned(),
            transport: transport.to_owned(),
            server_name: sni.to_owned(),
        }
    }

    #[tokio::test]
    async fn add_ip_upstream_persists_and_rebuilds() {
        let (_d, st) = state().await;
        let before = st.db.upstreams().list().await.unwrap().len();
        st.add_upstream(form("9.9.9.9", "udp", ""))
            .await
            .expect("add");
        let after = st.db.upstreams().list().await.unwrap();
        assert_eq!(after.len(), before + 1);
        assert!(after.iter().any(|u| u.address == "9.9.9.9"));
    }

    #[tokio::test]
    async fn add_dot_without_sni_is_rejected() {
        let (_d, st) = state().await;
        let err = st
            .add_upstream(form("1.1.1.1", "dot", ""))
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }

    #[tokio::test]
    async fn add_hostname_upstream_is_rejected() {
        let (_d, st) = state().await;
        let err = st
            .add_upstream(form("dns.quad9.net", "udp", ""))
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }

    #[tokio::test]
    async fn bad_transport_is_rejected() {
        let (_d, st) = state().await;
        let err = st
            .add_upstream(form("9.9.9.9", "grpc", ""))
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }
}
