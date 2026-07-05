//! Local DNS record management (SPEC §9, §5).
//!
//! CRUD for authoritative local records, including wildcards (`*.home.lan`).
//! Each record has a type (A/AAAA), value, and TTL; a single name may carry
//! both an A and an AAAA record (uniqueness is `(name, type)`).
//!
//! Mutations follow the write-through + snapshot-swap pattern: persist to E3,
//! then rebuild the [`LocalRecords`] snapshot from the database and swap it into
//! the shared [`ResolverState`](crate::resolver::state::ResolverState) so the
//! change resolves authoritatively on the next query.

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    resolver::{
        local::{LocalRecords, RecordData},
        state::build_local_records,
    },
    storage::local_records::{LocalRecordRepository, NewLocalRecord, RecordType},
    web::{
        AppState, Chrome,
        auth::CurrentUser,
        render::{DomainDisplay, WebError, WebResult},
    },
};

impl AppState {
    /// Rebuild the in-memory local-record snapshot from the database.
    pub(crate) async fn reload_local_records(&self) -> WebResult<()> {
        let rows = self.db.local_records().load_all().await?;
        let records = build_local_records(rows).map_err(|e| WebError::internal(e.to_string()))?;
        self.resolver.local().store(records);
        // The reverse index (and therefore hostname decoration, E14) is derived
        // from these records — drop cached reverse lookups so an edit takes
        // effect on the next render instead of waiting out the cache TTL.
        self.reverse.clear();
        Ok(())
    }

    /// Add a local record (validate, write through, swap).
    async fn add_local_record(
        &self,
        name: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> WebResult<()> {
        validate_local(name, record_type, value, ttl)?;
        self.db
            .local_records()
            .add(NewLocalRecord {
                name: name.to_owned(),
                record_type,
                value: value.to_owned(),
                ttl,
            })
            .await
            .map_err(|e| match e {
                // The only expected failure here is the (name, type) UNIQUE
                // constraint — surface it as a friendly client error.
                crate::storage::Error::Sqlx(_) => WebError::bad_request(format!(
                    "A {record_type} record already exists for {name}."
                )),
                other => WebError::from(other),
            })?;
        self.reload_local_records().await
    }

    /// Remove a local record by id (write through, swap).
    async fn remove_local_record(&self, id: i64) -> WebResult<()> {
        self.db.local_records().remove(id).await?;
        self.reload_local_records().await
    }

    async fn render_local(
        &self,
        user: &CurrentUser,
        error: Option<String>,
    ) -> WebResult<LocalPageTemplate> {
        let records = self
            .db
            .local_records()
            .list()
            .await?
            .into_iter()
            .map(|r| LocalRecordView {
                id: r.id,
                // Display the bare name; the stored value keeps its trailing dot.
                name: r.name.display_domain().to_owned(),
                record_type: r.record_type.as_str(),
                value: r.value,
                ttl: r.ttl,
            })
            .collect();
        Ok(LocalPageTemplate {
            chrome: self.chrome("local", user).await,
            records,
            error,
        })
    }

    /// `GET /local`.
    pub async fn local_page(
        user: CurrentUser,
        State(state): State<AppState>,
    ) -> WebResult<Response> {
        Ok(state.render_local(&user, None).await?.into_response())
    }

    /// `POST /local/add`.
    pub async fn local_add(
        user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<AddLocalForm>,
    ) -> WebResult<Response> {
        let record_type = form
            .record_type
            .parse::<RecordType>()
            .map_err(|_| WebError::bad_request("Record type must be A or AAAA."))?;
        match state
            .add_local_record(&form.name, record_type, &form.value, form.ttl)
            .await
        {
            Ok(()) => Ok(Redirect::to("/local").into_response()),
            // A validation error re-renders the form with the message and a 400.
            Err(WebError::BadRequest(msg)) => {
                let page = state.render_local(&user, Some(msg)).await?;
                Ok((StatusCode::BAD_REQUEST, page).into_response())
            }
            Err(e) => Err(e),
        }
    }

    /// `POST /local/remove`.
    pub async fn local_remove(
        _user: CurrentUser,
        State(state): State<AppState>,
        axum::Form(form): axum::Form<RemoveLocalForm>,
    ) -> WebResult<Response> {
        state.remove_local_record(form.id).await?;
        Ok(Redirect::to("/local").into_response())
    }
}

/// Validate a new local record without touching the database: the value must
/// parse as the right IP type, and the builder must accept the name (this is
/// the only place wildcard names are checked before insert).
fn validate_local(name: &str, record_type: RecordType, value: &str, ttl: u32) -> WebResult<()> {
    let data = match record_type {
        RecordType::A => RecordData::A(value.parse().map_err(|_| {
            WebError::bad_request(format!("'{value}' is not a valid IPv4 address."))
        })?),
        RecordType::Aaaa => RecordData::Aaaa(value.parse().map_err(|_| {
            WebError::bad_request(format!("'{value}' is not a valid IPv6 address."))
        })?),
    };
    let mut builder = LocalRecords::builder();
    builder
        .add(name.trim_end_matches('.'), data, ttl)
        .map_err(|e| WebError::bad_request(format!("Invalid record name: {e}")))?;
    Ok(())
}

/// Add-record form payload (`csrf_token` consumed by the CSRF layer).
#[derive(Debug, Deserialize)]
pub struct AddLocalForm {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
    ttl: u32,
}

/// Remove-record form payload.
#[derive(Debug, Deserialize)]
pub struct RemoveLocalForm {
    id: i64,
}

/// One local record row for display.
struct LocalRecordView {
    id: i64,
    name: String,
    record_type: &'static str,
    value: String,
    ttl: u32,
}

/// The local-records management page.
#[derive(Template, WebTemplate)]
#[template(path = "local.html")]
struct LocalPageTemplate {
    chrome: Chrome,
    records: Vec<LocalRecordView>,
    error: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{message::Qtype, name::Name},
        resolver::local::LocalMatch,
    };
    use tempfile::TempDir;

    async fn state() -> (TempDir, AppState) {
        let (dir, db) = crate::test_support::temp_db().await;
        let st = AppState::for_test(db).await;
        (dir, st)
    }

    #[tokio::test]
    async fn add_local_record_resolves_authoritatively() {
        let (_d, st) = state().await;
        st.add_local_record("router.home.lan", RecordType::A, "192.168.1.1", 300)
            .await
            .expect("add");

        let m = st
            .resolver
            .local()
            .lookup(&"router.home.lan".parse::<Name>().unwrap(), Qtype::A);
        assert!(matches!(m, LocalMatch::Answer { .. }), "got {m:?}");
    }

    #[tokio::test]
    async fn wildcard_record_resolves_for_subdomain() {
        let (_d, st) = state().await;
        st.add_local_record("*.home.lan", RecordType::A, "192.168.1.50", 120)
            .await
            .expect("add wildcard");

        let m = st
            .resolver
            .local()
            .lookup(&"nas.home.lan".parse::<Name>().unwrap(), Qtype::A);
        assert!(matches!(m, LocalMatch::Answer { .. }), "got {m:?}");
    }

    #[tokio::test]
    async fn local_page_shows_names_without_trailing_dot() {
        let (_d, st) = state().await;
        // Stored normalized to lowercase + trailing dot ...
        st.add_local_record("Router.Home.LAN", RecordType::A, "192.168.1.1", 300)
            .await
            .expect("add");
        st.add_local_record("*.home.lan", RecordType::Aaaa, "fd00::1", 120)
            .await
            .expect("add wildcard");

        let user = CurrentUser {
            user_id: 1,
            session_id: "sess".to_owned(),
        };
        let html = st
            .render_local(&user, None)
            .await
            .expect("render")
            .render()
            .expect("template");

        // ... but displayed bare (the trailing dot stays internal).
        assert!(html.contains("router.home.lan"));
        assert!(!html.contains("router.home.lan."));
        assert!(html.contains("*.home.lan"));
        assert!(!html.contains("*.home.lan."));
    }

    #[tokio::test]
    async fn local_name_with_only_a_gives_nodata_for_aaaa() {
        let (_d, st) = state().await;
        st.add_local_record("router.home.lan", RecordType::A, "192.168.1.1", 300)
            .await
            .expect("add");

        let m = st
            .resolver
            .local()
            .lookup(&"router.home.lan".parse::<Name>().unwrap(), Qtype::Aaaa);
        assert_eq!(m, LocalMatch::NameExistsNoData);
    }

    #[tokio::test]
    async fn invalid_ip_value_is_bad_request() {
        let (_d, st) = state().await;
        let err = st
            .add_local_record("router.home.lan", RecordType::A, "not-an-ip", 300)
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }

    #[tokio::test]
    async fn duplicate_name_type_is_bad_request() {
        let (_d, st) = state().await;
        st.add_local_record("router.home.lan", RecordType::A, "192.168.1.1", 300)
            .await
            .expect("first");
        let err = st
            .add_local_record("router.home.lan", RecordType::A, "192.168.1.2", 300)
            .await
            .unwrap_err();
        assert!(matches!(err, WebError::BadRequest(_)));
    }

    #[tokio::test]
    async fn remove_clears_from_live_set() {
        let (_d, st) = state().await;
        st.add_local_record("router.home.lan", RecordType::A, "192.168.1.1", 300)
            .await
            .expect("add");
        let id = st.db.local_records().list().await.unwrap()[0].id;
        st.remove_local_record(id).await.expect("remove");
        let m = st
            .resolver
            .local()
            .lookup(&"router.home.lan".parse::<Name>().unwrap(), Qtype::A);
        assert_eq!(m, LocalMatch::Miss);
    }
}
