//! Conditional-forward zone routing (SPEC §5, E13.4).
//!
//! [`ForwardZoneSet`] is the hot-path runtime view of the persisted
//! `forward_zones` rows: a suffix → target map plus a small set of upstream
//! forwarders (one per distinct target, deduplicated).  A query whose name falls
//! under an enabled zone is routed to that zone's resolver instead of the
//! default upstream pool.
//!
//! # Where it sits in the pipeline
//!
//! The decision stack ([`super::pipeline::layers`]) probes the set **after**
//! local records / local PTR synth and **before** the blacklist/blocklist
//! stages — you don't block your own reverse zones, and a local PTR answer still
//! wins over forwarding.  On a match it tags the request with the zone target
//! and falls through to the cache → forward leaf, so zone answers are cached
//! exactly like upstream answers.
//!
//! # Hot-swap
//!
//! Like the upstream pool, the set is an immutable snapshot rebuilt off the hot
//! path and swapped atomically (held in an `ArcSwap` inside
//! [`ResolverState`](super::state::ResolverState)) whenever the admin edits a
//! zone's target or enabled flag.

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
};

use tokio_util::task::TaskTracker;
use tracing::warn;

use crate::{
    codec::{message::Question, name::Name},
    resolver::upstream::{
        self, DEFAULT_QUERY_TIMEOUT, ForwardResult, RandomSelector, UpstreamConfig, UpstreamHealth,
        UpstreamPool, UpstreamTransport,
    },
    storage::forward_zones::ForwardZone,
};

// ── Default forward port ──────────────────────────────────────────────────────

/// Default DNS port applied to a bare-IP zone target (no explicit `:port`).
const DEFAULT_FORWARD_PORT: u16 = 53;

// ── ForwardZoneSet ────────────────────────────────────────────────────────────

/// An immutable snapshot of the enabled conditional-forward zones and their
/// upstream forwarders.
///
/// Build via [`ForwardZoneSet::build`] from `forward_zones.list_enabled()` and
/// install it with
/// [`ResolverState::store_forward_zones`](super::state::ResolverState::store_forward_zones).
pub struct ForwardZoneSet {
    /// Normalized zone suffix (lowercase, trailing dot) → target resolver.
    zones: HashMap<Box<str>, SocketAddr>,
    /// One forwarder per **distinct** target, so many zones pointed at the same
    /// router share a single client.
    forwarders: HashMap<SocketAddr, UpstreamPool>,
    /// Health tracker shared by the zone forwarders (the pool API requires one;
    /// single-target pools never fail over, so this is mostly bookkeeping).
    health: UpstreamHealth,
}

impl ForwardZoneSet {
    /// An empty set: matches nothing.  Used as the initial snapshot at hydration
    /// before the real set is built (the build needs a [`TaskTracker`], which is
    /// only available once the app is wiring up its background tasks).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            zones: HashMap::new(),
            forwarders: HashMap::new(),
            health: UpstreamHealth::new(),
        }
    }

    /// Build a snapshot from the enabled-and-targeted zone rows, connecting one
    /// UDP forwarder per distinct target.
    ///
    /// Rows whose `target` is missing/unparseable or whose `zone_suffix` is not
    /// a valid domain name are skipped with a warning, so one bad row never
    /// sinks the whole set.  Connection failures are tolerated by
    /// [`UpstreamPool::connect`] itself (it logs and yields an empty pool).
    pub async fn build(rows: &[ForwardZone], tracker: &TaskTracker) -> Self {
        let mut zones: HashMap<Box<str>, SocketAddr> = HashMap::new();

        for row in rows {
            let Some(target) = row.target.as_deref().and_then(parse_target) else {
                warn!(
                    zone = %row.zone_suffix,
                    target = ?row.target,
                    "forward zone has no usable target; skipping"
                );
                continue;
            };
            let Ok(suffix) = row.zone_suffix.parse::<Name>() else {
                warn!(zone = %row.zone_suffix, "invalid forward-zone suffix; skipping");
                continue;
            };
            zones.insert(suffix.as_str().into(), target);
        }

        // One forwarder per distinct target.
        let mut forwarders: HashMap<SocketAddr, UpstreamPool> = HashMap::new();
        for &target in zones.values() {
            if forwarders.contains_key(&target) {
                continue;
            }
            let config = UpstreamConfig {
                addr: target,
                transport: UpstreamTransport::Udp,
                tls_server_name: None,
                http_endpoint: None,
            };
            // budget 0: a zone has a single target, so there is nothing to fail
            // over to.
            let pool = UpstreamPool::connect(
                std::slice::from_ref(&config),
                tracker,
                std::sync::Arc::new(RandomSelector),
                0,
                DEFAULT_QUERY_TIMEOUT,
            )
            .await;
            forwarders.insert(target, pool);
        }

        Self {
            zones,
            forwarders,
            health: UpstreamHealth::new(),
        }
    }

    /// The target resolver for `qname`, or `None` if no enabled zone matches.
    ///
    /// Most-specific zone wins: the probe strips the leftmost label one at a
    /// time, so the longest matching suffix is found first.  The zone apex
    /// itself matches (a query for `corp.internal` matches a `corp.internal`
    /// zone), unlike the local-record wildcard probe which excludes it.
    #[must_use]
    pub fn match_target(&self, qname: &Name) -> Option<SocketAddr> {
        if self.zones.is_empty() {
            return None;
        }

        let mut search = qname.as_str();
        loop {
            if let Some(&target) = self.zones.get(search) {
                return Some(target);
            }
            {
                let pos = search.find('.')?;
                search = &search[pos + 1..];
                if search.is_empty() || search == "." {
                    return None;
                }
            }
        }
    }

    /// Forward `question` to the zone forwarder for `target`.
    ///
    /// Returns [`upstream::Error::AllUpstreamsFailed`] if the snapshot no longer
    /// holds a forwarder for `target` (it was swapped out between the decision
    /// stage's match and this call) — the caller maps that to SERVFAIL.
    pub async fn forward(
        &self,
        target: SocketAddr,
        question: &Question,
    ) -> upstream::Result<ForwardResult> {
        match self.forwarders.get(&target) {
            Some(pool) => pool.forward(question, &self.health).await,
            None => Err(upstream::Error::AllUpstreamsFailed { attempts: 0 }),
        }
    }

    /// The number of matchable zones in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Whether the set matches nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

impl Default for ForwardZoneSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for ForwardZoneSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardZoneSet")
            .field("zones", &self.zones.len())
            .field("forwarders", &self.forwarders.len())
            .finish_non_exhaustive()
    }
}

// ── Target parsing ────────────────────────────────────────────────────────────

/// Parse a zone target string (`IP` or `IP:port`) into a [`SocketAddr`],
/// defaulting the port to 53 for a bare IP.  Returns `None` for anything that is
/// not a valid IP / socket address.
fn parse_target(s: &str) -> Option<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        Some(sa)
    } else {
        s.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, DEFAULT_FORWARD_PORT))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().expect("valid name")
    }

    /// Build a [`ForwardZoneSet`] directly from (suffix, target) pairs without
    /// connecting forwarders — for matching-only unit tests.
    fn zone_set(pairs: &[(&str, &str)]) -> ForwardZoneSet {
        let mut zones = HashMap::new();
        for (suffix, target) in pairs {
            let n: Name = suffix.parse().unwrap();
            zones.insert(n.as_str().into(), parse_target(target).unwrap());
        }
        ForwardZoneSet {
            zones,
            forwarders: HashMap::new(),
            health: UpstreamHealth::new(),
        }
    }

    #[test]
    fn parse_target_ip_and_socket() {
        assert_eq!(
            parse_target("192.168.1.1"),
            Some("192.168.1.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_target("10.0.0.1:5353"),
            Some("10.0.0.1:5353".parse().unwrap())
        );
        assert_eq!(
            parse_target("fd00::1"),
            Some("[fd00::1]:53".parse().unwrap())
        );
        assert_eq!(parse_target("not-an-ip"), None);
    }

    #[test]
    fn match_subdomain_and_apex() {
        let set = zone_set(&[("168.192.in-addr.arpa", "192.168.1.1")]);
        let target: SocketAddr = "192.168.1.1:53".parse().unwrap();

        // A reverse query under the zone matches.
        assert_eq!(
            set.match_target(&name("5.1.168.192.in-addr.arpa")),
            Some(target)
        );
        // The zone apex itself matches.
        assert_eq!(
            set.match_target(&name("168.192.in-addr.arpa")),
            Some(target)
        );
    }

    #[test]
    fn non_matching_name_is_none() {
        let set = zone_set(&[("168.192.in-addr.arpa", "192.168.1.1")]);
        assert_eq!(set.match_target(&name("example.com")), None);
        // A different RFC1918 reverse zone that isn't configured.
        assert_eq!(set.match_target(&name("5.1.10.in-addr.arpa")), None);
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = ForwardZoneSet::empty();
        assert!(set.is_empty());
        assert_eq!(set.match_target(&name("5.1.168.192.in-addr.arpa")), None);
    }

    #[test]
    fn most_specific_zone_wins() {
        // Overlapping zones: the more-specific suffix must win.
        let set = zone_set(&[
            ("10.in-addr.arpa", "10.0.0.1"),
            ("0.10.in-addr.arpa", "10.0.0.2"),
        ]);
        let specific: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let general: SocketAddr = "10.0.0.1:53".parse().unwrap();

        // Under the /16-ish more specific zone → specific target.
        assert_eq!(
            set.match_target(&name("5.1.0.10.in-addr.arpa")),
            Some(specific)
        );
        // Under only the broader zone → general target.
        assert_eq!(
            set.match_target(&name("5.1.9.10.in-addr.arpa")),
            Some(general)
        );
    }

    #[tokio::test]
    async fn build_dedups_forwarders_by_target() {
        // Three zones, two distinct targets → two forwarders.
        let rows = vec![
            ForwardZone {
                id: 1,
                zone_suffix: "10.in-addr.arpa".to_owned(),
                target: Some("10.0.0.1".to_owned()),
                enabled: true,
                sort_order: 0,
            },
            ForwardZone {
                id: 2,
                zone_suffix: "168.192.in-addr.arpa".to_owned(),
                target: Some("10.0.0.1".to_owned()),
                enabled: true,
                sort_order: 1,
            },
            ForwardZone {
                id: 3,
                zone_suffix: "16.172.in-addr.arpa".to_owned(),
                target: Some("10.0.0.2:5353".to_owned()),
                enabled: true,
                sort_order: 2,
            },
        ];
        let tracker = TaskTracker::new();
        let set = ForwardZoneSet::build(&rows, &tracker).await;

        assert_eq!(set.len(), 3, "three zones mapped");
        assert_eq!(
            set.forwarders.len(),
            2,
            "two distinct targets → two forwarders"
        );
    }

    #[tokio::test]
    async fn build_skips_bad_target_and_suffix() {
        let rows = vec![
            ForwardZone {
                id: 1,
                zone_suffix: "168.192.in-addr.arpa".to_owned(),
                target: Some("not-an-ip".to_owned()),
                enabled: true,
                sort_order: 0,
            },
            ForwardZone {
                id: 2,
                zone_suffix: "10.in-addr.arpa".to_owned(),
                target: Some("10.0.0.1".to_owned()),
                enabled: true,
                sort_order: 1,
            },
        ];
        let tracker = TaskTracker::new();
        let set = ForwardZoneSet::build(&rows, &tracker).await;
        // Only the valid row survives.
        assert_eq!(set.len(), 1);
        assert!(set.match_target(&name("5.1.10.in-addr.arpa")).is_some());
        assert!(
            set.match_target(&name("5.1.168.192.in-addr.arpa"))
                .is_none()
        );
    }
}
