//! Authoritative local-record matcher.
//!
//! [`LocalMatcher`] provides a lock-free, hot-swappable snapshot of local DNS
//! records — exact names and wildcard suffixes — mirroring the arc-swap pattern
//! used by [`super::matchset::MatchSet`].
//!
//! # Design (SPEC §3.1, §5 step 3)
//!
//! Two maps are maintained inside an immutable [`LocalRecords`] snapshot:
//!
//! - **exact**: `HashMap<Name, NameEntry>` — keyed by the full normalized name.
//! - **wildcard**: `HashMap<Name, NameEntry>` — keyed by the *suffix after `*.`*
//!   (e.g. `*.home.lan` is stored under suffix key `home.lan.`).
//!
//! Lookup probes exact first, then wildcard by stripping the leftmost label of
//! the query name one at a time (most-specific wins).  Because stripping starts
//! by removing ≥ 1 label before the first wildcard probe, `home.lan.` itself
//! can never match `*.home.lan`, and only exact `Name` equality (not
//! `ends_with`) is used, so `evilhome.lan.` can never match `*.home.lan`.
//!
//! The snapshot is installed atomically via [`arc_swap::ArcSwap`]; hot-path
//! readers never block.
//!
//! # Module layout
//!
//! | Type | Role |
//! |---|---|
//! | [`RecordData`] | Typed record value (A or AAAA) |
//! | [`LocalMatch`] | Lookup result routed by the pipeline |
//! | [`NameEntry`] | Per-name storage (at most one A + one AAAA) |
//! | [`LocalRecords`] | Immutable snapshot (built off the hot path) |
//! | [`LocalRecordsBuilder`] | Builder for [`LocalRecords`] |
//! | [`LocalMatcher`] | Arc-swap wrapper; primary interface for the hot path |

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use arc_swap::ArcSwap;

use crate::codec::{message::Qtype, name::Name};

// ── RecordData ────────────────────────────────────────────────────────────────

/// The typed value of a local DNS record.
///
/// A local record holds either an IPv4 address (A) or an IPv6 address (AAAA).
/// Wire-format synthesis is deferred to E2.5 / E6; this type is purely the
/// parsed, typed representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// A record: an IPv4 address (type 1, RFC 1035 §3.4.1).
    A(Ipv4Addr),
    /// AAAA record: an IPv6 address (type 28, RFC 3596).
    Aaaa(Ipv6Addr),
}

// ── LocalMatch ────────────────────────────────────────────────────────────────

/// The result of a local-record lookup.
///
/// The pipeline routes on this value:
///
/// - [`LocalMatch::Answer`] — a local name matched **and** has a record for the
///   requested qtype.  The pipeline synthesizes an authoritative answer.
/// - [`LocalMatch::NameExistsNoData`] — a local name matched but has **no**
///   record for the requested qtype (qtype mismatch, or non-A/AAAA qtype).
///   The pipeline returns authoritative NODATA — the private name must NOT be
///   forwarded upstream.
/// - [`LocalMatch::Miss`] — no local exact or wildcard name matched at all.
///   The pipeline continues to the next layer (blocklist, cache, upstream).
#[derive(Debug, PartialEq, Eq)]
pub enum LocalMatch {
    /// A local name matched and a record for the requested qtype exists.
    Answer {
        /// The typed record value.
        data: RecordData,
        /// TTL in seconds.
        ttl: u32,
    },
    /// A local name matched but no record exists for the requested qtype.
    ///
    /// Causes an authoritative NODATA response; the name is never forwarded.
    NameExistsNoData,
    /// No local name (exact or wildcard) matched the query name.
    Miss,
}

// ── NameEntry ─────────────────────────────────────────────────────────────────

/// Per-name storage for local records.
///
/// The storage layer enforces `(name, type)` uniqueness, so at most one A and
/// one AAAA record can exist per name.
#[derive(Debug, Clone, Default)]
pub struct NameEntry {
    /// A record: IPv4 address + TTL, if present.
    pub a: Option<(Ipv4Addr, u32)>,
    /// AAAA record: IPv6 address + TTL, if present.
    pub aaaa: Option<(Ipv6Addr, u32)>,
}

impl NameEntry {
    /// Resolve the entry against a query type, returning the appropriate
    /// [`LocalMatch`].
    ///
    /// The name is known to exist locally (either exact or wildcard hit), so
    /// a missing record for the requested qtype yields [`LocalMatch::NameExistsNoData`]
    /// rather than [`LocalMatch::Miss`].
    fn resolve(&self, qtype: Qtype) -> LocalMatch {
        match qtype {
            Qtype::A => match self.a {
                Some((addr, ttl)) => LocalMatch::Answer {
                    data: RecordData::A(addr),
                    ttl,
                },
                None => LocalMatch::NameExistsNoData,
            },
            Qtype::Aaaa => match self.aaaa {
                Some((addr, ttl)) => LocalMatch::Answer {
                    data: RecordData::Aaaa(addr),
                    ttl,
                },
                None => LocalMatch::NameExistsNoData,
            },
            // Any non-A/AAAA qtype: the name exists locally but we hold no
            // record of that type.  Return NODATA — do NOT forward the private
            // name upstream.
            Qtype::Other(_) => LocalMatch::NameExistsNoData,
        }
    }
}

// ── Builder error ─────────────────────────────────────────────────────────────

/// Error returned by [`LocalRecordsBuilder::add`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The wildcard pattern is syntactically invalid (e.g. `"*"` or `"*."`).
    #[error("invalid wildcard pattern {0:?}: must have at least one label after `*.`")]
    InvalidWildcard(String),

    /// The name string could not be parsed as a valid DNS [`Name`].
    #[error("invalid domain name {0:?}: {1}")]
    InvalidName(String, #[source] crate::codec::Error),
}

// ── LocalRecords ──────────────────────────────────────────────────────────────

/// An immutable snapshot of local DNS records.
///
/// Built off the hot path via [`LocalRecords::builder`] and installed
/// atomically into a [`LocalMatcher`] with [`LocalMatcher::store`].
///
/// # Storage
///
/// - `exact`: keyed by the fully-normalized name.
/// - `wildcard`: keyed by the suffix *after* `*.` — so `*.home.lan` is stored
///   under `home.lan.` — keeping probe lookups to plain `HashMap` gets.
#[derive(Debug, Default)]
pub struct LocalRecords {
    exact: HashMap<Name, NameEntry>,
    /// Keyed by the normalized suffix string (after `*.`) as a `Box<str>` so the
    /// hot-path probe can look up `&str` slices of the query name with no
    /// allocation (a `Name` key would force re-parsing each suffix per query).
    wildcard: HashMap<Box<str>, NameEntry>,
}

impl LocalRecords {
    /// Return a new builder for constructing a [`LocalRecords`] snapshot.
    pub fn builder() -> LocalRecordsBuilder {
        LocalRecordsBuilder::default()
    }

    // ── Hot-path lookup ───────────────────────────────────────────────────────

    /// Look up `qname`/`qtype` in this snapshot.
    ///
    /// # Precedence
    ///
    /// 1. **Exact match** wins over any wildcard.
    /// 2. **Most-specific wildcard** (longest remaining suffix after stripping
    ///    the leftmost label) wins over a less-specific one.
    /// 3. If neither matches → [`LocalMatch::Miss`].
    ///
    /// # False-positive safety
    ///
    /// The wildcard probe strips ≥ 1 label from `qname` before the first lookup,
    /// so `home.lan.` itself never triggers `*.home.lan`.  Suffix comparison is
    /// exact [`Name`] equality (hash-map key equality), never a substring or
    /// `ends_with` match, so `evilhome.lan.` never matches `*.home.lan`.
    pub fn lookup(&self, qname: &Name, qtype: Qtype) -> LocalMatch {
        // ── 1. Exact match ────────────────────────────────────────────────────
        if let Some(entry) = self.exact.get(qname) {
            return entry.resolve(qtype);
        }

        // No wildcards configured → nothing further to probe (the common case;
        // avoids walking the query name's labels for every non-local query).
        if self.wildcard.is_empty() {
            return LocalMatch::Miss;
        }

        // ── 2. Wildcard suffix-probe (most-specific first) ────────────────────
        //
        // Strip one label at a time from the left of `qname` and probe the
        // remaining suffix. The first probe uses the string *after* the first
        // label, so `qname` itself is never probed against the wildcard map —
        // this is what prevents `home.lan.` from matching `*.home.lan`. Lookup
        // is exact `&str` key equality (never `ends_with`), so `evilhome.lan.`
        // can't match `home.lan.` either. The slices borrow the already-
        // normalized `qname`, so the probe allocates nothing.
        //
        // Example for `a.b.home.lan.`:
        //   probe `b.home.lan.`  → wildcard map lookup
        //   probe `home.lan.`    → hits if `*.home.lan` is stored (most-specific)
        //   probe `lan.`         → wildcard map lookup
        //   (root `.` is never a wildcard suffix; loop ends naturally)
        let mut search = qname.as_str(); // e.g. "a.b.home.lan."
        while let Some(dot_pos) = search.find('.') {
            // Strip the leftmost label: advance past the first dot.
            search = &search[dot_pos + 1..];

            // Empty or bare root means every label has been consumed — stop.
            if search.is_empty() || search == "." {
                break;
            }

            if let Some(entry) = self.wildcard.get(search) {
                return entry.resolve(qtype);
            }
        }

        LocalMatch::Miss
    }
}

// ── LocalRecordsBuilder ───────────────────────────────────────────────────────

/// Builder for [`LocalRecords`].
///
/// Call [`add`](LocalRecordsBuilder::add) for each record, then
/// [`build`](LocalRecordsBuilder::build) to produce the immutable snapshot.
///
/// ```rust
/// use std::net::Ipv4Addr;
/// use sagittarius::resolver::local::{LocalRecords, RecordData};
///
/// let mut b = LocalRecords::builder();
/// b.add("router.home.lan", RecordData::A("192.168.1.1".parse().unwrap()), 300).unwrap();
/// b.add("*.home.lan", RecordData::A("192.168.1.2".parse().unwrap()), 60).unwrap();
/// let records = b.build();
/// ```
#[derive(Debug, Default)]
pub struct LocalRecordsBuilder {
    exact: HashMap<Name, NameEntry>,
    wildcard: HashMap<Box<str>, NameEntry>,
}

impl LocalRecordsBuilder {
    /// Add a record for `name` (exact or wildcard) with `data` and `ttl`.
    ///
    /// If `name` begins with `*.` it is treated as a wildcard: the `*.` prefix
    /// is stripped and the remaining suffix is stored in the wildcard map.
    /// Otherwise the name is stored in the exact map.
    ///
    /// Adding a second record type for the same name fills the other slot of its
    /// [`NameEntry`] (A and AAAA are independent).
    ///
    /// # Errors
    ///
    /// - [`BuildError::InvalidWildcard`] — name starts with `*` but is `"*"` or
    ///   `"*."` (no suffix label after the `*.`).
    /// - [`BuildError::InvalidName`] — name cannot be parsed as a valid
    ///   [`Name`].
    pub fn add(&mut self, name: &str, data: RecordData, ttl: u32) -> Result<(), BuildError> {
        if let Some(wildcard_suffix) = name.strip_prefix("*.") {
            // Validate that there is a non-empty suffix after `*.`.
            // `wildcard_suffix` must be a valid, non-empty domain name.
            if wildcard_suffix.is_empty() || wildcard_suffix == "." {
                return Err(BuildError::InvalidWildcard(name.to_owned()));
            }

            // Parse the suffix through `Name` to validate + normalize it once
            // at build time, then store its normalized string as the key.
            let suffix: Name = wildcard_suffix
                .parse()
                .map_err(|e| BuildError::InvalidName(name.to_owned(), e))?;

            let entry = self.wildcard.entry(suffix.as_str().into()).or_default();
            Self::fill_entry(entry, data, ttl);
        } else if name == "*" {
            // Bare `*` with no suffix.
            return Err(BuildError::InvalidWildcard(name.to_owned()));
        } else {
            let parsed: Name = name
                .parse()
                .map_err(|e| BuildError::InvalidName(name.to_owned(), e))?;

            let entry = self.exact.entry(parsed).or_default();
            Self::fill_entry(entry, data, ttl);
        }

        Ok(())
    }

    /// Consume the builder and produce an immutable [`LocalRecords`] snapshot.
    pub fn build(self) -> LocalRecords {
        LocalRecords {
            exact: self.exact,
            wildcard: self.wildcard,
        }
    }

    /// Fill the appropriate slot in `entry` for the given `data`.
    fn fill_entry(entry: &mut NameEntry, data: RecordData, ttl: u32) {
        match data {
            RecordData::A(addr) => entry.a = Some((addr, ttl)),
            RecordData::Aaaa(addr) => entry.aaaa = Some((addr, ttl)),
        }
    }
}

// ── LocalMatcher ─────────────────────────────────────────────────────────────

/// Lock-free, hot-swappable local-record matcher.
///
/// Wraps an [`ArcSwap`]-protected [`LocalRecords`] snapshot.  Readers on the
/// hot path perform a cheap atomic load followed by a [`LocalRecords::lookup`]
/// without ever blocking.  An admin edit or initial hydration builds a fresh
/// [`LocalRecords`] off the hot path and installs it with [`LocalMatcher::store`].
///
/// # Usage
///
/// ```rust
/// use std::net::Ipv4Addr;
/// use sagittarius::codec::{message::Qtype, name::Name};
/// use sagittarius::resolver::local::{LocalMatcher, LocalMatch, LocalRecords, RecordData};
///
/// let mut b = LocalRecords::builder();
/// b.add("router.home.lan", RecordData::A("192.168.1.1".parse().unwrap()), 300).unwrap();
/// let matcher = LocalMatcher::new(b.build());
///
/// let qname: Name = "router.home.lan".parse().unwrap();
/// let result = matcher.lookup(&qname, Qtype::A);
/// assert!(matches!(result, LocalMatch::Answer { .. }));
/// ```
pub struct LocalMatcher {
    inner: ArcSwap<LocalRecords>,
}

impl LocalMatcher {
    /// Construct a [`LocalMatcher`] pre-loaded with `records`.
    pub fn new(records: LocalRecords) -> Self {
        Self {
            inner: ArcSwap::from_pointee(records),
        }
    }

    /// Construct a [`LocalMatcher`] with an empty initial snapshot.
    pub fn empty() -> Self {
        Self::new(LocalRecords::default())
    }

    // ── Hot-path read ─────────────────────────────────────────────────────────

    /// Look up `qname`/`qtype` against the current snapshot.
    ///
    /// Performs a cheap atomic load and delegates to [`LocalRecords::lookup`].
    /// Never blocks.
    pub fn lookup(&self, qname: &Name, qtype: Qtype) -> LocalMatch {
        self.inner.load().lookup(qname, qtype)
    }

    // ── Rebuild-and-swap writer ───────────────────────────────────────────────

    /// Atomically install `records` as the new current snapshot.
    ///
    /// Builds the new snapshot off the hot path; this method merely wraps it in
    /// an [`Arc`] and performs the atomic swap.  Readers that are mid-load
    /// continue using the previous snapshot; new readers immediately see the
    /// new one.
    pub fn store(&self, records: LocalRecords) {
        self.inner.store(Arc::new(records));
    }
}

impl Default for LocalMatcher {
    /// An empty [`LocalMatcher`].
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for LocalMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.inner.load();
        f.debug_struct("LocalMatcher")
            .field("exact_len", &snap.exact.len())
            .field("wildcard_len", &snap.wildcard.len())
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::codec::message::Qtype;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        s.parse().expect("valid domain name in test")
    }

    fn ipv4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ipv6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// Build a LocalRecords snapshot from a list of (name, data, ttl) triples.
    fn records(entries: &[(&str, RecordData, u32)]) -> LocalRecords {
        let mut b = LocalRecords::builder();
        for (n, d, ttl) in entries {
            b.add(n, d.clone(), *ttl).expect("valid entry in test");
        }
        b.build()
    }

    // ── Exact match ───────────────────────────────────────────────────────────

    #[test]
    fn exact_a_hit() {
        let r = records(&[("router.home.lan", RecordData::A(ipv4("192.168.1.1")), 300)]);
        let result = r.lookup(&name("router.home.lan"), Qtype::A);
        assert_eq!(
            result,
            LocalMatch::Answer {
                data: RecordData::A(ipv4("192.168.1.1")),
                ttl: 300,
            }
        );
    }

    #[test]
    fn exact_aaaa_hit() {
        let r = records(&[("host.lan", RecordData::Aaaa(ipv6("::1")), 60)]);
        let result = r.lookup(&name("host.lan"), Qtype::Aaaa);
        assert_eq!(
            result,
            LocalMatch::Answer {
                data: RecordData::Aaaa(ipv6("::1")),
                ttl: 60,
            }
        );
    }

    // ── Same name holds both A and AAAA ──────────────────────────────────────

    #[test]
    fn both_a_and_aaaa_on_same_name() {
        let mut b = LocalRecords::builder();
        b.add("dual.lan", RecordData::A(ipv4("10.0.0.1")), 100)
            .unwrap();
        b.add("dual.lan", RecordData::Aaaa(ipv6("2001:db8::1")), 200)
            .unwrap();
        let r = b.build();

        assert_eq!(
            r.lookup(&name("dual.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("10.0.0.1")),
                ttl: 100,
            }
        );
        assert_eq!(
            r.lookup(&name("dual.lan"), Qtype::Aaaa),
            LocalMatch::Answer {
                data: RecordData::Aaaa(ipv6("2001:db8::1")),
                ttl: 200,
            }
        );
    }

    // ── Qtype mismatch → NameExistsNoData ────────────────────────────────────

    #[test]
    fn only_a_query_aaaa_is_name_exists_no_data() {
        let r = records(&[("a-only.lan", RecordData::A(ipv4("1.2.3.4")), 300)]);
        assert_eq!(
            r.lookup(&name("a-only.lan"), Qtype::Aaaa),
            LocalMatch::NameExistsNoData
        );
    }

    #[test]
    fn only_aaaa_query_a_is_name_exists_no_data() {
        let r = records(&[("aaaa-only.lan", RecordData::Aaaa(ipv6("::1")), 300)]);
        assert_eq!(
            r.lookup(&name("aaaa-only.lan"), Qtype::A),
            LocalMatch::NameExistsNoData
        );
    }

    #[test]
    fn non_a_aaaa_qtype_on_local_name_is_name_exists_no_data() {
        // MX (15), NS (2), TXT (16) — any Other(n) on a local name → NODATA.
        let r = records(&[("host.lan", RecordData::A(ipv4("1.2.3.4")), 300)]);
        for qtype_val in [2u16, 15, 16, 255] {
            assert_eq!(
                r.lookup(&name("host.lan"), Qtype::Other(qtype_val)),
                LocalMatch::NameExistsNoData,
                "expected NameExistsNoData for Other({qtype_val})"
            );
        }
    }

    // ── Miss for unrelated name ───────────────────────────────────────────────

    #[test]
    fn unrelated_name_is_miss() {
        let r = records(&[("known.lan", RecordData::A(ipv4("1.1.1.1")), 60)]);
        assert_eq!(r.lookup(&name("unknown.lan"), Qtype::A), LocalMatch::Miss);
        assert_eq!(r.lookup(&name("example.com"), Qtype::A), LocalMatch::Miss);
    }

    // ── Wildcard basic match ──────────────────────────────────────────────────

    #[test]
    fn wildcard_a_hit() {
        let r = records(&[("*.home.lan", RecordData::A(ipv4("10.0.0.99")), 120)]);
        assert_eq!(
            r.lookup(&name("device.home.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("10.0.0.99")),
                ttl: 120,
            }
        );
    }

    #[test]
    fn wildcard_multi_label_qname() {
        // *.home.lan should match a.b.home.lan via the suffix probe.
        let r = records(&[("*.home.lan", RecordData::A(ipv4("10.0.0.1")), 300)]);
        assert_eq!(
            r.lookup(&name("a.b.home.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("10.0.0.1")),
                ttl: 300,
            }
        );
    }

    // ── Wildcard most-specific wins ───────────────────────────────────────────

    #[test]
    fn wildcard_most_specific_wins() {
        let mut b = LocalRecords::builder();
        // *.home.lan → 10.0.0.1 (less specific)
        b.add("*.home.lan", RecordData::A(ipv4("10.0.0.1")), 300)
            .unwrap();
        // *.a.home.lan → 10.0.0.2 (more specific)
        b.add("*.a.home.lan", RecordData::A(ipv4("10.0.0.2")), 300)
            .unwrap();
        let r = b.build();

        // x.a.home.lan: probe `a.home.lan.` first (miss), then `home.lan.` (miss),
        // wait — actually probe order is: strip "x" → `a.home.lan.` → hits *.a.home.lan
        assert_eq!(
            r.lookup(&name("x.a.home.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("10.0.0.2")),
                ttl: 300,
            },
            "x.a.home.lan should resolve via the more specific *.a.home.lan"
        );

        // y.home.lan: probe `home.lan.` → hits *.home.lan
        assert_eq!(
            r.lookup(&name("y.home.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("10.0.0.1")),
                ttl: 300,
            },
            "y.home.lan should resolve via *.home.lan"
        );
    }

    // ── No false positives ────────────────────────────────────────────────────

    #[test]
    fn wildcard_does_not_match_the_suffix_itself() {
        // *.home.lan must NOT match home.lan (the bare suffix).
        let r = records(&[("*.home.lan", RecordData::A(ipv4("10.0.0.1")), 300)]);
        assert_eq!(
            r.lookup(&name("home.lan"), Qtype::A),
            LocalMatch::Miss,
            "home.lan itself must be a Miss, not matched by *.home.lan"
        );
    }

    #[test]
    fn wildcard_does_not_match_substring_prefix() {
        // *.home.lan must NOT match evilhome.lan.
        let r = records(&[("*.home.lan", RecordData::A(ipv4("10.0.0.1")), 300)]);
        assert_eq!(
            r.lookup(&name("evilhome.lan"), Qtype::A),
            LocalMatch::Miss,
            "evilhome.lan must be a Miss — substring match is forbidden"
        );
    }

    #[test]
    fn wildcard_matches_direct_child() {
        // Confirm that x.home.lan IS matched (positive case alongside the
        // false-positive checks above).
        let r = records(&[("*.home.lan", RecordData::A(ipv4("10.0.0.1")), 300)]);
        assert!(
            matches!(
                r.lookup(&name("x.home.lan"), Qtype::A),
                LocalMatch::Answer { .. }
            ),
            "x.home.lan should be an Answer via *.home.lan"
        );
    }

    // ── Exact beats wildcard ──────────────────────────────────────────────────

    #[test]
    fn exact_beats_wildcard() {
        let mut b = LocalRecords::builder();
        b.add("*.home.lan", RecordData::A(ipv4("10.0.0.99")), 300)
            .unwrap();
        // More specific exact entry for the same name.
        b.add("router.home.lan", RecordData::A(ipv4("192.168.1.1")), 3600)
            .unwrap();
        let r = b.build();

        assert_eq!(
            r.lookup(&name("router.home.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("192.168.1.1")),
                ttl: 3600,
            },
            "exact entry must win over matching wildcard"
        );
    }

    // ── Wildcard NameExistsNoData ─────────────────────────────────────────────

    #[test]
    fn wildcard_qtype_mismatch_is_name_exists_no_data() {
        // Wildcard only has A; query AAAA → NameExistsNoData (not Miss).
        let r = records(&[("*.home.lan", RecordData::A(ipv4("10.0.0.1")), 300)]);
        assert_eq!(
            r.lookup(&name("device.home.lan"), Qtype::Aaaa),
            LocalMatch::NameExistsNoData
        );
    }

    // ── LocalMatcher store ────────────────────────────────────────────────────

    #[test]
    fn matcher_store_swaps_snapshot() {
        let r1 = records(&[("old.lan", RecordData::A(ipv4("1.1.1.1")), 60)]);
        let matcher = LocalMatcher::new(r1);

        // Initial snapshot.
        assert!(matches!(
            matcher.lookup(&name("old.lan"), Qtype::A),
            LocalMatch::Answer { .. }
        ));
        assert_eq!(matcher.lookup(&name("new.lan"), Qtype::A), LocalMatch::Miss);

        // Swap in a new snapshot.
        let r2 = records(&[("new.lan", RecordData::A(ipv4("2.2.2.2")), 120)]);
        matcher.store(r2);

        // New snapshot observed.
        assert_eq!(
            matcher.lookup(&name("new.lan"), Qtype::A),
            LocalMatch::Answer {
                data: RecordData::A(ipv4("2.2.2.2")),
                ttl: 120,
            }
        );
        // Old name gone.
        assert_eq!(matcher.lookup(&name("old.lan"), Qtype::A), LocalMatch::Miss);
    }

    #[test]
    fn matcher_empty_returns_miss() {
        let m = LocalMatcher::empty();
        assert_eq!(m.lookup(&name("anything.com"), Qtype::A), LocalMatch::Miss);
    }

    #[test]
    fn matcher_default_is_empty() {
        let m = LocalMatcher::default();
        assert_eq!(m.lookup(&name("anything.com"), Qtype::A), LocalMatch::Miss);
    }

    // ── Builder error cases ───────────────────────────────────────────────────

    #[test]
    fn builder_rejects_bare_star() {
        let mut b = LocalRecords::builder();
        let err = b.add("*", RecordData::A(ipv4("1.1.1.1")), 300).unwrap_err();
        assert!(
            matches!(err, BuildError::InvalidWildcard(_)),
            "expected InvalidWildcard, got: {err}"
        );
    }

    #[test]
    fn builder_rejects_star_dot_only() {
        let mut b = LocalRecords::builder();
        let err = b
            .add("*.", RecordData::A(ipv4("1.1.1.1")), 300)
            .unwrap_err();
        assert!(
            matches!(err, BuildError::InvalidWildcard(_)),
            "expected InvalidWildcard, got: {err}"
        );
    }

    #[test]
    fn builder_rejects_invalid_name() {
        let mut b = LocalRecords::builder();
        // A name with an empty label in the middle.
        let err = b
            .add("foo..bar", RecordData::A(ipv4("1.1.1.1")), 300)
            .unwrap_err();
        assert!(
            matches!(err, BuildError::InvalidName(_, _)),
            "expected InvalidName, got: {err}"
        );
    }

    #[test]
    fn builder_rejects_label_too_long() {
        let long_label = "a".repeat(64);
        let name_str = format!("{long_label}.lan");
        let mut b = LocalRecords::builder();
        let err = b
            .add(&name_str, RecordData::A(ipv4("1.1.1.1")), 300)
            .unwrap_err();
        assert!(
            matches!(err, BuildError::InvalidName(_, _)),
            "expected InvalidName, got: {err}"
        );
    }

    // ── Debug impls ───────────────────────────────────────────────────────────

    #[test]
    fn matcher_debug_shows_lengths() {
        let mut b = LocalRecords::builder();
        b.add("a.lan", RecordData::A(ipv4("1.1.1.1")), 60).unwrap();
        b.add("*.b.lan", RecordData::A(ipv4("2.2.2.2")), 60)
            .unwrap();
        let m = LocalMatcher::new(b.build());
        let s = format!("{m:?}");
        assert!(s.contains("exact_len: 1"), "debug: {s}");
        assert!(s.contains("wildcard_len: 1"), "debug: {s}");
    }

    // ── Case insensitivity ────────────────────────────────────────────────────

    #[test]
    fn lookup_is_case_insensitive() {
        // Name normalizes to lowercase; mixed-case lookups must hit.
        let r = records(&[("Host.LAN", RecordData::A(ipv4("1.2.3.4")), 300)]);
        assert!(
            matches!(
                r.lookup(&name("host.lan"), Qtype::A),
                LocalMatch::Answer { .. }
            ),
            "lookup for lowercase must hit"
        );
        assert!(
            matches!(
                r.lookup(&name("HOST.LAN"), Qtype::A),
                LocalMatch::Answer { .. }
            ),
            "lookup for uppercase must hit"
        );
    }

    #[test]
    fn wildcard_lookup_is_case_insensitive() {
        let r = records(&[("*.Home.LAN", RecordData::A(ipv4("10.0.0.1")), 300)]);
        assert!(
            matches!(
                r.lookup(&name("DEVICE.home.lan"), Qtype::A),
                LocalMatch::Answer { .. }
            ),
            "wildcard lookup must be case-insensitive"
        );
    }
}
