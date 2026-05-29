//! Blocklist aggregation — merge per-source domain sets and atomically install
//! the result into the resolver's [`MatchSet`] (SPEC §6, E7.3).
//!
//! # Design
//!
//! Each enabled blocklist source produces a [`HashSet<Name>`] after parsing
//! (E7.2).  This module accepts those per-source sets, merges them into a single
//! deduplicated [`HashSet<Name>`], tracks how many entries each source
//! contributed, and then atomically swaps the merged set into the shared
//! [`MatchSet`] via [`MatchSet::store`].
//!
//! The merge happens entirely off the hot path; readers are never blocked.
//! Persistence of per-source counts is left to the caller (E7.4), which
//! receives a [`Vec<SourceContribution<K>>`] from [`Aggregator::install`].
//!
//! # Example
//!
//! ```rust
//! use std::collections::HashSet;
//! use sagittarius::blocklist::aggregate::{Aggregator, SourceContribution};
//! use sagittarius::resolver::matchset::MatchSet;
//!
//! let target = MatchSet::empty();
//!
//! let mut agg: Aggregator<&str> = Aggregator::new();
//! agg.add("source-a", ["ads.example.com", "tracker.net"]
//!     .iter()
//!     .map(|s| s.parse().unwrap())
//!     .collect());
//! agg.add("source-b", ["tracker.net", "malware.io"]
//!     .iter()
//!     .map(|s| s.parse().unwrap())
//!     .collect());
//!
//! // 3 unique domains across 2 sources (tracker.net deduped).
//! assert_eq!(agg.len(), 3);
//!
//! let contributions = agg.install(&target);
//! assert_eq!(contributions.len(), 2);
//! assert!(target.contains(&"tracker.net".parse().unwrap()));
//! ```

use std::collections::HashSet;

use crate::{codec::name::Name, resolver::matchset::MatchSet};

// ── SourceContribution ────────────────────────────────────────────────────────

/// How many domains a single source contributed to the aggregated set.
///
/// `count` is the source's **own** deduplicated entry count — i.e.
/// `names.len()` as measured before cross-source deduplication.  This is the
/// value that gets persisted to `blocklists.entry_count` by E7.4.
///
/// The generic parameter `K` is the source-identifier type, keeping the
/// aggregator decoupled from the storage layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceContribution<K> {
    /// The source identifier (e.g. a database row id or a URL string).
    pub source: K,
    /// Number of unique domains this source contributed (pre-cross-source-dedup).
    pub count: usize,
}

// ── Aggregator ────────────────────────────────────────────────────────────────

/// Accumulates per-source domain sets into one deduplicated [`HashSet<Name>`].
///
/// Call [`Aggregator::add`] once per enabled source, then either consume the
/// accumulator via [`Aggregator::install`] (which atomically swaps the merged
/// set into a [`MatchSet`] and returns the per-source contributions) or inspect
/// it via [`Aggregator::into_parts`].
///
/// The generic parameter `K` is the source-identifier type; it is only stored,
/// so no bounds beyond those required by `Vec` are imposed here.
pub struct Aggregator<K> {
    /// The running union of all per-source domain sets.
    merged: HashSet<Name>,
    /// Per-source contribution records, in insertion order.
    contributions: Vec<SourceContribution<K>>,
}

impl<K> Aggregator<K> {
    /// Construct an empty [`Aggregator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            merged: HashSet::new(),
            contributions: Vec::new(),
        }
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Add `names` from `source` to the aggregation.
    ///
    /// Records a [`SourceContribution`] whose `count` equals `names.len()`
    /// (the source's own intra-source-deduplicated entry count), then merges
    /// `names` into the running union set.  Cross-source duplicates collapse
    /// silently — they are counted in the contributing source's `count` but
    /// appear only once in the merged set.
    pub fn add(&mut self, source: K, names: HashSet<Name>) {
        let count = names.len();
        self.contributions
            .push(SourceContribution { source, count });
        self.merged.extend(names);
    }

    // ── Read accessors ────────────────────────────────────────────────────────

    /// Number of unique domain names in the merged set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.merged.len()
    }

    /// `true` if no domains have been added yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.merged.is_empty()
    }

    // ── Consuming output ──────────────────────────────────────────────────────

    /// Decompose the aggregator into the merged set and per-source contributions
    /// without performing an atomic install.
    ///
    /// Useful for inspection or for callers that need to inspect or further
    /// transform the merged set before installing it.
    #[must_use]
    pub fn into_parts(self) -> (HashSet<Name>, Vec<SourceContribution<K>>) {
        (self.merged, self.contributions)
    }

    /// Atomically install the merged set into `target` and return the per-source
    /// contributions.
    ///
    /// This is the primary output path:
    ///
    /// 1. Calls [`MatchSet::store`] with the merged [`HashSet<Name>`], replacing
    ///    whatever was previously installed (including stale entries from a prior
    ///    refresh cycle).  This is the SPEC §3.2 rebuild-and-swap: the set is
    ///    built entirely off the hot path and installed atomically so readers
    ///    never observe a torn or partially-updated view.
    /// 2. Returns the [`Vec<SourceContribution<K>>`] so the caller (E7.4) can
    ///    persist each source's `count` back to `blocklists.entry_count`.
    ///
    /// Zero enabled sources installs an **empty** set and returns an empty
    /// `Vec` — this is intentional and will never panic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sagittarius::blocklist::aggregate::Aggregator;
    /// use sagittarius::resolver::matchset::MatchSet;
    ///
    /// let target = MatchSet::empty();
    /// let agg: Aggregator<u32> = Aggregator::new(); // no sources
    /// let contributions = agg.install(&target);
    /// assert!(target.is_empty());
    /// assert!(contributions.is_empty());
    /// ```
    #[must_use]
    pub fn install(self, target: &MatchSet) -> Vec<SourceContribution<K>> {
        let (merged, contributions) = self.into_parts();
        target.store(merged);
        contributions
    }
}

// ── Standard trait implementations ───────────────────────────────────────────

impl<K> Default for Aggregator<K> {
    /// An empty [`Aggregator`].
    fn default() -> Self {
        Self::new()
    }
}

impl<K: std::fmt::Debug> std::fmt::Debug for Aggregator<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aggregator")
            .field("merged_len", &self.merged.len())
            .field("contributions", &self.contributions)
            .finish()
    }
}

impl<K> FromIterator<(K, HashSet<Name>)> for Aggregator<K> {
    /// Build an [`Aggregator`] from an iterator of `(source, names)` pairs.
    ///
    /// Each item is passed to [`Aggregator::add`] in iteration order, so
    /// per-source counts and the merged set are accumulated exactly as if
    /// `add` were called manually.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::collections::HashSet;
    /// use sagittarius::blocklist::aggregate::Aggregator;
    ///
    /// let sources: Vec<(&str, HashSet<_>)> = vec![
    ///     ("a", ["x.com"].iter().map(|s| s.parse().unwrap()).collect()),
    ///     ("b", ["y.com"].iter().map(|s| s.parse().unwrap()).collect()),
    /// ];
    /// let agg: Aggregator<&str> = sources.into_iter().collect();
    /// assert_eq!(agg.len(), 2);
    /// ```
    fn from_iter<I: IntoIterator<Item = (K, HashSet<Name>)>>(iter: I) -> Self {
        let mut agg = Self::new();
        for (source, names) in iter {
            agg.add(source, names);
        }
        agg
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        s.parse().expect("valid domain name in test helper")
    }

    fn set_of(names: &[&str]) -> HashSet<Name> {
        names.iter().map(|s| name(s)).collect()
    }

    // ── Construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_is_empty() {
        let agg: Aggregator<u32> = Aggregator::new();
        assert!(agg.is_empty());
        assert_eq!(agg.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let agg: Aggregator<&str> = Aggregator::default();
        assert!(agg.is_empty());
    }

    // ── Single source ─────────────────────────────────────────────────────────

    #[test]
    fn single_source_add_records_contribution_and_len() {
        let mut agg: Aggregator<&str> = Aggregator::new();
        agg.add("source-a", set_of(&["ads.example.com", "tracker.net"]));

        assert_eq!(agg.len(), 2);

        let (merged, contributions) = agg.into_parts();
        assert_eq!(contributions.len(), 1);
        assert_eq!(contributions[0].source, "source-a");
        assert_eq!(contributions[0].count, 2);
        assert!(merged.contains(&name("ads.example.com")));
        assert!(merged.contains(&name("tracker.net")));
    }

    // ── Cross-source deduplication ────────────────────────────────────────────

    /// Two sources sharing some domains → merged set is the union; each source's
    /// `count` is its OWN set size (before cross-source dedup).
    #[test]
    fn dedup_across_overlapping_sources() {
        let mut agg: Aggregator<&str> = Aggregator::new();
        // source-a: 3 domains
        agg.add(
            "source-a",
            set_of(&["ads.example.com", "tracker.net", "shared.bad"]),
        );
        // source-b: 3 domains, 1 shared with source-a
        agg.add(
            "source-b",
            set_of(&["shared.bad", "malware.io", "evil.org"]),
        );

        // Union = 5 distinct domains (shared.bad appears in both but only once).
        assert_eq!(agg.len(), 5);

        let (merged, contributions) = agg.into_parts();

        // Verify merged set is the correct union.
        assert!(merged.contains(&name("ads.example.com")));
        assert!(merged.contains(&name("tracker.net")));
        assert!(merged.contains(&name("shared.bad")));
        assert!(merged.contains(&name("malware.io")));
        assert!(merged.contains(&name("evil.org")));

        // Per-source counts reflect each source's own (pre-cross-dedup) size.
        assert_eq!(contributions[0].source, "source-a");
        assert_eq!(contributions[0].count, 3);
        assert_eq!(contributions[1].source, "source-b");
        assert_eq!(contributions[1].count, 3);
    }

    // ── install: atomic swap into MatchSet ────────────────────────────────────

    /// After install the MatchSet contains exactly the merged names and stale
    /// pre-existing entries are gone.
    #[test]
    fn install_swaps_into_matchset_and_removes_stale() {
        // Pre-seed the target with a stale entry.
        let target = MatchSet::new(set_of(&["stale.example.com"]));
        assert!(target.contains(&name("stale.example.com")));

        let mut agg: Aggregator<&str> = Aggregator::new();
        agg.add("source-a", set_of(&["ads.example.com", "tracker.net"]));
        agg.add("source-b", set_of(&["tracker.net", "malware.io"]));

        let contributions = agg.install(&target);

        // Merged set (3 domains) is visible.
        assert!(target.contains(&name("ads.example.com")));
        assert!(target.contains(&name("tracker.net")));
        assert!(target.contains(&name("malware.io")));
        assert_eq!(target.len(), 3);

        // Stale entry is gone (whole-snapshot replacement).
        assert!(!target.contains(&name("stale.example.com")));

        // Contributions are returned to the caller.
        assert_eq!(contributions.len(), 2);
        assert_eq!(contributions[0].source, "source-a");
        assert_eq!(contributions[0].count, 2);
        assert_eq!(contributions[1].source, "source-b");
        // source-b saw tracker.net + malware.io = 2 (intra-source dedup; both
        // were distinct, so count is 2).
        assert_eq!(contributions[1].count, 2);
    }

    /// Reader observes the new set immediately after install.
    #[test]
    fn install_new_set_immediately_visible() {
        let target = MatchSet::empty();

        let mut agg: Aggregator<u32> = Aggregator::new();
        agg.add(1, set_of(&["new.example.com"]));
        let _ = agg.install(&target);

        assert!(target.contains(&name("new.example.com")));
        assert_eq!(target.len(), 1);
    }

    // ── Zero sources: no panic, empty install ─────────────────────────────────

    #[test]
    fn zero_sources_installs_empty_set_no_panic() {
        let target = MatchSet::new(set_of(&["previously-blocked.example.com"]));

        let agg: Aggregator<u32> = Aggregator::new();
        let contributions = agg.install(&target);

        assert!(
            target.is_empty(),
            "install of empty aggregator must clear the set"
        );
        assert!(contributions.is_empty());
    }

    // ── Per-source intra-source dedup (count = deduped size) ─────────────────

    /// A source whose raw input contained case-duplicates collapses intra-source;
    /// the reported `count` is the already-deduped size of the HashSet.
    ///
    /// The parse layer (E7.2) already produces deduplicated sets because
    /// `Name` normalises to lowercase, so mixed-case inputs in the same source
    /// produce a single entry.  We verify here that `count` reflects the deduped
    /// size — i.e. what was actually in the `HashSet<Name>` passed to `add`.
    #[test]
    fn per_source_count_is_intra_source_deduped_size() {
        // Build the set as the parse layer would: mixed-case → same Name.
        let mut raw: HashSet<Name> = HashSet::new();
        raw.insert("ADS.EXAMPLE.COM".parse().unwrap());
        raw.insert("ads.example.com".parse().unwrap()); // same after normalisation
        raw.insert("tracker.net".parse().unwrap());

        // After normalisation, the set contains 2 distinct entries.
        assert_eq!(raw.len(), 2, "pre-condition: set has 2 deduped entries");

        let mut agg: Aggregator<&str> = Aggregator::new();
        agg.add("source-a", raw);

        let (_, contributions) = agg.into_parts();
        assert_eq!(
            contributions[0].count, 2,
            "count must be the deduped set size"
        );
    }

    // ── into_parts round-trip ─────────────────────────────────────────────────

    #[test]
    fn into_parts_returns_same_merged_set_and_contributions() {
        let mut agg: Aggregator<i64> = Aggregator::new();
        agg.add(10, set_of(&["a.example.com", "b.example.com"]));
        agg.add(20, set_of(&["b.example.com", "c.example.com"]));

        let (merged, contributions) = agg.into_parts();

        // Union of the two sets.
        assert_eq!(merged.len(), 3);
        assert!(merged.contains(&name("a.example.com")));
        assert!(merged.contains(&name("b.example.com")));
        assert!(merged.contains(&name("c.example.com")));

        // Contributions in insertion order with correct counts.
        assert_eq!(contributions.len(), 2);
        assert_eq!(
            contributions[0],
            SourceContribution {
                source: 10,
                count: 2
            }
        );
        assert_eq!(
            contributions[1],
            SourceContribution {
                source: 20,
                count: 2
            }
        );
    }

    // ── FromIterator ──────────────────────────────────────────────────────────

    #[test]
    fn from_iterator_builds_same_result_as_manual_add() {
        let sources = vec![
            ("a", set_of(&["x.com", "y.com"])),
            ("b", set_of(&["y.com", "z.com"])),
        ];

        let agg: Aggregator<&str> = sources.into_iter().collect();

        assert_eq!(agg.len(), 3);
        let (merged, contributions) = agg.into_parts();
        assert!(merged.contains(&name("x.com")));
        assert!(merged.contains(&name("y.com")));
        assert!(merged.contains(&name("z.com")));
        assert_eq!(contributions[0].source, "a");
        assert_eq!(contributions[0].count, 2);
        assert_eq!(contributions[1].source, "b");
        assert_eq!(contributions[1].count, 2);
    }
}
