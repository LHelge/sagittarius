//! Blocklist aggregation — merge per-source domain sets into a
//! `Name → primary blocklist_id` map and atomically install it into the
//! resolver's [`AttributedSet`] (SPEC §6, E7.3, E11).
//!
//! # Design
//!
//! Each enabled blocklist source produces a [`HashSet<Name>`] after parsing
//! (E7.2).  This module accepts those per-source sets, merges them into a
//! single deduplicated [`HashMap<Name, i64>`] keyed by [`Name`] with the value
//! being the **primary** source's `blocklist_id`, tracks how many entries each
//! source contributed, and then atomically swaps the merged map into the shared
//! [`AttributedSet`] via [`AttributedSet::store`].
//!
//! ## Primary-source attribution (first-writer-wins)
//!
//! When a domain appears in more than one source, only the **first** source to
//! contribute it is recorded as its primary (`HashMap::entry(..).or_insert`).
//! The caller must therefore add sources in ascending `blocklist_id` order so
//! the **lowest id wins** the overlap — i.e. the oldest-subscribed list is
//! credited.  The storage layer's `list_enabled()` already returns sources
//! `ORDER BY id`, so the scheduler satisfies this for free.  Storing a single
//! primary keeps the map value a bare `i64` (SPEC §6 / E11 locked decision).
//!
//! The merge happens entirely off the hot path; readers are never blocked.
//! Persistence of per-source counts is left to the caller (E7.4), which
//! receives a [`Vec<SourceContribution>`] from [`Aggregator::install`].
//!
//! # Example
//!
//! ```rust
//! use std::collections::HashSet;
//! use sagittarius::blocklist::aggregate::Aggregator;
//! use sagittarius::resolver::matchset::AttributedSet;
//!
//! let target = AttributedSet::empty();
//!
//! let mut agg = Aggregator::new();
//! agg.add(1, ["ads.example.com", "tracker.net"]
//!     .iter()
//!     .map(|s| s.parse().unwrap())
//!     .collect());
//! agg.add(2, ["tracker.net", "malware.io"]
//!     .iter()
//!     .map(|s| s.parse().unwrap())
//!     .collect());
//!
//! // 3 unique domains across 2 sources (tracker.net deduped).
//! assert_eq!(agg.len(), 3);
//!
//! let contributions = agg.install(&target);
//! assert_eq!(contributions.len(), 2);
//! // tracker.net was first contributed by source 1, so 1 is its primary.
//! assert_eq!(target.primary_source(&"tracker.net".parse().unwrap()), Some(1));
//! ```

use std::collections::{HashMap, HashSet};

use crate::{codec::name::Name, resolver::matchset::AttributedSet};

// ── SourceContribution ────────────────────────────────────────────────────────

/// How many domains a single source contributed to the aggregated set.
///
/// `count` is the source's **own** deduplicated entry count — i.e.
/// `names.len()` as measured before cross-source deduplication.  This is the
/// value that gets persisted to `blocklists.entry_count` by E7.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceContribution {
    /// The source identifier — a `blocklists` row id (`blocklist_id`).
    pub source: i64,
    /// Number of unique domains this source contributed (pre-cross-source-dedup).
    pub count: usize,
}

// ── Aggregator ────────────────────────────────────────────────────────────────

/// Accumulates per-source domain sets into one `Name → primary blocklist_id`
/// [`HashMap`].
///
/// Call [`Aggregator::add`] once per enabled source **in ascending
/// `blocklist_id` order**, then either consume the accumulator via
/// [`Aggregator::install`] (which atomically swaps the merged map into an
/// [`AttributedSet`] and returns the per-source contributions) or inspect it
/// via [`Aggregator::into_parts`].
pub struct Aggregator {
    /// The merged map: each blocked name → the `blocklist_id` of the first
    /// source that contributed it (its primary source).
    merged: HashMap<Name, i64>,
    /// Per-source contribution records, in insertion order.
    contributions: Vec<SourceContribution>,
}

impl Aggregator {
    /// Construct an empty [`Aggregator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            merged: HashMap::new(),
            contributions: Vec::new(),
        }
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Add `names` from source `source_id` to the aggregation.
    ///
    /// Records a [`SourceContribution`] whose `count` equals `names.len()`
    /// (the source's own intra-source-deduplicated entry count), then merges
    /// each name into the running map with [`HashMap::entry`]`.or_insert` —
    /// **first writer wins**, so a name already attributed to an earlier source
    /// keeps that source as its primary.  Callers add sources in ascending
    /// `blocklist_id` order, so the lowest id wins any overlap.
    pub fn add(&mut self, source_id: i64, names: HashSet<Name>) {
        let count = names.len();
        self.contributions.push(SourceContribution {
            source: source_id,
            count,
        });
        for name in names {
            self.merged.entry(name).or_insert(source_id);
        }
    }

    // ── Read accessors ────────────────────────────────────────────────────────

    /// Number of unique domain names in the merged map.
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

    /// Decompose the aggregator into the merged map and per-source contributions
    /// without performing an atomic install.
    #[must_use]
    pub fn into_parts(self) -> (HashMap<Name, i64>, Vec<SourceContribution>) {
        (self.merged, self.contributions)
    }

    /// Atomically install the merged map into `target` and return the per-source
    /// contributions.
    ///
    /// This is the primary output path:
    ///
    /// 1. Calls [`AttributedSet::store`] with the merged [`HashMap<Name, i64>`],
    ///    replacing whatever was previously installed (including stale entries
    ///    from a prior refresh cycle).  This is the SPEC §3.2 rebuild-and-swap:
    ///    the map is built entirely off the hot path and installed atomically so
    ///    readers never observe a torn or partially-updated view.
    /// 2. Returns the [`Vec<SourceContribution>`] so the caller (E7.4) can
    ///    persist each source's `count` back to `blocklists.entry_count`.
    ///
    /// Zero enabled sources installs an **empty** map and returns an empty
    /// `Vec` — this is intentional and will never panic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sagittarius::blocklist::aggregate::Aggregator;
    /// use sagittarius::resolver::matchset::AttributedSet;
    ///
    /// let target = AttributedSet::empty();
    /// let agg = Aggregator::new(); // no sources
    /// let contributions = agg.install(&target);
    /// assert!(target.is_empty());
    /// assert!(contributions.is_empty());
    /// ```
    #[must_use]
    pub fn install(self, target: &AttributedSet) -> Vec<SourceContribution> {
        let (merged, contributions) = self.into_parts();
        target.store(merged);
        contributions
    }
}

// ── Standard trait implementations ───────────────────────────────────────────

impl Default for Aggregator {
    /// An empty [`Aggregator`].
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Aggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aggregator")
            .field("merged_len", &self.merged.len())
            .field("contributions", &self.contributions)
            .finish()
    }
}

impl FromIterator<(i64, HashSet<Name>)> for Aggregator {
    /// Build an [`Aggregator`] from an iterator of `(source_id, names)` pairs.
    ///
    /// Each item is passed to [`Aggregator::add`] in iteration order, so
    /// per-source counts and the first-writer-wins primary attribution are
    /// accumulated exactly as if `add` were called manually.  Feed the pairs in
    /// ascending `source_id` order for the lowest-id tie-break.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::collections::HashSet;
    /// use sagittarius::blocklist::aggregate::Aggregator;
    ///
    /// let sources: Vec<(i64, HashSet<_>)> = vec![
    ///     (1, ["x.com"].iter().map(|s| s.parse().unwrap()).collect()),
    ///     (2, ["y.com"].iter().map(|s| s.parse().unwrap()).collect()),
    /// ];
    /// let agg: Aggregator = sources.into_iter().collect();
    /// assert_eq!(agg.len(), 2);
    /// ```
    fn from_iter<I: IntoIterator<Item = (i64, HashSet<Name>)>>(iter: I) -> Self {
        let mut agg = Self::new();
        for (source_id, names) in iter {
            agg.add(source_id, names);
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
        let agg = Aggregator::new();
        assert!(agg.is_empty());
        assert_eq!(agg.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let agg = Aggregator::default();
        assert!(agg.is_empty());
    }

    // ── Single source ─────────────────────────────────────────────────────────

    #[test]
    fn single_source_add_records_contribution_and_len() {
        let mut agg = Aggregator::new();
        agg.add(1, set_of(&["ads.example.com", "tracker.net"]));

        assert_eq!(agg.len(), 2);

        let (merged, contributions) = agg.into_parts();
        assert_eq!(contributions.len(), 1);
        assert_eq!(contributions[0].source, 1);
        assert_eq!(contributions[0].count, 2);
        // Both names attributed to source 1.
        assert_eq!(merged.get(&name("ads.example.com")), Some(&1));
        assert_eq!(merged.get(&name("tracker.net")), Some(&1));
    }

    // ── Cross-source deduplication + primary attribution ──────────────────────

    /// Two sources sharing some domains → merged map is the union; each source's
    /// `count` is its OWN set size (before cross-source dedup), and a shared
    /// domain is attributed to the first (lowest-id) source that contributed it.
    #[test]
    fn dedup_across_overlapping_sources_attributes_to_first() {
        let mut agg = Aggregator::new();
        // source 1: 3 domains
        agg.add(1, set_of(&["ads.example.com", "tracker.net", "shared.bad"]));
        // source 2: 3 domains, 1 shared with source 1
        agg.add(2, set_of(&["shared.bad", "malware.io", "evil.org"]));

        // Union = 5 distinct domains (shared.bad appears in both but only once).
        assert_eq!(agg.len(), 5);

        let (merged, contributions) = agg.into_parts();

        // shared.bad must be attributed to source 1 (first writer wins).
        assert_eq!(
            merged.get(&name("shared.bad")),
            Some(&1),
            "overlap must be attributed to the first (lowest-id) source"
        );
        assert_eq!(merged.get(&name("malware.io")), Some(&2));
        assert_eq!(merged.get(&name("evil.org")), Some(&2));

        // Per-source counts reflect each source's own (pre-cross-dedup) size.
        assert_eq!(contributions[0].source, 1);
        assert_eq!(contributions[0].count, 3);
        assert_eq!(contributions[1].source, 2);
        assert_eq!(contributions[1].count, 3);
    }

    /// The tie-break is purely first-writer-wins: whichever source is `add`-ed
    /// first owns the overlap, even if its id is numerically larger.  The
    /// scheduler guarantees ascending-id order so "first" == "lowest id".
    #[test]
    fn first_writer_wins_regardless_of_id_value() {
        let mut agg = Aggregator::new();
        agg.add(10, set_of(&["shared.bad"]));
        agg.add(2, set_of(&["shared.bad"]));

        let (merged, _) = agg.into_parts();
        assert_eq!(
            merged.get(&name("shared.bad")),
            Some(&10),
            "the source added first keeps the attribution"
        );
    }

    // ── install: atomic swap into AttributedSet ───────────────────────────────

    /// After install the set contains exactly the merged names with their
    /// primary ids, and stale pre-existing entries are gone.
    #[test]
    fn install_swaps_into_set_and_removes_stale() {
        // Pre-seed the target with a stale entry.
        let target: AttributedSet = [(name("stale.example.com"), 99)].into_iter().collect();
        assert!(target.contains(&name("stale.example.com")));

        let mut agg = Aggregator::new();
        agg.add(1, set_of(&["ads.example.com", "tracker.net"]));
        agg.add(2, set_of(&["tracker.net", "malware.io"]));

        let contributions = agg.install(&target);

        // Merged map (3 domains) is visible with correct attribution.
        assert_eq!(target.primary_source(&name("ads.example.com")), Some(1));
        assert_eq!(target.primary_source(&name("tracker.net")), Some(1));
        assert_eq!(target.primary_source(&name("malware.io")), Some(2));
        assert_eq!(target.len(), 3);

        // Stale entry is gone (whole-snapshot replacement).
        assert!(!target.contains(&name("stale.example.com")));

        // Contributions are returned to the caller.
        assert_eq!(contributions.len(), 2);
        assert_eq!(contributions[0].source, 1);
        assert_eq!(contributions[0].count, 2);
        assert_eq!(contributions[1].source, 2);
        assert_eq!(contributions[1].count, 2);
    }

    /// Reader observes the new set immediately after install.
    #[test]
    fn install_new_set_immediately_visible() {
        let target = AttributedSet::empty();

        let mut agg = Aggregator::new();
        agg.add(1, set_of(&["new.example.com"]));
        let _ = agg.install(&target);

        assert!(target.contains(&name("new.example.com")));
        assert_eq!(target.len(), 1);
    }

    // ── Zero sources: no panic, empty install ─────────────────────────────────

    #[test]
    fn zero_sources_installs_empty_set_no_panic() {
        let target: AttributedSet = [(name("previously-blocked.example.com"), 1)]
            .into_iter()
            .collect();

        let agg = Aggregator::new();
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
    #[test]
    fn per_source_count_is_intra_source_deduped_size() {
        // Build the set as the parse layer would: mixed-case → same Name.
        let mut raw: HashSet<Name> = HashSet::new();
        raw.insert("ADS.EXAMPLE.COM".parse().unwrap());
        raw.insert("ads.example.com".parse().unwrap()); // same after normalisation
        raw.insert("tracker.net".parse().unwrap());

        // After normalisation, the set contains 2 distinct entries.
        assert_eq!(raw.len(), 2, "pre-condition: set has 2 deduped entries");

        let mut agg = Aggregator::new();
        agg.add(1, raw);

        let (_, contributions) = agg.into_parts();
        assert_eq!(
            contributions[0].count, 2,
            "count must be the deduped set size"
        );
    }

    // ── into_parts round-trip ─────────────────────────────────────────────────

    #[test]
    fn into_parts_returns_merged_map_and_contributions() {
        let mut agg = Aggregator::new();
        agg.add(10, set_of(&["a.example.com", "b.example.com"]));
        agg.add(20, set_of(&["b.example.com", "c.example.com"]));

        let (merged, contributions) = agg.into_parts();

        // Union of the two sets with first-writer attribution.
        assert_eq!(merged.len(), 3);
        assert_eq!(merged.get(&name("a.example.com")), Some(&10));
        assert_eq!(merged.get(&name("b.example.com")), Some(&10)); // first writer
        assert_eq!(merged.get(&name("c.example.com")), Some(&20));

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
            (1, set_of(&["x.com", "y.com"])),
            (2, set_of(&["y.com", "z.com"])),
        ];

        let agg: Aggregator = sources.into_iter().collect();

        assert_eq!(agg.len(), 3);
        let (merged, contributions) = agg.into_parts();
        assert_eq!(merged.get(&name("x.com")), Some(&1));
        assert_eq!(merged.get(&name("y.com")), Some(&1)); // first writer
        assert_eq!(merged.get(&name("z.com")), Some(&2));
        assert_eq!(contributions[0].source, 1);
        assert_eq!(contributions[0].count, 2);
        assert_eq!(contributions[1].source, 2);
        assert_eq!(contributions[1].count, 2);
    }
}
