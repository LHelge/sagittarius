//! Lock-free, hot-swappable domain name match set.
//!
//! [`MatchSet`] wraps an [`ArcSwap`]-protected [`HashSet<Name>`] to provide
//! the core primitive used for the admin blacklist and allowlist (SPEC §3.1,
//! §3.2).  The aggregated blocklist uses the sibling [`AttributedSet`], which
//! additionally records the **primary source** (a `blocklist_id`) for each
//! blocked name so the query log can attribute blocks to a list (E11).
//!
//! # Design
//!
//! Both sets are thin domain wrappers over the shared [`HotSwap`] core, which
//! owns the SPEC §3.2 rebuild-and-swap guarantee: the DNS hot path reads the
//! current snapshot with a cheap atomic load and **never blocks**, while an
//! admin edit or blocklist refresh builds a fresh [`HashSet`]/[`HashMap`]
//! *off* the hot path and installs it atomically, so no reader ever sees a
//! torn or partially-updated set.
//!
//! Three independent sets are used — admin blacklist and allowlist as
//! [`MatchSet`]s, the aggregated blocklist as an [`AttributedSet`] — with
//! cross-list precedence handled by the query pipeline layer (E6), not here.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use arc_swap::{ArcSwap, Guard};

use crate::codec::name::Name;

// ── HotSwap ───────────────────────────────────────────────────────────────────

/// Lock-free, hot-swappable snapshot holder — the SPEC §3.2 rebuild-and-swap
/// core shared by [`MatchSet`] and [`AttributedSet`].
///
/// Readers load the current snapshot with a cheap atomic operation and never
/// block.  Writers build a complete replacement value *off* the hot path and
/// install it atomically with [`HotSwap::store`]: readers that are mid-load
/// continue using the previous snapshot until their [`Guard`]/[`Arc`] drops,
/// new readers immediately see the new value, and no reader ever observes a
/// torn or partially-updated view.
pub struct HotSwap<T> {
    inner: ArcSwap<T>,
}

impl<T> HotSwap<T> {
    /// Wrap `value` as the initial snapshot.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: ArcSwap::from_pointee(value),
        }
    }

    /// Load the current snapshot as a short-lived [`Guard`].
    ///
    /// The [`Guard`] holds a reference to the current [`Arc`] without
    /// incrementing its reference count, making it slightly cheaper than
    /// [`HotSwap::load_full`].  Prefer this for short-lived reads (single
    /// method call); use [`load_full`](HotSwap::load_full) when the snapshot
    /// must outlive an await point or be stored in a struct.
    #[must_use]
    pub fn snapshot(&self) -> Guard<Arc<T>> {
        self.inner.load()
    }

    /// Load the current snapshot as a full, owned [`Arc`].
    ///
    /// Increments the reference count, so the snapshot stays alive as long as
    /// the returned [`Arc`] is held.
    #[must_use]
    pub fn load_full(&self) -> Arc<T> {
        self.inner.load_full()
    }

    /// Atomically install `value` as the new current snapshot.
    pub fn store(&self, value: T) {
        self.store_arc(Arc::new(value));
    }

    /// Atomically install a pre-boxed snapshot.
    ///
    /// Useful when the caller has already wrapped the value in an [`Arc`],
    /// for example to share the same snapshot across multiple data structures
    /// without an extra allocation.
    pub fn store_arc(&self, arc: Arc<T>) {
        self.inner.store(arc);
    }
}

// ── MatchSet ──────────────────────────────────────────────────────────────────

/// A lock-free, hot-swappable set of [`Name`]s.
///
/// Wraps an [`ArcSwap`]-protected [`HashSet<Name>`] so that:
/// - Reads (hot path) are cheap atomic loads that never block.
/// - Writes atomically swap an entirely new immutable snapshot in, so readers
///   always observe a consistent whole-set view.
///
/// # Usage
///
/// ```rust
/// use std::collections::HashSet;
/// use sagittarius::resolver::matchset::MatchSet;
///
/// let set: MatchSet = ["example.com", "ads.example.net"]
///     .iter()
///     .map(|s| s.parse().unwrap())
///     .collect();
///
/// assert!(set.contains(&"example.com".parse().unwrap()));
/// assert!(!set.contains(&"safe.example.com".parse().unwrap()));
/// ```
pub struct MatchSet {
    inner: HotSwap<HashSet<Name>>,
}

impl MatchSet {
    /// Construct a [`MatchSet`] pre-populated with `set`.
    #[must_use]
    pub fn new(set: HashSet<Name>) -> Self {
        Self {
            inner: HotSwap::new(set),
        }
    }

    /// Construct an empty [`MatchSet`].
    ///
    /// The blocklist set starts empty and is filled by the background refresh
    /// scheduler (E7).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(HashSet::new())
    }

    // ── Hot-path reads ────────────────────────────────────────────────────────

    /// Return `true` if `name` is a member of the current snapshot.
    ///
    /// Performs a cheap atomic load followed by a [`HashSet::contains`] lookup.
    /// This is the per-query lookup; it never blocks.
    #[must_use]
    pub fn contains(&self, name: &Name) -> bool {
        self.inner.snapshot().contains(name)
    }

    /// Load the current snapshot as a short-lived [`Guard`]
    /// (see [`HotSwap::snapshot`]).
    #[must_use]
    pub fn snapshot(&self) -> Guard<Arc<HashSet<Name>>> {
        self.inner.snapshot()
    }

    /// Load the current snapshot as a full, owned [`Arc`]
    /// (see [`HotSwap::load_full`]).
    #[must_use]
    pub fn load_full(&self) -> Arc<HashSet<Name>> {
        self.inner.load_full()
    }

    /// Return the number of entries in the current snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.snapshot().len()
    }

    /// Return `true` if the current snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.snapshot().is_empty()
    }

    // ── Rebuild-and-swap writer ───────────────────────────────────────────────

    /// Atomically install `set` as the new current snapshot.
    ///
    /// The caller builds the new [`HashSet`] *off* the hot path; the install
    /// gives the [`HotSwap`] no-torn-read guarantee.
    pub fn store(&self, set: HashSet<Name>) {
        self.inner.store(set);
    }

    /// Atomically install a pre-boxed snapshot (see [`HotSwap::store_arc`]).
    pub fn store_arc(&self, arc: Arc<HashSet<Name>>) {
        self.inner.store_arc(arc);
    }
}

// ── Standard trait implementations ───────────────────────────────────────────

impl Default for MatchSet {
    /// An empty [`MatchSet`].
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for MatchSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchSet")
            .field("len", &self.len())
            .finish()
    }
}

impl FromIterator<Name> for MatchSet {
    /// Build a [`MatchSet`] from an iterator of [`Name`]s.
    fn from_iter<I: IntoIterator<Item = Name>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

// ── AttributedSet ───────────────────────────────────────────────────────────

/// A lock-free, hot-swappable map from a blocked [`Name`] to the **primary**
/// blocklist source (`blocklist_id`) responsible for it (SPEC §6, E11).
///
/// This is the aggregated-blocklist counterpart to [`MatchSet`].  It behaves
/// like a [`MatchSet`] on the hot path — [`contains`](AttributedSet::contains)
/// is a presence check that keeps the [`DecisionStack`] a pure
/// `Name → bool` test — but it additionally remembers which source put each
/// name there.  The off-hot-path query-log writer reads that with
/// [`primary_source`](AttributedSet::primary_source) to attribute a block to a
/// specific list.
///
/// # Tiers (E19)
///
/// Since E19 the snapshot carries **three** attributed tiers, matched in this
/// order:
///
/// 1. `exact` — bare-domain rules; only the queried name itself matches.
/// 2. `suffix` — `||domain^` rules; the name matches if any ancestor of it
///    (most-specific first) is a rule.  The rule's own apex matches too, so
///    `||example.com^` blocks `example.com` *and* all its subdomains.
/// 3. `exceptions` — `@@||domain^` rules; checked with the same ancestor walk
///    **only when** a block match was found.  A hit suppresses the block
///    (returns [`BlockDecision::Exception`]).
///
/// The hot-path decision is [`match_name`](AttributedSet::match_name): one
/// exact hash probe, then at most one probe per name label (no allocation —
/// the walk slices the normalized FQDN string), plus an exception walk only
/// on a block hit.  Attribution follows the matched rule, per tier,
/// first-writer-wins (the aggregator iterates enabled sources in
/// `blocklist_id` order, so the lowest-id list wins an overlap).
///
/// # Usage
///
/// ```rust
/// use sagittarius::resolver::matchset::{AttributedSet, AttributedTiers};
/// use sagittarius::codec::name::Name;
///
/// let tiers = AttributedTiers {
///     exact: [("ads.example.com".parse().unwrap(), 7)].into_iter().collect(),
///     suffix: [("doubleclick.net".parse().unwrap(), 3)].into_iter().collect(),
///     exceptions: [("safe.doubleclick.net".parse().unwrap(), 4)].into_iter().collect(),
/// };
///
/// let set = AttributedSet::new_tiered(tiers);
/// assert!(set.contains(&"ads.example.com".parse().unwrap()));
/// // A subdomain of a suffix rule is blocked by that rule's source.
/// assert!(set.contains(&"stats.doubleclick.net".parse().unwrap()));
/// // …unless an exception covers it.
/// match set.match_name(&"safe.doubleclick.net".parse().unwrap()) {
///     Some(d) => assert!(d.is_exception()),
///     None => panic!("suffix rule must match"),
/// }
/// assert_eq!(set.primary_source(&"stats.doubleclick.net".parse().unwrap()), Some(3));
/// assert_eq!(set.primary_source(&"safe.example.com".parse().unwrap()), None);
/// ```
///
/// [`DecisionStack`]: crate::resolver::pipeline
pub struct AttributedSet {
    inner: HotSwap<AttributedTiers>,
}

/// The three attributed tiers of an [`AttributedSet`] snapshot (E19).
///
/// Each tier maps a rule domain to the `blocklist_id` of the source that
/// contributed it (first-writer-wins per tier).  Constructed by the
/// aggregator and installed atomically via
/// [`AttributedSet::store_tiers`](AttributedSet::store_tiers).
#[derive(Debug, Clone, Default)]
pub struct AttributedTiers {
    /// Bare-domain rules — exact match only.
    pub exact: HashMap<Name, i64>,
    /// `||domain^` rules — matched by ancestor (suffix) walk, apex included.
    pub suffix: HashMap<Name, i64>,
    /// `@@||domain^` rules — suppress blocklist matches on ancestor walk.
    pub exceptions: HashMap<Name, i64>,
}

/// The outcome of the hot-path blocklist decision
/// ([`AttributedSet::match_name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDecision {
    /// The name is blocked by a rule whose primary source is `source`.
    Block { source: i64 },
    /// A `@@` exception covers the name and suppresses the block; `source`
    /// is the exception rule's primary source.
    Exception { source: i64 },
}

impl BlockDecision {
    /// `true` if this decision is a block (not an exception).
    #[must_use]
    pub fn is_block(self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// `true` if this decision is an exception (block suppressed).
    #[must_use]
    pub fn is_exception(self) -> bool {
        matches!(self, Self::Exception { .. })
    }

    /// The `blocklist_id` of the rule that produced this decision.
    #[must_use]
    pub fn source(self) -> i64 {
        match self {
            Self::Block { source } | Self::Exception { source } => source,
        }
    }
}

/// Walk `search` (a normalized FQDN with trailing dot) and its ancestors,
/// probing `map` at each step.  Most-specific (leftmost) match wins.
///
/// The walk is bounded by the label count: each iteration slices off one
/// label and stops when nothing remains.  The root (`.`) is never probed.
/// No allocation — every candidate is a `&str` slice of the original.
fn walk_labels(map: &HashMap<Name, i64>, mut search: &str) -> Option<i64> {
    loop {
        if let Some(&id) = map.get(search) {
            return Some(id);
        }
        let pos = search.find('.')?;
        search = &search[pos + 1..];
        if search.is_empty() {
            return None;
        }
    }
}

/// Resolve the blocking source for `name`: exact probe first, then the
/// suffix ancestor walk.  `None` if no blocking rule matches.
fn block_source(tiers: &AttributedTiers, name: &Name) -> Option<i64> {
    if let Some(&id) = tiers.exact.get(name.as_str()) {
        return Some(id);
    }
    walk_labels(&tiers.suffix, name.as_str())
}

impl AttributedSet {
    /// Construct an [`AttributedSet`] pre-populated with an exact-tier `map`.
    #[must_use]
    pub fn new(map: HashMap<Name, i64>) -> Self {
        Self::new_tiered(AttributedTiers {
            exact: map,
            suffix: HashMap::new(),
            exceptions: HashMap::new(),
        })
    }

    /// Construct an [`AttributedSet`] from all three tiers.
    #[must_use]
    pub fn new_tiered(tiers: AttributedTiers) -> Self {
        Self {
            inner: HotSwap::new(tiers),
        }
    }

    /// Construct an empty [`AttributedSet`].
    ///
    /// The blocklist starts empty and is filled by the background refresh
    /// scheduler (E7) via the aggregator's `install`.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(HashMap::new())
    }

    // ── Hot-path reads ────────────────────────────────────────────────────────

    /// Return the hot-path blocklist decision for `name`.
    ///
    /// Matching order (E19):
    ///
    /// 1. Exact probe of the `exact` tier.
    /// 2. Ancestor walk of the `suffix` tier (most-specific first, apex
    ///    included, root never probed).
    /// 3. Only when a block match was found: ancestor walk of the
    ///    `exceptions` tier — a hit suppresses the block.
    ///
    /// The work is a handful of hash probes (one exact + at most one per
    /// name label, plus the exception walk on a hit) with **no allocation**.
    /// Returns `None` when no blocking rule matches.
    #[must_use]
    pub fn match_name(&self, name: &Name) -> Option<BlockDecision> {
        let snap = self.inner.snapshot();
        let source = block_source(&snap, name)?;

        if let Some(exc) = walk_labels(&snap.exceptions, name.as_str()) {
            return Some(BlockDecision::Exception { source: exc });
        }

        Some(BlockDecision::Block { source })
    }

    /// Return `true` if `name` is blocked by any tier (exact or suffix).
    ///
    /// This is the hot-path presence check; it is a cheap atomic load plus
    /// hash probes and never blocks.  Exceptions are **not** consulted here —
    /// the decision layer uses [`match_name`](AttributedSet::match_name) when
    /// it needs exception-aware semantics (E19.3).
    #[must_use]
    pub fn contains(&self, name: &Name) -> bool {
        block_source(&self.inner.snapshot(), name).is_some()
    }

    /// Return the primary `blocklist_id` for `name`, or `None` if it is not
    /// blocked.
    ///
    /// Resolves an exact-tier hit first, then the most-specific suffix-tier
    /// ancestor.  Used off the hot path by the query-log writer (E11.3) to
    /// attribute a block to the source that introduced the name.
    #[must_use]
    pub fn primary_source(&self, name: &Name) -> Option<i64> {
        block_source(&self.inner.snapshot(), name)
    }

    /// Load the current snapshot as a short-lived [`Guard`]
    /// (see [`HotSwap::snapshot`]).
    #[must_use]
    pub fn snapshot(&self) -> Guard<Arc<AttributedTiers>> {
        self.inner.snapshot()
    }

    /// Load the current snapshot as a full, owned [`Arc`]
    /// (see [`HotSwap::load_full`]).
    #[must_use]
    pub fn load_full(&self) -> Arc<AttributedTiers> {
        self.inner.load_full()
    }

    /// Return the number of blocking entries (exact + suffix tiers) in the
    /// current snapshot.
    ///
    /// Exception rules are not blocking entries and are not counted; they are
    /// available via [`exceptions_len`](AttributedSet::exceptions_len).
    #[must_use]
    pub fn len(&self) -> usize {
        let snap = self.inner.snapshot();
        snap.exact.len() + snap.suffix.len()
    }

    /// Return the number of exception rules in the current snapshot.
    #[must_use]
    pub fn exceptions_len(&self) -> usize {
        self.inner.snapshot().exceptions.len()
    }

    /// Return `true` if the current snapshot has no blocking entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ── Rebuild-and-swap writer ───────────────────────────────────────────────

    /// Atomically install `map` as the new exact tier, clearing the suffix
    /// and exception tiers.
    ///
    /// The caller (the aggregator) builds the map *off* the hot path; the
    /// install gives the [`HotSwap`] no-torn-read guarantee.  Tiered callers
    /// should use [`store_tiers`](AttributedSet::store_tiers) instead.
    pub fn store(&self, map: HashMap<Name, i64>) {
        self.store_tiers(AttributedTiers {
            exact: map,
            suffix: HashMap::new(),
            exceptions: HashMap::new(),
        });
    }

    /// Atomically install all three tiers as the new current snapshot.
    ///
    /// The caller (the aggregator) builds the tiers *off* the hot path; the
    /// install gives the [`HotSwap`] no-torn-read guarantee.
    pub fn store_tiers(&self, tiers: AttributedTiers) {
        self.inner.store(tiers);
    }

    /// Atomically install a pre-boxed snapshot (see [`HotSwap::store_arc`]).
    pub fn store_arc(&self, arc: Arc<AttributedTiers>) {
        self.inner.store_arc(arc);
    }
}

impl Default for AttributedSet {
    /// An empty [`AttributedSet`].
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for AttributedSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snap = self.inner.snapshot();
        f.debug_struct("AttributedSet")
            .field("exact", &snap.exact.len())
            .field("suffix", &snap.suffix.len())
            .field("exceptions", &snap.exceptions.len())
            .finish()
    }
}

impl FromIterator<(Name, i64)> for AttributedSet {
    /// Build an [`AttributedSet`] from an iterator of `(name, blocklist_id)`
    /// pairs.  On duplicate names the last pair wins (standard [`HashMap`]
    /// collection semantics); the aggregator instead enforces first-writer-wins
    /// before constructing the map.
    fn from_iter<I: IntoIterator<Item = (Name, i64)>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, thread};

    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        s.parse().expect("valid domain name")
    }

    fn set_of(names: &[&str]) -> HashSet<Name> {
        names.iter().map(|s| name(s)).collect()
    }

    // ── Construction ─────────────────────────────────────────────────────────

    #[test]
    fn empty_is_empty() {
        let ms = MatchSet::empty();
        assert!(ms.is_empty());
        assert_eq!(ms.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let ms = MatchSet::default();
        assert!(ms.is_empty());
    }

    #[test]
    fn new_with_set() {
        let ms = MatchSet::new(set_of(&["example.com", "ads.example.net"]));
        assert_eq!(ms.len(), 2);
        assert!(!ms.is_empty());
    }

    #[test]
    fn from_iterator() {
        let ms: MatchSet = ["a.com", "b.com", "c.com"]
            .iter()
            .map(|s| name(s))
            .collect();
        assert_eq!(ms.len(), 3);
    }

    // ── Lookup: hit and miss ──────────────────────────────────────────────────

    #[test]
    fn contains_hit() {
        let ms = MatchSet::new(set_of(&["blocked.example.com", "ads.tracker.net"]));
        assert!(ms.contains(&name("blocked.example.com")));
        assert!(ms.contains(&name("ads.tracker.net")));
    }

    #[test]
    fn contains_miss() {
        let ms = MatchSet::new(set_of(&["blocked.example.com"]));
        assert!(!ms.contains(&name("safe.example.com")));
        assert!(!ms.contains(&name("example.com")));
        assert!(!ms.contains(&name("other.net")));
    }

    #[test]
    fn contains_case_insensitive() {
        // Name normalizes to lowercase, so mixed-case lookups must still hit.
        let ms = MatchSet::new(set_of(&["Blocked.Example.COM"]));
        assert!(ms.contains(&name("blocked.example.com")));
        assert!(ms.contains(&name("BLOCKED.EXAMPLE.COM")));
    }

    #[test]
    fn empty_contains_nothing() {
        let ms = MatchSet::empty();
        assert!(!ms.contains(&name("example.com")));
    }

    // ── snapshot / load_full ──────────────────────────────────────────────────

    #[test]
    fn snapshot_reflects_current_set() {
        let ms = MatchSet::new(set_of(&["a.com", "b.com"]));
        let snap = ms.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains(&name("a.com")));
    }

    #[test]
    fn load_full_reflects_current_set() {
        let ms = MatchSet::new(set_of(&["x.org"]));
        let arc = ms.load_full();
        assert!(arc.contains(&name("x.org")));
    }

    // ── store: atomic swap ────────────────────────────────────────────────────

    #[test]
    fn store_replaces_set() {
        let ms = MatchSet::new(set_of(&["old.com"]));
        assert!(ms.contains(&name("old.com")));

        ms.store(set_of(&["new.com", "other.net"]));

        // New entries visible.
        assert!(ms.contains(&name("new.com")));
        assert!(ms.contains(&name("other.net")));
        // Old entry gone.
        assert!(!ms.contains(&name("old.com")));
        assert_eq!(ms.len(), 2);
    }

    #[test]
    fn store_arc_replaces_set() {
        let ms = MatchSet::new(set_of(&["before.com"]));
        ms.store_arc(Arc::new(set_of(&["after.com"])));
        assert!(ms.contains(&name("after.com")));
        assert!(!ms.contains(&name("before.com")));
    }

    #[test]
    fn store_empty_clears_set() {
        let ms = MatchSet::new(set_of(&["a.com", "b.com"]));
        ms.store(HashSet::new());
        assert!(ms.is_empty());
        assert!(!ms.contains(&name("a.com")));
    }

    // ── Concurrency: consistent snapshots ────────────────────────────────────

    /// Prove that each load returns a consistent whole-set snapshot.
    ///
    /// Two sets are constructed so they are entirely disjoint:
    ///   V1 = { "alpha.com", "beta.com" }
    ///   V2 = { "gamma.com", "delta.com" }
    ///
    /// Invariant: within any single snapshot, membership is all-or-nothing for
    /// each version.  A reader that sees `alpha.com` must also see `beta.com`
    /// and must NOT see either V2 member — a torn read would violate this.
    ///
    /// Reader threads repeatedly call `contains` on all four names, checking
    /// the invariant on every iteration.  A writer thread repeatedly swaps
    /// between V1 and V2.  With `ArcSwap` each `load` is guaranteed to return
    /// a consistent `Arc` snapshot, so the invariant always holds.
    #[test]
    fn concurrent_store_and_contains_sees_consistent_snapshot() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let v1 = Arc::new(set_of(&["alpha.com", "beta.com"]));
        let v2 = Arc::new(set_of(&["gamma.com", "delta.com"]));

        let ms = Arc::new(MatchSet::new((*v1).clone()));

        let stop = Arc::new(AtomicBool::new(false));

        // Spawn reader threads.
        const READER_THREADS: usize = 4;
        let mut handles = Vec::with_capacity(READER_THREADS + 1);

        for _ in 0..READER_THREADS {
            let ms_r = Arc::clone(&ms);
            let stop_r = Arc::clone(&stop);
            let alpha = name("alpha.com");
            let beta = name("beta.com");
            let gamma = name("gamma.com");
            let delta = name("delta.com");

            handles.push(thread::spawn(move || {
                while !stop_r.load(Ordering::Relaxed) {
                    // Load via snapshot so we operate on a single consistent Arc.
                    let snap = ms_r.snapshot();

                    let in_v1 = snap.contains(&alpha);
                    let also_v1 = snap.contains(&beta);
                    let in_v2 = snap.contains(&gamma);
                    let also_v2 = snap.contains(&delta);

                    // Within a single snapshot, V1 members must agree.
                    assert_eq!(in_v1, also_v1, "torn V1 read: alpha={in_v1} beta={also_v1}");
                    // Within a single snapshot, V2 members must agree.
                    assert_eq!(
                        in_v2, also_v2,
                        "torn V2 read: gamma={in_v2} delta={also_v2}"
                    );
                    // The snapshot must be exactly one of V1 or V2.
                    assert_ne!(
                        in_v1, in_v2,
                        "snapshot mixed V1 and V2: alpha={in_v1} gamma={in_v2}"
                    );
                }
            }));
        }

        // Writer thread: alternate between V1 and V2.
        {
            let ms_w = Arc::clone(&ms);
            let stop_w = Arc::clone(&stop);
            let v1_w = Arc::clone(&v1);
            let v2_w = Arc::clone(&v2);

            handles.push(thread::spawn(move || {
                for i in 0..2_000 {
                    if i % 2 == 0 {
                        ms_w.store_arc(Arc::clone(&v2_w));
                    } else {
                        ms_w.store_arc(Arc::clone(&v1_w));
                    }
                }
                stop_w.store(true, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    // ── Debug ─────────────────────────────────────────────────────────────────

    #[test]
    fn debug_shows_len() {
        let ms = MatchSet::new(set_of(&["a.com", "b.com", "c.com"]));
        let s = format!("{ms:?}");
        assert!(s.contains("len: 3"), "debug output was: {s}");
    }

    // ── AttributedSet ─────────────────────────────────────────────────────────

    /// Build an [`AttributedSet`] from `(name, id)` pairs.
    fn attributed(entries: &[(&str, i64)]) -> AttributedSet {
        entries.iter().map(|(n, id)| (name(n), *id)).collect()
    }

    #[test]
    fn attributed_empty_is_empty() {
        let set = AttributedSet::empty();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.primary_source(&name("anything.com")), None);
    }

    #[test]
    fn attributed_default_is_empty() {
        assert!(AttributedSet::default().is_empty());
    }

    /// `contains` is parity with the old set: membership matches the map's keys.
    #[test]
    fn attributed_contains_matches_keys() {
        let set = attributed(&[("ads.example.com", 1), ("tracker.net", 2)]);
        assert!(set.contains(&name("ads.example.com")));
        assert!(set.contains(&name("tracker.net")));
        assert!(!set.contains(&name("safe.example.com")));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn attributed_contains_case_insensitive() {
        let set = attributed(&[("Blocked.Example.COM", 5)]);
        assert!(set.contains(&name("blocked.example.com")));
        assert!(set.contains(&name("BLOCKED.EXAMPLE.COM")));
    }

    /// `primary_source` returns the stored id, and `None` for non-members.
    #[test]
    fn attributed_primary_source_returns_id_or_none() {
        let set = attributed(&[("ads.example.com", 42), ("tracker.net", 7)]);
        assert_eq!(set.primary_source(&name("ads.example.com")), Some(42));
        assert_eq!(set.primary_source(&name("tracker.net")), Some(7));
        assert_eq!(set.primary_source(&name("safe.example.com")), None);
    }

    #[test]
    fn attributed_store_replaces_snapshot() {
        let set = attributed(&[("old.com", 1)]);
        assert_eq!(set.primary_source(&name("old.com")), Some(1));

        set.store(
            [(name("new.com"), 9)]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        );

        assert_eq!(set.primary_source(&name("new.com")), Some(9));
        assert!(!set.contains(&name("old.com")));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn attributed_snapshot_and_load_full_reflect_current() {
        let set = attributed(&[("a.com", 3)]);
        assert_eq!(set.snapshot().exact.get(&name("a.com")).copied(), Some(3));
        assert_eq!(set.load_full().exact.get(&name("a.com")).copied(), Some(3));
    }

    #[test]
    fn attributed_debug_shows_tiers() {
        let set = AttributedSet::new_tiered(AttributedTiers {
            exact: attributed_map(&[("a.com", 1)]),
            suffix: attributed_map(&[("b.com", 2), ("c.net", 3)]),
            exceptions: attributed_map(&[("safe.b.com", 2)]),
        });
        let s = format!("{set:?}");
        assert!(
            s.contains("exact: 1") && s.contains("suffix: 2") && s.contains("exceptions: 1"),
            "debug output was: {s}"
        );
    }

    // ── Tiered matching (E19) ─────────────────────────────────────────────────

    /// Build a `Name → id` map from `(name, id)` pairs.
    fn attributed_map(entries: &[(&str, i64)]) -> HashMap<Name, i64> {
        entries
            .iter()
            .map(|(n, id)| (name(n), *id))
            .collect::<HashMap<_, _>>()
    }

    fn tiers_of(
        exact: &[(&str, i64)],
        suffix: &[(&str, i64)],
        exceptions: &[(&str, i64)],
    ) -> AttributedTiers {
        AttributedTiers {
            exact: attributed_map(exact),
            suffix: attributed_map(suffix),
            exceptions: attributed_map(exceptions),
        }
    }

    /// An exact-tier hit blocks the name itself and attributes to its source.
    #[test]
    fn tiered_exact_hit_blocks_with_source() {
        let set = AttributedSet::new_tiered(tiers_of(&[("ads.example.com", 7)], &[], &[]));
        assert_eq!(
            set.match_name(&name("ads.example.com")),
            Some(BlockDecision::Block { source: 7 })
        );
        // Exact rules never match subdomains.
        assert_eq!(set.match_name(&name("sub.ads.example.com")), None);
    }

    /// A suffix rule blocks its apex and every subdomain, most-specific
    /// ancestor first, with the rule's source as attribution.
    #[test]
    fn tiered_suffix_blocks_apex_and_subdomains() {
        let set = AttributedSet::new_tiered(tiers_of(&[], &[("doubleclick.net", 3)], &[]));
        for qname in [
            "doubleclick.net",
            "stats.doubleclick.net",
            "a.b.stats.doubleclick.net",
        ] {
            assert_eq!(
                set.match_name(&name(qname)),
                Some(BlockDecision::Block { source: 3 }),
                "{qname} must be blocked by the suffix rule"
            );
        }
        assert_eq!(set.match_name(&name("doubleclick.org")), None);
    }

    /// A deeper suffix rule wins over a shallower one (most-specific first).
    #[test]
    fn tiered_suffix_most_specific_wins() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[],
            &[("example.com", 1), ("ads.example.com", 9)],
            &[],
        ));
        assert_eq!(
            set.match_name(&name("x.ads.example.com")),
            Some(BlockDecision::Block { source: 9 })
        );
        assert_eq!(
            set.match_name(&name("www.example.com")),
            Some(BlockDecision::Block { source: 1 })
        );
    }

    /// An exact-tier hit takes precedence over a suffix-tier ancestor.
    #[test]
    fn tiered_exact_beats_suffix() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[("mail.example.com", 2)],
            &[("example.com", 1)],
            &[],
        ));
        assert_eq!(
            set.match_name(&name("mail.example.com")),
            Some(BlockDecision::Block { source: 2 })
        );
    }

    /// An exception suppresses both exact and suffix blocks for the name and
    /// its subdomains, and carries the exception's source.
    #[test]
    fn tiered_exception_suppresses_block() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[("banned.example.net", 1)],
            &[("example.net", 2)],
            &[("safe.example.net", 4)],
        ));
        for qname in ["safe.example.net", "deep.safe.example.net"] {
            assert_eq!(
                set.match_name(&name(qname)),
                Some(BlockDecision::Exception { source: 4 }),
                "{qname} must be excepted"
            );
        }
        // A sibling under the same suffix is still blocked.
        assert_eq!(
            set.match_name(&name("other.example.net")),
            Some(BlockDecision::Block { source: 2 })
        );
    }

    /// An exception on its own never blocks anything.
    #[test]
    fn tiered_exception_alone_does_not_block() {
        let set = AttributedSet::new_tiered(tiers_of(&[], &[], &[("safe.example.net", 4)]));
        assert_eq!(set.match_name(&name("safe.example.net")), None);
        assert_eq!(set.match_name(&name("sub.safe.example.net")), None);
        assert!(!set.contains(&name("safe.example.net")));
    }

    /// No exceptions are consulted when no block matched (hot-path budget).
    #[test]
    fn tiered_no_block_no_exception_walk() {
        // An exception that is also an ancestor of the queried name but the
        // name is not blocked → None, not an Exception decision.
        let set = AttributedSet::new_tiered(tiers_of(
            &[],
            &[("ads.example.net", 1)],
            &[("example.net", 5)],
        ));
        // Blocked, but the more general exception does not cover the deeper
        // suffix hit — wait: example.net IS an ancestor, so it excepts.
        assert_eq!(
            set.match_name(&name("ads.example.net")),
            Some(BlockDecision::Exception { source: 5 })
        );
        // Unblocked name → None (exception never manufactures a decision).
        assert_eq!(set.match_name(&name("www.example.net")), None);
    }

    /// `contains` ignores exceptions (pure presence check).
    #[test]
    fn tiered_contains_ignores_exceptions() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[],
            &[("example.net", 1)],
            &[("safe.example.net", 2)],
        ));
        assert!(set.contains(&name("safe.example.net")));
        assert!(
            set.match_name(&name("safe.example.net"))
                .unwrap()
                .is_exception()
        );
    }

    /// `len` counts blocking entries only; `exceptions_len` the rest.
    #[test]
    fn tiered_len_counts_blocking_entries_only() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[("a.com", 1)],
            &[("b.com", 1), ("c.com", 2)],
            &[("safe.b.com", 2)],
        ));
        assert_eq!(set.len(), 3);
        assert_eq!(set.exceptions_len(), 1);
        assert!(!set.is_empty());
    }

    /// `store_tiers` replaces the whole snapshot; stale entries in every tier
    /// are gone.
    #[test]
    fn tiered_store_tiers_replaces_everything() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[("stale.com", 1)],
            &[("old.net", 2)],
            &[("gone.org", 3)],
        ));

        set.store_tiers(tiers_of(
            &[("fresh.com", 9)],
            &[("new.net", 8)],
            &[("ok.net", 7)],
        ));

        assert!(set.contains(&name("fresh.com")));
        assert!(set.contains(&name("sub.new.net")));
        assert_eq!(
            set.match_name(&name("ok.net")),
            None,
            "exception alone never blocks"
        );
        assert!(!set.contains(&name("stale.com")));
        assert!(!set.contains(&name("old.net")));
        assert_eq!(set.exceptions_len(), 1);
    }

    /// The flat `store` path (exact-only callers) clears suffix + exceptions.
    #[test]
    fn flat_store_clears_other_tiers() {
        let set = AttributedSet::new_tiered(tiers_of(
            &[("a.com", 1)],
            &[("b.com", 2)],
            &[("safe.b.com", 3)],
        ));

        set.store(attributed_map(&[("c.com", 4)]));

        assert!(set.contains(&name("c.com")));
        assert!(!set.contains(&name("b.com")));
        assert!(!set.contains(&name("sub.b.com")));
        assert_eq!(set.exceptions_len(), 0);
    }

    /// The root is never probed: a rule for the root zone is unreachable by
    /// the walk, and single-label names terminate cleanly.
    #[test]
    fn tiered_walk_terminates_on_tld() {
        let set = AttributedSet::new_tiered(tiers_of(&[], &[("com", 1)], &[]));
        // "com." itself matches (the apex is probed)…
        assert_eq!(
            set.match_name(&name("com")),
            Some(BlockDecision::Block { source: 1 })
        );
        // …and the walk stops after the last label without probing root.
        assert!(set.contains(&name("anything.com")));
        assert_eq!(set.match_name(&name("org")), None);
    }
}
