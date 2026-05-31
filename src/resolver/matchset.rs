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
//! The DNS hot path reads the current snapshot with a cheap atomic load and
//! **never blocks**.  An admin edit or blocklist refresh builds a fresh
//! [`HashSet`]/[`HashMap`] *off* the hot path and atomically installs it with
//! [`MatchSet::store`]/[`AttributedSet::store`], so no reader ever sees a torn
//! or partially-updated set.  This is the core SPEC §3.2 guarantee.
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
    inner: ArcSwap<HashSet<Name>>,
}

impl MatchSet {
    /// Construct a [`MatchSet`] pre-populated with `set`.
    #[must_use]
    pub fn new(set: HashSet<Name>) -> Self {
        Self {
            inner: ArcSwap::from_pointee(set),
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
        self.inner.load().contains(name)
    }

    /// Load the current snapshot as a short-lived [`Guard`].
    ///
    /// The returned [`Guard`] holds a reference to the current [`Arc`] without
    /// incrementing its reference count, making it slightly cheaper than
    /// [`MatchSet::load_full`].  Prefer this for short-lived reads (single
    /// method call); use [`load_full`](MatchSet::load_full) when you need to
    /// keep the snapshot alive across await points or store it in a struct.
    #[must_use]
    pub fn snapshot(&self) -> Guard<Arc<HashSet<Name>>> {
        self.inner.load()
    }

    /// Load the current snapshot as a full, owned [`Arc`].
    ///
    /// Increments the reference count, so the snapshot stays alive as long as
    /// the returned [`Arc`] is held.  Use this when you need to keep the
    /// snapshot alive across an await point or store it alongside other data.
    #[must_use]
    pub fn load_full(&self) -> Arc<HashSet<Name>> {
        self.inner.load_full()
    }

    /// Return the number of entries in the current snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// Return `true` if the current snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }

    // ── Rebuild-and-swap writer ───────────────────────────────────────────────

    /// Atomically install `set` as the new current snapshot.
    ///
    /// The caller builds the new [`HashSet`] *off* the hot path; this method
    /// merely wraps it in an [`Arc`] and performs the atomic swap.  Readers
    /// that are mid-load continue using the previous snapshot until their
    /// [`Guard`]/[`Arc`] is dropped; new readers immediately see the new set.
    /// No reader ever observes a torn or partially-updated view.
    pub fn store(&self, set: HashSet<Name>) {
        self.store_arc(Arc::new(set));
    }

    /// Atomically install a pre-boxed snapshot.
    ///
    /// Useful when the caller has already wrapped the set in an [`Arc`], for
    /// example to share the same snapshot across multiple data structures
    /// without an extra allocation.
    pub fn store_arc(&self, arc: Arc<HashSet<Name>>) {
        self.inner.store(arc);
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
        let snap = self.inner.load();
        f.debug_struct("MatchSet")
            .field("len", &snap.len())
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
/// # Attribution model
///
/// Exactly one **primary** source is stored per name (first-writer-wins as the
/// aggregator iterates enabled sources in `blocklist_id` order, so the
/// lowest-id list wins an overlap).  This keeps the value a single `i64` — no
/// bitmask, no per-name source list — at the cost of not tracking every list a
/// domain appears on.
///
/// # Usage
///
/// ```rust
/// use std::collections::HashMap;
/// use sagittarius::resolver::matchset::AttributedSet;
/// use sagittarius::codec::name::Name;
///
/// let mut map: HashMap<Name, i64> = HashMap::new();
/// map.insert("ads.example.com".parse().unwrap(), 7);
///
/// let set = AttributedSet::new(map);
/// assert!(set.contains(&"ads.example.com".parse().unwrap()));
/// assert_eq!(set.primary_source(&"ads.example.com".parse().unwrap()), Some(7));
/// assert_eq!(set.primary_source(&"safe.example.com".parse().unwrap()), None);
/// ```
///
/// [`DecisionStack`]: crate::resolver::pipeline
pub struct AttributedSet {
    inner: ArcSwap<HashMap<Name, i64>>,
}

impl AttributedSet {
    /// Construct an [`AttributedSet`] pre-populated with `map`.
    #[must_use]
    pub fn new(map: HashMap<Name, i64>) -> Self {
        Self {
            inner: ArcSwap::from_pointee(map),
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

    /// Return `true` if `name` is a member of the current snapshot.
    ///
    /// This is the hot-path presence check used by the decision layer; it is a
    /// cheap atomic load followed by [`HashMap::contains_key`] and never blocks.
    /// The attribution value is intentionally ignored here so the decision
    /// layer stays a pure presence test.
    #[must_use]
    pub fn contains(&self, name: &Name) -> bool {
        self.inner.load().contains_key(name)
    }

    /// Return the primary `blocklist_id` for `name`, or `None` if it is not a
    /// member of the current snapshot.
    ///
    /// Used off the hot path by the query-log writer (E11.3) to attribute a
    /// block to the source that introduced the name.
    #[must_use]
    pub fn primary_source(&self, name: &Name) -> Option<i64> {
        self.inner.load().get(name).copied()
    }

    /// Load the current snapshot as a short-lived [`Guard`].
    #[must_use]
    pub fn snapshot(&self) -> Guard<Arc<HashMap<Name, i64>>> {
        self.inner.load()
    }

    /// Load the current snapshot as a full, owned [`Arc`].
    ///
    /// Increments the reference count so the snapshot stays alive as long as
    /// the returned [`Arc`] is held — use it when the snapshot must outlive an
    /// await point.
    #[must_use]
    pub fn load_full(&self) -> Arc<HashMap<Name, i64>> {
        self.inner.load_full()
    }

    /// Return the number of entries in the current snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// Return `true` if the current snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }

    // ── Rebuild-and-swap writer ───────────────────────────────────────────────

    /// Atomically install `map` as the new current snapshot.
    ///
    /// The caller (the aggregator) builds the `Name → blocklist_id` map *off*
    /// the hot path; this method wraps it in an [`Arc`] and performs the atomic
    /// swap with the same no-torn-read guarantee as [`MatchSet::store`].
    pub fn store(&self, map: HashMap<Name, i64>) {
        self.store_arc(Arc::new(map));
    }

    /// Atomically install a pre-boxed snapshot.
    pub fn store_arc(&self, arc: Arc<HashMap<Name, i64>>) {
        self.inner.store(arc);
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
        let snap = self.inner.load();
        f.debug_struct("AttributedSet")
            .field("len", &snap.len())
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
        assert_eq!(set.snapshot().get(&name("a.com")).copied(), Some(3));
        assert_eq!(set.load_full().get(&name("a.com")).copied(), Some(3));
    }

    #[test]
    fn attributed_debug_shows_len() {
        let set = attributed(&[("a.com", 1), ("b.com", 2)]);
        let s = format!("{set:?}");
        assert!(s.contains("len: 2"), "debug output was: {s}");
    }
}
