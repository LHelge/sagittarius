//! A tiny wall-clock helper shared across subsystems.
//!
//! Sessions, the blocklist scheduler, and a few admin views all need "now" as
//! whole seconds since the Unix epoch.  Rather than repeat the `SystemTime`
//! incantation, they go through [`Clock`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A [`Duration`] of `n` whole days.
///
/// Centralizes the day→seconds arithmetic that would otherwise appear as bare
/// `n * 24 * 3600` / `n * 86_400_000` literals across the retention purge,
/// dashboard window, and session-timeout constants. `const fn`, so it can seed
/// `const` values.
pub const fn days(n: u64) -> Duration {
    Duration::from_secs(n * 86_400)
}

/// The system wall clock, expressed as whole seconds since the Unix epoch.
pub struct Clock;

impl Clock {
    /// Current Unix time in whole seconds.
    ///
    /// Saturates to `0` if the system clock is somehow set before the epoch
    /// (rather than panicking), matching the previous per-call-site behavior.
    pub fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Current Unix time in whole milliseconds.
    ///
    /// Used for the persistent query log (E10), where sub-second ordering of a
    /// high-rate event stream matters. Saturates to `0` before the epoch, like
    /// [`Clock::now_secs`].
    pub fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Epoch-millisecond cutoff `d` in the past — i.e. `now_millis() - d`.
    ///
    /// The single place "now minus a window" is computed for retention/dashboard
    /// boundaries, so the duration unit is converted once instead of via bare
    /// `* 86_400_000` arithmetic at each call site.
    pub fn millis_ago(d: Duration) -> i64 {
        Self::now_millis() - d.as_millis() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_is_positive_and_monotonicish() {
        let a = Clock::now_secs();
        let b = Clock::now_secs();
        assert!(a > 1_700_000_000, "clock should be well past 2023: {a}");
        assert!(b >= a, "time should not go backwards within a test");
    }

    #[test]
    fn days_converts_to_seconds() {
        assert_eq!(days(0), Duration::ZERO);
        assert_eq!(days(1).as_secs(), 86_400);
        assert_eq!(days(30).as_secs(), 2_592_000);
    }

    #[test]
    fn millis_ago_subtracts_the_window() {
        let before = Clock::now_millis();
        let cutoff = Clock::millis_ago(days(1));
        let after = Clock::now_millis();
        // cutoff must be ~one day behind "now", bracketed by readings around it.
        assert!(cutoff <= before - 86_400_000 + 5);
        assert!(cutoff >= after - 86_400_000 - 5);
    }

    #[test]
    fn now_millis_is_positive_and_consistent_with_secs() {
        let millis = Clock::now_millis();
        let secs = Clock::now_secs();
        assert!(
            millis > 1_700_000_000_000,
            "millis clock should be well past 2023: {millis}"
        );
        // The two clocks must agree to within a second of each other.
        assert!(
            (millis / 1000 - secs).abs() <= 1,
            "now_millis/1000 ({}) must track now_secs ({secs})",
            millis / 1000
        );
    }
}
