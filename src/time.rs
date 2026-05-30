//! A tiny wall-clock helper shared across subsystems.
//!
//! Sessions, the blocklist scheduler, and a few admin views all need "now" as
//! whole seconds since the Unix epoch.  Rather than repeat the `SystemTime`
//! incantation, they go through [`Clock`].

use std::time::{SystemTime, UNIX_EPOCH};

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
}
