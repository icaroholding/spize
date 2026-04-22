//! Injectable clock for deterministic time in tests.
//!
//! Per decision 9 (Sprint 2 plan-eng-review 2026-04-21), handlers that
//! need "now" (freshness windows, key-rotation grace periods, ticket
//! expiries) take time from a [`Clock`] in [`AppState`] rather than
//! calling [`time::OffsetDateTime::now_utc`] directly. Production runs
//! with [`SystemClock`]; tests that need to advance time (e.g. crossing
//! the 24h rotation grace boundary) swap in [`FrozenClock`] and step
//! forward explicitly.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

/// Abstract source of wall-clock time.
///
/// Implementations return an [`OffsetDateTime`] with sub-second
/// precision — this matters for the rotation-grace filter, which
/// compares `valid_from` (DB `TIMESTAMPTZ` with microsecond precision)
/// against `at`. A truncated-to-seconds `at` could end up BEHIND the
/// `valid_from` of a row that was inserted a few milliseconds earlier
/// in the same request's lifecycle, and the filter would wrongly
/// exclude it.
pub trait Clock: Send + Sync + 'static {
    /// Current wall-clock time. The default implementations below use
    /// microsecond precision; `now_unix` is derived by truncating.
    fn now(&self) -> OffsetDateTime;

    /// Current Unix timestamp in seconds. Matches the granularity of
    /// every `issued_at` field on the wire.
    fn now_unix(&self) -> i64 {
        self.now().unix_timestamp()
    }
}

/// Production clock: reads the system wall time.
#[derive(Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        Self
    }

    pub fn arc() -> Arc<dyn Clock> {
        Arc::new(Self)
    }
}

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Test-only clock that returns whatever the test last set with
/// [`FrozenClock::set`] or [`FrozenClock::advance`]. Interior mutability
/// via `AtomicI64` so tests can advance time from a spawned task
/// without threading a `&mut` through handler state.
#[derive(Debug)]
pub struct FrozenClock {
    now: AtomicI64,
}

impl FrozenClock {
    pub fn new(initial_unix: i64) -> Self {
        Self {
            now: AtomicI64::new(initial_unix),
        }
    }

    pub fn set(&self, now_unix: i64) {
        self.now.store(now_unix, Ordering::SeqCst);
    }

    pub fn advance(&self, by: Duration) {
        self.now.fetch_add(by.as_secs() as i64, Ordering::SeqCst);
    }
}

impl Clock for FrozenClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.now.load(Ordering::SeqCst))
            .expect("frozen clock timestamp out of range")
    }

    fn now_unix(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_clock_returns_initial() {
        let c = FrozenClock::new(1_700_000_000);
        assert_eq!(c.now_unix(), 1_700_000_000);
    }

    #[test]
    fn frozen_clock_advance() {
        let c = FrozenClock::new(1_700_000_000);
        c.advance(Duration::from_secs(3600));
        assert_eq!(c.now_unix(), 1_700_003_600);
    }

    #[test]
    fn frozen_clock_set_is_absolute() {
        let c = FrozenClock::new(1);
        c.set(1_700_000_000);
        assert_eq!(c.now_unix(), 1_700_000_000);
    }

    #[test]
    fn frozen_clock_now_offset_datetime_matches_unix() {
        let c = FrozenClock::new(1_700_000_000);
        assert_eq!(c.now().unix_timestamp(), 1_700_000_000);
    }

    #[test]
    fn system_clock_is_close_to_wall_time() {
        let c = SystemClock::new();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let seen = c.now_unix();
        assert!((seen - now).abs() <= 2, "system clock drifted too far");
    }
}
