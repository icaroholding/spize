//! Exponential-backoff retry helpers keyed to the normative AEX retry policy.
//!
//! See `docs/protocol-v1.md` §5.1 for the wire-level normative spec. This
//! module is the single Rust implementation of that algorithm; the Python
//! and TypeScript SDKs carry conforming reimplementations.

use std::future::Future;
use std::time::Duration;

use rand::Rng;

/// Exponential-backoff retry policy with bounded jitter.
///
/// Sleep computed for the Nth retry (1-indexed, where N=1 is the initial
/// attempt with no delay):
///
/// ```text
/// sleep(n) = 0                                   if n == 1
/// sleep(n) = base * multiplier^(n-2) + U(-jitter, +jitter)   otherwise
/// ```
///
/// The jitter is clamped so the sleep never goes negative.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum attempts including the first. Must be ≥ 1.
    pub max_attempts: u32,
    /// Base delay used for the first retry.
    pub base_delay: Duration,
    /// Multiplier applied between successive retries.
    pub multiplier: f64,
    /// Absolute jitter sampled uniformly in `[-jitter, +jitter]` per retry.
    pub jitter: Duration,
}

impl RetryPolicy {
    /// The normative AEX retry policy defined in `docs/protocol-v1.md` §5.1:
    /// 3 attempts, 1 s base, 2× multiplier, ±100 ms jitter.
    ///
    /// All AEX components — Rust, Python SDK, TypeScript SDK — must behave
    /// identically when retrying a network operation against an AEX control
    /// or data plane. The conformance test at `tests/conformance/retry.rs`
    /// pins the values here to the spec.
    pub const fn normative() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_secs(1),
            multiplier: 2.0,
            jitter: Duration::from_millis(100),
        }
    }

    /// Compute the backoff to sleep *before* attempt `n` (1-indexed).
    ///
    /// For `n == 1` returns [`Duration::ZERO`] — the first attempt runs
    /// immediately. For `n ≥ 2`, samples a jittered exponential value.
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        let exp = (attempt - 2) as i32;
        let base_secs = self.base_delay.as_secs_f64() * self.multiplier.powi(exp);
        let jitter_secs = self.jitter.as_secs_f64();
        let j = if jitter_secs > 0.0 {
            rand::thread_rng().gen_range(-jitter_secs..=jitter_secs)
        } else {
            0.0
        };
        let total = (base_secs + j).max(0.0);
        Duration::from_secs_f64(total)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::normative()
    }
}

/// Run an async operation with bounded retry on failure.
///
/// - `policy` controls max attempts and backoff curve.
/// - `should_retry` is invoked with each error and returns whether to retry.
///   Callers pass a closure that inspects the error type, e.g.
///   `|e| e.is_timeout() || e.is_connect()` for `reqwest::Error`. Returning
///   `false` short-circuits the loop on non-transient failures.
/// - `op` is the async operation. It is re-invoked once per retry.
///
/// A `tracing::debug!` event is emitted per failed attempt with the attempt
/// number and the formatted error, so callers get per-retry observability
/// without having to instrument manually.
///
/// Returns the first `Ok` from `op`, or the last `Err` on exhaustion /
/// short-circuit.
pub async fn retry_with_backoff<F, Fut, T, E, S>(
    policy: &RetryPolicy,
    mut should_retry: S,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    S: FnMut(&E) -> bool,
    E: std::fmt::Debug,
{
    assert!(
        policy.max_attempts >= 1,
        "RetryPolicy::max_attempts must be >= 1"
    );

    for attempt in 1..=policy.max_attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                let is_last = attempt == policy.max_attempts;
                let retriable = should_retry(&e);
                tracing::debug!(
                    attempt,
                    max_attempts = policy.max_attempts,
                    retriable,
                    err = ?e,
                    "retry_with_backoff attempt failed"
                );
                if is_last || !retriable {
                    return Err(e);
                }
                let wait = policy.backoff_for_attempt(attempt + 1);
                tokio::time::sleep(wait).await;
            }
        }
    }

    unreachable!("the for-loop always returns on the final attempt");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn normative_matches_protocol_v1_spec() {
        let p = RetryPolicy::normative();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.base_delay, Duration::from_secs(1));
        assert!((p.multiplier - 2.0).abs() < f64::EPSILON);
        assert_eq!(p.jitter, Duration::from_millis(100));
    }

    #[test]
    fn default_equals_normative() {
        let d = RetryPolicy::default();
        let n = RetryPolicy::normative();
        assert_eq!(d.max_attempts, n.max_attempts);
        assert_eq!(d.base_delay, n.base_delay);
        assert_eq!(d.jitter, n.jitter);
    }

    #[test]
    fn first_attempt_has_zero_backoff() {
        let p = RetryPolicy::normative();
        assert_eq!(p.backoff_for_attempt(1), Duration::ZERO);
        assert_eq!(p.backoff_for_attempt(0), Duration::ZERO);
    }

    #[test]
    fn second_attempt_jitter_is_bounded() {
        let p = RetryPolicy::normative();
        // Attempt 2: base * 2^0 = 1s, jitter ±100ms → range [900ms, 1100ms].
        for _ in 0..500 {
            let d = p.backoff_for_attempt(2);
            assert!(
                d >= Duration::from_millis(900) && d <= Duration::from_millis(1100),
                "attempt 2 backoff {d:?} out of [900ms, 1100ms]"
            );
        }
    }

    #[test]
    fn third_attempt_doubles_base() {
        let p = RetryPolicy::normative();
        // Attempt 3: base * 2^1 = 2s, jitter ±100ms → range [1900ms, 2100ms].
        for _ in 0..500 {
            let d = p.backoff_for_attempt(3);
            assert!(
                d >= Duration::from_millis(1900) && d <= Duration::from_millis(2100),
                "attempt 3 backoff {d:?} out of [1900ms, 2100ms]"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn succeeds_on_first_attempt() {
        let p = RetryPolicy::normative();
        let attempts = AtomicU32::new(0);
        let result: Result<i32, &'static str> = retry_with_backoff(
            &p,
            |_| true,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Ok(42) }
            },
        )
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn succeeds_after_two_transient_failures() {
        let p = RetryPolicy::normative();
        let attempts = AtomicU32::new(0);
        let result: Result<i32, &'static str> = retry_with_backoff(
            &p,
            |_| true,
            || {
                let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if n < 3 {
                        Err("transient")
                    } else {
                        Ok(7)
                    }
                }
            },
        )
        .await;
        assert_eq!(result, Ok(7));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_last_error_on_exhaustion() {
        let p = RetryPolicy::normative();
        let attempts = AtomicU32::new(0);
        let result: Result<i32, &'static str> = retry_with_backoff(
            &p,
            |_| true,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err("always fails") }
            },
        )
        .await;
        assert_eq!(result, Err("always fails"));
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "must run exactly max_attempts"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_retriable_error_short_circuits() {
        let p = RetryPolicy::normative();
        let attempts = AtomicU32::new(0);
        let result: Result<i32, &'static str> = retry_with_backoff(
            &p,
            |e| *e != "permanent",
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err("permanent") }
            },
        )
        .await;
        assert_eq!(result, Err("permanent"));
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "non-retriable must not retry"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// For any valid attempt number, the actual backoff must stay within
        /// `[deterministic_base - jitter, deterministic_base + jitter]`,
        /// clamped to non-negative.
        #[test]
        fn backoff_jitter_within_bound(attempt in 2u32..8) {
            let p = RetryPolicy::normative();
            let d = p.backoff_for_attempt(attempt);

            let exp = (attempt - 2) as i32;
            let base_ms = (p.base_delay.as_secs_f64() * p.multiplier.powi(exp) * 1000.0) as u128;
            let jitter_ms = p.jitter.as_millis();
            let lower = base_ms.saturating_sub(jitter_ms);
            let upper = base_ms + jitter_ms;
            let d_ms = d.as_millis();

            prop_assert!(
                d_ms >= lower && d_ms <= upper,
                "attempt={attempt}: backoff={d_ms}ms not in [{lower}, {upper}]"
            );
        }

        /// Deterministic component (base × multiplier^(n-2)) grows monotonically
        /// with the attempt number. We check the deterministic component
        /// because the jittered samples aren't monotone on individual draws.
        #[test]
        fn deterministic_component_is_monotone(
            a in 2u32..6,
            b_offset in 1u32..=4
        ) {
            let p = RetryPolicy::normative();
            let b = a + b_offset;
            let det_a = p.base_delay.as_secs_f64() * p.multiplier.powi((a - 2) as i32);
            let det_b = p.base_delay.as_secs_f64() * p.multiplier.powi((b - 2) as i32);
            prop_assert!(det_b >= det_a, "det({b})={det_b} < det({a})={det_a}");
        }
    }
}
