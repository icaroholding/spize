//! Conformance: `RetryPolicy::normative()` must match `docs/protocol-v1.md` §5.1.
//!
//! Bumping any of these constants is a wire-level breaking change and requires
//! a coordinated update to the protocol spec, the Python SDK, and the
//! TypeScript SDK simultaneously.

use std::time::Duration;

use aex_net::RetryPolicy;

#[test]
fn normative_retry_policy_matches_protocol_v1_section_5_1() {
    let p = RetryPolicy::normative();

    assert_eq!(p.max_attempts, 3, "protocol-v1 §5.1 max_attempts");
    assert_eq!(
        p.base_delay,
        Duration::from_secs(1),
        "protocol-v1 §5.1 base_delay"
    );
    assert!(
        (p.multiplier - 2.0).abs() < f64::EPSILON,
        "protocol-v1 §5.1 multiplier"
    );
    assert_eq!(
        p.jitter,
        Duration::from_millis(100),
        "protocol-v1 §5.1 jitter"
    );
}
